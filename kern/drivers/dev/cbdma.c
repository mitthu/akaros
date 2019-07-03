/*
 * File: cbdma.c - Driver for using Intel CBDMA
 * Author: Aditya Basu <mitthu@google.com>
 */

#include <kmalloc.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <error.h>
#include <net/ip.h>
#include <linux_compat.h>
#include <arch/pci.h>
#include <page_alloc.h>
#include <pmap.h>
#include <cbdma_regs.h>
#include <arch/pci_regs.h>

struct dev                cbdmadevtab;
static struct pci_device  *pci;
static void               *mmio; /* TODO: assumes 64-bit architecture */
static void               *mmio_phy; /* physical addr */
static uint32_t           mmio_sz;
static bool               ktest_done = false;   /* TODO: needs locking */
static char               ktest_stats[4096];
static uint32_t           cbdma_status;

/* PCI config registers; from Intel Xeon E7 2800/4800/8800 Datasheet Vol. 2 */
static struct {
        uint32_t dmauncerrsts; /* DMA Cluster Uncorrectable Error Status */
        uint32_t chanerr_int;

} cbdmapciregs;

/* MMIO address space; from Intel Xeon E7 2800/4800/8800 Datasheet Vol. 2 */
static struct {
        uint8_t  chancnt;
        uint8_t  chancmd;
        uint8_t  xrefcap;
        uint8_t  cbver;
        uint16_t chanctrl;
        uint16_t dmacount;
        uint32_t chanerr;
        uint64_t chansts;
        uint64_t chainaddr;
} cbdmadev;

/* QID Path */
enum {
        Qdir           = 0,
        Qcbdmaktest    = 1,
        Qcbdmastats    = 2,
        Qcbdmareset    = 3,
};

static struct dirtab cbdmadir[] = {
        {".",         {Qdir, 0, QTDIR}, 0, 0555},
        {"ktest",     {Qcbdmaktest, 0, QTFILE}, 0, 0555},
        {"stats",     {Qcbdmastats, 0, QTFILE}, 0, 0555},
        {"reset",     {Qcbdmareset, 0, QTFILE}, 0, 0755},
};

/* Descriptor structue as defined in the programmer's guide.
 * It describes a single DMA transfer
 */
struct desc {
        uint32_t  xfer_size;
        uint32_t  descriptor_control;
        uint64_t  src_addr;
        uint64_t  dest_addr;
        uint64_t  next_desc_addr;
        uint64_t  next_source_address;
        uint64_t  next_destination_address;
        uint64_t  reserved0;
        uint64_t  reserved1;
} __attribute__((packed));

#if 1
/* Helper functions */
static unsigned char read_8(char *base, int offset) {
  asm volatile("mfence");
  return base[offset];
}

static void write_8(char *base, int offset, unsigned char val) {
  asm volatile("mfence");
  base[offset] = val;
  asm volatile("mfence");
}

static void write_16(char *base, int offset, uint16_t val) {
  asm volatile("mfence");
  *((uint16_t*) (&base[offset])) = val;
  asm volatile("mfence");
}

static uint32_t read_32(char *base, int offset) {
  uint32_t dword;
  asm volatile("mfence");
  dword = *((uint32_t*) &base[offset]);
  asm volatile("mfence");
  return dword;
}

static void write_32(char *base, int offset, uint32_t value) {
  asm volatile("mfence");
  *((uint32_t*) (&base[offset])) = value;
  asm volatile("mfence");
}

static uint64_t read_64(char *base, int offset) {
  uint64_t low, high;

  asm volatile("mfence");
  low = *((uint32_t*) (&base[offset]));
  high = *((uint32_t*) (&base[offset+4]));
  asm volatile("mfence");
  return low | (high << 32ull);
}

static void write_64(char *base, int offset, uint64_t value) {
  asm volatile("mfence");
  *((uint32_t*) (&base[offset])) = value & 0xffffffff;
  *((uint32_t*) (&base[offset + 4])) = value >> 32;
  asm volatile("mfence");
}
#endif

/* Function definitions start here */
static char *devname(void) {
        return cbdmadevtab.name;
}

static struct chan *cbdmaattach(char *spec) {
        return devattach(devname(), spec);
}

struct walkqid *cbdmawalk(struct chan *c, struct chan *nc, char **name,
                         unsigned int nname) {
        return devwalk(c, nc, name, nname, cbdmadir,
                       ARRAY_SIZE(cbdmadir), devgen);
}

/*
 * TODO: Check if necessary to write a custom stat function
 */
static size_t cbdmastat(struct chan *c, uint8_t *dp, size_t n) {
        return devstat(c, dp, n, cbdmadir, ARRAY_SIZE(cbdmadir), devgen);
}

static struct chan *cbdmaopen(struct chan *c, int omode) {
        return devopen(c, omode, cbdmadir, ARRAY_SIZE(cbdmadir), devgen);
}

/*
 * All files are synthetic. Hence we do not need to implement any close
 * function.
 */
static void cbdmaclose(struct chan *_) {
}

/* return string representation of chansts */
char *cbdma_str_chansts(uint64_t chansts) {
        char *status = "unrecognized status";

        switch (chansts & IOAT_CHANSTS_STATUS) {
                case IOAT_CHANSTS_ACTIVE:
                status = "ACTIVE";
                break;

                case IOAT_CHANSTS_DONE:
                status = "DONE";
                break;

                case IOAT_CHANSTS_SUSPENDED:
                status = "SUSPENDED";
                break;

                case IOAT_CHANSTS_HALTED:
                status = "HALTED";
                break;

                case IOAT_CHANSTS_ARMED:
                status = "ARMED";
                break;

                default:
                break;
        }
        return status;
}

/* print descriptors on console (for debugging) */
static void dump_desc(struct desc *d, int count) {
        printk(KERN_INFO "dumping descriptors:\n");

        while (count > 0) {
                printk(KERN_INFO "desc: 0x%x, size: %d bytes\n",
                        d, sizeof(struct desc));
                printk(KERN_INFO "[32] desc->xfer_size: 0x%x\n",
                        d->xfer_size);
                printk(KERN_INFO "[32] desc->descriptor_control: 0x%x\n",
                        d->descriptor_control);
                printk(KERN_INFO "[64] desc->src_addr: 0x%x\n",
                        d->src_addr);
                printk(KERN_INFO "[64] desc->dest_addr: 0x%x\n",
                        d->dest_addr);
                printk(KERN_INFO "[64] desc->next_desc_addr: 0x%x\n",
                        d->next_desc_addr);
                printk(KERN_INFO "[64] desc->next_source_address: 0x%x\n",
                        d->next_source_address);
                printk(KERN_INFO "[64] desc->next_destination_address: 0x%x\n",
                        d->next_destination_address);
                printk(KERN_INFO "[64] desc->reserved0: 0x%x\n",
                        d->reserved0);
                printk(KERN_INFO "[64] desc->reserved1: 0x%x\n",
                        d->reserved1);

                count--;
                if (count > 0) {
                        printk(KERN_INFO "\n");
                        d = (struct desc *) d->next_desc_addr;
                }
        }
}

/* cbdma_ktest: performs functional test on CBDMA
   
 - Allocates 2 kernel pages: ktest_src and ktest_dst.
 - memsets the ktest_src page
 - Prepare descriptors for DMA transfer (need to be aligned)
 - Initiate the transfer
 - Verify results
 - Print stats
 */ 
static size_t cbdma_ktest(struct chan *c, void *va, size_t n, off64_t offset) {
        static char *ktest_src = NULL;
        static char *ktest_dst = NULL;
        const int ktest_size = 64;

        char *desc_page;
        uint64_t desc_page_paddr;
        static struct desc *d;

        /* check for previously initialed ktest */
        if(ktest_done) {
                printk(KERN_INFO "ktest done! curr dst: %s\n", ktest_dst);
                goto done;
        } else
                ktest_done = true; /* TODO: lock or atomic operation */

        /* allocate ktest_src & ktest_dst buffers and initialize with different values */
        ktest_src = ktest_src == NULL ? kmalloc(ktest_size, MEM_WAIT)
                                      : ktest_src;
        ktest_dst = ktest_dst == NULL ? kmalloc(ktest_size, MEM_WAIT)
                                      : ktest_dst;
        memset(ktest_src, 0x31, ktest_size); /* ascii for '1' */
        memset(ktest_dst, 0x30, ktest_size); /* ascii for '0' */
        ktest_src[ktest_size-1] = '\0';
        ktest_dst[ktest_size-1] = '\0';

        printk(KERN_INFO "ktest_src:%x ktest_dst:%x\n", ktest_src, ktest_dst);

        /* allocate pages for descriptors, last 6-bits must be zero */
        desc_page = kpage_alloc_addr();
        memset(desc_page, 0x0, PGSIZE);

        desc_page_paddr = (uint64_t) PADDR(desc_page);
        assert((desc_page_paddr & 0x3F) == 0);

        printk(KERN_INFO "desc_page:%x desc_page_paddr:%x\n", desc_page,
                         desc_page_paddr);

        /* preparing descriptors */
        d = (struct desc *) desc_page;
        d->next_desc_addr       = (uint64_t) PADDR(d + 1);
        d->xfer_size            = (uint32_t) ktest_size;
        d->src_addr             = (uint64_t) PADDR(ktest_src);
        d->dest_addr            = (uint64_t) PADDR(ktest_dst);
        d->descriptor_control   = CBDMA_DESC_CTRL_INTR_ON_COMPLETION |
                                  CBDMA_DESC_CTRL_WRITE_CHANCMP_ON_COMPLETION;

        dump_desc(d, 1);
        /* initiate transfer */
        printk(KERN_INFO "[before_transfer] ktest_dst:%s\n", ktest_dst);

        /* Set "Any Error Abort Enable": enables abort for any error encountered
         * Set "Error Completion Enable": enables completion write to address in
                                          CHANCMP for any error
         * Reset "Interrupt Disable": W1C, when clear enables interrupt to fire
                                    for next descriptor that specifies interrupt
        */
        printk(KERN_INFO "[before_transfer] update: CHANCTRL\n");

        write8(IOAT_CHANCTRL_ANY_ERR_ABORT_EN | IOAT_CHANCTRL_ERR_COMPLETION_EN,
               mmio + CBDMA_CHANCTRL_OFFSET);

        /* Set channel completion register where CBDMA will write content of
         * CHANSTS register upon successful DMA completion or error condition
         */
        printk(KERN_INFO "[before_transfer] update: CHANCMP\n");
        write_64(mmio, CBDMA_CHANCMP_OFFSET,
                (uint64_t) PADDR(&cbdmadev.chansts));
        // write64((uint64_t) PADDR(&cbdmadev.chansts),
        //         mmio + CBDMA_CHANCMP_OFFSET);

        /* write addr of first desc */
        printk(KERN_INFO "[before_transfer] update: CHAINADDR\n");
        // write_64(mmio, CBDMA_CHAINADDR_OFFSET, (uint64_t) PADDR(d));
        write64((uint64_t) PADDR(d), mmio + CBDMA_CHAINADDR_OFFSET);

        /* write valid number of descs: starts the DMA */
        printk(KERN_INFO "[before_transfer] update: DMACOUNT\n");
        write16(1, mmio + CBDMA_DMACOUNT_OFFSET);

        /* wait for completion */
        while ((cbdmadev.chansts & IOAT_CHANSTS_STATUS)
                == IOAT_CHANSTS_ACTIVE) {
                printk(KERN_INFO "[after_transfer] read: CHANSTS\n");
                cbdmadev.chansts = read64(mmio + CBDMA_CHANSTS_OFFSET);
        }
        printk(KERN_INFO "[after_transfer] CHANSTS: %s\n",
                cbdma_str_chansts(cbdmadev.chansts));
        printk(KERN_INFO "[after_transfer] ktest_dst:%s\n", ktest_dst);

kpage_free:
        /* TODO: free the kpage */
kmalloc_free: /* TODO: find way to avoid freeing buffer */
        //kfree(ktest_dst);
        //kfree(ktest_src);
done:
        return 0;
}

/* cbdma_update_cbdmapciregs: read the PCI registers and populate cbdmapciregs
 */ 
void cbdma_update_cbdmapciregs(void) {
        /* get updated: DMAUNCERRSTS */
        cbdmapciregs.dmauncerrsts = pcidev_read32(pci,
                                                  IOAT_PCI_DMAUNCERRSTS_OFFSET);

        /* get updated: CHANERR_INT */
        cbdmapciregs.chanerr_int = pcidev_read32(pci,
                                                 IOAT_PCI_CHANERR_INT_OFFSET);
}

/* cbdma_update_cbdmadev: read the MMIO registers and populate cmdadev
 */ 
void cbdma_update_cbdmadev(void) {
        /* get updated: CHANCNT */
        cbdmadev.chancnt = read_64(mmio, CBDMA_CHANCNT_OFFSET);
        // cbdmadev.chancnt = read64(mmio + CBDMA_CHANCNT_OFFSET);

        /* get updated: CHANCMD */
        cbdmadev.chancmd = read8(mmio + CBDMA_CHANCMD_OFFSET);

        /* get updated: CBVER */
        cbdmadev.cbver = read8(mmio + IOAT_VER_OFFSET);

        /* get updated: CHANCTRL */
        cbdmadev.chanctrl = read_64(mmio, CBDMA_CHANCTRL_OFFSET);
        // cbdmadev.chanctrl = read64(mmio + CBDMA_CHANCTRL_OFFSET);

        /* get updated: CHANSTS */
        cbdmadev.chansts = read_64(mmio, CBDMA_CHANSTS_OFFSET);
        // cbdmadev.chansts = read64(mmio + CBDMA_CHANSTS_OFFSET);

        /* get updated: CHAINADDR */
        cbdmadev.chainaddr = read_64(mmio, CBDMA_CHAINADDR_OFFSET);
        // cbdmadev.chainaddr = read64(mmio + CBDMA_CHAINADDR_OFFSET);

        /* get updated: DMACOUNT */
        cbdmadev.dmacount = read16(mmio + CBDMA_DMACOUNT_OFFSET);

        /* get updated: CHANERR */
        cbdmadev.chanerr = read16(mmio + CBDMA_CHANERR_OFFSET);
}

/* cbdma_stats: get stats about the device and driver
 */
static size_t cbdma_stats(struct chan *c, void *va, size_t n, off64_t offset) {
        char buf[4096];
        char *ebuf = buf + sizeof(buf);
        char *iter = buf;
        uint64_t value;

        iter = seprintf(iter, ebuf,
                "Intel CBDM [%x:%x] mmio:%x mmio_phy:%x mmio_sz:%lu\n",
                pci->ven_id, pci->dev_id, mmio, mmio_phy, mmio_sz);

        /* print the PCI registers */
        cbdma_update_cbdmapciregs();
        iter = seprintf(iter, ebuf, "    PCI Registers:\n");

        /* PCI: DMAUNCERRSTS */
        iter = seprintf(iter, ebuf, "\tDMAUNCERRSTS: 0x%x\n",
                                        cbdmapciregs.dmauncerrsts);

        /* PCI: CHANERR_INT */
        iter = seprintf(iter, ebuf, "\tCHANERR_INT: 0x%x\n",
                                        cbdmapciregs.chanerr_int);

        /* sort these out correctly once I solve the reset issue */
        static enum {
                PCISTS = 0x6, // 16-bit
                PCICMD = 0x4, // 16-bit
                CB_BAR = 0x10, // 64-bit
                DEVSTS = 0x9a, // 16-bit
                PMCSR  = 0xe4, // 32-bit

                /* PCIe configuration space */
                DMAUNCERRSTS = 0x148, // 32-bit
                DMAUNCERRMSK = 0x14c, // 32-bit
                DMAUNCERRSEV = 0x150, // 32-bit
                DMAUNCERRPTR = 0x154, // 8-bit
                DMAGLBERRPTR = 0x160, // 8-bit

                CHANERR_INT    = 0x180, // 32-bit
                CHANERRMSK_INT = 0x184, // 32-bit
                CHANERRSEV_INT = 0x188, // 32-bit
                CHANERRPTR     = 0x18c, // 8-bit
        } cbdma_pci_config_registers;

        value = 0; value = pcidev_read16(pci, PCISTS);
        iter = seprintf(iter, ebuf, "\tPCISTS: 0x%x\n", value);

        value = 0; value = pcidev_read16(pci, PCICMD);
        iter = seprintf(iter, ebuf, "\tPCICMD: 0x%x\n", value);

        value = 0; value = pcidev_read32(pci, CB_BAR); // 64-bit value
        iter = seprintf(iter, ebuf, "\tCB_BAR: 0x%x\n", value);

        value = 0; value = pcidev_read16(pci, DEVSTS);
        iter = seprintf(iter, ebuf, "\tDEVSTS: 0x%x\n", value);

        value = 0; value = pcidev_read32(pci, PMCSR);
        iter = seprintf(iter, ebuf, "\tPMCSR: 0x%x\n", value);

        value = 0; value = pcidev_read32(pci, DMAUNCERRSTS);
        iter = seprintf(iter, ebuf, "\tDMAUNCERRSTS: 0x%x\n", value);

        value = 0; value = pcidev_read32(pci, DMAUNCERRMSK);
        iter = seprintf(iter, ebuf, "\tDMAUNCERRMSK: 0x%x\n", value);

        value = 0; value = pcidev_read32(pci, DMAUNCERRSEV);
        iter = seprintf(iter, ebuf, "\tDMAUNCERRSEV: 0x%x\n", value);

        value = 0; value = pcidev_read8(pci, DMAUNCERRPTR);
        iter = seprintf(iter, ebuf, "\tDMAUNCERRPTR: 0x%x\n", value);

        value = 0; value = pcidev_read8(pci, DMAGLBERRPTR);
        iter = seprintf(iter, ebuf, "\tDMAGLBERRPTR: 0x%x\n", value);

        value = 0; value = pcidev_read32(pci, CHANERR_INT);
        iter = seprintf(iter, ebuf, "\tCHANERR_INT: 0x%x\n", value);

        value = 0; value = pcidev_read32(pci, CHANERRMSK_INT);
        iter = seprintf(iter, ebuf, "\tCHANERRMSK_INT: 0x%x\n", value);

        value = 0; value = pcidev_read32(pci, CHANERRSEV_INT);
        iter = seprintf(iter, ebuf, "\tCHANERRSEV_INT: 0x%x\n", value);

        value = 0; value = pcidev_read8(pci, CHANERRPTR);
        iter = seprintf(iter, ebuf, "\tCHANERRPTR: 0x%x\n", value);

        /* ----------------------------------------------------- */

        /* print the MMIO registers */
        cbdma_update_cbdmadev();
        iter = seprintf(iter, ebuf, "    MMIO Registers:\n");

        /* MMIO: CHANCNT */
        iter = seprintf(iter, ebuf, "\tCHANCNT: 0x%x\n", cbdmadev.chancnt);

        /* MMIO: CHANCMD */
        iter = seprintf(iter, ebuf, "\tCHANCMD: 0x%x\n", cbdmadev.chancmd);

        /* MMIO: CHANCTRL */
        iter = seprintf(iter, ebuf, "\tCHANCTRL: 0x%x\n", cbdmadev.chanctrl);

        /* MMIO: CBVER */
        iter = seprintf(iter, ebuf, "\tCBVER: 0x%x major=%d minor=%d\n",
                cbdmadev.cbver,
                GET_IOAT_VER_MAJOR(cbdmadev.cbver),
                GET_IOAT_VER_MINOR(cbdmadev.cbver));

        /* MMIO: CHANSTS */
        iter = seprintf(iter, ebuf, "\tCHANSTS: 0x%x [%s], desc_addr: 0x%x, "
                "raw: 0x%x\n",
                (cbdmadev.chansts & IOAT_CHANSTS_STATUS),
                cbdma_str_chansts(cbdmadev.chansts),
                (cbdmadev.chansts & IOAT_CHANSTS_COMPLETED_DESCRIPTOR_ADDR),
                cbdmadev.chansts);

        /* MMIO: CHAINADDR */
        iter = seprintf(iter, ebuf, "\tCHAINADDR: 0x%x\n", cbdmadev.chainaddr);

        /* MMIO: DMACOUNT */
        iter = seprintf(iter, ebuf, "\tDMACOUNT: 0x%x\n", cbdmadev.dmacount);

        /* MMIO: CHANERR */
        iter = seprintf(iter, ebuf, "\tCHANERR: 0x%x\n", cbdmadev.chanerr);

        *iter   = '\0';
        return readstr(offset, va, n, buf);
}

/* cbdma_reset_device: this fixes any programming errors done before
 */
void cbdma_reset_device() {
        int cbdmaver;
        uint32_t error;
 
        pcidev_write16(pci, PCI_COMMAND, PCI_COMMAND_IO | PCI_COMMAND_MEMORY
                                                        | PCI_COMMAND_MASTER);
        /* fetch version */
        cbdmaver = read8(mmio + IOAT_VER_OFFSET);

        /* ack channel errros */
        error = read32(mmio + CBDMA_CHANERR_OFFSET);
        write32(error, mmio + CBDMA_CHANERR_OFFSET);

        /* ack pci device level errros */
        /* clear DMA Cluster Uncorrectable Error Status */
        error = pcidev_read32(pci, IOAT_PCI_DMAUNCERRSTS_OFFSET);
        pcidev_write32(pci, IOAT_PCI_DMAUNCERRSTS_OFFSET, error);

        /* clear DMA Channel Error Status */
        error = pcidev_read32(pci, IOAT_PCI_CHANERR_INT_OFFSET);
        pcidev_write32(pci, IOAT_PCI_CHANERR_INT_OFFSET, error);

        /* reset */
        write8(IOAT_CHANCMD_RESET, mmio
                                   + IOAT_CHANNEL_MMIO_SIZE
                                   + IOAT_CHANCMD_OFFSET(cbdmaver));

        pcidev_write16(pci, PCI_COMMAND, PCI_COMMAND_IO | PCI_COMMAND_MEMORY
                        | PCI_COMMAND_MASTER | PCI_COMMAND_INTX_DISABLE);

        printk(KERN_INFO "Reset: Intel CBDMA\n");
}

/* cbdma_is_reset_pending: returns true if reset is pending
 */
bool cbdma_is_reset_pending() {
        int cbdmaver;
        int status;

        /* fetch version */
        cbdmaver = read8(mmio + IOAT_VER_OFFSET);

        status = read8(mmio + IOAT_CHANNEL_MMIO_SIZE
                        + IOAT_CHANCMD_OFFSET(cbdmaver));

        return (status & IOAT_CHANCMD_RESET) == IOAT_CHANCMD_RESET;
}

static size_t cbdmaread(struct chan *c, void *va, size_t n, off64_t offset) {
        switch (c->qid.path) {
        case Qdir:
                return devdirread(c, va, n, cbdmadir,
                                  ARRAY_SIZE(cbdmadir), devgen);

        case Qcbdmaktest:
                return cbdma_ktest(c, va, n, offset);

        case Qcbdmastats:
                return cbdma_stats(c, va, n, offset);

        case Qcbdmareset:
                if (cbdma_is_reset_pending() == TRUE)
                        return readstr(offset, va, n,
                                "Status: Reset Pending\n"
                                "Write '1' to perform reset!\n");
                else
                        return readstr(offset, va, n,
                                "Status: Active\n"
                                "Write '1' to perform reset!\n");

        default:
                panic("cbdmaread: qid 0x%x is impossible", c->qid.path);
        }

        return -1;      /* not reached */
}

static size_t cbdmawrite(struct chan *c, void *va, size_t n, off64_t offset) {
        switch (c->qid.path) {
        case Qdir:
                error(EPERM, "writing not permitted");

        case Qcbdmaktest:
                error(EPERM, "writing not permitted");

        case Qcbdmastats:
                error(EPERM, "writing not permitted");

        case Qcbdmareset:
                if (offset == 0 && n > 0 && *(char *)va == '1') {
                        cbdma_reset_device();
                } else
                        error(EINVAL, "invalid argument");
                return n;

        default:
                panic("cbdmawrite: qid 0x%x is impossible", c->qid.path);
        }

        return -1;      /* not reached */
}

void cbdmainit(void) {
        int tbdf        = MKBUS(BusPCI, 0, 0x4, 0);
        pci             = NULL;
        mmio            = NULL;
        mmio_sz         = -1;
        int i;

        /* initialize cbdmadev */
        memset(&cbdmadev, 0x0, sizeof(cbdmadev));

        /* search for the device 00:04.0 */
        pci = pci_match_tbdf(tbdf);
        if (pci == NULL) {
                error(EINVAL, "Intel CBDMA PCI device not found\n");
                return;
        }

        /* search and find the mapped mmio region */
        for (i = 0; i < COUNT_OF(pci->bar); i++) {
                if (pci->bar[i].mmio_sz == 0)
                        continue;
                mmio_phy = (void *) pci->bar[i].mmio_base64;
                mmio     = (void *) KADDR(pci->bar[i].mmio_base64);
                mmio_sz  = pci->bar[i].mmio_sz;
                break;
        }

        if (mmio == NULL || mmio_sz == -1) {
                error(EINVAL, "Cannot register Intel CBDMA\n");                
        }

        /* reset device */
        cbdma_reset_device();

        printk(KERN_INFO
                "Registered: Intel CBDM [%x:%x] mmio:%x mmio_sz:%lu\n",
                pci->ven_id, pci->dev_id, mmio, mmio_sz);
}

struct dev cbdmadevtab __devtab = {
        .name       = "cbdma",
        .reset      = devreset,
        .init       = cbdmainit,
        .shutdown   = devshutdown,
        .attach     = cbdmaattach,
        .walk       = cbdmawalk,
        .stat       = cbdmastat,
        .open       = cbdmaopen,
        .create     = devcreate,
        .close      = cbdmaclose,
        .read       = cbdmaread,
        .bread      = devbread,
        .write      = cbdmawrite,
        .bwrite     = devbwrite,
        .remove     = devremove,
        .wstat      = devwstat,
};
