/*
 * File: cbdma.c - Driver for using Intel CBDMA
 * Author: Aditya Basu <mitthu@google.com>
 * Date: July 3, 2019
 *
 * Useful resources:
 *   - Intel Xeon E7 2800/4800/8800 Datasheet Vol. 2
 *   - Purley Programmer's Guide
 *
 * Acronyms:
 *   - IOAT: (Intel) I/O Acceleration Technology
 *   - CDMA: Crystal Beach DMA
 *
 * CBDMA Notes
 * ===========
 * Every CBDMA PCI function, has one MMIO address space (so only BAR0). Each
 * function can have multiple channels. Currently these devices only have one
 * channel per function. This can be read from the CHANCNT register (8-bit)
 * at offset 0x0.
 *
 * Each channel be independently configured for DMA. The MMIO config space of
 * every channel is 0x80 bytes. The first channel (or CHANNEL_0) starts at 0x80
 * offset.
 *
 * CHAINADDR points to a descriptor (desc) ring buffer. More precisely it points
 * to the first desc in the ring buffer. Each desc represents a single DMA
 * operation. Look at "struct desc" for it's structure.
 *
 * Each desc is 0x40 bytes (or 64 bytes) in size. A 4k page will be able to hold
 * 4k/64 = 64 entries. Note that the lower 6 bits of CHANADDR should be zero. So
 * the first desc's address needs to be aligned accordingly. Page-aligning the
 * first desc address will work because 4k page-aligned addresses will have
 * the last 12 bits as zero.
 *
 * Userpace (TODO)
 * ========
 * - Create API for DMA commands. Create a ctl file for user API?
 * - Freeze VA->PA page mappings till DMA is completed
 *
 * TODO
 * ====
 * *MAJOR*
 *   - Update to the correct struct desc (from Linux kernel)
 *   - Make the status field embedded in the channel struct (no ptr business)
 *   - Add file for errors
 *   - Add locks to guard desc access
 *   - Need for a debug file?
 *   - Add file for errors
 * *MINOR*
 *   - In stats print the total numer of desc
 *   - Replace all CBDMA_* constants with IOAT_*
 *   - Remove repeated cbdma_regs.h header file
 *   - Initializes only the first found CBDMA device
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

#define NDESC 1 // initialize these many descs

struct dev                cbdmadevtab;
static struct pci_device  *pci;
static void               *mmio;
static uint64_t           mmio_phy; /* physical addr */
static uint32_t           mmio_sz;
static uint8_t            chancnt; /* Total number of channels per function */
static bool               iommu_enabled = false;

/* PCIe Config Space; from Intel Xeon E7 2800/4800/8800 Datasheet Vol. 2 */
enum {
        DEVSTS = 0x9a, // 16-bit
        PMCSR  = 0xe4, // 32-bit

        DMAUNCERRSTS = 0x148, // 32-bit (DMA Cluster Uncorrectable Error Status)
        DMAUNCERRMSK = 0x14c, // 32-bit
        DMAUNCERRSEV = 0x150, // 32-bit
        DMAUNCERRPTR = 0x154, // 8-bit
        DMAGLBERRPTR = 0x160, // 8-bit

        CHANERR_INT    = 0x180, // 32-bit
        CHANERRMSK_INT = 0x184, // 32-bit
        CHANERRSEV_INT = 0x188, // 32-bit
        CHANERRPTR     = 0x18c, // 8-bit
};

/* QID Path */
enum {
        Qdir           = 0,
        Qcbdmaktest    = 1,
        Qcbdmastats    = 2,
        Qcbdmareset    = 3,
        Qcbdmaucopy    = 4,
        Qcbdmaiommu    = 5,
};

/* supported ioat devices */
enum {
        ioat2021 = (0x2021 << 16) | 0x8086,
        ioat2f20 = (0x2f20 << 16) | 0x8086,
};

static struct dirtab cbdmadir[] = {
        {".",         {Qdir, 0, QTDIR}, 0, 0555},
        {"ktest",     {Qcbdmaktest, 0, QTFILE}, 0, 0755},
        {"stats",     {Qcbdmastats, 0, QTFILE}, 0, 0555},
        {"reset",     {Qcbdmareset, 0, QTFILE}, 0, 0755},
        {"ucopy",     {Qcbdmaucopy, 0, QTFILE}, 0, 0755},
        {"iommu",     {Qcbdmaiommu, 0, QTFILE}, 0, 0755},
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

/* The channels are indexed starting from 0 */
static struct channel {
        uint8_t                 number; // channel number
        struct desc             *pdesc; // desc ptr
        int                     ndesc;  // num. of desc
        volatile uint64_t       status; // reg: CHANSTS, needs to be 64B aligned
        uint8_t                 ver;    // reg: CBVER

/* DEPRECATED */
/* MMIO address space; from Intel Xeon E7 2800/4800/8800 Datasheet Vol. 2
 * Every channel 0x80 bytes in size.
 */
        uint8_t  chancmd;
        uint8_t  xrefcap;
        uint16_t chanctrl;
        uint16_t dmacount;
        uint32_t chanerr;
        uint64_t chansts;
        uint64_t chainaddr;
} cbdmadev, channel0;

#define KTEST_SIZE 64
static struct {
        bool    done;
        char    printbuf[4096];
        char    src[KTEST_SIZE];
        char    dst[KTEST_SIZE];
        char    srcfill;
        char    dstfill;
} ktest;    /* TODO: needs locking */

/* struct passed from the userspace */
struct ucbdma {
        struct desc             desc;
        volatile uint64_t       status;
        uint16_t                ndesc;
};

#if 0
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
static inline bool is_initialized() {
        if (!pci || !mmio)
                return false;
        else
                return true;
}

static void *get_register(struct channel *c, int offset) {
        uint64_t base = (c->number + 1) * IOAT_CHANNEL_MMIO_SIZE;
        printk("cbdma: get_register: offset = 0x%x addr = 0x%x\n",
                offset, (char *) mmio + base + offset);
        return (char *) mmio + base + offset;
}

static char *devname(void) {
        return cbdmadevtab.name;
}

static struct chan *cbdmaattach(char *spec) {
        if (!is_initialized())
                error(ENODEV, "no cbdma device detected");
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
        printk(KERN_INFO "dumping descriptors (count = %d):\n", count);

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
                if (count > 0)
                        d = (struct desc *) KADDR(d->next_desc_addr);
                printk(KERN_INFO "\n");
        }
}

/* initialize desc ring
 
 - Can be called multiple times, with different "ndesc" values.
 - NOTE: Max value of ndesc on x86 = 64. Reason we only allocate _one_ 4k page.
 - NOTE: The next_desc_addr of last desc, does not point to the first desc.
 */
static void init_desc(struct channel *c, int ndesc) {
        struct desc *d;
        int i;
        const int max_ndesc = PGSIZE / sizeof(struct desc);

        /* sanity checks */
        if (ndesc > max_ndesc) {
                printk(KERN_INFO
                        "cbdma: allocating only %d desc instead of %d desc\n",
                        max_ndesc, ndesc);
                ndesc = max_ndesc;
        }

        c->ndesc = ndesc;

        /* allocate pages for descriptors, last 6-bits must be zero */
        if (!c->pdesc)
                c->pdesc = kpage_alloc_addr();

        if (!c->pdesc) /* error does not return */
                error(ENOMEM, "cbdma: cannot alloc page for desc");

        memset(c->pdesc, 0x0, PGSIZE);

        /* should be always valid for page aligned addresses */
        assert((PADDR(c->pdesc) & 0x3F) == 0);

        /* preparing descriptors */
        d = (struct desc *) c->pdesc;

        for (i = 0; i < c->ndesc; i++) {
                d->next_desc_addr = PADDR(d) + ((i+1) * sizeof(struct desc));
                d++;
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
static bool foo;
void toggle_foo() {
        foo = !foo;
        printk("cbdma: foo = %d\n", foo);
}
static size_t cbdma_ktest(struct chan *c, void *va, size_t n, off64_t offset) {
        static struct desc *d;
        char *ebuf = ktest.printbuf + sizeof(ktest.printbuf);
        char *iter = ktest.printbuf;
        bool did_run;
        uint64_t value;

        /* check for previously initialed ktest */
        if(ktest.done) {
                did_run = false;
                goto done;
        }
        else {
                did_run = true;
        }

        /* initialize src and dst address */
        memset(ktest.src, ktest.srcfill, KTEST_SIZE);
        memset(ktest.dst, ktest.dstfill, KTEST_SIZE);
        ktest.src[KTEST_SIZE-1] = '\0';
        ktest.dst[KTEST_SIZE-1] = '\0';

        /* preparing descriptors */
        d = channel0.pdesc;
        d->xfer_size            = (uint32_t) KTEST_SIZE;
        d->src_addr             = (uint64_t) PADDR(ktest.src);
        d->dest_addr            = (uint64_t) PADDR(ktest.dst);
        d->descriptor_control   = CBDMA_DESC_CTRL_INTR_ON_COMPLETION |
                                  CBDMA_DESC_CTRL_WRITE_CHANCMP_ON_COMPLETION;

        /* old desc */
        memset((uint64_t *)channel0.status, 0, sizeof(channel0.status));

        /* Set channel completion register where CBDMA will write content of
         * CHANSTS register upon successful DMA completion or error condition
         */
        write64(PADDR(channel0.status),
                get_register(&channel0, IOAT_CHANCMP_OFFSET));

        /* get updated: DMACOUNT */
        // value = 0; value = read16(mmio + CBDMA_DMACOUNT_OFFSET);
        // printk("\tDMACOUNT: 0x%x\n", value);

        // write16(0, mmio + CBDMA_DMACOUNT_OFFSET);

        // value = 0; value = read16(mmio + CBDMA_DMACOUNT_OFFSET);
        // printk("\tDMACOUNT: 0x%x\n", value);

        /* write locate of first desc to register CHAINADDR */
        write64((uint64_t) PADDR(channel0.pdesc), mmio + CBDMA_CHAINADDR_OFFSET);

        /* writing valid number of descs: starts the DMA */
        write16(1, mmio + CBDMA_DMACOUNT_OFFSET);

        /* wait for completion */
        while (((*(uint64_t *)channel0.status) & IOAT_CHANSTS_STATUS)
                == IOAT_CHANSTS_ACTIVE) {
                cpu_relax();
                if (foo)
                        break;
        }

        /* clear out DMACOUNT */
        // value = read16(mmio + CBDMA_DMACOUNT_OFFSET);
        write16(0, mmio + CBDMA_DMACOUNT_OFFSET);

        /* ack errors */
        value = pcidev_read32(pci, CHANERR_INT);
        if (value != 0)
                printk("cbdma: error: CHANERR_INT = 0x%x\n", value);
        pcidev_write32(pci, CHANERR_INT, value);

        ktest.done = true; /* TODO: lock or atomic operation */

done:
        iter = seprintf(iter, ebuf,
           "Self-test Intel CBDMA [%x:%x] registered at %02x:%02x.%x\n",
           pci->ven_id, pci->dev_id, pci->bus, pci->dev, pci->func);

        iter = seprintf(iter, ebuf,"\tHelp: Write 1 to re-run the test.\n");

        iter = seprintf(iter, ebuf,"\tRun this time? %s\n",
                did_run ? "Yes" : "No");

        iter = seprintf(iter, ebuf,"\tCompleted? %s\n",
                ktest.done ? "Yes" : "No");

        iter = seprintf(iter, ebuf,"\tChannel Status: %s (raw: 0x%x)\n",
                cbdma_str_chansts(*((uint64_t *)channel0.status)),
                (*((uint64_t *)channel0.status) & IOAT_CHANSTS_STATUS));

        iter = seprintf(iter, ebuf,"\tCopy Size: %d (0x%x)\n",
                KTEST_SIZE, KTEST_SIZE);

        iter = seprintf(iter, ebuf,"\tsrcfill: %c (0x%x)\n",
                ktest.srcfill, ktest.srcfill);
        iter = seprintf(iter, ebuf,"\tdstfill: %c (0x%x)\n",
                ktest.dstfill, ktest.dstfill);
        iter = seprintf(iter, ebuf,"\tsrc_str (after copy): %s\n", ktest.src);
        iter = seprintf(iter, ebuf,"\tdst_str (after copy): %s\n", ktest.dst);

        return readstr(offset, va, n, ktest.printbuf);
}

/* convert a userspace pointer to kaddr based pointer */
static inline void *uptr_to_kptr(void *ptr)
{
        return (void *) uva2kva(current, ptr, 1, PROT_WRITE);
}

/* function that uses kernel addresses to perform DMA.
   NOTE: does not perform error checks for src / dest addr.
 */
static void issue_dma_kaddr(struct ucbdma *u) {
        struct ucbdma *_u = uptr_to_kptr(u);
        struct desc *d = (struct desc *) _u; /* first field is struct desc */
        uint64_t value;

        if (!_u) {
                printk("[kern] cannot get kaddr for useraddr: %p\n", u);
                return;
        }
        printk("[kern] ucbdma: user: %p kern: %p\n", u, _u);
 
        /* preparing descriptors */
        d->src_addr             = (uint64_t) PADDR(uptr_to_kptr((void*) d->src_addr));
        d->dest_addr            = (uint64_t) PADDR(uptr_to_kptr((void*) d->dest_addr));
        d->descriptor_control   = CBDMA_DESC_CTRL_INTR_ON_COMPLETION |
                                  CBDMA_DESC_CTRL_WRITE_CHANCMP_ON_COMPLETION;

        /* zero out status */
        _u->status = 0;

        /* Set channel completion register where CBDMA will write content of
         * CHANSTS register upon successful DMA completion or error condition
         */
        write64(PADDR(&_u->status),
                get_register(&channel0, IOAT_CHANCMP_OFFSET));

        /* write locate of first desc to register CHAINADDR */
        write64((uint64_t) PADDR(d), mmio + CBDMA_CHAINADDR_OFFSET);

        /* writing valid number of descs: starts the DMA */
        write16(1, mmio + CBDMA_DMACOUNT_OFFSET);

        /* wait for completion */
        while (((_u->status) & IOAT_CHANSTS_STATUS)
                == IOAT_CHANSTS_ACTIVE) {
                cpu_relax();
                if (foo)
                        break;
        }

        /* clear out DMACOUNT */
        write16(0, mmio + CBDMA_DMACOUNT_OFFSET);

        /* ack errors */
        value = pcidev_read32(pci, CHANERR_INT);
        if (value != 0)
                printk("cbdma: error: CHANERR_INT = 0x%x\n", value);
        pcidev_write32(pci, CHANERR_INT, value);
}

/* function that uses virtual (process) addresses to perform DMA; IOMMU = ON
   TODO: Verify once the IOMMU is setup and enabled.
*/
static void issue_dma_vaddr(struct ucbdma *u) {
        struct ucbdma *_u = uptr_to_kptr(u);
        uint64_t value;

        printk("[kern] IOMMU = ON\n");

        printk("[kern] ucbdma: user: %p kern: %p\n", u, &u->desc);
 
        /* preparing descriptors */
        _u->desc.descriptor_control   = CBDMA_DESC_CTRL_INTR_ON_COMPLETION |
                                  CBDMA_DESC_CTRL_WRITE_CHANCMP_ON_COMPLETION;

        /* zero out status */
        _u->status = 0;

        /* Set channel completion register where CBDMA will write content of
         * CHANSTS register upon successful DMA completion or error condition
         */
        write64((uint64_t) &u->status,
                get_register(&channel0, IOAT_CHANCMP_OFFSET));

        /* write locate of first desc to register CHAINADDR */
        write64((uint64_t) &u->desc, mmio + CBDMA_CHAINADDR_OFFSET);

        /* writing valid number of descs: starts the DMA */
        write16(1, mmio + CBDMA_DMACOUNT_OFFSET);

        /* wait for completion */
        while (((_u->status) & IOAT_CHANSTS_STATUS)
                == IOAT_CHANSTS_ACTIVE) { }

        /* clear out DMACOUNT */
        write16(0, mmio + CBDMA_DMACOUNT_OFFSET);

        /* ack errors */
        value = pcidev_read32(pci, CHANERR_INT);
        if (value != 0)
                printk("cbdma: error: CHANERR_INT = 0x%x\n", value);
        pcidev_write32(pci, CHANERR_INT, value);
}

#if 0
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
        write64((uint64_t) PADDR(&cbdmadev.chansts),
                mmio + CBDMA_CHANCMP_OFFSET);

        /* write addr of first desc */
        printk(KERN_INFO "[before_transfer] update: CHAINADDR\n");
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
#endif

/* cbdma_stats: get stats about the device and driver
 */
static size_t cbdma_stats(struct chan *c, void *va, size_t n, off64_t offset) {
        char buf[4096]; /* TODO: parameterize size */
        char *ebuf = buf + sizeof(buf);
        char *iter = buf;
        uint64_t value;
        const uint8_t width = 20; /* width of register name column */

        iter = seprintf(iter, ebuf,
                "Intel CBDMA [%x:%x] registered at %02x:%02x.%x\n",
                pci->ven_id, pci->dev_id, pci->bus, pci->dev, pci->func);

        /* driver info. */
        iter = seprintf(iter, ebuf, "    Driver Information:\n");
        iter = seprintf(iter, ebuf,
                "\tmmio: %p\n"
                "\tmmio_phy: 0x%x\n"
                "\tmmio_sz: %lu\n"
                "\ttotal_channels: %d\n"
                "\tdesc_kaddr: %p\n"
                "\tdesc_paddr: %p\n"
                "\tdesc_num: %d\n"
                "\tver: 0x%x\n"
                "\tstatus_kaddr: %p\n"
                "\tstatus_paddr: %p\n"
                "\tstatus_value: 0x%x\n",
                mmio, mmio_phy, mmio_sz, chancnt,
                channel0.pdesc, PADDR(channel0.pdesc), channel0.ndesc,
                channel0.ver, channel0.status, PADDR(channel0.status),
                *(uint64_t *)channel0.status);

        /* print the PCI registers */
        iter = seprintf(iter, ebuf, "    PCIe Config Registers:\n");

        value = 0; value = pcidev_read16(pci, PCI_CMD_REG);
        iter = seprintf(iter, ebuf, "\tPCICMD: 0x%x\n", value);

        value = 0; value = pcidev_read16(pci, PCI_STATUS_REG);
        iter = seprintf(iter, ebuf, "\tPCISTS: 0x%x\n", value);

        value = 0; value = pcidev_read16(pci, PCI_REVID_REG);
        iter = seprintf(iter, ebuf, "\tRID: 0x%x\n", value);

        value = 0; value = pcidev_read32(pci, PCI_BAR0_STD);
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

        /* print the CHANNEL_0 MMIO registers */
        iter = seprintf(iter, ebuf, "    CHANNEL_0 MMIO Registers:\n");

        /* get updated: CHANCMD */
        value = 0; value = read8(mmio + CBDMA_CHANCMD_OFFSET);
        iter = seprintf(iter, ebuf, "\tCHANCMD: 0x%x\n", value);

        /* get updated: CBVER */
        value = 0; value = read8(mmio + IOAT_VER_OFFSET);
        iter = seprintf(iter, ebuf, "\tCBVER: 0x%x major=%d minor=%d\n",
                value,
                GET_IOAT_VER_MAJOR(value),
                GET_IOAT_VER_MINOR(value));

        /* get updated: CHANCTRL */
        value = 0; value = read16(mmio + CBDMA_CHANCTRL_OFFSET);
        iter = seprintf(iter, ebuf, "\tCHANCTRL: 0x%llx\n", value);

        /* get updated: CHANSTS */
        value = 0; value = read64(mmio + CBDMA_CHANSTS_OFFSET);
        iter = seprintf(iter, ebuf, "\tCHANSTS: 0x%x [%s], desc_addr: %p, "
                "raw: 0x%llx\n",
                (value & IOAT_CHANSTS_STATUS),
                cbdma_str_chansts(value),
                (value & IOAT_CHANSTS_COMPLETED_DESCRIPTOR_ADDR),
                value);

        /* get updated: CHAINADDR */
        value = 0; value = read64(mmio + CBDMA_CHAINADDR_OFFSET);
        iter = seprintf(iter, ebuf, "\tCHAINADDR: %p\n", value);

        /* get updated: CHANCMP */
        value = 0; value = read64(mmio + CBDMA_CHANCMP_OFFSET);
        iter = seprintf(iter, ebuf, "\tCHANCMP: %p\n", value);

        /* get updated: DMACOUNT */
        value = 0; value = read16(mmio + CBDMA_DMACOUNT_OFFSET);
        iter = seprintf(iter, ebuf, "\tDMACOUNT: 0x%x\n", value);

        /* get updated: CHANERR */
        value = 0; value = read16(mmio + CBDMA_CHANERR_OFFSET);
        iter = seprintf(iter, ebuf, "\tCHANERR: 0x%x\n", value);

        *iter   = '\0';
        return readstr(offset, va, n, buf);
}

/* cbdma_reset_device: this fixes any programming errors done before
 */
static void cbdma_reset_device() {
        int cbdmaver;
        uint32_t error;

        /* make sure the driver is initialized */
        if (!mmio) {
                error(EPERM, "cbdma: mmio addr not set");
                return; /* does not reach */
        }
 
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

        printk(KERN_INFO "cbdma: reset performed\n");
}

/* cbdma_is_reset_pending: returns true if reset is pending
 */
static bool cbdma_is_reset_pending() {
        int cbdmaver;
        int status;

        /* make sure the driver is initialized */
        if (!mmio) {
                error(EPERM, "cbdma: mmio addr not set");
                return false; /* does not reach */
        }

        /* fetch version */
        cbdmaver = read8(mmio + IOAT_VER_OFFSET);

        status = read8(mmio + IOAT_CHANNEL_MMIO_SIZE
                        + IOAT_CHANCMD_OFFSET(cbdmaver));

        return (status & IOAT_CHANCMD_RESET) == IOAT_CHANCMD_RESET;
}

static size_t cbdmaread(struct chan *c, void *va, size_t n, off64_t offset) {
        char buf[4096]; /* TODO: parameterize size */
        char *ebuf = buf + sizeof(buf);
        char *iter = buf;

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

        case Qcbdmaucopy:
                return readstr(offset, va, n,
                        "Write address of struct ucopy to issue DMA.\n");

        case Qcbdmaiommu:
                iter = seprintf(iter, ebuf,
                        "IOMMU enabled = %s || ", iommu_enabled ? "yes":"no");
                iter = seprintf(iter, ebuf,
                        "write '0' to disable or '1' to enable the IOMMU\n");

                // printk("cbdma: iommu = %s\n", iommu_enabled ? "yes":"no");
                return readstr(offset, va, n, buf);

        default:
                panic("cbdmaread: qid 0x%x is impossible", c->qid.path);
        }

        return -1;      /* not reached */
}

static void init_channel(struct channel *c, int cnum, int ndesc) {
        c->number = cnum;
        c->pdesc = NULL;
        init_desc(c, ndesc);
        
        printk(KERN_INFO "cbdma: done init_desc\n");
        
        /* this is a writeback field; the hardware will update this value */
        if (c->status == 0)
                c->status = (uint64_t)
                        kmalloc_align(sizeof(uint64_t), MEM_WAIT, 8);
        assert(c->status != 0);
        assert((c->status & 0x7) == 0);

        printk(KERN_INFO "cbdma: c->status = %x\n", c->status);

        /* cbdma version */
        c->ver = read8(mmio + IOAT_VER_OFFSET);

        /* Set "Any Error Abort Enable": enables abort for any error encountered
         * Set "Error Completion Enable": enables completion write to address in
                                          CHANCMP for any error
         * Reset "Interrupt Disable": W1C, when clear enables interrupt to fire
                                    for next descriptor that specifies interrupt
        */
        write8(IOAT_CHANCTRL_ANY_ERR_ABORT_EN | IOAT_CHANCTRL_ERR_COMPLETION_EN,
               get_register(c, IOAT_CHANCTRL_OFFSET));

        /* Set channel completion register where CBDMA will write content of
         * CHANSTS register upon successful DMA completion or error condition
         */
        write64(PADDR(c->status), get_register(c, IOAT_CHANCMP_OFFSET));
}

static size_t cbdmawrite(struct chan *c, void *va, size_t n, off64_t offset) {
        switch (c->qid.path) {
        case Qdir:
                error(EPERM, "writing not permitted");

        case Qcbdmaktest:
                if (offset == 0 && n > 0 && *(char *)va == '1') {
                        /* TODO: use locks to verify no running test */
                        ktest.done = false;
                        ktest.srcfill += 1;
                } else
                        error(EINVAL, "cannot be empty string");
                return n;

        case Qcbdmastats:
                error(EPERM, ERROR_FIXME);

        case Qcbdmareset:
                if (offset == 0 && n > 0 && *(char *)va == '1') {
                        cbdma_reset_device();
                        init_channel(&channel0, 0, NDESC);
                } else
                        error(EINVAL, "cannot be empty string");
                return n;

        case Qcbdmaucopy:
                if (offset == 0 && n > 0) {
                        printk("[kern] value from userspace: %p\n", va);

                        if (iommu_enabled)
                                issue_dma_vaddr(va);
                        else
                                issue_dma_kaddr(va);
                        
                        return sizeof(8);
                }
                return 0;

        case Qcbdmaiommu:
                if (offset == 0 && n > 0 && *(char *)va == '1')
                        iommu_enabled = true;
                else if (offset == 0 && n > 0 && *(char *)va == '0')
                        iommu_enabled = false;
                else
                        error(EINVAL, "cannot be empty string");
                return n;

        default:
                panic("cbdmawrite: qid 0x%x is impossible", c->qid.path);
        }

        return -1;      /* not reached */
}

static void cbdma_interrupt(struct hw_trapframe *hw_tf, void *arg)
{
        uint16_t value;

        I_AM_HERE;
        
        value = read16(get_register(&channel0, IOAT_CHANCTRL_OFFSET));
        printk("[READ] IOAT_CHANCTRL_OFFSET = 0x%x\n", value);
        printk("[WRITE] IOAT_CHANCTRL_OFFSET = 0x%x\n", value|IOAT_CHANCTRL_INT_REARM);
        write16(value|IOAT_CHANCTRL_INT_REARM,
               get_register(&channel0, IOAT_CHANCTRL_OFFSET));
        value = read16(get_register(&channel0, IOAT_CHANCTRL_OFFSET));
        printk("[READ] IOAT_CHANCTRL_OFFSET = 0x%x\n", value);

}

void cbdmainit(void) {
        pci             = NULL;
        mmio            = NULL;
        mmio_sz         = -1;
        int tbdf;
        int i;
        int id;
        struct pci_device *pci_iter;

        /* initialize cbdmadev */
        memset(&cbdmadev, 0x0, sizeof(cbdmadev));

        /* search for the device 00:04.0 */
        STAILQ_FOREACH (pci_iter, &pci_devices, all_dev) {
                id = pci_iter->dev_id << 16 | pci_iter->ven_id;
                switch (id) {
                default:
                        continue;
                case ioat2021:
                case ioat2f20:
                        /* dirty hack: bus 0 is the PCI_ALL iommu */
                        if (pci_iter->bus != 0)
                                continue;
                        pci = pci_iter;
                        break;
                }
        }

        if (pci == NULL) {
                printk("cbdma: no Intel CBDMA device found\n");
                return;
        }

        /* search and find the mapped mmio region */
        for (i = 0; i < COUNT_OF(pci->bar); i++) {
                if (pci->bar[i].mmio_sz == 0)
                        continue;
                mmio_phy = (pci->bar[0].mmio_base32
                         ? pci->bar[0].mmio_base32
                         : pci->bar[0].mmio_base64);
                mmio_sz  = pci->bar[i].mmio_sz;
                mmio     = (void *) vmap_pmem_nocache(mmio_phy, mmio_sz);
                break;
        }

        /* handle any errors */
        if (mmio_sz == -1) {
                error(EINVAL, "cbdma: invalid mmio_sz");
        }

        if (mmio == NULL) {
                error(EINVAL, "cbdma: cannot map %p\n", mmio_phy);
        }

        /* performance related stuff */
        pci_set_cacheline_size(pci);

        /* Get the channel count. Top 3 bits of the register are reserved. */
        chancnt = read8(mmio + IOAT_CHANCNT_OFFSET) & 0x1F;

        /* initialization successful; print stats */
        printk(KERN_INFO
                "cbdma: registered [%x:%x] at %02x:%02x.%x // "
                "mmio:%p mmio_sz:%lu\n",
                pci->ven_id, pci->dev_id, pci->bus, pci->dev, pci->func,
                mmio, mmio_sz);
        
        tbdf = MKBUS(BusPCI, pci->bus, pci->dev, pci->func);
        register_irq(pci->irqline, cbdma_interrupt, NULL, tbdf);

        /* reset device */
        cbdma_reset_device();

        /* initialize channel(s) */
        init_channel(&channel0, 0, NDESC);

        /* setup ktest struct */
        ktest.done    = false;
        ktest.srcfill = '1';
        ktest.dstfill = '0';
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
