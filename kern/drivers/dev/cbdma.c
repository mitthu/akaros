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

struct dev                cbdmadevtab;
static struct pci_device  *pci;
static char               *mmio;
static uint32_t           mmio_sz;
/* QID Path */
enum {
        Qdir           = 0,
        Qcbdmaktest    = 1,
        Qcbdmastats    = 2,
};

static struct dirtab cbdmadir[] = {
        {".",         {Qdir, 0, QTDIR}, 0, 0555},
        {"ktest",     {Qcbdmaktest, 0, QTFILE}, 0, 0555},
        {"stats",     {Qcbdmastats, 0, QTFILE}, 0, 0555},
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

/* cbdma_ktest: performs functional test on CBDMA
   
 - Allocates 2 kernel pages: src and dest.
 - memsets the src page
 - Prepare descriptors for DMA transfer (need to be aligned)
 - Initiate the transfer
 - Verify results
 - Print stats
 */ 
static size_t cbdma_ktest(struct chan *c, void *va, size_t n, off64_t offset) {
        char *src;
        char *dst;
        const int size = 1024;

        char *desc_page;
        uint64_t desc_page_paddr;
        struct desc *d;

        /* allocate src & dst buffers and initialize with different values */
        src = kmalloc(size, MEM_WAIT);
        dst = kmalloc(size, MEM_WAIT);
        memset(src, 0x0F, size);
        memset(dst, 0x00, size);

        printk(KERN_INFO "src:%x dst:%x\n", src, dst);

        /* allocate pages for descriptors, last 6-bits must be zero */
        desc_page = kpage_alloc_addr();
        memset(desc_page, 0x0, PGSIZE);

        desc_page_paddr = (uint64_t) PADDR(desc_page);
        assert((desc_page_paddr & 0x3F) == 0);

        printk(KERN_INFO "desc_page:%x desc_page_paddr:%x\n", desc_page, desc_page_paddr);

        /* preparing descriptors */
        d = (struct desc *) desc_page;
        d->next_desc_addr       = (uint64_t) d + sizeof(struct desc);
        d->xfer_size            = (uint32_t) size;
        d->src_addr             = (uint64_t) src;
        d->dest_addr            = (uint64_t) dst;
        d->descriptor_control   = IOAT_DESC_CTRL_INTR_ON_COMPLETION |
                                  IOAT_DESC_CTRL_WRITE_CHANCMP_ON_COMPLETION;

        /* initiate transfer */
        ;

kpage_free:
        /* TODO: free the kpage */
kmalloc_free:
        kfree(dst);
        kfree(src);
        return 0;
}

/* cbdma_stats: some stats about the driver
 */ 
static size_t cbdma_stats(struct chan *c, void *va, size_t n, off64_t offset) {
        char buf[4096];
        char *ebuf = buf + sizeof(buf) - 1; /* -1 for newline */
        char *iter = buf;

        iter = seprintf(iter, ebuf, "Intel CBDM [%x:%x] mmio:%x mmio_sz:%lu",
                        pci->ven_id, pci->dev_id, mmio, mmio_sz);
        *iter++ = '\n';
        *iter   = '\0';
        return readstr(offset, va, n, buf);
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

        default:
                panic("cbdmawrite: qid 0x%x is impossible", c->qid.path);
        }

        return -1;      /* not reached */
}

void cbdmainit(void) {
        int tbdf  = MKBUS(BusPCI, 0, 0x4, 0);
        pci       = NULL;
        mmio      = NULL;
        mmio_sz   = -1;
        int i;

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
                mmio    = (char *) pci->bar[i].mmio_base64;
                mmio_sz = pci->bar[i].mmio_sz;
                break;
        }

        if (mmio == NULL || mmio_sz == -1) {
                error(EINVAL, "Cannot register Intel CBDMA\n");                
        }

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
