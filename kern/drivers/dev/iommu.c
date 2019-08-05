/*
 * File: iommu.c - Driver for accessing Intel iommu
 * Author: Aditya Basu <mitthu@google.com>

 TODO
 ====
 - Add a linked list for root-entries corresponding to different PCI domains.
 - For now, we setup (add to regspace) the IOMMU root entry on every mapping.
 - Similarly we tear down (remove from regspace) the root entry on deletion of
 mapping. Note that the in memory paging structures are not deleted.
 */

#include <stdio.h>
#include <error.h>
#include <net/ip.h>
#include <atomic.h>

#include <acpi.h>
#include <arch/iommu.h>
#include <env.h>
#include <arch/pci.h>
#include <linux_compat.h>

#define IOMMU "iommu: "
#define BUFFERSZ 4096
#define PCI_DOMAIN 0

struct dev iommudevtab;
static spinlock_t iommu_lock;
static char buf_mappings[BUFFERSZ];
static char buf_info[BUFFERSZ];
physaddr_t iommu_rt; // TODO: support multiple root tables based on PCI domains

/* QID Path */
enum {
        Qdir         = 0,
        Qmappings    = 1,
        Qadddev      = 2,
        Qremovedev   = 3,
        Qinfo        = 4,
};

static struct dirtab iommudir[] = {
        {".",                   {Qdir, 0, QTDIR}, 0, 0555},
        {"mappings",            {Qmappings, 0, QTFILE}, 0, 0755},
        {"attach",              {Qadddev, 0, QTFILE}, 0, 0755},
        {"detach",              {Qremovedev, 0, QTFILE}, 0, 0755},
        {"info",                {Qinfo, 0, QTFILE}, 0, 0755},
};

/////// START: ROOT TABLE //////////////////////////////////////////////////////
// TODO: find the regspace for the current device; currently returns the first
/* Find the reg space associated with the device.
 */
static uintptr_t _get_regspace(struct pci_device *p)
{
        struct Dmar *dt;

        /* dmar is a global variable. see acpi.h */
        if (dmar == NULL) {
                printk(IOMMU "DMAR not found\n");
                return 0;
        }

        dt = dmar->tbl;
        for (int i = 0; i < dmar->nchildren; i++) {
                struct Atable *at = dmar->children[i];
                struct Drhd *drhd = at->tbl;

                if (drhd->all & 1 )
                        return drhd->rba;
        }

        return 0;
}

static inline struct root_entry *get_root_entry(physaddr_t paddr)
{
        return (struct root_entry *) KADDR(paddr);
}

static inline struct context_entry *get_context_entry(physaddr_t paddr)
{
        return (struct context_entry *) KADDR(paddr);
}

static physaddr_t ct_init(uint16_t domain)
{
        struct context_entry *cte;
        physaddr_t ct;
        int i;

        cte = (struct context_entry *) kpage_zalloc_addr();
        ct = PADDR(cte);

        for (i = 0; i < 32 * 8; i++, cte++) { // device * func
                /* initializations such as the domain */
                cte->hi |= (domain << CTX_HI_DID_SHIFT); // DID bit: 72 to 87
                cte->lo = 0;
        }

        return ct;
}

/* Get a new root_entry table. Allocates all context entries. */
static physaddr_t rt_init(uint16_t domain)
{
        struct root_entry *rte;
        physaddr_t rt;
        uintptr_t ct;
        int i;

        /* Page Align = 0x1000 */
        rte = (struct root_entry *) kpage_zalloc_addr();
        rt = PADDR(rte);
        // printk(IOMMU "rt returned: %p // %p (phy)\n", rte, rt);

        /* create context table */
        for (i = 0; i < 256; i++, rte++) {
                ct = ct_init(domain);
                rte->lo = (ct | 1UL); // 1UL: is present
                rte->hi = 0;
        }

        return rt;
}

static int rt_enable(void __iomem *regspace, physaddr_t rt_paddr)
{
        struct root_entry *rt = get_root_entry(rt_paddr);
        uint32_t cmd = 0, status = 0;

        // write the root table address
        printk(IOMMU "write rtaddr: value = 0x%x @%p\n", rt_paddr,
                (uint64_t *) regspace + DMAR_RTADDR_REG);

        write64(rt_paddr, regspace + DMAR_RTADDR_REG);

        // issue command to reload the root table address
        // TODO: flush IOTLB if reported as necessary by cap register
        // TODO: issue TE only once
        cmd = DMA_GCMD_TE | DMA_GCMD_SRTP;
        write32(cmd, regspace + DMAR_GCMD_REG);
        // printk(IOMMU "write cmd: 0x%x\n", cmd);

        status = read32(regspace + DMAR_GSTS_REG);
        // printk(IOMMU "raw cmd status: 0x%x\n", status);

        printk(IOMMU "translation %s\n",
                status & DMA_GSTS_TES ? "enabled" : "disabled");
        printk(IOMMU "root table %s\n",
                status & DMA_GSTS_TES ? "is set" : "is not set");

        // TODO: return based on values in the register
        return status;
}

static void set_pte(int bus, int dev, int func, physaddr_t pg)
{

}

/////// END: ROOT TABLE ////////////////////////////////////////////////////////


/* Helpers for set/get/init PCI device (BDF) <=> Process map */
//////// BEGIN: MAPPING ////////////////////////////////////////////////////////
/* TODO: Manage regspace in a separate struct. We currently remap the regspace
with NOCACHE and remove this PTE on deletion. For multiple devices we will want
to manage it differently.
*/
static struct mapping {
    struct pci_device *device;
    struct proc *process;
    void __iomem *regspace;
} map;

static void __iomem *get_regspace(struct pci_device *device)
{
        uintptr_t tmp;
        tmp = _get_regspace(device);
        if (!tmp) {
                printk(IOMMU "no regspace for pci device\n");
                return 0;
        }

        return (void __iomem *) vmap_pmem_nocache(tmp, VTD_PAGE_SIZE);
}

static struct mapping *add_map_dev(struct pci_device *device,
                                         struct proc *process)
{
        if (!device) {
                printk(IOMMU "cannot find pci dev\n");
                return NULL;
        }

        if (!process) {
                printk(IOMMU "cannot find process\n");
                return NULL;
        }

        map.device = device;
        map.process = process;
        map.regspace = get_regspace(map.device);

        return &map;
}

static struct mapping *add_map_bdf(int bus, int dev, int func,
                                        pid_t pid)
{
        int tbdf = MKBUS(BusPCI, bus, dev, func);
        struct pci_device *d = pci_match_tbdf(tbdf);
        struct proc *p = pid2proc(pid);

        if (!d) {
                printk(IOMMU "cannot find dev %x:%x.%x\n", bus, dev, func);
                return NULL;
        }

        if (!p) {
                printk(IOMMU "cannot find pid %d\n", pid);
                return NULL;
        }

        return add_map_dev(d, p);
}

/* We just have one entry. However when we have a linked list, we can choose by
   process. */
static struct mapping *get_map(struct proc *process)
{
        return &map;
}

static void del_map(struct mapping *m)
{
        map.device = NULL;
        map.process = NULL;
        if (map.regspace) {
                vunmap_vmem((uintptr_t) map.regspace, VTD_PAGE_SIZE);
                map.regspace = NULL;
        }
}

static bool map_is_empty()
{
        if (map.process == NULL || map.device == NULL)
                return true;
        return false;
}

/////// END: MAPPING ///////////////////////////////////////////////////////////

/////// MISC ///////////////////////////////////////////////////////////////////
static int write_add_dev(char *va, size_t n)
{
        int bus, dev, func, err;
        pid_t pid;
        struct mapping *m = NULL;

        err = sscanf(va, "%x:%x.%x %d\n", &bus, &dev, &func, &pid);
        printk(IOMMU "parsed:\n"
                "\tb = %x\n"
                "\td = %x\n"
                "\tf = %x\n"
                "\tpid = %d\n",
                bus, dev, func, pid);

        if (err != 4) {
                printk(IOMMU "error parsing #iommu/attach; items parsed: %d\n",
                        err);
                return 0;
        }

        m = add_map_bdf(bus, dev, func, pid);
        if (!m) {
                printk(IOMMU "passthru failed\n");
                return 0;
        }

        // enable root table
        rt_enable(m->regspace, iommu_rt);

        return n;
}

static int write_remove_dev(char *va, size_t n)
{
        int err;
        pid_t pid;

        err = sscanf(va, "%d\n", &pid);
        printk(IOMMU "parsed:\n"
                "\tpid = %d\n", pid);

        if (err != 1) {
                printk(IOMMU "error parsing #iommu/detach; items parsed: %d\n",
                        err);
                return 0;
        }

        del_map(&map);

        return n;
}

static void open_mappings(void)
{
        char *ebuf = buf_mappings + sizeof(buf_mappings);
        char *iter = buf_mappings;

        iter = seprintf(iter, ebuf, "mappings:\n");
        if (map_is_empty()){
                iter = seprintf(iter, ebuf, "\t<none>\n");
                return;
        }

        iter = seprintf(iter, ebuf, "\tdevice = %x:%x.%x // ",
                map.device->bus, map.device->dev, map.device->func);
        iter = seprintf(iter, ebuf, "process = %d\n",
                map.process->pid);
}

static void open_info(void)
{
        char *ebuf = buf_info + sizeof(buf_info);
        char *iter = buf_info;
        uint64_t value;

        iter = seprintf(iter, ebuf, "driver info:\n");

        value = PCI_DOMAIN;
        iter = seprintf(iter, ebuf, "\ttarget PCI domain = %d\n", value);
        iter = seprintf(iter, ebuf, "\troot table paddr = %p\n", iommu_rt);

        iter = seprintf(iter, ebuf, "iommu info:\n");
        if (map_is_empty()){
                iter = seprintf(iter, ebuf, "\t<none> // map empty\n");
                return;
        }

        iter = seprintf(iter, ebuf, "\tregspace@%p\n", map.regspace);
        
        value = 0; value = read32(map.regspace + DMAR_VER_REG);
        iter = seprintf(iter, ebuf, "\tversion = 0x%x\n", value);


        value = read64(map.regspace + DMAR_CAP_REG);
        iter = seprintf(iter, ebuf, "\tcapabilities = 0x%x\n", value);

        value = 0; value = read64(map.regspace + DMAR_ECAP_REG);
        iter = seprintf(iter, ebuf, "\text. capabilities = 0x%x\n", value);

        value = read32(map.regspace + DMAR_GSTS_REG);
        iter = seprintf(iter, ebuf, "\tglobal status = 0x%x\n", value);

        value = read64(map.regspace + DMAR_RTADDR_REG);
        iter = seprintf(iter, ebuf,
                "\troot entry table = %p (phy) or %p (vir)\n",
                value, KADDR(value));
}

/////// GENERIC ////////////////////////////////////////////////////////////////

static char *devname(void)
{
        return iommudevtab.name;
}

static struct chan *iommuattach(char *spec)
{
        return devattach(devname(), spec);
}

static struct walkqid *iommuwalk(struct chan *c, struct chan *nc, char **name,
                         unsigned int nname)
{
        return devwalk(c, nc, name, nname, iommudir,
                       ARRAY_SIZE(iommudir), devgen);
}

static size_t iommustat(struct chan *c, uint8_t *dp, size_t n)
{
        return devstat(c, dp, n, iommudir, ARRAY_SIZE(iommudir), devgen);
}

static struct chan *iommuopen(struct chan *c, int omode)
{
        spin_lock_irqsave(&iommu_lock);

        switch (c->qid.path) {
        case Qmappings:
                open_mappings();
                break;

        case Qinfo:
                open_info();
                break;

        case Qadddev:
        case Qremovedev:
        case Qdir:
        default:
                break;
        }

        spin_unlock_irqsave(&iommu_lock);

        return devopen(c, omode, iommudir, ARRAY_SIZE(iommudir), devgen);
}

/*
 * All files are synthetic. Hence we do not need to implement any close
 * function.
 */
static void iommuclose(struct chan *_)
{
}

static size_t iommuread(struct chan *c, void *va, size_t n, off64_t offset)
{
        switch (c->qid.path) {
        case Qdir:
                return devdirread(c, va, n, iommudir,
                                  ARRAY_SIZE(iommudir), devgen);

        case Qmappings:
                return readstr(offset, va, n, buf_mappings);

        case Qadddev:
                return readstr(offset, va, n,
                    "write format: xx:yy.z pid\n"
                    "   xx  = bus (in hex)\n"
                    "   yy  = device (in hex)\n"
                    "   z   = function (in hex)\n"
                    "   pid = process pid\n"
                    "\nexample:\n"
                    "$ echo 00:1f.2 13 >\\#iommu/attach\n");

        case Qremovedev:
                return readstr(offset, va, n,
                    "write format: pid\n"
                    "example:\n"
                    "$ echo 13 >\\#iommu/detach\n");

        case Qinfo:
                return readstr(offset, va, n, buf_info);

        default:
                panic(IOMMU "read: qid %d is impossible\n", c->qid.path);
        }

        return -1;      /* not reached */
}

static size_t iommuwrite(struct chan *c, void *va, size_t n, off64_t offset)
{
        int err = -1;

        spin_lock_irqsave(&iommu_lock);

        switch (c->qid.path) {
        case Qadddev:
                err = write_add_dev(va, n);
                break;

        case Qremovedev:
                err = write_remove_dev(va, n);
                break;

        case Qmappings:
        case Qinfo:
        case Qdir:
                printk(IOMMU "write: qid %d not implemented\n", c->qid.path);
                break;
        default:
                printk(IOMMU "write: qid %d is impossible\n", c->qid.path);
                break;
        }

        spin_unlock_irqsave(&iommu_lock);

        return err;
}

static void iommuinit(void)
{
        spinlock_init_irqsave(&iommu_lock);
        iommu_rt = rt_init(PCI_DOMAIN);  // hardcoded for PCI domain = 0

        printk(IOMMU "initialized\n");
}

struct dev iommudevtab __devtab = {
        .name       = "iommu",
        .reset      = devreset,
        .init       = iommuinit,
        .shutdown   = devshutdown,
        .attach     = iommuattach,
        .walk       = iommuwalk,
        .stat       = iommustat,
        .open       = iommuopen,
        .create     = devcreate,
        .close      = iommuclose,
        .read       = iommuread,
        .bread      = devbread,
        .write      = iommuwrite,
        .bwrite     = devbwrite,
        .remove     = devremove,
        .wstat      = devwstat,
};
