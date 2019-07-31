/*
 * File: iommu.c - Driver for accessing Intel iommu
 * Author: Aditya Basu <mitthu@google.com>
 */

#include <stdio.h>
#include <error.h>
#include <net/ip.h>
#include <atomic.h>

#include <acpi.h>
#include <arch/intel-iommu.h>
#include <env.h>
#include <arch/pci.h>
#include <linux_compat.h>

#define IOMMU "iommu: "
#define BUFFERSZ 4096

struct dev iommudevtab;
static spinlock_t iommu_lock;
static char buf_mappings[BUFFERSZ];
static char buf_info[BUFFERSZ];

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

                return drhd->rba;
        }

        return 0;
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
    uintptr_t regspace;
} map;

static uintptr_t get_regspace(struct pci_device *device)
{
        uintptr_t tmp;
        tmp = _get_regspace(device);
        if (!tmp) {
                printk(IOMMU "no regspace for pci device\n");
                return 0;
        }

        return vmap_pmem_nocache(tmp, VTD_PAGE_SIZE);
}

static struct mapping *add_map_dev(struct pci_device *device,
                                         struct proc *process)
{
        map.device = device;
        map.process = process;
        map.regspace = get_regspace(map.device);

        return &map;
}

static struct mapping *add_map_bdf(int bus, int dev, int func,
                                        pid_t pid)
{
        int tbdf = MKBUS(BusPCI, bus, dev, func);
        struct pci_device *d;
        struct proc *p = pid2proc(pid);

        d = pci_match_tbdf(tbdf);
        if (!d) {
                printk(IOMMU "cannot find dev %x:%x.%x\n", bus, dev, func);
                return NULL;
        }

        if (!p) {
                printk(IOMMU "cannot find pid %d\n", pid);
                return NULL;
        }

        map.device = d;
        map.process = p;
        map.regspace = get_regspace(map.device);

        return &map;
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
        if (map.regspace)
                vunmap_vmem(map.regspace, VTD_PAGE_SIZE);
}

static bool map_is_empty()
{
        if (map.process == NULL || map.device == NULL)
                return true;
        return false;
}

/////// END: MAPPING ///////////////////////////////////////////////////////////

/////// ROOT TABLE /////////////////////////////////////////////////////////////

// TODO: incomplete
static void rt_init(void)
{
        /* Page Align = 0x1000 */
        kpage_alloc_addr();
        kmalloc_align(sizeof(uint64_t), MEM_WAIT, 0x1000);
}

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

        iter = seprintf(iter, ebuf, "iommu info:\n");
        if (map_is_empty()){
                iter = seprintf(iter, ebuf, "\t<none> // map empty\n");
                return;
        }

        iter = seprintf(iter, ebuf, "\tregspace@%p\n", map.regspace);
        
        value = read32((uint32_t *) map.regspace + DMAR_VER_REG);
        iter = seprintf(iter, ebuf, "\tversion = 0x%x\n", value);

        value = read64((uint64_t *) map.regspace + DMAR_CAP_REG);
        iter = seprintf(iter, ebuf, "\tcapabilities = 0x%x\n", value);

        value = read64((uint64_t *) map.regspace + DMAR_ECAP_REG);
        iter = seprintf(iter, ebuf, "\text. capabilities = 0x%x\n", value);

        value = read32((uint32_t *) map.regspace + DMAR_GSTS_REG);
        iter = seprintf(iter, ebuf, "\tglobal status = 0x%x\n", value);

        value = read64((uint64_t *) map.regspace + DMAR_RTADDR_REG);
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
