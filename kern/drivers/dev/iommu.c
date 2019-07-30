/*
 * File: iommu.c - Driver for accessing Intel iommu
 * Author: Aditya Basu <mitthu@google.com>
 */

#include <stdio.h>
#include <error.h>
#include <net/ip.h>

#include <acpi.h>
#include <arch/intel-iommu.h>
#include <env.h>
#include <arch/pci.h>
#include <linux_compat.h>

#define IOMMU "iommu: "

struct dev iommudevtab;

/* QID Path */
enum {
        Qdir         = 0,
        Qmappings    = 1,
        Qadddev      = 2,
        Qremovedev   = 3,
};

static struct dirtab iommudir[] = {
        {".",                   {Qdir, 0, QTDIR}, 0, 0555},
        {"mappings",            {Qmappings, 0, QTFILE}, 0, 0555},
        {"add_dev",             {Qadddev, 0, QTFILE}, 0, 0555},
        {"remove_dev",          {Qremovedev, 0, QTFILE}, 0, 0555},
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

        return &map;
}

static struct mapping *add_map_bdf(int bus, int dev, int func,
                                         struct proc *process)
{
        int tbdf = MKBUS(BusPCI, bus, dev, func);
        map.device = pci_match_tbdf(tbdf);
        if (!map.device) {
                printk(IOMMU "cannot find dev %x:%x.%x\n", bus, dev, func);
                return NULL;
        }

        map.process = process;

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
/////// END: MAPPING ///////////////////////////////////////////////////////////


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
                return readstr(offset, va, n, "not yet implemented!\n");

        case Qadddev:
                return readstr(offset, va, n, "not yet implemented!\n");

        case Qremovedev:
                return readstr(offset, va, n, "not yet implemented!\n");

        default:
                panic("iommu: read: qid %d is impossible", c->qid.path);
        }

        return -1;      /* not reached */
}

static size_t iommuwrite(struct chan *c, void *va, size_t n, off64_t offset)
{
        error(EPERM, "writing not yet implemented");
}

struct dev iommudevtab __devtab = {
        .name       = "iommu",
        .reset      = devreset,
        .init       = devinit,
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
