/*
 * File: iommu.c - Driver for accessing Intel iommu
 * Author: Aditya Basu <mitthu@google.com>
 */

#include <stdio.h>
#include <error.h>
#include <net/ip.h>

#define DEBUG

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
