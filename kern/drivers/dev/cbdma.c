/*
 * File: cbdma.c - Driver for accessing Intel CBDMA
 * Author: Aditya Basu <mitthu@google.com>
 */

#include <slab.h>
#include <kmalloc.h>
#include <kref.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <error.h>
#include <cpio.h>
#include <pmap.h>
#include <smp.h>
#include <net/ip.h>
#include <arch/io.h>

struct dev cbdmadevtab;

/* QID Path */
enum {
        Qdir           = 0,
        Qcbdmaktest    = 1,
};

static struct dirtab cbdmadir[] = {
        {".",         {Qdir, 0, QTDIR}, 0, 0555},
        {"ktest",     {Qcbdmaktest, 0, QTFILE}, 0, 0555},
};

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

static size_t cbdmaread(struct chan *c, void *va, size_t n, off64_t offset) {
        switch (c->qid.path) {
        case Qdir:
                return devdirread(c, va, n, cbdmadir,
                                  ARRAY_SIZE(cbdmadir), devgen);

        case Qcbdmaktest:
                error(EPERM, "Reading is not yet implemented!");

        default:
                panic("cbdmaread: qid %d is impossible", c->qid.path);
        }

        return -1;      /* not reached */
}

static size_t cbdmawrite(struct chan *c, void *va, size_t n, off64_t offset) {
        error(EPERM, "Writing is not yet implemented!");
        return -1;
        // uint8_t *a;
        // int i, r, tbdf;
        // uint32_t x;
        // struct pci_device *p;

        // if (n > PCI_CONFIG_SZ)
        //         n = PCI_CONFIG_SZ;
        // a = va;

        // switch (TYPE(c->qid)) {
        // case Qpciraw:
        //         tbdf = MKBUS(BusPCI, 0, 0, 0) | BUSBDF((uint32_t) c->qid.path);
        //         p = pci_match_tbdf(tbdf);
        //         if (p == NULL)
        //                 error(EINVAL, ERROR_FIXME);
        //         if (offset > PCI_CONFIG_SZ)
        //                 return 0;
        //         if (n + offset > PCI_CONFIG_SZ)
        //                 n = PCI_CONFIG_SZ - offset;
        //         r = offset;
        //         if (!(r & 3) && n == 4) {
        //                 x = GBIT32(a);
        //                 pcidev_write32(p, r, x);
        //                 return 4;
        //         }
        //         if (!(r & 1) && n == 2) {
        //                 x = GBIT16(a);
        //                 pcidev_write16(p, r, x);
        //                 return 2;
        //         }
        //         for (i = 0; i < n; i++) {
        //                 x = GBIT8(a);
        //                 pcidev_write8(p, r, x);
        //                 a++;
        //                 r++;
        //         }
        //         return i;
        // default:
        //         error(EINVAL, ERROR_FIXME);
        // }
        // return n;
}

struct dev cbdmadevtab __devtab = {
        .name       = "cbdma",
        .reset      = devreset,
        .init       = devinit,
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
