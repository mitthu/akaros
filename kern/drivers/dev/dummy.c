/*
 * File: dummy.c - Driver for accessing Intel dummy
 * Author: Aditya Basu <mitthu@google.com>
 */

#include <stdio.h>
#include <error.h>
#include <net/ip.h>

#define DEBUG

struct dev dummydevtab;

/* QID Path */
enum {
        Qdir             = 0,
        Qdirdir          = 1,
        Qdummyafile      = 2,
        Qdummysomefile   = 3,
};

static struct dirtab dummydir[] = {
        {".",                   {Qdir, 0, QTDIR}, 0, 0555},
        {"dir",                 {Qdirdir, 0, QTDIR}, 0, 0555},
        {"afile",               {Qdummyafile, 0, QTFILE}, 0, 0555},
};

static struct dirtab dummydirdir[] = {
        {".",                   {Qdirdir, 0, QTDIR}, 0, 0555},
        {"somefile",            {Qdummysomefile, 0, QTFILE}, 0, 0555},
};

static char *devname(void) {
        return dummydevtab.name;
}

static struct chan *dummyattach(char *spec) {
        return devattach(devname(), spec);
}

struct walkqid *dummywalk(struct chan *c, struct chan *nc, char **name,
                         unsigned int nname) {
        if (c->qid.path == Qdirdir || c->qid.path == Qdummysomefile)
                return devwalk(c, nc, name, nname, dummydirdir,
                               ARRAY_SIZE(dummydirdir), devgen);
        else
                return devwalk(c, nc, name, nname, dummydir,
                               ARRAY_SIZE(dummydir), devgen);

        // switch (c->qid.path) {
        // case Qdir:
        // default:
        //         return devwalk(c, nc, name, nname, dummydir,
        //                        ARRAY_SIZE(dummydir), devgen);
        // case Qdirdir:
        //         return devwalk(c, nc, name, nname, dummydirdir,
        //                        ARRAY_SIZE(dummydirdir), devgen);
        // }

        return NULL;      /* not reached */
}

static size_t dummystat(struct chan *c, uint8_t *dp, size_t n) {
        if (c->qid.path == Qdirdir || c->qid.path == Qdummysomefile)
                return devstat(c, dp, n, dummydirdir,
                               ARRAY_SIZE(dummydirdir), devgen);
        else
                return devstat(c, dp, n, dummydir,
                               ARRAY_SIZE(dummydir), devgen);
//        return devstat(c, dp, n, dummydir, ARRAY_SIZE(dummydir), devgen);
}

static struct chan *dummyopen(struct chan *c, int omode) {
        if (c->qid.path == Qdirdir || c->qid.path == Qdummysomefile)
                return devopen(c, omode, dummydirdir, ARRAY_SIZE(dummydirdir), devgen);
        else
                return devopen(c, omode, dummydir, ARRAY_SIZE(dummydir), devgen);

//        return devopen(c, omode, dummydir, ARRAY_SIZE(dummydir), devgen);
}

/*
 * All files are synthetic. Hence we do not need to implement any close
 * function.
 */
static void dummyclose(struct chan *_) {
}

static size_t dummyread(struct chan *c, void *va, size_t n, off64_t offset) {
        switch (c->qid.path) {
        case Qdir:
                return devdirread(c, va, n, dummydir,
                                  ARRAY_SIZE(dummydir), devgen);

        case Qdirdir:
                return devdirread(c, va, n, dummydirdir,
                                  ARRAY_SIZE(dummydirdir), devgen);

        case Qdummyafile:
                return readstr(offset, va, n, "This is afile!\n");

        case Qdummysomefile:
                error(EPERM, "reading not yet implemented for: somefile");

        default:
                panic("dummyread: qid %d is impossible", c->qid.path);
        }

        return -1;      /* not reached */
}

static size_t dummywrite(struct chan *c, void *va, size_t n, off64_t offset) {
        error(EPERM, "writing not yet implemented");
        return -1;
}

struct dev dummydevtab __devtab = {
        .name       = "dummy",
        .reset      = devreset,
        .init       = devinit,
        .shutdown   = devshutdown,
        .attach     = dummyattach,
        .walk       = dummywalk,
        .stat       = dummystat,
        .open       = dummyopen,
        .create     = devcreate,
        .close      = dummyclose,
        .read       = dummyread,
        .bread      = devbread,
        .write      = dummywrite,
        .bwrite     = devbwrite,
        .remove     = devremove,
        .wstat      = devwstat,
};
