// INFERNO
#include <vfs.h>
#include <kfs.h>
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
#include <ip.h>

static void
nullbind(struct ipifc *unused_ipifc, int unused_int, char **unused_char_pp_t)
{
	error("cannot bind null device");
}

static void
nullunbind(struct ipifc *unused_ipifc)
{
}

static void
nullbwrite(struct ipifc *unused_ipifc, struct block*, int unused_int, uint8_t *unused_uint8_p_t)
{
	error("nullbwrite");
}

struct medium nullmedium =
{
.name=		"null",
.bind=		nullbind,
.unbind=	nullunbind,
.bwrite=	nullbwrite,
};

void
nullmediumlink(void)
{
	addipmedium(&nullmedium);
}
