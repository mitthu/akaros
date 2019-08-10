/*
 * File: iommu.c - Driver for accessing Intel iommu
 * Author: Aditya Basu <mitthu@google.com>

 TODO
 ====
 - Disallow attaching #iommu is iommu_supported() returns false
 - In acpi.c, force parsedmar() in acpiinit()
 - Decide locking for 'info' and 'mappings' files. Do we use a global lock?
 - In struct proc, initialize pcidev_stailq during process init.

 - Add a linked list for root-entries corresponding to different PCI domains.
 - For now, we setup (add to regspace) the IOMMU root entry on every mapping.
 - Similarly we tear down (remove from regspace) the root entry on deletion of
 mapping. Note that the in memory paging structures are not deleted.
 */

#include <stdio.h>
#include <error.h>
#include <common.h>
#include <net/ip.h>
#include <atomic.h>

#include <acpi.h>
#include <arch/iommu.h>
#include <env.h>
#include <arch/pci.h>
#include <linux_compat.h>

#define IOMMU "iommu: "
#define BUFFERSZ 4096

struct dev iommudevtab;
struct iommu_list_tq iommu_list = TAILQ_HEAD_INITIALIZER(iommu_list);

/* QID Path */
enum {
        Qdir         = 0,
        Qmappings    = 1,
        Qadddev      = 2,
        Qremovedev   = 3,
        Qinfo        = 4,
        Qpower       = 5,
};

static struct dirtab iommudir[] = {
        {".",                   {Qdir, 0, QTDIR}, 0, 0555},
        {"mappings",            {Qmappings, 0, QTFILE}, 0, 0755},
        {"attach",              {Qadddev, 0, QTFILE}, 0, 0755},
        {"detach",              {Qremovedev, 0, QTFILE}, 0, 0755},
        {"info",                {Qinfo, 0, QTFILE}, 0, 0755},
        {"power",               {Qpower, 0, QTFILE}, 0, 0755},
};

/////// START: ROOT TABLE //////////////////////////////////////////////////////
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

        cte = (struct context_entry *) kpage_zalloc_addr();
        ct = PADDR(cte);

        for (int i = 0; i < 32 * 8; i++, cte++) { // device * func
                /* initializations such as the domain */
                cte->hi = 0
                        | (domain << CTX_HI_DID_SHIFT) // DID bit: 72 to 87
                        | (CTX_AW_DEFAULT << CTX_HI_AW_SHIFT); // AW
                cte->lo = 0
                        | (0x1 << CTX_LO_PRESET_SHIFT) // is present
                        | (0x2 << CTX_LO_TRANS_SHIFT) // 0x2: pass through
                        | (0x1 << CTX_LO_FPD_SHIFT); // disable faults
        }

        return ct;
}

/* Get a new root_entry table. Allocates all context entries. */
static physaddr_t rt_init(uint16_t did)
{
        struct root_entry *rte;
        physaddr_t rt;
        physaddr_t ct;

        /* Page Align = 0x1000 */
        rte = (struct root_entry *) kpage_zalloc_addr();
        rt = PADDR(rte);
        // printk(IOMMU "rt returned: %p // %p (phy)\n", rte, rt);

        /* create context table */
        for (int i = 0; i < 256; i++, rte++) {
                ct = ct_init(did);
                rte->hi = 0;
                rte->lo = 0
                        | ct
                        | (0x1 << RT_LO_PRESET_SHIFT);
        }

        return rt;
}

static void setup_page_tables(struct proc *p, struct pci_device *d)
{
        // setup the pte
}

static void teardown_page_tables(struct proc *p, struct pci_device *d)
{

}

/////// END: ROOT TABLE ////////////////////////////////////////////////////////

/////// START: ENABLE / DISABLE IOMMU //////////////////////////////////////////

static bool _iommu_enable(struct iommu *iommu)
{
        uint32_t cmd, status;

        spin_lock_irqsave(&iommu->iommu_lock);

        /* write the root table address */
        write64(iommu->roottable, iommu->regio + DMAR_RTADDR_REG);

        // TODO: flush IOTLB if reported as necessary by cap register
        // TODO: issue TE only once
        /* enable translation and set root table */
        cmd = DMA_GCMD_TE | DMA_GCMD_SRTP;
        write32(cmd, iommu->regio + DMAR_GCMD_REG);

        /* read status */
        status = read32(iommu->regio + DMAR_GSTS_REG);

        spin_unlock_irqsave(&iommu->iommu_lock);

        return status & DMA_GSTS_TES;
}

void iommu_enable(void)
{
        struct iommu *iommu;

        /* races are possible; add a global lock? */
        if (iommu_status())
                return;

        TAILQ_FOREACH(iommu, &iommu_list, iommu_link) {
                _iommu_enable(iommu);
        }
}

static bool _iommu_disable(struct iommu *iommu)
{
        uint32_t cmd, status;

        spin_lock_irqsave(&iommu->iommu_lock);

        /* write the root table address */
        write64(iommu->roottable, iommu->regio + DMAR_RTADDR_REG);

        // TODO: flush IOTLB if reported as necessary by cap register
        // TODO: issue TE only once
        /* disable translation */
        cmd = 0;
        write32(cmd, iommu->regio + DMAR_GCMD_REG);

        /* read status */
        status = read32(iommu->regio + DMAR_GSTS_REG);

        spin_unlock_irqsave(&iommu->iommu_lock);

        return status & DMA_GSTS_TES;
}

void iommu_disable(void)
{
        struct iommu *iommu;

        /* races are possible; add a global lock? */
        if (!iommu_status())
                return;

        TAILQ_FOREACH(iommu, &iommu_list, iommu_link) {
                _iommu_disable(iommu);
        }
}

static bool _iommu_status(struct iommu *iommu)
{
        uint32_t status = 0;

        spin_lock_irqsave(&iommu->iommu_lock);

        /* read status */
        status = read32(iommu->regio + DMAR_GSTS_REG);

        spin_unlock_irqsave(&iommu->iommu_lock);

        return status & DMA_GSTS_TES;
}

bool iommu_status(void)
{
        struct iommu *iommu;

        TAILQ_FOREACH(iommu, &iommu_list, iommu_link) {
                if(_iommu_status(iommu))
                        return true;
        }

        return false;
}

/////// END: ENABLE / DISABLE IOMMU ////////////////////////////////////////////

/* Helpers for set/get/init PCI device (BDF) <=> Process map */

//////// BEGIN: MAPPING ////////////////////////////////////////////////////////

/* come up with a better name! */
static bool proc_already_in_iommu_list(struct iommu *iommu, struct proc *p)
{
        struct proc *proc_iter;

        TAILQ_FOREACH(proc_iter, &iommu->procs, iommu_link) {
                if (proc_iter == p)
                        return true;
        }

        return false;
}

/* this function retains a KREF to struct proc for each assigned PCI device */
static bool assign_device(int bus, int dev, int func, pid_t pid)
{
        int tbdf = MKBUS(BusPCI, bus, dev, func);
        struct pci_device *d = pci_match_tbdf(tbdf);
        struct proc *p = pid2proc(pid);

        if (!p) {
                printk(IOMMU "cannot find pid %d\n", pid);
                return false;
        }

        if (!d) {
                printk(IOMMU "cannot find dev %x:%x.%x\n", bus, dev, func);
                proc_decref(p);
                return false;
        }

        if (d->proc_owner) {
                printk(IOMMU "dev already assigned to pid = %d\n", p->pid);
                proc_decref(p);
                return false;
        }

        /* grab locks */
        spin_lock_irqsave(&p->proc_lock);
        spin_lock_irqsave(&d->iommu->iommu_lock);

        d->proc_owner = p; /* protected by iommu_lock */
        d->iommu->num_assigned_devs += 1; /* protected by iommu_lock */

        /* add device to list in struct proc */
        TAILQ_INSERT_TAIL(&p->pci_devices, d, proc_link);

        /* add proc to list in struct iommu */
        if (!proc_already_in_iommu_list(d->iommu, p))
                TAILQ_INSERT_TAIL(&d->iommu->procs, p, iommu_link);

        /* release locks */
        spin_unlock_irqsave(&d->iommu->iommu_lock);
        spin_unlock_irqsave(&p->proc_lock);

        /* setup the actual page tables */
        setup_page_tables(p, d);

        return true;
}

static bool unassign_device(int bus, int dev, int func)
{
        int tbdf = MKBUS(BusPCI, bus, dev, func);
        struct pci_device *d = pci_match_tbdf(tbdf);
        struct proc *p;

        if (!d) {
                printk(IOMMU "cannot find dev %x:%x.%x\n", bus, dev, func);
                return false;
        }

        p = d->proc_owner;
        if (!p) {
                printk(IOMMU "%x:%x.%x is not assigned to any process\n",
                        bus, dev, func);
                return false;
        }

        /* teardown page table association */
        teardown_page_tables(p, d);

        /* grab locks */
        spin_lock_irqsave(&p->proc_lock);
        spin_lock_irqsave(&d->iommu->iommu_lock);

        d->proc_owner = NULL; /* protected by iommu_lock */
        d->iommu->num_assigned_devs -= 1; /* protected by iommu_lock */

        /* remove device from list in struct proc */
        TAILQ_REMOVE(&p->pci_devices, d, proc_link);

        /* remove proc from list in struct iommu, if active device passthru */
        if (TAILQ_EMPTY(&p->pci_devices))
                TAILQ_REMOVE(&d->iommu->procs, p, iommu_link);

        /* release locks */
        spin_unlock_irqsave(&d->iommu->iommu_lock);
        spin_unlock_irqsave(&p->proc_lock);

        /* decrement KREF for this PCI device */
        proc_decref(p);

        return true;
}

/////// END: MAPPING ///////////////////////////////////////////////////////////

/////// MISC ///////////////////////////////////////////////////////////////////
static int write_add_dev(char *va, size_t n)
{
        int bus, dev, func, err;
        pid_t pid;

        err = sscanf(va, "%x:%x.%x %d\n", &bus, &dev, &func, &pid);
        // printk(IOMMU "parsed:\n"
        //         "\tb = %x\n"
        //         "\td = %x\n"
        //         "\tf = %x\n"
        //         "\tpid = %d\n",
        //         bus, dev, func, pid);

        if (err != 4)
                error(EIO,
                  IOMMU "error parsing #iommu/attach; items parsed: %d", err);

        if (!assign_device(bus, dev, func, pid))
                printk(IOMMU "passthru failed\n");

        return n;
}

static int write_remove_dev(char *va, size_t n)
{
        int bus, dev, func, err;

        err = sscanf(va, "%x:%x.%x\n", &bus, &dev, &func);
        // printk(IOMMU "parsed:\n"
        //         "\tb = %x\n"
        //         "\td = %x\n"
        //         "\tf = %x\n",
        //         bus, dev, func);

        if (err != 3) {
                error(EIO,
                  IOMMU "error parsing #iommu/detach; items parsed: %d", err);
                return 0;
        }

        if (!unassign_device(bus, dev, func))
                printk(IOMMU "passthru failed\n");

        return n;
}

static int write_power(char *va, size_t n)
{
        int err;

        if (!strcmp(va, "enable\n") || !strcmp(va, "on\n")) {
                iommu_enable();
                return n;
        } else if (!strcmp(va, "disable\n") || !strcmp(va, "off\n")) {
                iommu_disable();
                return n;
        } else
                return n;
}

static void _open_mappings(struct sized_alloc *sza, struct proc *proc)
{
        struct pci_device *pcidev;
        sza_printf(sza, "\tpid = %d\n", proc->pid);

        TAILQ_FOREACH(pcidev, &proc->pci_devices, proc_link) {
                sza_printf(sza, "\t\tdevice = %x:%x.%x\n", pcidev->bus,
                                pcidev->dev, pcidev->func);
        }
}

static struct sized_alloc *open_mappings(void)
{
        struct iommu *iommu;
        struct proc *proc;
        struct sized_alloc *sza = sized_kzmalloc(BUFFERSZ, MEM_WAIT);

        TAILQ_FOREACH(iommu, &iommu_list, iommu_link) {
                spin_lock_irqsave(&iommu->iommu_lock);

                sza_printf(sza, "Mappings for iommu@%p\n", iommu);
                if(TAILQ_EMPTY(&iommu->procs))
                        sza_printf(sza, "\t<empty>\n");
                else
                        TAILQ_FOREACH(proc, &iommu->procs, iommu_link) {
                                _open_mappings(sza, proc);
                        }

                spin_unlock_irqsave(&iommu->iommu_lock);
        }

        return sza;
}

static void _open_info(struct iommu *iommu, struct sized_alloc *sza)
{
        uint64_t value;
 
        sza_printf(sza, "\niommu@%p\n", iommu);
        sza_printf(sza, "\trba = %p\n", iommu->rba);
        sza_printf(sza, "\tsupported = %s\n", iommu->supported ? "yes" : "no");
        sza_printf(sza, "\tnum_assigned_devs = %d\n", iommu->num_assigned_devs);
        sza_printf(sza, "\tregspace = %p\n", iommu->regio);
        
        value = read32(iommu->regio + DMAR_VER_REG);
        sza_printf(sza, "\tversion = 0x%x\n", value);

        value = read64(iommu->regio + DMAR_CAP_REG);
        sza_printf(sza, "\tcapabilities = %p\n", value);

        value = read64(iommu->regio + DMAR_ECAP_REG);
        sza_printf(sza, "\text. capabilities = %p\n", value);
        sza_printf(sza, "\t\tpass through: %s\n",
                ecap_pass_through(value) ? "yes" : "no");
        sza_printf(sza, "\t\tiotlb: %s\n",
                ecap_dev_iotlb_support(value) ? "yes" : "no");

        value = read32(iommu->regio + DMAR_GSTS_REG);
        sza_printf(sza, "\tglobal status = 0x%x\n", value);
        sza_printf(sza, "\t\ttranslation: %s\n",
                value & DMA_GSTS_TES ? "enabled" : "disabled");
        sza_printf(sza, "\t\troot table: %s\n",
                value & DMA_GSTS_RTPS ? "set" : "not set");

        value = read64(iommu->regio + DMAR_RTADDR_REG);
        sza_printf(sza, "\troot entry table = %p (phy) or %p (vir)\n",
                        value, KADDR(value));
}

static struct sized_alloc *open_info(void)
{
        struct sized_alloc *sza = sized_kzmalloc(BUFFERSZ, MEM_WAIT);
        uint64_t value;
        struct iommu *iommu;

        sza_printf(sza, "Driver info:\n");

        value = IOMMU_DID_DEFAULT;
        sza_printf(sza, "\tDefault DID = %d\n", value);
        sza_printf(sza, "\tStatus = %s\n",
                iommu_status() ? "enabled" : "disabled");
        sza_printf(sza, "\tForce support = %s\n",
                IOMMU_FORCE_SUPPORT ? "yes (should be 'no' in prod)" : "no");

        TAILQ_FOREACH(iommu, &iommu_list, iommu_link) {
                _open_info(iommu, sza);
        }

        return sza;
}

static struct sized_alloc *open_power(void)
{
        struct sized_alloc *sza = sized_kzmalloc(BUFFERSZ, MEM_WAIT);
        uint64_t value;
        struct iommu *iommu;

        sza_printf(sza, "IOMMU status: %s\n\n",
                iommu_status() ? "enabled" : "disabled");

        sza_printf(sza, "Write 'enable\\n' or 'disable\\n' OR 'on\\n' or 'off\\n' to change status\n");

        return sza;
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
        switch (c->qid.path) {
        case Qmappings:
                c->synth_buf = open_mappings();
                break;

        case Qinfo:
                c->synth_buf = open_info();
                break;

        case Qpower:
                c->synth_buf = open_power();
                break;

        case Qadddev:
        case Qremovedev:
        case Qdir:
        default:
                break;
        }

        return devopen(c, omode, iommudir, ARRAY_SIZE(iommudir), devgen);
}

/*
 * All files are synthetic. Hence we do not need to implement any close
 * function.
 */
static void iommuclose(struct chan *c)
{
        switch (c->qid.path) {
        case Qmappings:
        case Qinfo:
        case Qpower:
                kfree(c->synth_buf);
                c->synth_buf = NULL;
                break;

        case Qadddev:
        case Qremovedev:
        case Qdir:
        default:
                break;
        }
}

static size_t iommuread(struct chan *c, void *va, size_t n, off64_t offset)
{
        struct sized_alloc *sza = c->synth_buf;

        switch (c->qid.path) {
        case Qdir:
                return devdirread(c, va, n, iommudir,
                                  ARRAY_SIZE(iommudir), devgen);

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
                    "write format: xx:yy.z\n"
                    "   xx  = bus (in hex)\n"
                    "   yy  = device (in hex)\n"
                    "   z   = function (in hex)\n"
                    "\nexample:\n"
                    "$ echo 00:1f.2 >\\#iommu/detach\n");

        case Qmappings:
        case Qinfo:
        case Qpower:
                return readstr(offset, va, n, sza->buf);

        default:
                panic(IOMMU "read: qid %d is impossible\n", c->qid.path);
        }

        return -1;      /* not reached */
}

static size_t iommuwrite(struct chan *c, void *va, size_t n, off64_t offset)
{
        int err = -1;

        switch (c->qid.path) {
        case Qadddev:
                if (!iommu_supported())
                        error(EROFS, IOMMU "not supported");
                err = write_add_dev(va, n);
                break;

        case Qremovedev:
                if (!iommu_supported())
                        error(EROFS, IOMMU "not supported");
                err = write_remove_dev(va, n);
                break;

        case Qpower:
                err = write_power(va, n);
                break;

        case Qmappings:
        case Qinfo:
        case Qdir:
                error(EROFS, IOMMU "cannot modify");
                break;
        default:
                printk(IOMMU "write: qid %d is impossible\n", c->qid.path);
                break;
        }

        return err;
}

/////// BEGIN: assertions //////////////////////////////////////////////////////

/* Iterate over all IOMMUs and make sure the "rba" present in DRHD are unique */
static bool iommu_asset_unique_regio(void)
{
        struct iommu *outer, *inner;
        uint64_t rba;
        bool result = true;

        TAILQ_FOREACH(outer, &iommu_list, iommu_link) {
                rba = outer->rba;

                TAILQ_FOREACH(inner, &iommu_list, iommu_link) {
                        if (outer != inner && rba == inner->rba) {
                                outer->supported = false;
                                result = false;
                        }
                }
        }

        return result;
} 

static bool iommu_assert_required_capabilities(struct iommu *iommu)
{
        uint64_t cap, ecap;
        bool support, result;

        if (!iommu || !iommu->regio)
                return false;

        cap = read64(iommu->regio + DMAR_CAP_REG);
        ecap = read64(iommu->regio + DMAR_ECAP_REG);
        result = true; /* default */

        support = cap_sagaw(cap) & 0x4;
        if (!support) {
                printk(IOMMU "%p: 4-level paging not supported\n", iommu);
                result = false;
        }

        support = cap_super_page_val(cap) & 0x1;
        if (!support) {
                printk(IOMMU "%p: 1GB super pages not supported\n", iommu);
                result = false;
        }

        support = ecap_pass_through(ecap);
        if (!support) {
                printk(IOMMU "%p: pass-through translation type in context entries not supported\n", iommu);
                result = false;
        }

        /* required for '01b' translation type in context entries */
        support = ecap_dev_iotlb_support(ecap);
        if (!support) {
                printk(IOMMU "%p: device IOTLB not supported\n", iommu);
                result = false;
        }

        /* mark the iommu as not supported, if any required cap is present */
        if (!result)
                iommu->supported = false;

        return result;
}

static void iommu_assert_all(void)
{
        struct iommu *iommu;

        if (!iommu_asset_unique_regio()) {
                printk(IOMMU "WARN: same register base addresses detected");
        }

        TAILQ_FOREACH(iommu, &iommu_list, iommu_link) {
                iommu_assert_required_capabilities(iommu);
        }
}

/* Run this function after all individual IOMMUs are initialized. */
void iommu_initialize_global(void)
{
        /* fill the supported field in struct iommu */
        run_once(iommu_assert_all());

        iommu_enable();
}

/* should only be called after all iommus are initialized */
bool iommu_supported(void)
{
        struct iommu *iommu;

        if (IOMMU_FORCE_SUPPORT) /* for debugging in QEMU */
                return true;

        /* return false if any of the iommus isn't supported  */
        TAILQ_FOREACH(iommu, &iommu_list, iommu_link) {
                if (!iommu->supported)
                        return false;
        }

        return true;
}

/* grabs the iommu of the first DRHD with INCLUDE_PCI_ALL */
struct iommu *get_default_iommu(void)
{
        struct Dmar *dt;

        /* dmar is a global variable; see acpi.h */
        if (dmar == NULL) {
                return NULL;
        }

        dt = dmar->tbl;
        for (int i = 0; i < dmar->nchildren; i++) {
                struct Atable *at = dmar->children[i];
                struct Drhd *drhd = at->tbl;

                if (drhd->all & 1)
                        return &drhd->iommu;
        }

        return NULL;
}

void iommu_map_pci_devices(void)
{
        struct pci_device *pci_iter;
        struct iommu *iommu = get_default_iommu();

        if (!iommu)
                return;

        /* set the default iommu */
        STAILQ_FOREACH (pci_iter, &pci_devices, all_dev) {
                pci_iter->iommu = iommu;
        }

        // TODO: parse devscope and assign scoped iommus
}

/* This is called from acpi.c to initialize struct iommu.
 * The actual IOMMU hardware is not touch or configured in any way. */
void iommu_initialize(struct iommu *iommu, uint64_t rba)
{
        /* initilize the struct */
        TAILQ_INIT(&iommu->procs);
        spinlock_init_irqsave(&iommu->iommu_lock);
        iommu->rba = rba;
        iommu->regio = (void __iomem *) vmap_pmem_nocache(rba, VTD_PAGE_SIZE);
        iommu->roottable = rt_init(IOMMU_DID_DEFAULT);
        iommu->supported = true; /* this gets updated by iommu_supported() */
        iommu->num_assigned_devs = 0;

        /* add the iommu to the list of all discovered iommu */
        TAILQ_INSERT_TAIL(&iommu_list, iommu, iommu_link);
}

static void iommuinit(void)
{
        if (iommu_supported())
                printk(IOMMU "initialized\n");
        else
                printk(IOMMU "not supported\n");
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
