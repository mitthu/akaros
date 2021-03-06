/* Copyright (c) 2016 Google Inc
 * Barret Rhoden <brho@cs.berkeley.edu>
 * See LICENSE for details.
 *
 * Arena resource allocator, based on Bonwick and Adams's "Magazines and Vmem:
 * Extending the Slab Allocator to Many CPUs and Arbitrary Resources".
 *
 * There are two major arenas (or arena types; see the NUMA discussion below):
 * base_arena and kpages_arena.  The base_arena consists of all the virtual
 * addresses of the KERNBASE mapping, and is entirely self-sufficient.  Some
 * slab caches pull directly from this arena.  The kpages_arena pulls from the
 * base_arena and adds a level of quantum/slab caching.  Most users will pull
 * from kpages_arena.
 *
 * For jumbo pages, you'd think we'd want a larger page sizes to be the source
 * for the smaller page size arenas.  E.g. 'base' is a PML3 allocator.  The
 * problem with that is that a base allocator needs to be self-sufficient, which
 * means it needs to allocate its own boundary tags.  We'd prefer to use a small
 * page for that.  So instead, we can flip the hierarchy around.  A base
 * allocator uses a PGSIZE quantum, and the jumbo allocators are source from
 * the base arena using an aligned allocation helper for its afunc.  I think,
 * without a lot of thought, that the fragmentation would be equivalent.
 *
 * In the future, we can set up N base_arenas, one for each NUMA domain, each of
 * which is a source for other NUMA allocators, e.g. kpages_i_arena.  Higher
 * level allocators (kmalloc()) will need to choose a NUMA domain and call into
 * the correct allocator.  Each NUMA base arena is self-sufficient: they have no
 * qcaches and their BTs come from their own free page list.  This just
 * replicates the default memory allocator across each NUMA node, and at some
 * point, some generic allocator software needs to pick which node to pull from.
 * I tried to keep assumptions about a single base_arena to a minimum, but
 * you'll see some places where the arena code needs to find some base arena for
 * its BT allocations.  Also note that the base setup happens before we know
 * about NUMA domains.  The plan is to do a small part of domain 0 during
 * pmem_init(), then once we know the full memory layout, add in the rest of
 * domain 0's memory and bootstrap the other domains.
 *
 * When it comes to importing spans, it's not clear whether or not we should
 * import exactly the current allocation request or to bring in more.  If we
 * don't bring in more, then a child arena will have a span for every allocation
 * and will return that span to the source whenever the segment is freed.  We'll
 * never get the Figure 4.4 from the Vmem paper.  Alternatively, we could either
 * allow partial frees of segments or we could hang on to completely free spans
 * for a *while*, and possibly require a reclaim callback.  In the meantime, I
 * added a per-arena scaling factor where we can adjust how much we import.
 *
 * TODO:
 * - Blocking.  We'll probably want to reserve some memory for emergencies to
 *   help us get out of OOM.  So we might block when we're at low-mem, not at 0.
 *   We probably should have a sorted list of desired amounts, and unblockers
 *   poke the CV if the first waiter is likely to succeed.
 * - Reclaim: have a ktask that sleeps on a rendez.  We poke it, even from IRQ
 *   context.  It qlocks arenas_and_slabs_lock, then does the reclaim.
 *
 * FAQ:
 * - Does allocating memory from an arena require it to take a btag?  Yes -
 *   unless the allocation is for the exact size of an existing btag/segment.
 * - Why does arena_free() need size?  Isn't it just for sanity checks?  No - it
 *   is also used to determine which slab/qcache to return the segment to.
 * - Why does a jumbo page arena use its own import function, instead of just
 *   xallocing from kpages with alignment?  Because of fragmentation.  kpages
 *   pulls directly from base, using a normal alloc for its import function
 *   (afunc).  Because of this, its xalloc needs to request size + align, which
 *   will fragment base.  It's better for jumbo to call xalloc directly on base,
 *   in essence pushing the aligned alloc as far down the stack as possible.
 * - Does the stuff in a qcache (allocated or free/available) count against the
 *   arena's total/free amounts?  No, at least not the way I did it.  That's why
 *   it's called amt_total_segs: segments, not free memory.  Those slab/qcaches
 *   will have their own stats, and it'd be a minor pain to sync up with them
 *   all the time.  Also, the important stat is when the base arena starts to
 *   run out of memory, and base arenas don't have qcaches, so it's moot.
 */

#include <arena.h>
#include <kmalloc.h>
#include <string.h>
#include <stdio.h>
#include <hash.h>
#include <slab.h>
#include <kthread.h>

struct arena_tailq all_arenas = TAILQ_HEAD_INITIALIZER(all_arenas);
qlock_t arenas_and_slabs_lock = QLOCK_INITIALIZER(arenas_and_slabs_lock);

struct arena *base_arena;
struct arena *kpages_arena;

/* Misc helpers and forward declarations */
static struct btag *__get_from_freelists(struct arena *arena, int list_idx);
static bool __account_alloc(struct arena *arena, struct btag *bt, size_t size,
                            struct btag *new);
static void *__xalloc_nextfit(struct arena *arena, size_t size, size_t align,
                              size_t phase, size_t nocross);
static void __try_hash_resize(struct arena *arena, int flags,
                              void **to_free_addr, size_t *to_free_sz);
static void __arena_asserter(struct arena *arena);
void print_arena_stats(struct arena *arena, bool verbose);

/* For NUMA situations, where there are multiple base arenas, we'll need a way
 * to find *some* base arena.  Ideally, it'll be in the same NUMA domain as
 * arena. */
static struct arena *find_my_base(struct arena *arena)
{
	/* TODO: could walk down sources until is_base is set.  But barring
	 * that, we'd still need a way to find a base arena for some other
	 * allocator that just wants a page.  arena may be NULL, so handle that.
	 * */
	return base_arena;
}

static void setup_qcaches(struct arena *arena, size_t quantum,
                          size_t qcache_max)
{
	int nr_qcaches = qcache_max / quantum;
	char kc_name[KMC_NAME_SZ];
	size_t qc_size;

	if (!nr_qcaches)
		return;

	/* TODO: same as with hash tables, here and in slab.c, we ideally want
	 * the nearest kpages arena, but bootstrappers need to use base_alloc.
	 * */
	arena->qcaches = base_alloc(arena,
				    nr_qcaches * sizeof(struct kmem_cache),
				    MEM_WAIT);
	for (int i = 0; i < nr_qcaches; i++) {
		qc_size = (i + 1) * quantum;
		snprintf(kc_name, KMC_NAME_SZ, "%s_%d", arena->name, qc_size);
		__kmem_cache_create(&arena->qcaches[i], kc_name, qc_size,
				    quantum, KMC_NOTOUCH | KMC_QCACHE, arena,
				    NULL, NULL, NULL);
	}
}

/* Helper to init.  Split out from create so we can bootstrap. */
static void arena_init(struct arena *arena, char *name, size_t quantum,
                       void *(*afunc)(struct arena *, size_t, int),
                       void (*ffunc)(struct arena *, void *, size_t),
                       struct arena *source, size_t qcache_max)
{
	static_assert((ARENA_ALLOC_STYLES & MEM_FLAGS) == 0);

	spinlock_init_irqsave(&arena->lock);
	arena->import_scale = 0;
	arena->is_base = FALSE;
	if (qcache_max % quantum)
		panic("Arena %s, qcache_max %p must be a multiple of quantum %p",
		      name, qcache_max, quantum);
	arena->quantum = quantum;
	arena->qcache_max = qcache_max;
	arena->afunc = afunc;
	arena->ffunc = ffunc;
	arena->source = source;
	if (source)
		assert(afunc && ffunc);
	arena->amt_total_segs = 0;
	arena->amt_alloc_segs = 0;
	arena->nr_allocs_ever = 0;

	arena->all_segs = RB_ROOT;
	BSD_LIST_INIT(&arena->unused_btags);
	for (int i = 0; i < ARENA_NR_FREE_LISTS; i++)
		BSD_LIST_INIT(&arena->free_segs[i]);

	arena->alloc_hash = arena->static_hash;
	hash_init_hh(&arena->hh);
	for (int i = 0; i < arena->hh.nr_hash_lists; i++)
		BSD_LIST_INIT(&arena->static_hash[i]);

	TAILQ_INIT(&arena->__importing_arenas);
	TAILQ_INIT(&arena->__importing_slabs);

	strlcpy(arena->name, name, ARENA_NAME_SZ);
	setup_qcaches(arena, quantum, qcache_max);

	if (source)
		add_importing_arena(source, arena);
	qlock(&arenas_and_slabs_lock);
	TAILQ_INSERT_TAIL(&all_arenas, arena, next);
	qunlock(&arenas_and_slabs_lock);
}

struct arena *arena_create(char *name, void *base, size_t size, size_t quantum,
                           void *(*afunc)(struct arena *, size_t, int),
                           void (*ffunc)(struct arena *, void *, size_t),
                           struct arena *source, size_t qcache_max, int flags)
{
	struct arena *arena;

	/* See note in arena_add() */
	if (source && base)
		panic("Arena can't have both a source and an initial span");
	if (!base && size)
		panic("Arena can't have a base starting at 0");
	arena = kmalloc(sizeof(struct arena), flags);
	if (!arena)
		return 0;
	arena_init(arena, name, quantum, afunc, ffunc, source, qcache_max);
	if (base) {
		if (!arena_add(arena, base, size, flags)) {
			warn("Failed to add base to arena %s, aborting!",
			     arena->name);
			arena_destroy(arena);
			return 0;
		}
	}
	return arena;
}

void arena_destroy(struct arena *arena)
{
	struct btag *bt_i, *temp;

	qlock(&arenas_and_slabs_lock);
	TAILQ_REMOVE(&all_arenas, arena, next);
	qunlock(&arenas_and_slabs_lock);
	if (arena->source)
		del_importing_arena(arena->source, arena);

	for (int i = 0; i < arena->hh.nr_hash_lists; i++)
		assert(BSD_LIST_EMPTY(&arena->alloc_hash[i]));
	if (arena->alloc_hash != arena->static_hash)
		kfree(arena->alloc_hash);
	/* We shouldn't have any spans left.  We can tell we messed up if we had
	 * a source and still have some free segments.  Otherwise, just collect
	 * the free tags on the unused btag list. */
	for (int i = 0; i < ARENA_NR_FREE_LISTS; i++) {
		if (arena->source)
			assert(BSD_LIST_EMPTY(&arena->free_segs[i]));
		BSD_LIST_FOREACH_SAFE(bt_i, &arena->free_segs[i], misc_link,
				      temp) {
			BSD_LIST_REMOVE(bt_i, misc_link);
			BSD_LIST_INSERT_HEAD(&arena->unused_btags, bt_i,
					     misc_link);
		}
	}
	/* To free our BTs, we need to give the page back to the base arena.
	 * The BTs that are page aligned are the ones we want.  We can just
	 * ignore the others (unlink from the list). */
	BSD_LIST_FOREACH_SAFE(bt_i, &arena->unused_btags, misc_link, temp) {
		if (PGOFF(bt_i->start))
			BSD_LIST_REMOVE(bt_i, misc_link);
	}
	/* Now the remaining BTs are the first on their page. */
	BSD_LIST_FOREACH_SAFE(bt_i, &arena->unused_btags, misc_link, temp)
		arena_free(find_my_base(arena), (void*)bt_i->start, PGSIZE);
	kfree(arena);
}

static void __insert_btag(struct rb_root *root, struct btag *bt)
{
	struct rb_node **new = &root->rb_node, *parent = NULL;
	struct btag *node;

	while (*new) {
		node = container_of(*new, struct btag, all_link);
		parent = *new;
		/* Span (BTAG_SPAN) nodes are ahead (less than) of regular
		 * segment nodes (BTAG_FREE or BTAG_ALLOC) that have the same
		 * start. */
		if (bt->start < node->start)
			new = &parent->rb_left;
		else if (bt->start > node->start)
			new = &parent->rb_right;
		else if (node->status == BTAG_SPAN)
			new = &parent->rb_right;
		else
			panic("BT %p already in tree %p!", bt, root);
	}
	rb_link_node(&bt->all_link, parent, new);
	rb_insert_color(&bt->all_link, root);
}

/* Helper: tracks a seg pointed to by @bt as being allocated, assuming it is
 * already off the free list (or was never on).  This doesn't do anything with
 * all_segs; that's someone else's job (usually bt is already on it). */
static void __track_alloc_seg(struct arena *arena, struct btag *bt)
{
	size_t hash_idx;

	bt->status = BTAG_ALLOC;
	hash_idx = hash_long(bt->start, arena->hh.nr_hash_bits);
	BSD_LIST_INSERT_HEAD(&arena->alloc_hash[hash_idx], bt, misc_link);
	arena->hh.nr_items++;
}

/* Helper: untracks a seg pointed to by @bt as being allocated.  Basically,
 * removes it from the alloc_hash. */
static struct btag *__untrack_alloc_seg(struct arena *arena, uintptr_t start)
{
	size_t hash_idx;
	struct btag *bt_i;

	hash_idx = hash_long(start, arena->hh.nr_hash_bits);
	BSD_LIST_FOREACH(bt_i, &arena->alloc_hash[hash_idx], misc_link) {
		if (bt_i->start == start) {
			BSD_LIST_REMOVE(bt_i, misc_link);
			assert(bt_i->status == BTAG_ALLOC);
			arena->hh.nr_items--;
			return bt_i;
		}
	}
	return NULL;
}

/* Helper, tries to resize our hash table, if necessary.  Call with the lock
 * held, but beware that this will unlock and relock - meaning, don't rely on
 * the lock to protect invariants, but hold it as an optimization.
 *
 * A lot of the nastiness here is related to the allocation.  Critically, we
 * might be the base arena, so it'd be nice to unlock before calling into
 * ourselves (o/w deadlock).  Likewise, we'd like to be able to do a blocking
 * allocation, if flags has MEM_WAIT.  We'd need to unlock for that too. */
static void __try_hash_resize(struct arena *arena, int flags,
                              void **to_free_addr, size_t *to_free_sz)
{
	struct btag_list *new_tbl, *old_tbl;
	struct btag *bt_i;
	unsigned int new_tbl_nr_lists, old_tbl_nr_lists;
	size_t new_tbl_sz, old_tbl_sz;
	size_t hash_idx;

	if (!hash_needs_more(&arena->hh))
		return;
	new_tbl_nr_lists = hash_next_nr_lists(&arena->hh);
	/* We want future checkers to not think we need an increase, to avoid
	 * excessive hash resizers as well as base arena deadlocks (base_alloc
	 * must not call into base_alloc infinitely) */
	hash_set_load_limit(&arena->hh, SIZE_MAX);
	spin_unlock_irqsave(&arena->lock);
	new_tbl_sz = new_tbl_nr_lists * sizeof(struct btag_list);
	/* Regardless of the caller's style, we'll try and be quick with
	 * INSTANT. */
	flags &= ~ARENA_ALLOC_STYLES;
	flags |= ARENA_INSTANTFIT;
	new_tbl = base_zalloc(arena, new_tbl_sz, flags);
	spin_lock_irqsave(&arena->lock);
	if (!new_tbl) {
		/* Need to reset so future callers will try to grow. */
		hash_reset_load_limit(&arena->hh);
		spin_unlock_irqsave(&arena->lock);
		return;
	}
	/* After relocking, we need to re-verify that we want to go ahead.  It's
	 * possible that another thread resized the hash already, which we can
	 * detect because our alloc size is wrong. */
	if (new_tbl_nr_lists != hash_next_nr_lists(&arena->hh)) {
		spin_unlock_irqsave(&arena->lock);
		base_free(arena, new_tbl, new_tbl_sz);
		return;
	}
	old_tbl = arena->alloc_hash;
	old_tbl_nr_lists = arena->hh.nr_hash_lists;
	old_tbl_sz = old_tbl_nr_lists * sizeof(struct btag_list);
	arena->alloc_hash = new_tbl;
	hash_incr_nr_lists(&arena->hh);
	for (int i = 0; i < old_tbl_nr_lists; i++) {
		while ((bt_i = BSD_LIST_FIRST(&old_tbl[i]))) {
			BSD_LIST_REMOVE(bt_i, misc_link);
			hash_idx = hash_long(bt_i->start,
					     arena->hh.nr_hash_bits);
			BSD_LIST_INSERT_HEAD(&arena->alloc_hash[hash_idx], bt_i,
					     misc_link);
		}
	}
	hash_reset_load_limit(&arena->hh);
	if (old_tbl != arena->static_hash) {
		*to_free_addr = old_tbl;
		*to_free_sz = old_tbl_sz;
	}
}

/* Typically this will be just checking for one or two BTs on the free list */
static bool __has_enough_btags(struct arena *arena, size_t nr_needed)
{
	struct btag *bt_i;
	size_t so_far = 0;

	BSD_LIST_FOREACH(bt_i, &arena->unused_btags, misc_link) {
		so_far++;
		if (so_far == nr_needed)
			return TRUE;
	}
	return FALSE;
}

/* Allocs new boundary tags and puts them on the arena's free list.  Returns 0
 * on failure, which could happen if MEM_ATOMIC is set).  Hold the lock when you
 * call this, but note it will unlock and relock.
 *
 * The base arena is special in that it must be self-sufficient.  It will create
 * get its free page from itself.  Other arena's just pull from base in the
 * normal fashion.  We could pull from kpages_arena, but that would require a
 * little more special casing.  Maybe in the future.
 *
 * Note that BTs are only freed when the arena is destroyed.  We use the fact
 * that the first BT is at an aligned address to track the specific page it came
 * from. */
static struct btag *__add_more_btags(struct arena *arena, int mem_flags)
{
	struct btag *bt, *tags;
	size_t nr_bts = PGSIZE / sizeof(struct btag);

	if (arena->is_base) {
		bt = __get_from_freelists(arena, LOG2_UP(PGSIZE));
		if (!bt) {
			/* TODO: block / reclaim if not MEM_ATOMIC.  Remember,
			 * we hold the lock!  We might need to rework this or
			 * get a reserved page. */
			if (!(mem_flags & MEM_ATOMIC))
				panic("Base failed to alloc its own btag, OOM");
			return 0;
		}
		/* __account_alloc() will often need a new BT; specifically when
		 * we only need part of the segment tracked by the BT.  Since we
		 * don't have any extra BTs, we'll use the first one on the page
		 * we just allocated. */
		tags = (struct btag*)bt->start;
		if (__account_alloc(arena, bt, PGSIZE, &tags[0])) {
			/* We used the tag[0]; we'll have to skip over it now.*/
			tags++;
			nr_bts--;
		}
	} else {
		/* Here's where we unlock and relock around a blocking call */
		spin_unlock_irqsave(&arena->lock);
		tags = arena_alloc(find_my_base(arena), PGSIZE,
		                   mem_flags | ARENA_INSTANTFIT);
		spin_lock_irqsave(&arena->lock);
		if (!tags)
			return 0;
	}
	for (int i = 0; i < nr_bts; i++)
		BSD_LIST_INSERT_HEAD(&arena->unused_btags, &tags[i], misc_link);
	return tags;
}

/* Helper, returns TRUE when we have enough BTs.  Hold the lock, but note this
 * will unlock and relock, and will attempt to acquire more BTs.  Returns FALSE
 * if an alloc failed (MEM_ATOMIC).
 *
 * This complexity is so that we never fail an arena operation due to lack of
 * memory unless the caller has MEM_ATOMIC set.  Further, __get_btag() never
 * fails, which makes other code easier.  Otherwise, functions that currently
 * call __get_btag will need one or two BTs passed in from their callers, who
 * allocate/remove from the list at a place where they can easily fail. */
static bool __get_enough_btags(struct arena *arena, size_t nr_needed,
                               int mem_flags)
{
	if (__has_enough_btags(arena, nr_needed))
		return TRUE;
	/* This will unlock and relock, and maybe block. */
	if (!__add_more_btags(arena, mem_flags)) {
		/* This is the only failure scenario */
		assert(mem_flags & MEM_ATOMIC);
		return FALSE;
	}
	/* Since the lock was held in __add_more_btags, no one should have been
	 * able to drain them.  If someone asked for more than a page worth of
	 * BTs, there's a problem somewhere else. */
	assert(__has_enough_btags(arena, nr_needed));
	return TRUE;
}

/* Helper: gets a btag.  All callpaths must have made sure the arena has enough
 * tags before starting its operation, holding the lock throughout.  Thus, this
 * cannot fail. */
static struct btag *__get_btag(struct arena *arena)
{
	struct btag *ret;

	ret = BSD_LIST_FIRST(&arena->unused_btags);
	/* All code paths should have made sure that there were enough BTs
	 * before diving in. */
	assert(ret);
	BSD_LIST_REMOVE(ret, misc_link);
	return ret;
}

static void __free_btag(struct arena *arena, struct btag *bt)
{
	BSD_LIST_INSERT_HEAD(&arena->unused_btags, bt, misc_link);
}

/* Helper: adds seg pointed to by @bt to the appropriate free list of @arena. */
static void __track_free_seg(struct arena *arena, struct btag *bt)
{
	int list_idx = LOG2_DOWN(bt->size);

	bt->status = BTAG_FREE;
	BSD_LIST_INSERT_HEAD(&arena->free_segs[list_idx], bt, misc_link);
}

/* Helper: removes seg pointed to by @bt from the appropriate free list of
 * @arena. */
static void __untrack_free_seg(struct arena *arena, struct btag *bt)
{
	BSD_LIST_REMOVE(bt, misc_link);
}

/* Helper: we decided we want to alloc part of @bt, which has been removed from
 * its old list.  We need @size units.  The rest can go back to the arena.
 *
 * Takes @new, which we'll use if we need a new btag.  If @new is NULL, we'll
 * allocate one.  If we used the caller's btag, we'll return TRUE.  This
 * complexity is for a base arena's manual btag allocation. */
static bool __account_alloc(struct arena *arena, struct btag *bt,
                            size_t size, struct btag *new)
{
	bool ret = FALSE;

	assert(bt->status == BTAG_FREE);
	if (bt->size != size) {
		assert(bt->size > size);
		if (new)
			ret = TRUE;
		else
			new = __get_btag(arena);
		new->start = bt->start + size;
		new->size = bt->size - size;
		bt->size = size;
		__track_free_seg(arena, new);
		__insert_btag(&arena->all_segs, new);
	}
	__track_alloc_seg(arena, bt);
	arena->amt_alloc_segs += size;
	arena->nr_allocs_ever++;
	return ret;
}

/* Helper: gets the first segment from the smallest, populated list. */
static struct btag *__get_from_freelists(struct arena *arena, int list_idx)
{
	struct btag *ret = NULL;

	for (int i = list_idx; i < ARENA_NR_FREE_LISTS; i++) {
		ret = BSD_LIST_FIRST(&arena->free_segs[i]);
		if (ret) {
			BSD_LIST_REMOVE(ret, misc_link);
			break;
		}
	}
	return ret;
}

/* Allocates using the 'best fit' policy.  Recall that each free_segs list holds
 * segments of size [ 2^n, 2^(n+1) )  We try to find the smallest segment on
 * that list that can satisfy the request.  Otherwise, any segment from a larger
 * list will suffice. */
static void *__alloc_bestfit(struct arena *arena, size_t size)
{
	int list_idx = LOG2_DOWN(size);
	struct btag *bt_i, *best = NULL;

	BSD_LIST_FOREACH(bt_i, &arena->free_segs[list_idx], misc_link) {
		if (bt_i->size >= size) {
			if (!best || (best->size > bt_i->size))
				best = bt_i;
		}
	}
	if (best)
		BSD_LIST_REMOVE(best, misc_link);
	else
		best = __get_from_freelists(arena, list_idx + 1);
	if (!best)
		return NULL;
	__account_alloc(arena, best, size, NULL);
	return (void*)best->start;
}

static void *__alloc_nextfit(struct arena *arena, size_t size)
{
	return __xalloc_nextfit(arena, size, arena->quantum, 0, 0);
}

/* Instant fit grabs the first segment guaranteed to be big enough.  Note that
 * we round list_idx up, compared to bestfit's initial list.  That way, you're
 * always sure you have a big enough segment. */
static void *__alloc_instantfit(struct arena *arena, size_t size)
{
	struct btag *ret;

	ret = __get_from_freelists(arena, LOG2_UP(size));
	if (!ret)
		return NULL;
	__account_alloc(arena, ret, size, NULL);
	return (void*)ret->start;
}

/* Non-qcache allocation.  Hold the arena's lock.  Note that all allocations are
 * done in multiples of the quantum. */
static void *alloc_from_arena(struct arena *arena, size_t size, int flags)
{
	void *ret;
	void *to_free_addr = 0;
	size_t to_free_sz = 0;

	spin_lock_irqsave(&arena->lock);
	if (!__get_enough_btags(arena, 1, flags & MEM_FLAGS)) {
		spin_unlock_irqsave(&arena->lock);
		return NULL;
	}
	if (flags & ARENA_BESTFIT)
		ret = __alloc_bestfit(arena, size);
	else if (flags & ARENA_NEXTFIT)
		ret = __alloc_nextfit(arena, size);
	else
		ret = __alloc_instantfit(arena, size);
	/* Careful, this will unlock and relock.  It's OK right before an
	 * unlock. */
	__try_hash_resize(arena, flags, &to_free_addr, &to_free_sz);
	spin_unlock_irqsave(&arena->lock);
	if (to_free_addr)
		base_free(arena, to_free_addr, to_free_sz);
	return ret;
}

/* It's probably a kernel bug if we're adding the wrong sized segments, whether
 * via direct add, a source import, or creation. */
static void assert_quantum_alignment(struct arena *arena, void *base,
                                     size_t size)
{
	if (!ALIGNED(base, arena->quantum))
		panic("Unaligned base %p for arena %s, quantum %p, source %s",
		      base, arena->name, arena->quantum,
		      arena->source ? arena->source->name : "none");
	if (!ALIGNED(size, arena->quantum))
		panic("Unaligned size %p for arena %s, quantum %p, source %s",
		      size, arena->name, arena->quantum,
		      arena->source ? arena->source->name : "none");
}

/* Adds segment [@base, @base + @size) to @arena.  We'll add a span tag if the
 * arena had a source. */
static void *__arena_add(struct arena *arena, void *base, size_t size,
                         int flags)
{
	struct btag *bt, *span_bt;

	/* These are just sanity checks.  Our client is the kernel, and it could
	 * mess with us in other ways, such as adding overlapping spans. */
	assert_quantum_alignment(arena, base, size);
	assert(base < base + size);
	spin_lock_irqsave(&arena->lock);
	/* Make sure there are two, bt and span. */
	if (!__get_enough_btags(arena, 2, flags & MEM_FLAGS)) {
		spin_unlock_irqsave(&arena->lock);
		return NULL;
	}
	bt = __get_btag(arena);
	if (arena->source) {
		span_bt = __get_btag(arena);
		span_bt->start = (uintptr_t)base;
		span_bt->size = size;
		span_bt->status = BTAG_SPAN;
		/* Note the btag span is not on any list, but it is in all_segs
		 */
		__insert_btag(&arena->all_segs, span_bt);
	}
	bt->start = (uintptr_t)base;
	bt->size = size;
	arena->amt_total_segs += size;
	__track_free_seg(arena, bt);
	__insert_btag(&arena->all_segs, bt);
	spin_unlock_irqsave(&arena->lock);
	return base;
}

/* Adds segment [@base, @base + @size) to @arena. */
void *arena_add(struct arena *arena, void *base, size_t size, int flags)
{
	/* This wasn't clear from the paper, but mixing source spans and
	 * manually added spans seems like a pain when coalescing BTs and
	 * freeing. */
	if (arena->source)
		panic("Arenas with sources must not manually add resources.");
	if (!base && size)
		panic("Arena can't have a base starting at 0");
	return __arena_add(arena, base, size, flags);
}

/* Attempt to get more resources, either from a source or by blocking.  Returns
 * TRUE if we got something.  FALSE on failure (e.g. MEM_ATOMIC). */
static bool get_more_resources(struct arena *arena, size_t size, int flags)
{
	void *span;
	size_t import_size;

	/* MAX check, in case size << scale overflows */
	import_size = MAX(size, size << arena->import_scale);
	if (arena->source) {
		span = arena->afunc(arena->source, import_size, flags);
		if (!span)
			return FALSE;
		if (!__arena_add(arena, span, import_size, flags)) {
			/* We could fail if MEM_ATOMIC and we couldn't get a BT
			 */
			warn("Excessively rare failure, tell brho");
			arena->ffunc(arena->source, span, import_size);
			return FALSE;
		}
	} else {
		/* TODO: allow blocking */
		if (!(flags & MEM_ATOMIC))
			panic("OOM!");
		return FALSE;
	}
	return TRUE;
}

/* Helper.  For a given size, return the applicable qcache. */
static struct kmem_cache *size_to_qcache(struct arena *arena, size_t size)
{
	/* If we ever get grumpy about the costs of dividing (both here and in
	 * the ROUND ops, we could either insist that quantum is a power of two,
	 * or track whether or not it is and use other shifting ops. */
	return &arena->qcaches[(size / arena->quantum) - 1];
}

void *arena_alloc(struct arena *arena, size_t size, int flags)
{
	void *ret;

	size = ROUNDUP(size, arena->quantum);
	if (!size)
		panic("Arena %s, request for zero", arena->name);
	if (size <= arena->qcache_max) {
		/* NEXTFIT is an error, since free won't know to skip the qcache
		 * and then we'd be handing an item to the qcache that it didn't
		 * alloc. */
		if (flags & ARENA_NEXTFIT)
			panic("Arena %s, NEXTFIT, but has qcaches. Use xalloc.",
			      arena->name);
		return kmem_cache_alloc(size_to_qcache(arena, size), flags);
	}
	while (1) {
		ret = alloc_from_arena(arena, size, flags);
		if (ret)
			return ret;
		/* This is a little nasty.  We asked our source for enough, but
		 * it may be a bestfit sized chunk, not an instant fit.  Since
		 * we already failed once, we can just downgrade to BESTFIT,
		 * which will likely find our recently-allocated span.  Even
		 * worse, the source might only give us segments that are
		 * BESTFIT, and if we only look at the INSTANTFIT, we'll keep
		 * looping.  The invariant here is that if we
		 * get_more_resources, then our allocation can succeed if no one
		 * else grabs that memory first.
		 *
		 * We actually have two options here.  Either we downgrade to
		 * BESTFIT or we round up our request to our source to the
		 * nearest power of two.  Doing so brings some of the
		 * fragmentation into our arena, but an instant fit is likely to
		 * succeed.  Considering how the first item on the BESTFIT list
		 * is likely ours, downgrading makes sense. */
		flags &= ~ARENA_ALLOC_STYLES;
		flags |= ARENA_BESTFIT;
		if (!get_more_resources(arena, size, flags))
			return NULL;
	}
}

/* Helper: given a BT's start and size, return a starting address within the BT
 * that satisfies the constraints.  Returns 0 on failure.
 *
 * The rough idea is to go from the start, round up to align, add the phase, and
 * see if it's still within the BT.  The 'nocross' boundary (also an alignment)
 * complicates things a little. */
static uintptr_t __find_sufficient(uintptr_t bt_start, size_t bt_size,
                                   size_t size, size_t align,
                                   size_t phase, size_t nocross)
{
	uintptr_t try;
	size_t try_size;

	try = bt_start;
	try = ROUNDUP(try, align);
	try += phase;
	/* Wraparound due to phase. */
	if (try < bt_start)
		return 0;
	/* Check wraparound */
	if (try + size < try)
		return 0;
	/* Too big for BT, no chance. */
	if (try + size > bt_start + bt_size)
		return 0;
	if (nocross == 0)
		return try;
	/* Got to deal with nocross boundaries.  If we round up from our
	 * potential start and that is beyond our potential finish, we're OK. */
	if (ROUNDUP(try, nocross) >= try + size)
		return try;
	/* The segment still might have a chance.  Perhaps we started right
	 * before a nocross.  Let's try again, being careful of overflow.  The
	 * ROUNDUP shouldn't trigger a wraparound. */
	try = ROUNDUP(bt_start, nocross);
	try_size = bt_size - (try - bt_start);
	/* Underflow of bt_size - large_number. */
	if (try_size > bt_size)
		return 0;
	/* The caller has some control over our next invocation's bt_start and
	 * bt_size.  Let's enforce sanity. */
	if (try + try_size < try)
		return 0;
	return __find_sufficient(try, try_size, size, align, phase, 0);
}

/* Helper: splits bt, which is not on any freelist, at @at, and puts the front
 * part back on a free list. */
static void __split_bt_at(struct arena *arena, struct btag *bt, uintptr_t at)
{
	struct btag *front = __get_btag(arena);

	/* We're changing bt's start, which is its key for its position in the
	 * all_segs tree.  However, we don't need to remove and reinsert it,
	 * since although we increased its start, we know that no BT should be
	 * between its old start and its new start.  That's actually where the
	 * front BT will get inserted (so long as we insert after changing bt's
	 * start). */
	front->status = BTAG_FREE;
	front->start = bt->start;
	front->size = at - bt->start;
	bt->start += front->size;
	bt->size -= front->size;
	__track_free_seg(arena, front);
	__insert_btag(&arena->all_segs, front);
	/* At this point, bt's old space in all_segs is broken into: front:
	 * [old_start, try), bt: [try, old_end).  front is on the free list.  bt
	 * is not. */
}

/* Helper.  We want the first bt >= mindaddr, with prev < minaddr. */
static bool __found_least_upper_btag(struct btag *bt, uintptr_t minaddr)
{
	struct rb_node *prev;

	if (bt->start < minaddr)
		return FALSE;
	prev = rb_prev(&bt->all_link);
	if (!prev)
		return TRUE;
	if (container_of(prev, struct btag, all_link)->start < minaddr)
		return TRUE;
	return FALSE;
}

/* Does the a search in min/max for a segment. */
static void *__xalloc_min_max(struct arena *arena, size_t size,
                              size_t align, size_t phase, size_t nocross,
                              uintptr_t minaddr, uintptr_t maxaddr)
{
	struct rb_node *node = arena->all_segs.rb_node;
	struct btag *bt;
	uintptr_t try;

	/* Find the first bt >= minaddr */
	while (node) {
		bt = container_of(node, struct btag, all_link);
		if (__found_least_upper_btag(bt, minaddr))
			break;
		if (minaddr < bt->start)
			node = node->rb_left;
		else
			node = node->rb_right;
	}
	/* Now we're probably at the first start point (or there's no node).
	 * Just scan from here. */
	for (/* node set */; node; node = rb_next(node)) {
		bt = container_of(node, struct btag, all_link);
		try = __find_sufficient(bt->start, bt->size, size, align, phase,
		                        nocross);
		if (!try)
			continue;
		if (maxaddr && (try + size > maxaddr))
			return NULL;
		__untrack_free_seg(arena, bt);
		if (try != bt->start)
			__split_bt_at(arena, bt, try);
		__account_alloc(arena, bt, size, NULL);
		return (void*)bt->start;
	}
	return NULL;
}

/* For xalloc, there isn't any real instant fit, due to the nocross issues.  We
 * can still try to get a quicker fit by starting on a higher order list. */
static void *__xalloc_from_freelists(struct arena *arena, size_t size,
                                     size_t align, size_t phase, size_t nocross,
                                     bool try_instant_fit)
{
	int list_idx;
	struct btag *bt_i;
	uintptr_t try = 0;

	if (ROUNDUP(size, align) + phase < size)
		return NULL;
	list_idx = LOG2_DOWN(ROUNDUP(size, align) + phase);
	list_idx += try_instant_fit ? 1 : 0;
	for (int i = list_idx; i < ARENA_NR_FREE_LISTS; i++) {
		BSD_LIST_FOREACH(bt_i, &arena->free_segs[i], misc_link) {
			try = __find_sufficient(bt_i->start, bt_i->size, size,
						align, phase, nocross);
			if (try) {
				BSD_LIST_REMOVE(bt_i, misc_link);
				break;
			}
		}
		if (try)
			break;
	}
	if (!try)
		return NULL;
	if (try != bt_i->start)
		__split_bt_at(arena, bt_i, try);
	__account_alloc(arena, bt_i, size, NULL);
	return (void*)bt_i->start;
}

static void *__xalloc_nextfit(struct arena *arena, size_t size, size_t align,
                              size_t phase, size_t nocross)
{
	void *ret;

	/* NEXTFIT is a lot like a minaddr.  We can start from the old addr + 1,
	 * since the implementation of that helper starts a search from minaddr.
	 * If it fails, we can try again from 1 (quantum, really), skipping 0.
	 * */
	ret = __xalloc_min_max(arena, size, align, phase, nocross,
	                       arena->last_nextfit_alloc + arena->quantum, 0);
	if (!ret) {
		ret = __xalloc_min_max(arena, size, align, phase, nocross,
		                       arena->quantum, 0);
	}
	if (!ret)
		return NULL;
	arena->last_nextfit_alloc = (uintptr_t)ret;
	return ret;
}

static void *xalloc_from_arena(struct arena *arena, size_t size,
                               size_t align, size_t phase, size_t nocross,
                               void *minaddr, void *maxaddr, int flags)
{
	void *ret;
	void *to_free_addr = 0;
	size_t to_free_sz = 0;

	spin_lock_irqsave(&arena->lock);
	/* Need two, since we might split a BT into 3 BTs. */
	if (!__get_enough_btags(arena, 2, flags & MEM_FLAGS)) {
		spin_unlock_irqsave(&arena->lock);
		return NULL;
	}
	if (minaddr || maxaddr) {
		ret = __xalloc_min_max(arena, size, align, phase, nocross,
		                       (uintptr_t)minaddr, (uintptr_t)maxaddr);
	} else {
		if (flags & ARENA_BESTFIT) {
			ret = __xalloc_from_freelists(arena, size, align, phase,
						      nocross, FALSE);
		} else if (flags & ARENA_NEXTFIT) {
			ret = __xalloc_nextfit(arena, size, align, phase,
					       nocross);
		} else {
			ret = __xalloc_from_freelists(arena, size, align, phase,
						      nocross, TRUE);
		}
	}
	/* Careful, this will unlock and relock.  It's OK right before an
	 * unlock. */
	__try_hash_resize(arena, flags, &to_free_addr, &to_free_sz);
	spin_unlock_irqsave(&arena->lock);
	if (to_free_addr)
		base_free(arena, to_free_addr, to_free_sz);
	return ret;
}

void *arena_xalloc(struct arena *arena, size_t size, size_t align, size_t phase,
                   size_t nocross, void *minaddr, void *maxaddr, int flags)
{
	void *ret;
	size_t req_size;

	size = ROUNDUP(size, arena->quantum);
	if (!size)
		panic("Arena %s, request for zero", arena->name);
	if (!IS_PWR2(align))
		panic("Arena %s, non-power of two align %p", arena->name,
		      align);
	if (nocross && !IS_PWR2(nocross))
		panic("Arena %s, non-power of nocross %p", arena->name,
		      nocross);
	if (!ALIGNED(align, arena->quantum))
		panic("Arena %s, non-aligned align %p", arena->name, align);
	if (!ALIGNED(nocross, arena->quantum))
		panic("Arena %s, non-aligned nocross %p", arena->name, nocross);
	if (!ALIGNED(phase, arena->quantum))
		panic("Arena %s, non-aligned phase %p", arena->name, phase);
	if (size + align < size)
		panic("Arena %s, size %p + align %p overflow%p", arena->name,
		      size, align);
	if (size + phase < size)
		panic("Arena %s, size %p + phase %p overflow%p", arena->name,
		      size, phase);
	if (align + phase < align)
		panic("Arena %s, align %p + phase %p overflow%p", arena->name,
		      align, phase);
	/* Ok, it's a pain to import resources from a source such that we'll be
	 * able to guarantee we make progress without stranding resources if we
	 * have nocross or min/maxaddr.  For min/maxaddr, when we ask the
	 * source, we aren't easily able to xalloc from their (it may depend on
	 * the afunc).  For nocross, we can't easily ask the source for the
	 * right span that satisfies the request (again, no real xalloc).  Some
	 * constraints might not even be possible.
	 *
	 * If we get a span from the source and never use it, then we run a risk
	 * of fragmenting and stranding a bunch of spans in our current arena.
	 * Imagine the loop where we keep asking for spans (e.g. 8 pgs) and
	 * getting something that doesn't work.  Those 8 pgs are fragmented, and
	 * we won't give them back to the source until we allocate and then free
	 * them (barring some sort of reclaim callback).
	 *
	 * Besides, I don't know if we even need/want nocross/min/maxaddr. */
	if (arena->source && (nocross || minaddr || maxaddr))
		panic("Arena %s, has source, can't xalloc with nocross %p, minaddr %p, or maxaddr %p",
		      arena->name, nocross, minaddr, maxaddr);
	while (1) {
		ret = xalloc_from_arena(arena, size, align, phase, nocross,
					minaddr, maxaddr, flags);
		if (ret)
			return ret;
		/* We checked earlier than no two of these overflow, so I think
		 * we don't need to worry about multiple overflows. */
		req_size = size + align + phase;
		/* Note that this check isn't the same as the one we make when
		 * finding a sufficient segment.  Here we check overflow on the
		 * requested size.  Later, we check aligned bt_start + phase.
		 * The concern is that this check succeeds, but the other fails.
		 * (Say size = PGSIZE, phase =
		 * -PGSIZE -1.  req_size is very large.
		 *
		 * In this case, we're still fine - if our source is able to
		 * satisfy the request, our bt_start and bt_size will be able to
		 * express that size without wrapping. */
		if (req_size < size)
			panic("Arena %s, size %p + align %p + phase %p overflw",
			      arena->name, size, align, phase);
		if (!get_more_resources(arena, req_size, flags))
			return NULL;
		/* Our source may have given us a segment that is on the BESTFIT
		 * list, same as with arena_alloc. */
		flags &= ~ARENA_ALLOC_STYLES;
		flags |= ARENA_BESTFIT;
		/* TODO: could put a check in here to make sure we don't loop
		 * forever, in case we trip some other bug. */
	}
}

/* Helper: if possible, merges the right BT to the left.  Returns TRUE if we
 * merged. */
static bool __merge_right_to_left(struct arena *arena, struct btag *left,
                                  struct btag *right)
{
	/* These checks will also make sure we never merge SPAN boundary tags.*/
	if (left->status != BTAG_FREE)
		return FALSE;
	if (right->status != BTAG_FREE)
		return FALSE;
	if (left->start + left->size == right->start) {
		/* Need to yank left off its list before changing its size. */
		__untrack_free_seg(arena, left);
		__untrack_free_seg(arena, right);
		left->size += right->size;
		__track_free_seg(arena, left);
		rb_erase(&right->all_link, &arena->all_segs);
		__free_btag(arena, right);
		return TRUE;
	}
	return FALSE;
}

/* Merges @bt's segments with its adjacent neighbors.  If we end up having an
 * entire span free, we'll stop tracking it in this arena and return it for our
 * caller to free. */
static void __coalesce_free_seg(struct arena *arena, struct btag *bt,
                                void **to_free_addr, size_t *to_free_sz)
{
	struct rb_node *rb_p, *rb_n;
	struct btag *bt_p, *bt_n;

	rb_n = rb_next(&bt->all_link);
	if (rb_n) {
		bt_n = container_of(rb_n, struct btag, all_link);
		__merge_right_to_left(arena, bt, bt_n);
	}
	rb_p = rb_prev(&bt->all_link);
	if (rb_p) {
		bt_p = container_of(rb_p, struct btag, all_link);
		if (__merge_right_to_left(arena, bt_p, bt))
			bt = bt_p;
	}
	/* Check for a span */
	rb_p = rb_prev(&bt->all_link);
	if (rb_p) {
		bt_p = container_of(rb_p, struct btag, all_link);
		if ((bt_p->status == BTAG_SPAN) &&
		    (bt_p->start == bt->start) &&
		    (bt_p->size == bt->size)) {

			*to_free_addr = (void*)bt_p->start;
			*to_free_sz = bt_p->size;
			/* Note the span was not on a free list */
			__untrack_free_seg(arena, bt);
			rb_erase(&bt_p->all_link, &arena->all_segs);
			__free_btag(arena, bt_p);
			rb_erase(&bt->all_link, &arena->all_segs);
			__free_btag(arena, bt);
		}
	}
}

static void free_from_arena(struct arena *arena, void *addr, size_t size)
{
	struct btag *bt;
	void *to_free_addr = 0;
	size_t to_free_sz = 0;

	spin_lock_irqsave(&arena->lock);
	bt = __untrack_alloc_seg(arena, (uintptr_t)addr);
	if (!bt)
		panic("Free of unallocated addr %p from arena %s", addr,
		      arena->name);
	if (bt->size != size)
		panic("Free of %p with wrong size %p (%p) from arena %s", addr,
		      size, bt->size, arena->name);
	arena->amt_alloc_segs -= size;
	__track_free_seg(arena, bt);
	__coalesce_free_seg(arena, bt, &to_free_addr, &to_free_sz);
	arena->amt_total_segs -= to_free_sz;
	spin_unlock_irqsave(&arena->lock);
	if (to_free_addr)
		arena->ffunc(arena->source, to_free_addr, to_free_sz);
}

void arena_free(struct arena *arena, void *addr, size_t size)
{
	size = ROUNDUP(size, arena->quantum);
	if (size <= arena->qcache_max)
		return kmem_cache_free(size_to_qcache(arena, size), addr);
	free_from_arena(arena, addr, size);
}

void arena_xfree(struct arena *arena, void *addr, size_t size)
{
	size = ROUNDUP(size, arena->quantum);
	free_from_arena(arena, addr, size);
}

/* Low-level arena builder.  Pass in a page address, and this will build an
 * arena in that memory.
 *
 * This will be used for each NUMA domain's base arena, kpages_arena, and
 * kmalloc_arena, since the normal arena_create() won't work yet (no kmalloc).
 */
struct arena *arena_builder(void *pgaddr, char *name, size_t quantum,
                            void *(*afunc)(struct arena *, size_t, int),
                            void (*ffunc)(struct arena *, void *, size_t),
                            struct arena *source, size_t qcache_max)
{
	struct arena *a = (struct arena*)pgaddr;
	struct btag *two_tags = (struct btag*)(pgaddr + sizeof(struct arena));

	static_assert(sizeof(struct arena) + 2 * sizeof(struct btag) <= PGSIZE);

	arena_init(a, name, quantum, afunc, ffunc, source, qcache_max);
	if (!source)
		a->is_base = TRUE;
	BSD_LIST_INSERT_HEAD(&a->unused_btags, &two_tags[0], misc_link);
	BSD_LIST_INSERT_HEAD(&a->unused_btags, &two_tags[1], misc_link);
	return a;
}

/* Sanity checker for an arena's structures.  Hold the lock. */
static void __arena_asserter(struct arena *arena)
{
	struct btag *bt_i;
	struct rb_node *rb_i;
	size_t amt_free = 0, amt_alloc = 0, nr_allocs = 0;

	for (int i = 0; i < ARENA_NR_FREE_LISTS; i++) {
		BSD_LIST_FOREACH(bt_i, &arena->free_segs[i], misc_link) {
			assert(bt_i->status == BTAG_FREE);
			assert(bt_i->size >= (1ULL << i));
			assert(bt_i->size < (1ULL << (i + 1)));
		}
	}
	for (int i = 0; i < arena->hh.nr_hash_lists; i++) {
		BSD_LIST_FOREACH(bt_i, &arena->alloc_hash[i], misc_link)
			assert(bt_i->status == BTAG_ALLOC);
	}
	for (rb_i = rb_first(&arena->all_segs); rb_i; rb_i = rb_next(rb_i)) {
		bt_i = container_of(rb_i, struct btag, all_link);
		if (bt_i->status == BTAG_FREE)
			amt_free += bt_i->size;
		if (bt_i->status == BTAG_ALLOC) {
			amt_alloc += bt_i->size;
			nr_allocs++;
		}
	}
	assert(arena->amt_total_segs == amt_free + amt_alloc);
	assert(arena->amt_alloc_segs == amt_alloc);
	assert(arena->hh.nr_items == nr_allocs);
}

size_t arena_amt_free(struct arena *arena)
{
	return arena->amt_total_segs - arena->amt_alloc_segs;
}

size_t arena_amt_total(struct arena *arena)
{
	return arena->amt_total_segs;
}

void add_importing_arena(struct arena *source, struct arena *importer)
{
	qlock(&arenas_and_slabs_lock);
	TAILQ_INSERT_TAIL(&source->__importing_arenas, importer, import_link);
	qunlock(&arenas_and_slabs_lock);
}

void del_importing_arena(struct arena *source, struct arena *importer)
{
	qlock(&arenas_and_slabs_lock);
	TAILQ_REMOVE(&source->__importing_arenas, importer, import_link);
	qunlock(&arenas_and_slabs_lock);
}

void add_importing_slab(struct arena *source, struct kmem_cache *importer)
{
	qlock(&arenas_and_slabs_lock);
	TAILQ_INSERT_TAIL(&source->__importing_slabs, importer, import_link);
	qunlock(&arenas_and_slabs_lock);
}

void del_importing_slab(struct arena *source, struct kmem_cache *importer)
{
	qlock(&arenas_and_slabs_lock);
	TAILQ_REMOVE(&source->__importing_slabs, importer, import_link);
	qunlock(&arenas_and_slabs_lock);
}

void *base_alloc(struct arena *guess, size_t size, int flags)
{
	return arena_alloc(find_my_base(guess), size, flags);
}

void *base_zalloc(struct arena *guess, size_t size, int flags)
{
	void *ret = base_alloc(guess, size, flags);

	if (!ret)
		return NULL;
	memset(ret, 0, size);
	return ret;
}

void base_free(struct arena *guess, void *addr, size_t size)
{
	return arena_free(find_my_base(guess), addr, size);
}
