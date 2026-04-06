---
title: "[Linux kernel side notes - SLUB] kmem_cache"
published: 2022-07-18
category: "research"
draft: false
---

## Introduction

The `kmem_cache` structure is one of the main structures of the SLUB algorithm. It contains pointers to other structures (`cpu_slab`, `node` array) and informations about the cache it describes (`object_size`, `name`). Every notes target [linux kernel 5.18.12](https://elixir.bootlin.com/linux/v5.18.12/source/kernel).

Overview of its role among the allocation process:

![SLUB schema](/pic/SLUB_schema1.png)

## Let's dig into

Here is the definition of the `kmem_cache` structure:

```c
// https://elixir.bootlin.com/linux/latest/source/include/linux/slub_def.h#L90
/*
 * Slab cache management.
 */
struct kmem_cache {
	struct kmem_cache_cpu __percpu *cpu_slab;
	/* Used for retrieving partial slabs, etc. */
	slab_flags_t flags;
	unsigned long min_partial;
	unsigned int size;	/* The size of an object including metadata */
	unsigned int object_size;/* The size of an object without metadata */
	struct reciprocal_value reciprocal_size;
	unsigned int offset;	/* Free pointer offset */
#ifdef CONFIG_SLUB_CPU_PARTIAL
	/* Number of per cpu partial objects to keep around */
	unsigned int cpu_partial;
	/* Number of per cpu partial slabs to keep around */
	unsigned int cpu_partial_slabs;
#endif
	struct kmem_cache_order_objects oo;

	/* Allocation and freeing of slabs */
	struct kmem_cache_order_objects max;
	struct kmem_cache_order_objects min;
	gfp_t allocflags;	/* gfp flags to use on each alloc */
	int refcount;		/* Refcount for slab cache destroy */
	void (*ctor)(void *);
	unsigned int inuse;		/* Offset to metadata */
	unsigned int align;		/* Alignment */
	unsigned int red_left_pad;	/* Left redzone padding size */
	const char *name;	/* Name (only for display!) */
	struct list_head list;	/* List of slab caches */
#ifdef CONFIG_SYSFS
	struct kobject kobj;	/* For sysfs */
#endif
#ifdef CONFIG_SLAB_FREELIST_HARDENED
	unsigned long random;
#endif

#ifdef CONFIG_NUMA
	/*
	 * Defragmentation by allocating from a remote node.
	 */
	unsigned int remote_node_defrag_ratio;
#endif

#ifdef CONFIG_SLAB_FREELIST_RANDOM
	unsigned int *random_seq;
#endif

#ifdef CONFIG_KASAN
	struct kasan_cache kasan_info;
#endif

	unsigned int useroffset;	/* Usercopy region offset */
	unsigned int usersize;		/* Usercopy region size */

	struct kmem_cache_node *node[MAX_NUMNODES];
};
```

- `cpu_slab` is a pointer to the `__percpu` `kmem_cache_cpu` structure. Each cpu has its own `kmem_cache_cpu` to easily and faster return objects without having to trigger the "slowpath" code path which will search through the partial list of the `kmem_cache_cpu` or by allocating one more slab.
- `flags` are the internal flags used to describe the cache. The whole (I hope so) list would be:
```c
// https://elixir.bootlin.com/linux/latest/source/include/linux/slab.h#L27
/*
 * Flags to pass to kmem_cache_create().
 * The ones marked DEBUG are only valid if CONFIG_DEBUG_SLAB is set.
 */
/* DEBUG: Perform (expensive) checks on alloc/free */
#define SLAB_CONSISTENCY_CHECKS	((slab_flags_t __force)0x00000100U)
/* DEBUG: Red zone objs in a cache */
#define SLAB_RED_ZONE		((slab_flags_t __force)0x00000400U)
/* DEBUG: Poison objects */
#define SLAB_POISON		((slab_flags_t __force)0x00000800U)
/* Align objs on cache lines */
#define SLAB_HWCACHE_ALIGN	((slab_flags_t __force)0x00002000U)
/* Use GFP_DMA memory */
#define SLAB_CACHE_DMA		((slab_flags_t __force)0x00004000U)
/* Use GFP_DMA32 memory */
#define SLAB_CACHE_DMA32	((slab_flags_t __force)0x00008000U)
/* DEBUG: Store the last owner for bug hunting */
#define SLAB_STORE_USER		((slab_flags_t __force)0x00010000U)
/* Panic if kmem_cache_create() fails */
#define SLAB_PANIC		((slab_flags_t __force)0x00040000U)
/*
 * SLAB_TYPESAFE_BY_RCU - **WARNING** READ THIS!
 *
 * This delays freeing the SLAB page by a grace period, it does _NOT_
 * delay object freeing. This means that if you do kmem_cache_free()
 * that memory location is free to be reused at any time. Thus it may
 * be possible to see another object there in the same RCU grace period.
 *
 * This feature only ensures the memory location backing the object
 * stays valid, the trick to using this is relying on an independent
 * object validation pass. Something like:
 *
 *  rcu_read_lock()
 * again:
 *  obj = lockless_lookup(key);
 *  if (obj) {
 *    if (!try_get_ref(obj)) // might fail for free objects
 *      goto again;
 *
 *    if (obj->key != key) { // not the object we expected
 *      put_ref(obj);
 *      goto again;
 *    }
 *  }
 *  rcu_read_unlock();
 *
 * This is useful if we need to approach a kernel structure obliquely,
 * from its address obtained without the usual locking. We can lock
 * the structure to stabilize it and check it's still at the given address,
 * only if we can be sure that the memory has not been meanwhile reused
 * for some other kind of object (which our subsystem's lock might corrupt).
 *
 * rcu_read_lock before reading the address, then rcu_read_unlock after
 * taking the spinlock within the structure expected at that address.
 *
 * Note that SLAB_TYPESAFE_BY_RCU was originally named SLAB_DESTROY_BY_RCU.
 */
/* Defer freeing slabs to RCU */
#define SLAB_TYPESAFE_BY_RCU	((slab_flags_t __force)0x00080000U)
/* Spread some memory over cpuset */
#define SLAB_MEM_SPREAD		((slab_flags_t __force)0x00100000U)
/* Trace allocations and frees */
#define SLAB_TRACE		((slab_flags_t __force)0x00200000U)

/* Flag to prevent checks on free */
#ifdef CONFIG_DEBUG_OBJECTS
# define SLAB_DEBUG_OBJECTS	((slab_flags_t __force)0x00400000U)
#else
# define SLAB_DEBUG_OBJECTS	0
#endif

/* Avoid kmemleak tracing */
#define SLAB_NOLEAKTRACE	((slab_flags_t __force)0x00800000U)

/* Fault injection mark */
#ifdef CONFIG_FAILSLAB
# define SLAB_FAILSLAB		((slab_flags_t __force)0x02000000U)
#else
# define SLAB_FAILSLAB		0
#endif
/* Account to memcg */
#ifdef CONFIG_MEMCG_KMEM
# define SLAB_ACCOUNT		((slab_flags_t __force)0x04000000U)
#else
# define SLAB_ACCOUNT		0
#endif

#ifdef CONFIG_KASAN
#define SLAB_KASAN		((slab_flags_t __force)0x08000000U)
#else
#define SLAB_KASAN		0
#endif

/* The following flags affect the page allocator grouping pages by mobility */
/* Objects are reclaimable */
#define SLAB_RECLAIM_ACCOUNT	((slab_flags_t __force)0x00020000U)
#define SLAB_TEMPORARY		SLAB_RECLAIM_ACCOUNT	/* Objects are short-lived */
```
- `min_partial` stands for the minimum amount of partial slabs (`node->nr_partial`) within the `kmem_cache_node` structure. When a slab attempts to be freed, if `node->nr_partial` < `min_partial`, the free process is aborted. For further informations to a look at [this](https://elixir.bootlin.com/linux/latest/source/mm/slub.c#L3388).
- `size` stands for -- according to the comment -- The size of an object including metadata.
- `object_size` stands for -- according to the comment -- The size of an object without metadata.
- `reciprocal_size` is a `reciprocal_value` structure that stands for the reciprocal value of the `size`. It's basically a magic structure that allows linux to compute faster a division between an integer and a predefined constant (the `size` for our case). It allows linux to do a multiplication instead of a directly a division. Further informations below:
```c
// https://elixir.bootlin.com/linux/latest/source/include/linux/reciprocal_div.h#L23
/*
 * This algorithm is based on the paper "Division by Invariant
 * Integers Using Multiplication" by Torbjörn Granlund and Peter
 * L. Montgomery.
 *
 * The assembler implementation from Agner Fog, which this code is
 * based on, can be found here:
 * http://www.agner.org/optimize/asmlib.zip
 *
 * This optimization for A/B is helpful if the divisor B is mostly
 * runtime invariant. The reciprocal of B is calculated in the
 * slow-path with reciprocal_value(). The fast-path can then just use
 * a much faster multiplication operation with a variable dividend A
 * to calculate the division A/B.
 */

struct reciprocal_value {
	u32 m;
	u8 sh1, sh2;
};
```
- `offset` stands for the offset up to the next free pointer among each object.
- `cpu_partial` stands for the number of per cpu partial objects to keep around. Which means if the sum of every freed objects among partial cpu slabs is bigger than `cpu_partial`, part of it is moved to the node cache.
- `cpu_partial_slabs` stands for the number of per cpu partial slabs to keep around.
- `oo` stands for both the number of objects among a slab and the size of the whole slab. Here are the two functions that compute the conversion and the one that computes the `oo` from the order and the size of the object:
```c
// https://elixir.bootlin.com/linux/latest/source/mm/slub.c#L407
static inline unsigned int oo_order(struct kmem_cache_order_objects x)
{
	return x.x >> OO_SHIFT;
}

static inline unsigned int oo_objects(struct kmem_cache_order_objects x)
{
	return x.x & OO_MASK;
}

// https://elixir.bootlin.com/linux/latest/source/mm/slub.c#L392

static inline unsigned int order_objects(unsigned int order, unsigned int size)
{
	return ((unsigned int)PAGE_SIZE << order) / size;
}

static inline struct kmem_cache_order_objects oo_make(unsigned int order,
		unsigned int size)
{
	struct kmem_cache_order_objects x = {
		(order << OO_SHIFT) + order_objects(order, size)
	};

	return x;
}
```
- `allocflags` GFP allocation flags. Here are most of them:
```c
// https://elixir.bootlin.com/linux/latest/source/include/linux/gfp.h#L340
#define GFP_ATOMIC	(__GFP_HIGH|__GFP_ATOMIC|__GFP_KSWAPD_RECLAIM)
#define GFP_KERNEL	(__GFP_RECLAIM | __GFP_IO | __GFP_FS)
#define GFP_KERNEL_ACCOUNT (GFP_KERNEL | __GFP_ACCOUNT)
#define GFP_NOWAIT	(__GFP_KSWAPD_RECLAIM)
#define GFP_NOIO	(__GFP_RECLAIM)
#define GFP_NOFS	(__GFP_RECLAIM | __GFP_IO)
#define GFP_USER	(__GFP_RECLAIM | __GFP_IO | __GFP_FS | __GFP_HARDWALL)
#define GFP_DMA		__GFP_DMA
#define GFP_DMA32	__GFP_DMA32
#define GFP_HIGHUSER	(GFP_USER | __GFP_HIGHMEM)
#define GFP_HIGHUSER_MOVABLE	(GFP_HIGHUSER | __GFP_MOVABLE | \
			 __GFP_SKIP_KASAN_POISON)
#define GFP_TRANSHUGE_LIGHT	((GFP_HIGHUSER_MOVABLE | __GFP_COMP | \
			 __GFP_NOMEMALLOC | __GFP_NOWARN) & ~__GFP_RECLAIM)
#define GFP_TRANSHUGE	(GFP_TRANSHUGE_LIGHT | __GFP_DIRECT_RECLAIM)

/* Convert GFP flags to their corresponding migrate type */
#define GFP_MOVABLE_MASK (__GFP_RECLAIMABLE|__GFP_MOVABLE)
#define GFP_MOVABLE_SHIFT 3
```
- `refcount` stands for the amount of time the `kmem_cache` has been reused and "aliased". For further informations, take a look at `__kmem_cache_alias` [here](https://elixir.bootlin.com/linux/latest/source/mm/slub.c#L4863).
- `ctor` stands for a constructor called at every object intitialization, it's called in `setup_object` which is itself called in `shuffle_freelist` and in `allocate_slab` at the slab allocation level so.
- `inuse` stands for the offset of the first metadata, we can distinguish several cases:
```c
// https://elixir.bootlin.com/linux/v5.18.12/source/mm/slub.c#L987
/* object + s->inuse
 * 	Meta data starts here.
 *
 * 	A. Free pointer (if we cannot overwrite object on free)
 * 	B. Tracking data for SLAB_STORE_USER
 *	C. Padding to reach required alignment boundary or at minimum
 * 		one word if debugging is on to be able to detect writes
 * 		before the word boundary.
 *
 *	Padding is done using 0x5a (POISON_INUSE)
*/
```
- `align` alignement needed for each object.
- `red_left_pad` stands for the left pad to prevent right out of bound write.

<img align="center" width="75%" src="../../left_pad.jpg">

- `name` stands for the cache name.
- `list` stands for the doubly linked list that groups every `kmem_cache`, the `HEAD` is the `slab_caches` symbol.
- `kobj` stands for the internal kobjets reference counter, see [this LWN article](https://lwn.net/Articles/51437/) for further informations.
- `random` stands for the secret kept in each `kmem_cache` when the kernel is compiled with the `CONFIG_SLAB_FREELIST_HARDENED`. It's initialized in `kmem_cache_open` and used to decrypt the next free pointer of free chunks belonging to the cache:
```c
// https://elixir.bootlin.com/linux/v5.18.12/source/mm/slub.c#L4180
static int kmem_cache_open(struct kmem_cache *s, slab_flags_t flags)
{
	s->flags = kmem_cache_flags(s->size, flags, s->name);
#ifdef CONFIG_SLAB_FREELIST_HARDENED
	s->random = get_random_long();

// https://elixir.bootlin.com/linux/v5.18.12/source/mm/slub.c#L334

/*
 * Returns freelist pointer (ptr). With hardening, this is obfuscated
 * with an XOR of the address where the pointer is held and a per-cache
 * random number.
 */
static inline void *freelist_ptr(const struct kmem_cache *s, void *ptr,
				 unsigned long ptr_addr)
{
#ifdef CONFIG_SLAB_FREELIST_HARDENED
	/*
	 * When CONFIG_KASAN_SW/HW_TAGS is enabled, ptr_addr might be tagged.
	 * Normally, this doesn't cause any issues, as both set_freepointer()
	 * and get_freepointer() are called with a pointer with the same tag.
	 * However, there are some issues with CONFIG_SLUB_DEBUG code. For
	 * example, when __free_slub() iterates over objects in a cache, it
	 * passes untagged pointers to check_object(). check_object() in turns
	 * calls get_freepointer() with an untagged pointer, which causes the
	 * freepointer to be restored incorrectly.
	 */
	return (void *)((unsigned long)ptr ^ s->random ^
			swab((unsigned long)kasan_reset_tag((void *)ptr_addr)));
#else
	return ptr;
#endif
}
```
- `remote_node_defrag_ratio` bigger the `remote_node_defrag_ratio` is, more the allocator returns objets that belong to remote nodes:
```c
// https://elixir.bootlin.com/linux/v5.18.12/source/mm/slub.c#L2200
	/*
	 * The defrag ratio allows a configuration of the tradeoffs between
	 * inter node defragmentation and node local allocations. A lower
	 * defrag_ratio increases the tendency to do local allocations
	 * instead of attempting to obtain partial slabs from other nodes.
	 *
	 * If the defrag_ratio is set to 0 then kmalloc() always
	 * returns node local objects. If the ratio is higher then kmalloc()
	 * may return off node objects because partial slabs are obtained
	 * from other nodes and filled up.
	 *
	 * If /sys/kernel/slab/xx/remote_node_defrag_ratio is set to 100
	 * (which makes defrag_ratio = 1000) then every (well almost)
	 * allocation will first attempt to defrag slab caches on other nodes.
	 * This means scanning over all nodes to look for partial slabs which
	 * may be expensive if we do it every time we are trying to find a slab
	 * with available objects.
	 */
```
- `random_seq` represents a shuffled array of offset of chunks that belong to a slab. Given the freelist stuff is done only on a slab, the offset should not exceed `page_limit` which is `nr_objects * size`.cDepends on `CONFIG_SLAB_FREELIST_RANDOM`. Here are some functions that use `random_seq`:
```c
// https://elixir.bootlin.com/linux/v5.18.12/source/mm/slub.c#L1855

/* Get the next entry on the pre-computed freelist randomized */
static void *next_freelist_entry(struct kmem_cache *s, struct slab *slab,
				unsigned long *pos, void *start,
				unsigned long page_limit,
				unsigned long freelist_count)
{
	unsigned int idx;

	/*
	 * If the target page allocation failed, the number of objects on the
	 * page might be smaller than the usual size defined by the cache.
	 */
	do {
		idx = s->random_seq[*pos];
		*pos += 1;
		if (*pos >= freelist_count)
			*pos = 0;
	} while (unlikely(idx >= page_limit));

	return (char *)start + idx;
}

// https://elixir.bootlin.com/linux/v5.18.12/source/mm/slub.c#L1843

/* Initialize each random sequence freelist per cache */
static void __init init_freelist_randomization(void)
{
	struct kmem_cache *s;

	mutex_lock(&slab_mutex);

	list_for_each_entry(s, &slab_caches, list)
		init_cache_random_seq(s);

	mutex_unlock(&slab_mutex);
}

// https://elixir.bootlin.com/linux/v5.18.12/source/mm/slub.c#L1816

static int init_cache_random_seq(struct kmem_cache *s)
{
	unsigned int count = oo_objects(s->oo);
	int err;

	/* Bailout if already initialised */
	if (s->random_seq)
		return 0;

	err = cache_random_seq_create(s, count, GFP_KERNEL);
	if (err) {
		pr_err("SLUB: Unable to initialize free list for %s\n",
			s->name);
		return err;
	}

	/* Transform to an offset on the set of pages */
	if (s->random_seq) {
		unsigned int i;

		for (i = 0; i < count; i++)
			s->random_seq[i] *= s->size;
	}
	return 0;
}
```
- `kasan_info` is a cache used by the Kernel Address Sanizer (KASAN), it keeps track of freed chunks, especially by storing informations within the redzone. Here are some of the operations performed by KASAN:
```c
// https://elixir.bootlin.com/linux/v5.18.12/source/mm/kasan/common.c#L138

void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
			  slab_flags_t *flags)
{
	unsigned int ok_size;
	unsigned int optimal_size;

	/*
	 * SLAB_KASAN is used to mark caches as ones that are sanitized by
	 * KASAN. Currently this flag is used in two places:
	 * 1. In slab_ksize() when calculating the size of the accessible
	 *    memory within the object.
	 * 2. In slab_common.c to prevent merging of sanitized caches.
	 */
	*flags |= SLAB_KASAN;

	if (!kasan_stack_collection_enabled())
		return;

	ok_size = *size;

	/* Add alloc meta into redzone. */
	cache->kasan_info.alloc_meta_offset = *size;
	*size += sizeof(struct kasan_alloc_meta);

	/*
	 * If alloc meta doesn't fit, don't add it.
	 * This can only happen with SLAB, as it has KMALLOC_MAX_SIZE equal
	 * to KMALLOC_MAX_CACHE_SIZE and doesn't fall back to page_alloc for
	 * larger sizes.
	 */
	if (*size > KMALLOC_MAX_SIZE) {
		cache->kasan_info.alloc_meta_offset = 0;
		*size = ok_size;
		/* Continue, since free meta might still fit. */
	}

	/* Only the generic mode uses free meta or flexible redzones. */
	if (!IS_ENABLED(CONFIG_KASAN_GENERIC)) {
		cache->kasan_info.free_meta_offset = KASAN_NO_FREE_META;
		return;
	}

	/*
	 * Add free meta into redzone when it's not possible to store
	 * it in the object. This is the case when:
	 * 1. Object is SLAB_TYPESAFE_BY_RCU, which means that it can
	 *    be touched after it was freed, or
	 * 2. Object has a constructor, which means it's expected to
	 *    retain its content until the next allocation, or
	 * 3. Object is too small.
	 * Otherwise cache->kasan_info.free_meta_offset = 0 is implied.
	 */
	if ((cache->flags & SLAB_TYPESAFE_BY_RCU) || cache->ctor ||
	    cache->object_size < sizeof(struct kasan_free_meta)) {
		ok_size = *size;

		cache->kasan_info.free_meta_offset = *size;
		*size += sizeof(struct kasan_free_meta);

		/* If free meta doesn't fit, don't add it. */
		if (*size > KMALLOC_MAX_SIZE) {
			cache->kasan_info.free_meta_offset = KASAN_NO_FREE_META;
			*size = ok_size;
		}
	}

	/* Calculate size with optimal redzone. */
	optimal_size = cache->object_size + optimal_redzone(cache->object_size);
	/* Limit it with KMALLOC_MAX_SIZE (relevant for SLAB only). */
	if (optimal_size > KMALLOC_MAX_SIZE)
		optimal_size = KMALLOC_MAX_SIZE;
	/* Use optimal size if the size with added metas is not large enough. */
	if (*size < optimal_size)
		*size = optimal_size;
}

void __kasan_cache_create_kmalloc(struct kmem_cache *cache)
{
	cache->kasan_info.is_kmalloc = true;
}

size_t __kasan_metadata_size(struct kmem_cache *cache)
{
	if (!kasan_stack_collection_enabled())
		return 0;
	return (cache->kasan_info.alloc_meta_offset ?
		sizeof(struct kasan_alloc_meta) : 0) +
		(cache->kasan_info.free_meta_offset ?
		sizeof(struct kasan_free_meta) : 0);
}

struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
					      const void *object)
{
	if (!cache->kasan_info.alloc_meta_offset)
		return NULL;
	return kasan_reset_tag(object) + cache->kasan_info.alloc_meta_offset;
}

#ifdef CONFIG_KASAN_GENERIC
struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
					    const void *object)
{
	BUILD_BUG_ON(sizeof(struct kasan_free_meta) > 32);
	if (cache->kasan_info.free_meta_offset == KASAN_NO_FREE_META)
		return NULL;
	return kasan_reset_tag(object) + cache->kasan_info.free_meta_offset;
}
#endif

void __kasan_poison_slab(struct slab *slab)
{
	struct page *page = slab_page(slab);
	unsigned long i;

	for (i = 0; i < compound_nr(page); i++)
		page_kasan_tag_reset(page + i);
	kasan_poison(page_address(page), page_size(page),
		     KASAN_KMALLOC_REDZONE, false);
}
```

