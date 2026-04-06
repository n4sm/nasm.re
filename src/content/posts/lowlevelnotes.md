---
title: "Linux kernel side notes"
published: 2022-07-18
category: "research"
draft: false
---

Here are just some side notes about linux kernel internals I put here to avoid to have to learn same things again and again. Every notes target [linux kernel 5.18.12](https://elixir.bootlin.com/linux/v5.18.12/source/kernel).
There will be a lot of code for which I do not comment the whole part.

# Kernel heap management (SLUB, SLAB, SLOB)

Same way as for userland, the kernel has many algorithms to manage memory allocation according to what the kernel is looking for (huge resources or not, safety needs etc).

## SLUB

The SLUB algorithm is the algorithm I know the more, so that's the one I will cover first. To allocate dynamically memory, the kernel provides the `kmalloc` function to which you can provide flags:
```c
/**
 * kmalloc - allocate memory
 * @size: how many bytes of memory are required.
 * @flags: the type of memory to allocate.
 *
 * kmalloc is the normal method of allocating memory
 * for objects smaller than page size in the kernel.
 *
 * The allocated object address is aligned to at least ARCH_KMALLOC_MINALIGN
 * bytes. For @size of power of two bytes, the alignment is also guaranteed
 * to be at least to the size.
 *
 * The @flags argument may be one of the GFP flags defined at
 * include/linux/gfp.h and described at
 * :ref:`Documentation/core-api/mm-api.rst <mm-api-gfp-flags>`
 *
 * The recommended usage of the @flags is described at
 * :ref:`Documentation/core-api/memory-allocation.rst <memory_allocation>`
 *
 * Below is a brief outline of the most useful GFP flags
 *
 * %GFP_KERNEL
 *	Allocate normal kernel ram. May sleep.
 *
 * %GFP_NOWAIT
 *	Allocation will not sleep.
 *
 * %GFP_ATOMIC
 *	Allocation will not sleep.  May use emergency pools.
 *
 * %GFP_HIGHUSER
 *	Allocate memory from high memory on behalf of user.
 *
 * Also it is possible to set different flags by OR'ing
 * in one or more of the following additional @flags:
 *
 * %__GFP_HIGH
 *	This allocation has high priority and may use emergency pools.
 *
 * %__GFP_NOFAIL
 *	Indicate that this allocation is in no way allowed to fail
 *	(think twice before using).
 *
 * %__GFP_NORETRY
 *	If memory is not immediately available,
 *	then give up at once.
 *
 * %__GFP_NOWARN
 *	If allocation fails, don't issue any warnings.
 *
 * %__GFP_RETRY_MAYFAIL
 *	Try really hard to succeed the allocation but fail
 *	eventually.
 */
```

What are the main structures of SLUB management ? This can be described by this picture for which we will review each of the data structures (pic from [here](https://programmersought.com/article/362810197389/)):


<img align="center" width="100%" src="../../../SLUB_schema1.png">


To cover the whole allocation process, we will review the main structures to then take a look at the actual allocation algorithm.
Given the complexity of such structures, each of these structures are treated in separate articles:
- [kmem_cache](../kmem_cache)  

Let's take a look at the source code of the `__kmalloc` SLUB implemementation:
```c
// https://elixir.bootlin.com/linux/v5.18.12/source/mm/slub.c#L4399
void *__kmalloc(size_t size, gfp_t flags)
{
	struct kmem_cache *s;
	void *ret;

	if (unlikely(size > KMALLOC_MAX_CACHE_SIZE))
		return kmalloc_large(size, flags);

	s = kmalloc_slab(size, flags);

	if (unlikely(ZERO_OR_NULL_PTR(s)))
		return s;

	ret = slab_alloc(s, NULL, flags, _RET_IP_, size);

	trace_kmalloc(_RET_IP_, ret, size, s->size, flags);

	ret = kasan_kmalloc(s, ret, size, flags);

	return ret;
}
EXPORT_SYMBOL(__kmalloc);
```

### Large allocations

Thus, if the requested size is larger than `KMALLOC_MAX_CACHE_SIZE`, `kmalloc_large` is called, and `kmalloc_order` is called according to a particular `order`that represents the number of pages from the requested size:
```c
// https://elixir.bootlin.com/linux/v5.18.12/source/mm/slab_common.c#L944
/*
 * To avoid unnecessary overhead, we pass through large allocation requests
 * directly to the page allocator. We use __GFP_COMP, because we will need to
 * know the allocation order to free the pages properly in kfree.
 */
void *kmalloc_order(size_t size, gfp_t flags, unsigned int order)
{
	void *ret = NULL;
	struct page *page;

	if (unlikely(flags & GFP_SLAB_BUG_MASK))
		flags = kmalloc_fix_flags(flags);

	flags |= __GFP_COMP;
	page = alloc_pages(flags, order);
	if (likely(page)) {
		ret = page_address(page);
		mod_lruvec_page_state(page, NR_SLAB_UNRECLAIMABLE_B,
				PAGE_SIZE << order);
	}
	ret = kasan_kmalloc_large(ret, size, flags);
	/* As ret might get tagged, call kmemleak hook after KASAN. */
	kmemleak_alloc(ret, size, 1, flags);
	return ret;
}
EXPORT_SYMBOL(kmalloc_order);
```

The `__GFP_COMP` stands for the allocation of "compound pages", to quote Jonathan Corbet from [this article](https://lwn.net/Articles/619514/):

>A compound page is simply a grouping of two or more physically contiguous pages into a unit that can, in many ways, be treated as a single, larger page. They are most commonly used to create huge pages, used within hugetlbfs or the transparent huge pages subsystem, but they show up in other contexts as well. Compound pages can serve as anonymous memory or be used as buffers within the kernel; they cannot, however, appear in the page cache, which is only prepared to deal with singleton pages.

The actual allocation is made in `alloc_pages`, more specifically in `__alloc_pages` that requests pages to the buddy allocator. But that's out of scope for now. Thus what we know is that large allocations are handled directly by the buddy system.

### Small allocations

By following the other code path `kmalloc_slab` is called:
```c
// https://elixir.bootlin.com/linux/v5.18.12/source/mm/slab_common.c#L730
/*
 * Find the kmem_cache structure that serves a given size of
 * allocation
 */
struct kmem_cache *kmalloc_slab(size_t size, gfp_t flags)
{
	unsigned int index;

	if (size <= 192) {
		if (!size)
			return ZERO_SIZE_PTR;

		index = size_index[size_index_elem(size)];
	} else {
		if (WARN_ON_ONCE(size > KMALLOC_MAX_CACHE_SIZE))
			return NULL;
		index = fls(size - 1);
	}

	return kmalloc_caches[kmalloc_type(flags)][index];
}
```

## kmem_cache_init

`kmalloc_slab` returns the `kmalloc_cache` entry that matchs the provided flags and size. Let's see how is initialized this array, the main initialization occurs in `kmem_cache_init`:

```c
void __init kmem_cache_init(void)
{
	static __initdata struct kmem_cache boot_kmem_cache,
			  boot_kmem_cache_node;
	int node;

	if (debug_guardpage_minorder())
		slub_max_order = 0;

	/* Print slub debugging pointers without hashing */
	if (__slub_debug_enabled())
		no_hash_pointers_enable(NULL);

	kmem_cache_node = &boot_kmem_cache_node;
	kmem_cache = &boot_kmem_cache;

	/*
	 * Initialize the nodemask for which we will allocate per node
	 * structures. Here we don't need taking slab_mutex yet.
	 */
	for_each_node_state(node, N_NORMAL_MEMORY)
		node_set(node, slab_nodes);
```

`slab_nodes` is a [bitmap](https://0xax.gitbooks.io/linux-insides/content/DataStructures/linux-datastructures-3.html) representing the nodes used by the kernel. Given we're on x86-64 the cpu is NUMA but behaves for compatibility purposes like a UMA system. Which means there is only one node used, and in it one "zone": `N_NORMAL_MEMORY`. This way `for_each_node_state` loops only one time:
```c
// https://elixir.bootlin.com/linux/latest/source/include/linux/nodemask.h#L482
#define for_each_node_state(node, __state) \
	for ( (node) = 0; (node) == 0; (node) = 1)
```
This way `slab_nodes` is initialized to `1`.

Then the first two kmem_cache are created: `kmem_cache_node` and `kmem_cache`:
```c
	// https://elixir.bootlin.com/linux/latest/source/mm/slub.c#L4819
	create_boot_cache(kmem_cache_node, "kmem_cache_node",
		sizeof(struct kmem_cache_node), SLAB_HWCACHE_ALIGN, 0, 0);

	register_hotmemory_notifier(&slab_memory_callback_nb);

	/* Able to allocate the per node structures */
	slab_state = PARTIAL;

	create_boot_cache(kmem_cache, "kmem_cache",
			offsetof(struct kmem_cache, node) +
				nr_node_ids * sizeof(struct kmem_cache_node *),
		       SLAB_HWCACHE_ALIGN, 0, 0);

	kmem_cache = bootstrap(&boot_kmem_cache);
	kmem_cache_node = bootstrap(&boot_kmem_cache_node);

	/* Now we can use the kmem_cache to allocate kmalloc slabs */
	setup_kmalloc_cache_index_table();
	create_kmalloc_caches(0);

	/* Setup random freelists for each cache */
	init_freelist_randomization();

	cpuhp_setup_state_nocalls(CPUHP_SLUB_DEAD, "slub:dead", NULL,
				  slub_cpu_dead);

	pr_info("SLUB: HWalign=%d, Order=%u-%u, MinObjects=%u, CPUs=%u, Nodes=%u\n",
		cache_line_size(),
		slub_min_order, slub_max_order, slub_min_objects,
		nr_cpu_ids, nr_node_ids);
}
```

Let's take a look at the main functions. But before that, let's review the internal layout of the `kmem_cache` structure.

# References

- [cdnblogs, Allocation of mm-slab objects](https://www.cnblogs.com/adera/p/11718758.html)
- [cdnblogs, Linux Memory Description of Memory Node Node - Linux Memory Management (II)](https://www.cnblogs.com/linhaostudy/p/9992639.html)
- [programmerSought, Linux Memory Management SLUB Distributor 2 [Kmalloc_Cache Structure]](https://programmersought.com/article/362810197389/)
- [dingmos, Linux kernel | Memory management - Slab allocator](https://www.dingmos.com/index.php/archives/23/)
- [wenqupro, Article about kmem_cache](https://wenqupro.com/?thread-20.htm)
- [cdnblogs, Slub Allocator Learning Series Linux 5.10](https://blog.csdn.net/m0_37637511/article/details/124960015)
- [zhuanlan, Non-professional understanding slub](https://zhuanlan.zhihu.com/p/458668727)
- [Birost, Analysis of linux slub allocator](https://blog.birost.com/a?ID=01100-ba652270-a5d4-4038-91a9-e0c56bcc643b)
- [LWN, The zen of kobjects](https://lwn.net/Articles/51437/)