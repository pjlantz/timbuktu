## Details
The vulnerability was introduced in the SPL 230305 and patched in 231205. This project is named after Timbuktu as it exploits a UAF in the Mali GPU driver.

A use-after-free was found in the Mali driver targeting devices running a new generation of Mali GPUs that have a feature called Command Stream Frontend (CSF). This CSF feature is present on the following GPUs: Mali-G710, Mali-G610, Mali-G510 and Mali-G310. Testing and exploit development has been done only on Pixel 7 devices.

The vulnerability is located in the function `kbase_kcpu_fence_signal_prepare` of the source file `csf/mali_kbase_csf_kcpu.c`

``` cpp
static int kbase_kcpu_fence_signal_prepare(
		struct kbase_kcpu_command_queue *kcpu_queue,
		struct base_kcpu_command_fence_info *fence_info,
		struct kbase_kcpu_command *current_command)
{
	struct kbase_context *const kctx = kcpu_queue->kctx;
#if (KERNEL_VERSION(4, 10, 0) > LINUX_VERSION_CODE)
	struct fence *fence_out;
#else
	struct dma_fence *fence_out;
#endif
	struct base_fence fence;
	struct sync_file *sync_file;
	int ret = 0;
	int fd;

	lockdep_assert_held(&kctx->csf.kcpu_queues.lock);

	if (copy_from_user(&fence, u64_to_user_ptr(fence_info->fence),
			sizeof(fence)))
		return -EFAULT;

	fence_out = kzalloc(sizeof(*fence_out), GFP_KERNEL); (1)
	if (!fence_out)
		return -ENOMEM;

	dma_fence_init(fence_out,
		       &kbase_fence_ops,
		       &kbase_csf_fence_lock,
		       kcpu_queue->fence_context,
		       ++kcpu_queue->fence_seqno);

#if (KERNEL_VERSION(4, 9, 67) >= LINUX_VERSION_CODE)
	/* Take an extra reference to the fence on behalf of the sync file.
	 * This is only needded on older kernels where sync_file_create()
	 * does not take its own reference. This was changed in v4.9.68
	 * where sync_file_create() now takes its own reference.
	 */
	dma_fence_get(fence_out);
#endif

	/* create a sync_file fd representing the fence */
	sync_file = sync_file_create(fence_out);
	if (!sync_file) {
		ret = -ENOMEM;
		goto file_create_fail;
	}

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		ret = fd;
		goto fd_flags_fail;
	}

	fence.basep.fd = fd;

	current_command->type = BASE_KCPU_COMMAND_TYPE_FENCE_SIGNAL;
	current_command->info.fence.fence = fence_out;

	if (copy_to_user(u64_to_user_ptr(fence_info->fence), &fence,
			sizeof(fence))) {
		ret = -EFAULT;
		goto fd_flags_fail; (2)
	}

	/* 'sync_file' pointer can't be safely dereferenced once 'fd' is
	 * installed, so the install step needs to be done at the last
	 * before returning success.
	 */
	fd_install(fd, sync_file->file);
	return 0;

fd_flags_fail:
	fput(sync_file->file);
file_create_fail:
	/*
	 * Upon failure, dma_fence refcount that was increased by
	 * dma_fence_get() or sync_file_create() needs to be decreased
	 * to release it.
	 */
	dma_fence_put(fence_out); (3)

	current_command->info.fence.fence = NULL;
	kfree(fence_out); (4)

	return ret;
}
```

At (1) a `dma_fence` object named `fence_out` is allocated, if a `copy_to_user` fails later on, cleanup and error handling in the label `file_create_fail` will be triggered as part of step (2). This allocated object `fence_out` has its reference counter decreased via a call to `dma_fence_put` (3) and will reach zero as there is only one reference to it at that stage. This will trigger the execution of the `dma_fence_release` function and later `dma_fence_free` which does not use the regular `kfree` but instead uses `kfree_rcu`. Just after step (3), the `fence_out` object is freed (4). `kfree_rcu` does not free an object immediately, but rather schedules it to be freed when certain criterias are met. This acts somewhat like a delayed free that introduces an uncertainty in the time when the object is freed. The `copy_to_user` can be triggered to fail by making the memory region read-only in the exploit code.

## Exploitation

As it is a double-free on an object of size 128 bytes, a heap spray is performed between the two free's. In this case, the well-known `msgsnd` technique is used. 

After the second free occurs, `pipe_buffer` objects are sprayed in order to replace the `msgsnd` object. We have references to the `msgsnd` sockets, so when these are closed it will force freeing of the more useful `pipe_buffer` object and then yet another spraying is done to reallocate the pipe buffer object, this will be used to gain a limited write primitive by simply writing to pipes. This primitive is achieved via `pipe_buffer` field `page` that is overwritten with the address of the current tasks `addr_limit` gained from a kernel leak, see the pipe buffer struct definition below. As soon as `addr_limit` is overwritten by writing to a pipe that has the reallocated `pipe_buffer` we control, and full arbitrary read/write primitive is gained.

``` cpp
struct pipe_buffer { 
       struct page *page; 
       unsigned int offset, len; 
       const struct pipe_buf_operations *ops; 
       unsigned int flags; 
       unsigned long private; 
}; 
```
The arbitrary r/w primitive is used to overwrite the current tasks cred structures with those of the `init` process and disabling SELinux. This is accomplished by having one thread with `addr_limit` set to `KERNEL_DS` using the limited write primitive in order to bypass User Access Override (UAO).  For a `kernel_read(addr, size)` operation, this thread will write the data from the kernel address `addr` to the pipe buffer by executing `write(pipe[1], addr, size)`. A `kernel_write(addr, size)` is implemented using a `read(pipe[0], addr, size)`. Another thread is then responsible for writing/reading data to/from a user-space address, see summary below.

``` cpp
int pipefds[2];
pipe(pipefds);

// arbitrary kernel read 8 bytes
unsigned long val;
write(pipefds[1], 0xffffff80..., 8); // Thread 1 with addr_limit set to KERN_DS
read(pipefds[0], &val, 8); // Thread 2 with untampered addr_limit

// arbitrary kernel write 8 bytes
val = some_val; 
write(pipefds[1], &val, 8); // Thread 2 with untampered addr_limit
read(pipefds[0], 0xffffff80...,, 8); // Thread 1 with addr_limit set to KERN_DS
```

Finally a root shell is spawned.

Note that on later updates of the Android kernel the overwriting of `addr_limit` was mitigated but a read/write primitive is still possible via the `pipe_buffer` object, this is the current implementation in the exploit.


## Kernel info leak

The root cause of the leak is a `WARN_ON_ONCE` macro that is triggered in `__alloc_pages_nodemask` in `mm/page_alloc.c` via the Mali driver.

```cpp
struct page *
__alloc_pages_nodemask(gfp_t gfp_mask, unsigned int order, int preferred_nid,
							nodemask_t *nodemask)
{
	struct page *page;
	unsigned int alloc_flags = ALLOC_WMARK_LOW;
	gfp_t alloc_mask; /* The gfp_t that was actually used for allocation */
	struct alloc_context ac = { };
	/*
	 * There are several places where we assume that the order value is sane
	 * so bail out early if the request is out of bound.
	 */
	if (unlikely(order >= MAX_ORDER)) {
		WARN_ON_ONCE(!(gfp_mask & __GFP_NOWARN));
		return NULL;
	}


        /* ... */
}
``` 
This will generate a kernel warning and trace in the logs as shown below.

```
<4>[12162.101675][T29118] ------------[ cut here ]------------
<4>[12162.101782][T29118] WARNING: CPU: 5 PID: 29118 at mm/page_alloc.c:5329 __alloc_pages_nodemask+0x1a0/0x394
<4>[12162.101799][T29118] Modules linked in: snd_soc_cs40l26(OE) input_cs40l26_i2c(OE) cl_dsp(OE) focal_touch(OE) bcmdhd4389(OE) wlan_ptracker(OE) snd_soc_cs35l45_i2c(OE) snd_soc_cs35l41_i2c(OE) overheat_mitigat>
<4>[12162.102138][T29118]  snd_soc_cs35l45(OE) snd_soc_cs35l41_spi(OE) snd_soc_cs35l41(OE) snd_soc_wm_adsp(OE) pca9468(OE) panel_samsung_sofef01(OE) panel_samsung_s6e3hc4(OE) panel_samsung_s6e3hc3(OE) panel_sams>
<4>[12162.102457][T29118]  exynos_acme(E) softdog(E) s2mpg13_spmic_thermal(E) gs_thermal(E) google_bcl(E) odpm(E) debug_reboot(E) smfc(E) exynos_mfc(E) i2c_dev(E) i2c_acpm(E) i2c_exynos5(E) rtc_s2mpg12(E) keycom>
<4>[12162.102779][T29118]  power_stats(E) exynos_pd_dbg(E) exynos_pd(E) dwc3_exynos_usb(E) gvotable(E) exynos_cpuhp(E) pixel_metrics(E) vh_i2c(E) vh_cgroup(E) vh_fs(E) vh_thermal(E) vh_preemptirq_long(E) vh_sche>
<4>[12162.103092][T29118]  exynos_pmu_if(E) phy_exynos_usbdrd_super(E) pkvm_s2mpu(E) exynos_pd_el3(E) lzo_rle(E) lzo(E) zsmalloc(E) fips140(E)
<4>[12162.103167][T29118] CPU: 5 PID: 29118 Comm: leak-and Tainted: G        W  OE     5.10.149-android13-4-00002-gca169caca7bb-ab9598324 #1
<4>[12162.103179][T29118] Hardware name: GS201 PANTHER MP based on GS201 (DT)
<4>[12162.103195][T29118] pstate: 20400005 (nzCv daif +PAN -UAO -TCO BTYPE=--)
<4>[12162.103210][T29118] pc : __alloc_pages_nodemask+0x1a0/0x394
<4>[12162.103231][T29118] lr : kmalloc_order+0x48/0x1c8
<4>[12162.103242][T29118] sp : ffffffc020e43ba0
<4>[12162.103254][T29118] x29: ffffffc020e43be0 x28: ffffff889f708000
<4>[12162.103272][T29118] x27: 0000000000000000 x26: ffffffd23580f158
<4>[12162.103287][T29118] x25: 0000000000000000 x24: ffffff889c5b0000
<4>[12162.103302][T29118] x23: 0000000000000000 x22: 0000000000000012
<4>[12162.103318][T29118] x21: 0000000000000012 x20: 0000000020001000
<4>[12162.103334][T29118] x19: 0000000020001000 x18: ffffffc01d99b050
<4>[12162.103350][T29118] x17: 0000000000000000 x16: 0000000000000000
<4>[12162.103364][T29118] x15: 00000000200000c0 x14: 0000000000000000
<4>[12162.103378][T29118] x13: 0000000000007ffb x12: 0000000004000000
<4>[12162.103394][T29118] x11: 0000000000000001 x10: 0000007fffffffff
<4>[12162.103409][T29118] x9 : 0000000000000040 x8 : 3d766335dc578100
<4>[12162.103423][T29118] x7 : 0000000000000001 x6 : ffffffc020e43d98
<4>[12162.103440][T29118] x5 : ffffffc020e43d98 x4 : 0000000000000000
<4>[12162.103454][T29118] x3 : 0000000000000000 x2 : 0000000000000000
<4>[12162.103470][T29118] x1 : 0000000000000012 x0 : 0000000000040dc0
<4>[12162.103489][T29118] Call trace:
<4>[12162.103506][T29118]  __alloc_pages_nodemask+0x1a0/0x394
<4>[12162.103521][T29118]  kmalloc_order+0x48/0x1c8
<4>[12162.103534][T29118]  kmalloc_order_trace+0x34/0x168
<4>[12162.103549][T29118]  __kmalloc+0x504/0x7a0
<4>[12162.103970][T29118]  kbase_csf_cpu_queue_dump+0x40/0x120 [mali_kbase]
<4>[12162.104337][T29118]  kbase_ioctl+0xd24/0x1058 [mali_kbase]
<4>[12162.104362][T29118]  __arm64_sys_ioctl+0x178/0x1fc
<4>[12162.104390][T29118]  el0_svc_common+0xd0/0x1e4
<4>[12162.104411][T29118]  el0_svc+0x28/0x88
<4>[12162.104425][T29118]  el0_sync_handler+0x8c/0xf0
<4>[12162.104442][T29118]  el0_sync+0x1b4/0x1c0
<4>[12162.104455][T29118] ---[ end trace d6a1224c8908af1b ]---
```

These logs can normally only be shown by root and `dmesg`, however a bugreport can be generated for which the kernel logs will be collected and placed among other logs in a zip archive in the `/bugreports` folder on the device. Currently the bugreport can be triggered by the `shell`, `system_app` and `system_server` context.

From the above kernel log, there is an information disclosure about an address of a kernel function (register `x26`). This can be used to calculate the kernel base address if the offset to this kernel function from the base address is known, and thus bypassing kASLR. Additionally, the register `x28` stores the current thread's `task_struct` address from which the current task's `addr_limit` address can be deduced. This is helpful when trying to achieve an arbitrary read/write primitive in the kernel by overwriting the `addr_limit` value. In this exploit, this is achieved using the `pipe_buffer` objects and pointing its struct member `page` to the address of `addr_limit`. 

Triggering this leak via the Mali driver is accomplished via the function `kbase_csf_cpu_queue_dump` in `csf/mali_kbase_csf_cpu_queue_debugfs.c`. This function is invoked with the IOCTL `KBASE_IOCTL_CS_CPU_QUEUE_DUMP`. Note that this function can only be invoked if the kernel has enabled `CONFIG_DEBUG_FS=y` which seems to be the default config. The reason for this bug in `kbase_csf_cpu_queue_dump` is due to missing validation of `buf_size` parameter from userspace, see code below. 

```cpp
int kbase_csf_cpu_queue_dump(struct kbase_context *kctx,
                u64 buffer, size_t buf_size)
{
        int err = 0;

        size_t alloc_size = buf_size;
        char *dump_buffer;

        if (!buffer || !alloc_size)
                goto done;

        alloc_size = (alloc_size + PAGE_SIZE) & ~(PAGE_SIZE - 1);
        dump_buffer = kzalloc(alloc_size, GFP_KERNEL);

        /* ... */
}
```

`kzalloc` will call `kmalloc` with a size value larger than `KMALLOC_MAX_CACHE_SIZE`, as a consequence the following branch will be taken in in `kmalloc`:

```cpp
void *__kmalloc(size_t size, gfp_t flags)
{
        struct kmem_cache *s;
        void *ret;

        if (unlikely(size > KMALLOC_MAX_CACHE_SIZE))
                return kmalloc_large(size, flags);
      
        /* ... /*
}
``` 

and `order` is calculated via `get_order()` in `kmalloc_large`

```cpp
static __always_inline void *kmalloc_large(size_t size, gfp_t flags)
{
        unsigned int order = get_order(size);
        return kmalloc_order_trace(size, flags, order);
}
``` 

Eventually what happens next is:

1. `kmalloc_order_trace()` does:
```cpp
void *kmalloc_order_trace(size_t size, gfp_t flags, unsigned int order)
{
        void *ret = kmalloc_order(size, flags, order);
        trace_kmalloc(_RET_IP_, ret, size, PAGE_SIZE << order, flags);
        return ret;
}
```

2. `kmalloc_order` does:
```cpp
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
```
The call to `alloc_pages` will end up in `__alloc_pages_nodemask` with an invalid `order` value larger than `MAX_ORDER` and the `WARN_ON_ONCE` macro is triggered.
