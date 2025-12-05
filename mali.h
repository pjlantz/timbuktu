#include <stdint.h> 
#include <inttypes.h>

#define KBASE_IOCTL_TYPE 0x80

#define __u8  uint8_t
#define __u16 uint16_t
#define __u32 uint32_t
#define __u64 uint64_t

struct kbase_ioctl_version_check {
        __u16 major;
        __u16 minor;
};
#define KBASE_IOCTL_VERSION_CHECK \
        _IOWR(KBASE_IOCTL_TYPE, 52, struct kbase_ioctl_version_check)

struct kbase_ioctl_set_flags {
        __u32 create_flags;
};
#define KBASE_IOCTL_SET_FLAGS \
        _IOW(KBASE_IOCTL_TYPE, 1, struct kbase_ioctl_set_flags)

typedef __u8 base_kcpu_queue_id; /* We support up to 256 active KCPU queues */


/**
 * struct kbase_ioctl_mem_profile_add - Provide profiling information to kernel
 * @buffer: Pointer to the information
 * @len: Length
 * @padding: Padding
 *
 * The data provided is accessible through a debugfs file
 */

struct kbase_ioctl_mem_profile_add {
        __u64 buffer;
        __u32 len;
        __u32 padding;
};


#define KBASE_IOCTL_MEM_PROFILE_ADD \
        _IOW(KBASE_IOCTL_TYPE, 27, struct kbase_ioctl_mem_profile_add)

/**
 * struct kbase_ioctl_kcpu_queue_new - Create a KCPU command queue
 *
 * @id: ID of the new command queue returned by the kernel
 * @padding: Padding to round up to a multiple of 8 bytes, must be zero
 */
struct kbase_ioctl_kcpu_queue_new {
  base_kcpu_queue_id id;
  __u8 padding[7];
};

#define KBASE_IOCTL_KCPU_QUEUE_CREATE \
  _IOR(KBASE_IOCTL_TYPE, 45, struct kbase_ioctl_kcpu_queue_new)

/**
 * struct kbase_ioctl_kcpu_queue_delete - Destroy a KCPU command queue
 *
 * @id: ID of the command queue to be destroyed
 * @padding: Padding to round up to a multiple of 8 bytes, must be zero
 */
struct kbase_ioctl_kcpu_queue_delete {
  base_kcpu_queue_id id;
  __u8 padding[7];
};

#define KBASE_IOCTL_KCPU_QUEUE_DELETE \
  _IOW(KBASE_IOCTL_TYPE, 46, struct kbase_ioctl_kcpu_queue_delete)

/**
 * struct kbase_ioctl_kcpu_queue_enqueue - Enqueue commands into the KCPU queue
 *
 * @addr: Memory address of an array of struct base_kcpu_queue_command
 * @nr_commands: Number of commands in the array
 * @id: kcpu queue identifier, returned by KBASE_IOCTL_KCPU_QUEUE_CREATE ioctl
 * @padding: Padding to round up to a multiple of 8 bytes, must be zero
 */
struct kbase_ioctl_kcpu_queue_enqueue {
  __u64 addr;
  __u32 nr_commands;
  base_kcpu_queue_id id;
  __u8 padding[3];
};

#define KBASE_IOCTL_KCPU_QUEUE_ENQUEUE \
  _IOW(KBASE_IOCTL_TYPE, 47, struct kbase_ioctl_kcpu_queue_enqueue)

#define LOCAL_PAGE_SHIFT 12
#define BASE_MEM_MAP_TRACKING_HANDLE (3ul << LOCAL_PAGE_SHIFT)
