#ifndef IETLINUX_H_
#define IETLINUX_H_	1

#include <linux/types.h>
#include <linux/pagemap.h>
#include <linux/seq_file.h>
#include <linux/mm.h>
#include <linux/crypto.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/version.h>
#include <linux/hash.h>
#include <linux/proc_fs.h>
#include <linux/ip.h>
#include <linux/ctype.h>
#include <linux/parser.h>
#include <linux/blkdev.h>
#include <linux/writeback.h>
#include <linux/buffer_head.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <asm/scatterlist.h>
#include <asm/byteorder.h>
#include <asm/ioctls.h>
#include <scsi/scsi.h>
#include "compat.h"

#define IET_PAGE_SHIFT		PAGE_SHIFT
#define IET_PAGE_SIZE		PAGE_SIZE
#define IET_PAGE_MASK		PAGE_MASK

typedef struct mutex mutex_t;
typedef struct semaphore semaphore_t;
typedef struct timer_list timer_list_t;
typedef struct page page_t;
typedef struct kmem_cache slab_cache_t;
typedef struct task_struct task_struct_t;
typedef struct completion completion_t;

#define kernel_thread_create(fn,dt,tsk,fmt,args...)		\
({								\
	int __ret = 0;						\
	tsk = kthread_run(fn,dt,fmt,##args);			\
	if (IS_ERR(tsk))					\
	{							\
		__ret = -1;					\
	}							\
	__ret;							\
})

typedef struct block_device iodev_t;
#define bio_get_private(b)	(b->bi_private)

#endif
