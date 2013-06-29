#ifndef IETBSD_H_
#define IETBSD_H_ 1

#include <sys/types.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/endian.h>
#include <sys/malloc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/bio.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <sys/fcntl.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/ucred.h>
#include <sys/namei.h>
#include <sys/disk.h>
#include <sys/sglist.h>
#include <sys/kthread.h>
#include <sys/random.h>
#include <sys/poll.h>
#include <sys/dirent.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/sockopt.h>
#include <sys/socketvar.h>
#include <sys/syscallsubr.h>
#include <sys/file.h>
#include <sys/filio.h>
#include <sys/ctype.h>
#include <sys/sysproto.h>
#include <sys/md5.h>
#include <geom/geom.h>
#include <cam/scsi/scsi_all.h>
#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_extern.h>
#include <vm/vm_pageout.h>
#include <vm/vm_pager.h>
#include <vm/vm_reserv.h>
#include <vm/uma.h>
#include <machine/atomic.h>
#include <machine/_inttypes.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <geom/geom.h>

#define IET_PAGE_SHIFT		16
#define IET_PAGE_SIZE		(1UL << IET_PAGE_SHIFT)
#define IET_PAGE_MASK		(~(IET_PAGE_SIZE - 1))
#define PAGE_CACHE_SHIFT	IET_PAGE_SHIFT
#define PAGE_CACHE_SIZE		IET_PAGE_SIZE
#define PAGE_CACHE_MASK		IET_PAGE_MASK
 
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef uint8_t __u8;
typedef int8_t __s8;
typedef uint16_t __u16;
typedef int16_t __s16;
typedef uint32_t __u32;
typedef int32_t __s32;
typedef uint64_t __u64;
typedef int64_t __s64;
typedef __u16 __be16;
typedef __u16 __le16;
typedef __u32 __be32;
typedef __u32 __le32;
typedef __u64 __be64;
typedef __u64 __le64;
typedef int bool_t;
#define false	0
#define true	1
static __inline void
clear_bit(int b, volatile void *p)
{
	atomic_clear_int(((volatile int *)p) + (b >> 5), 1 << (b & 0x1f));
}

static __inline void
set_bit(int b, volatile void *p)
{
	atomic_set_int(((volatile int *)p) + (b >> 5), 1 << (b & 0x1f));
}

static __inline int
test_bit(int b, volatile void *p)
{
	return ((volatile int *)p)[b >> 5] & (1 << (b & 0x1f));
}

static __inline int
test_and_clear_bit(int b, volatile void *p)
{
	return (atomic_cmpset_int(((volatile int *)p), ((*((volatile int *)p)) | (1 << b)), ((*((volatile int *)p)) & ~(1 << b))));
}

#define likely(x)		__builtin_expect(!!(x), 1)
#define unlikely(x)		__builtin_expect(!!(x), 0)
#define get_unaligned(ptr)	(*(ptr))
#define put_unaligned(val, ptr)	((void)( *(ptr) = (val) ))
#define simple_strtoull		strtouq
#define simple_strtoul		strtoul
#define simple_strtol		strtol
#define min_t(type, x, y) ({			\
	type __min1 = (x);			\
	type __min2 = (y);			\
	__min1 < __min2 ? __min1: __min2; })

#define max_t(type, x, y) ({			\
	type __max1 = (x);			\
	type __max2 = (y);			\
	__max1 > __max2 ? __max1: __max2; })


/*
 * match_* functions from linux kernel sources lib/parser.c
 */

/* associates an integer enumerator with a pattern string. */
struct match_token {
	int token;
	char *pattern;
};
typedef struct match_token match_table_t[];

/* Describe the location within a string of a substring */
typedef struct {
	char *from;
	char *to;
} substring_t;

/* Maximum number of arguments that match_token will find in a pattern */
enum {MAX_OPT_ARGS = 3};

int match_token(char *s, match_table_t table, substring_t args[]);
char *match_strdup(substring_t *s);
void match_strcpy(char *to, substring_t *s);

/* assumes size > 256 */
static inline unsigned int blksize_bits(unsigned int size)
{
	unsigned int bits = 8;
	do {
		bits++;
		size >>= 1;
	} while (size > 256);
	return bits;
}

static inline int is_power_of_2(unsigned long n)
{
	return (n != 0 && ((n & (n - 1)) == 0));
}

typedef unsigned long pgoff_t;
typedef struct sx mutex_t;
typedef struct sx rwlock_t;
typedef struct sx semaphore_t;
typedef struct callout timer_list_t;
typedef struct proc task_struct_t;

#define read_lock		sx_slock
#define read_unlock		sx_sunlock
#define write_lock		sx_xlock
#define write_unlock		sx_xunlock

#define mutex_init(lck)			sx_init(lck, "iet lck")
#define mutex_lock_interruptible	sx_xlock_sig
#define mutex_lock			sx_xlock
#define mutex_unlock			sx_xunlock

#define DEFINE_MUTEX(lck)					\
	struct sx lck;						\
	SX_SYSINIT(lck, &lck, #lck);				\

#define kernel_thread_create(fn,dt,tsk,fmt,args...)		\
({								\
	int __ret;						\
	__ret = kproc_create(fn,dt,&tsk,0,0,fmt,##args);	\
	__ret;							\
})


#define init_timer(x)		callout_init(x, CALLOUT_MPSAFE)
MALLOC_DECLARE(M_IET);

#define wake_up 	chan_wakeup_one

#if BYTE_ORDER == BIG_ENDIAN
#define __BIG_ENDIAN_BITFIELD
#define __BIG_ENDIAN	BIG_ENDIAN
#elif BYTE_ORDER == LITTLE_ENDIAN
#define __LITTLE_ENDIAN_BITFIELD
#define __LITTLE_ENDIAN	LITTLE_ENDIAN
#else
#error "Invalid byte order"
#endif

#define READ		UIO_READ
#define WRITE		UIO_WRITE

#define	__cpu_to_be16	htobe16
#define	__cpu_to_be32	htobe32
#define	__cpu_to_be64	htobe64
#define	__cpu_to_le16	htole16
#define	__cpu_to_le32	htole32
#define	__cpu_to_le64	htole64
#define __be16_to_cpu	be16toh
#define __be32_to_cpu	be32toh
#define __be64_to_cpu	be64toh
#define __le16_to_cpu	le16toh
#define __le32_to_cpu	le32toh
#define __le64_to_cpu	le64toh

#define cpu_to_be16	__cpu_to_be16
#define cpu_to_be32	__cpu_to_be32
#define cpu_to_be64	__cpu_to_be64
#define cpu_to_le16	__cpu_to_le16
#define cpu_to_le32	__cpu_to_le32
#define cpu_to_le64	__cpu_to_le64
#define be16_to_cpu	__be16_to_cpu
#define be32_to_cpu	__be32_to_cpu
#define be64_to_cpu	__be64_to_cpu
#define le16_to_cpu	__le16_to_cpu
#define le32_to_cpu	__le32_to_cpu
#define le64_to_cpu	__le64_to_cpu

#define loff_t		off_t
#define printk		printf
#define KERN_WARNING
#define KERN_INFO
#define KERN_CRIT
#define KERN_DEBUG
#define KERN_ERR

#define dump_stack()	do {} while (0)
#define BUG()		do {} while (0)
#define clear_page(page)  bzero((page), IET_PAGE_SIZE)
#define del_timer_sync		callout_drain

/* is s2<=s1<=s3 ? */
static inline int between(__u32 seq1, __u32 seq2, __u32 seq3)
{
	return seq3 - seq2 >= seq1 - seq2;
}

static inline int before(__u32 seq1, __u32 seq2)
{
	return (__s32)(seq1-seq2) < 0;
}

static inline int after(__u32 seq1, __u32 seq2)
{
	return (__s32)(seq2-seq1) < 0;
}

#define ILLEGAL_REQUEST	SSD_KEY_ILLEGAL_REQUEST
#define ABORTED_COMMAND	SSD_KEY_ABORTED_COMMAND
#define UNIT_ATTENTION	SSD_KEY_UNIT_ATTENTION
#define MODE_SENSE	MODE_SENSE_6
#define MODE_SELECT	MODE_SELECT_6
#define VERIFY		0x2f
#define jiffies		0
#define HZ		hz
#define get_fs()	do {} while (0)
#define set_fs(x)	do {} while (0)
#define ERESTARTSYS	ERESTART

struct wait_chan {
	struct mtx chan_lock;
	int done;
};

typedef struct wait_chan wait_queue_head_t;
typedef struct wait_chan wait_chan_t;
typedef struct wait_chan completion_t;

typedef void page_t;

#define page_address(x)		((void *)(x))
typedef int gfp_t;
#define GFP_KERNEL	M_WAITOK
#define GFP_USER	M_WAITOK
#define GFP_ATOMIC	M_NOWAIT
#define __GFP_NOFAIL	0

typedef struct uma_zone slab_cache_t;
#define kmem_cache_alloc	uma_zalloc
#define kmem_cache_free		uma_zfree
#define kmem_cache_destroy	uma_zdestroy

static inline void *
__alloc_page(uint32_t size, gfp_t flags)
{
	return malloc(size, M_IET, flags);
}

static inline void *
alloc_page(gfp_t flags)
{
	return __alloc_page(IET_PAGE_SIZE, flags);
}

static inline void
__free_page(page_t *pg)
{
	free(pg, M_IET);
}

#define free_page(x)	free((void *)(x), M_IET)
#define get_zeroed_page(flgs)	(unsigned long)alloc_page(flgs | M_ZERO)


static inline void
wait_chan_init(wait_chan_t *chan, const char *name)
{
	mtx_init(&chan->chan_lock, name, NULL, MTX_DEF);
}

static inline void
init_completion(wait_chan_t *chan)
{
	if (!mtx_initialized(&chan->chan_lock))
		wait_chan_init(chan, "comp");
	mtx_lock(&chan->chan_lock);
	chan->done = 0;
	mtx_unlock(&chan->chan_lock);
}

static inline int
mtx_lock_interruptible(struct mtx *mtx)
{
	mtx_lock(mtx);
	return 0;
}

static inline int
sx_xlock_interruptible(struct sx *sx)
{
	sx_xlock(sx);
	return 0;
}

#define __wait_on_chan(chn, condition)				\
do {								\
	mtx_lock(&chn->chan_lock);				\
	while (!(condition)) {					\
		msleep(chn, &chn->chan_lock, 0, "cwait", 0);	\
	}							\
	mtx_unlock(&chn->chan_lock);				\
} while (0)

#define __wait_on_chan_interruptible(chn, condition)				\
({								\
	int __ret = 0;						\
	mtx_lock(&chn->chan_lock);				\
	while (!(condition)) {					\
		__ret = msleep(chn, &chn->chan_lock, PCATCH, "cwait", 0);	\
		if (__ret)					\
			break;					\
	}							\
	mtx_unlock(&chn->chan_lock);				\
	__ret;							\
})

#define __wait_on_chan_timeout(chn, condition, timeo)		\
({								\
	int __ret = 0;						\
	mtx_lock(&chn->chan_lock);				\
	while (!(condition)) {					\
		__ret = msleep(chn, &chn->chan_lock, 0, "cwait", timeo);	\
		if (__ret)					\
			break;					\
	}							\
	mtx_unlock(&chn->chan_lock);				\
	__ret;							\
})

#define wait_on_chan(chan, condition)				\
do {								\
	wait_chan_t *chanptr = &(chan);				\
	__wait_on_chan(chanptr, condition);			\
} while (0)

#define __chan_wakeup_one(chan)	wakeup_one(chan)
#define __chan_wakeup(chan)	wakeup(chan)

#define wait_on_chan_interruptible(chan, condition)		\
({								\
	wait_chan_t *chanptr = &(chan);				\
	int __ret = 1;						\
	__ret = __wait_on_chan_interruptible(chanptr, condition);			\
	__ret;							\
})


static inline void
chan_wakeup_one(wait_chan_t *chan)
{
	mtx_lock(&chan->chan_lock);
	__chan_wakeup_one(chan);
	mtx_unlock(&chan->chan_lock);
}

static inline void
chan_wakeup(wait_chan_t *chan)
{
	mtx_lock(&chan->chan_lock);
	__chan_wakeup(chan);
	mtx_unlock(&chan->chan_lock);
}

#define chan_wakeup_interruptible(chan)	chan_wakeup(chan)

static inline void
wait_for_completion(wait_chan_t *chan)
{
	__wait_on_chan(chan, chan->done);
}

static inline int 
wait_for_completion_interruptible(wait_chan_t *chan)
{
	int ret;
	ret = __wait_on_chan_interruptible(chan, chan->done);
	return ret;
}

static inline int
wait_for_completion_timeout(wait_chan_t *chan, long timeout)
{
	long ret;

	ret = __wait_on_chan_timeout(chan, chan->done, timeout);
	if (!ret)
		ret = timeout;
	else
		ret = 0;
	return ret;
}

static inline void
complete(wait_chan_t *chan)
{
	mtx_lock(&chan->chan_lock);
	chan->done = 1;
	__chan_wakeup_one(chan);
	mtx_unlock(&chan->chan_lock);
}

static inline void
complete_all(wait_chan_t *chan)
{
	mtx_lock(&chan->chan_lock);
	chan->done = 1;
	__chan_wakeup(chan);
	mtx_unlock(&chan->chan_lock);
}

#define init_waitqueue_head(h)	wait_chan_init(h, "iet")
#define wait_event_interruptible	wait_on_chan_interruptible
#define wait_event			wait_on_chan
#if __FreeBSD_version >= 900032
#define yield() kern_yield(curthread->td_user_pri)
#else
#define yield	uio_yield
#endif
#define timer_pending callout_pending
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define strnicmp	strncasecmp
#define kstrdup(s,f)	strdup(s, M_IET)

#define DECLARE_COMPLETION_ONSTACK(d)		\
	completion_t d;				\
	memset(&d, 0, sizeof(d));		\
	init_completion(&d);

/* use a wait chan */
#define DECLARE_WAITQUEUE(d,td)		\
	wait_queue_head_t d;		\
	init_waitqueue_head(&d);


typedef struct {
        volatile unsigned int   val;
} atomic_t;

#define ATOMIC_INIT(i)  { (i) }

#define atomic_read(v)                  ((v)->val)
#define atomic_set(v, i)                ((v)->val = (i))

#define atomic_add(i, v)                atomic_add_int(&(v)->val, (i))
#define atomic_inc(v)                   atomic_add_int(&(v)->val, 1)
#define atomic_dec(v)                   atomic_subtract_int(&(v)->val, 1)
#define atomic_sub(i, v)                atomic_subtract_int(&(v)->val, (i))
#define atomic_dec_and_test(v)          (atomic_fetchadd_int(&(v)->val, -1) == 1)

struct list_head {
	struct list_head *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#undef LIST_HEAD
#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

#define DEFINE_RWLOCK(lck)	rwlock_t lck; SX_SYSINIT(lck, &lck, #lck);

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline void __list_add(struct list_head *new,
			      struct list_head *prev,
			      struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static inline void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	__list_add(new, head->prev, head);
}

static inline void __list_del(struct list_head * prev, struct list_head * next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
}

static inline void list_del_init(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	INIT_LIST_HEAD(entry);
}

static inline int list_empty(const struct list_head *head)
{
	return head->next == head;
}

#define container_of(ptr, type, member) ({			\
	__typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})


#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

#define list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); \
        	pos = pos->next)

#define list_for_each_prev(pos, head) \
	for (pos = (head)->prev; pos != (head); \
        	pos = pos->prev)

#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

#define list_for_each_entry(pos, head, member) \
	for (pos = list_entry((head)->next, __typeof(*pos), member); \
		&pos->member != (head);	\
		pos = list_entry(pos->member.next, __typeof(*pos), member))

#define list_for_each_entry_safe(pos, n, head, member)                  \
	for (pos = list_entry((head)->next, __typeof(*pos), member),      \
		n = list_entry(pos->member.next, __typeof(*pos), member); \
		&pos->member != (head);                                    \
		pos = n, n = list_entry(n->member.next, __typeof(*n), member))

typedef struct mtx spinlock_t;

static inline void
spin_lock_init(spinlock_t *lock)
{
	mtx_init(lock, "ietlck", NULL, MTX_DEF);
}

static inline void
spin_lock(spinlock_t *lock)
{
	mtx_lock(lock);
}

#define spin_lock_irq(l) spin_lock(l)
#define spin_lock_bh(l) spin_lock(l)
#define spin_lock_irqsave(l,flg) spin_lock(l)

static inline void
spin_unlock(spinlock_t *lock)
{
	mtx_unlock(lock);
}

#define kfree(x)	free(x, M_IET)
#define kmalloc(s,flg)	malloc(s, M_IET, flg)

static inline void * 
kzalloc(unsigned long size, gfp_t flags)
{
	void *ptr;

	ptr = malloc(size, M_IET, flags | M_ZERO);
	return ptr;
}

#define spin_unlock_irq(l) spin_unlock(l)
#define spin_unlock_bh(l) spin_unlock(l)
#define spin_unlock_irqrestore(l,flg) spin_unlock(l)

/* SCSI codes */
#define SAM_STAT_GOOD			SCSI_STATUS_OK
#define SAM_STAT_RESERVATION_CONFLICT	SCSI_STATUS_RESERV_CONFLICT
#define SAM_STAT_CHECK_CONDITION	SCSI_STATUS_CHECK_COND
#define WRITE_VERIFY			0x2e
#define VERIFY_16			0x8f
#define DATA_PROTECT			SSD_KEY_DATA_PROTECT
#define NO_SENSE			SSD_KEY_NO_SENSE
#define MEDIUM_ERROR			SSD_KEY_MEDIUM_ERROR
#define TYPE_NO_LUN			0x7f

extern struct module *ietmod;
#define THIS_MODULE     ietmod
static inline int
try_module_get(struct module *mod)
{
	MOD_XLOCK;
	module_reference(mod);
	MOD_XUNLOCK;
	return 1;
}

static inline void
module_put(struct module *mod)
{
	MOD_XLOCK;
	module_release(mod);
	MOD_XUNLOCK;
}

static inline void
uio_fill(struct uio *uio, struct iovec *iov, int iovcnt, ssize_t resid, int rw)
{
	uio->uio_iov = iov;
	uio->uio_iovcnt = iovcnt;
	uio->uio_offset = 0;
	uio->uio_resid = resid;
	uio->uio_rw = rw;
	uio->uio_segflg = UIO_SYSSPACE;
	uio->uio_td = curthread;
}

static inline void 
map_result(int *result, struct uio *uio, int len, int waitall)
{
	int res = *result;

	if (res) {
		if (uio->uio_resid != len)
			res = (len - uio->uio_resid);
		else
			res = -(res);
	} else {
		res = len - uio->uio_resid;
		if (!res && !waitall)
			res = -(EAGAIN);
	}
	*result = res;
}

/* From linux/hash.h */
#define BITS_PER_LONG	__LONG_BIT

#if BITS_PER_LONG == 32
#define GOLDEN_RATIO_PRIME	0x9e370001UL
#elif BITS_PER_LONG == 64
#define GOLDEN_RATIO_PRIME	0x9e37fffffffc0001UL
#else
#error "Invalid bits per long"
#endif

static inline unsigned long hash_long(unsigned long val, int bits)
{
	return ((val * GOLDEN_RATIO_PRIME) >> (BITS_PER_LONG - bits));
}

typedef struct vnode iodev_t;
#define bio_put		g_destroy_bio		/* Note it really not an equivalent, g_destroy_bio destroys the bio, while bio_put decrements ref count and frees only if refcount is zero */

#define bio_get_private(b)	(b->bio_caller2)
#define BIO_MAX_PAGES		1
#define FMODE_READ		FREAD
#define FMODE_WRITE		FWRITE
#define O_LARGEFILE		0 /*XXX need to recheck on this */

static inline int
bio_add_page(struct bio *bio, page_t *page, unsigned int len, unsigned int offset)
{
	if (bio->bio_data)
	{
		return 0;
	}

	/* remember that page is malloced data */
	bio->bio_data = (caddr_t)(page) + offset;
	bio->bio_length = len;
	bio->bio_bcount = bio->bio_length;
	return len;
}

#define BUG_ON(X) do {} while(0) /*XXX Need to make this an assert */

#ifndef WRITE_SAME_16
#define WRITE_SAME_16			0x93
#endif

#ifndef PERSISTENT_RESERVE_IN
#define PERSISTENT_RESERVE_IN		0x5e
#endif

#ifndef PERSISTENT_RESERVE_OUT
#define PERSISTENT_RESERVE_OUT		0x5f
#endif

#endif
