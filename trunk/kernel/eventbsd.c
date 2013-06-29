/*
 * Communication between user and kernel
 */

#include "iscsi.h" 

static struct selinfo kpoll_select;
spinlock_t ring_lock;
#define KCOMM_PAGES (IET_MMAP_SIZE >> PAGE_SHIFT)
#define KCOMM_MSGS_PER_PAGE (PAGE_SIZE / sizeof(struct iet_event))
#define KCOMM_MAX_MSGS (KCOMM_PAGES * KCOMM_MSGS_PER_PAGE)
 
page_t *kern_bufs[KCOMM_PAGES];
int kcomm_id;
atomic_t pending_read_msgs;

static struct iet_event *
kcomm_next_msg(int idx)
{
	int page_idx;
	int page_offset;

	page_idx = idx / KCOMM_MSGS_PER_PAGE;
	page_offset = idx % KCOMM_MSGS_PER_PAGE;

	return (struct iet_event *)((uint8_t *)(page_address(kern_bufs[page_idx])) + (sizeof(struct iet_event) * page_offset));
}

int event_send(u32 tid, u64 sid, u32 cid, u32 state, int atomic)
{
	struct iet_event *send_msg;

	spin_lock(&ring_lock);
	send_msg = kcomm_next_msg(kcomm_id);
	if (send_msg->inuse)
	{
		spin_unlock(&ring_lock);
		return -1;
	}
	kcomm_id++;
	if (kcomm_id == KCOMM_MAX_MSGS)
		kcomm_id = 0;
	memset(send_msg, 0, sizeof(*send_msg));
	send_msg->inuse = 1;
	send_msg->tid = tid;
	send_msg->sid = sid;
	send_msg->cid = cid;
	send_msg->state = state;
	atomic_inc(&pending_read_msgs);
	spin_unlock(&ring_lock);
	mb();
	selwakeup(&kpoll_select);
	return 0;
}

void
iet_mmap_exit(void)
{
	int i;

	for (i = 0; i < KCOMM_PAGES; i++)
	{
		if (!kern_bufs[i])
			continue;
		__free_page(kern_bufs[i]);
		kern_bufs[i] = 0;
	}

}

int
iet_mmap_init(void)
{
	int i;

	spin_lock_init(&ring_lock);
	for (i = 0; i < KCOMM_PAGES; i++)
	{
		kern_bufs[i] = __alloc_page(PAGE_SIZE, M_WAITOK | M_ZERO);
		if (!kern_bufs[i])
			return -1;
		memset((caddr_t)page_address(kern_bufs[i]), 0, PAGE_SIZE);
	}
	return 0;
}

int iet_poll(struct cdev *dev, int poll_events, struct thread *td)
{
	unsigned int ret = 0;

	spin_lock(&ring_lock);
	if ((poll_events & (POLLRDNORM | POLLIN)) != 0) {
		if (atomic_read(&pending_read_msgs) > 0) {
			atomic_dec(&pending_read_msgs);
			ret |= POLLIN | POLLRDNORM;
		}
	}
	spin_unlock(&ring_lock);

	if (ret == 0) {
		if (poll_events & (POLLIN | POLLRDNORM))
			selrecord(td, &kpoll_select);
	}

	return (ret);
}

#if __FreeBSD_version >= 900006
int iet_mmap(struct cdev *dev, vm_ooffset_t offset, vm_paddr_t *paddr, int nprot, vm_memattr_t *memattr __unused)
#else
int iet_mmap(struct cdev *dev, vm_offset_t offset, vm_paddr_t *paddr, int nprot)
#endif
{
	int page_idx;
	page_t **bufs;
	page_t *page;

	page_idx = offset/PAGE_SIZE;
	bufs = kern_bufs;
	page = bufs[page_idx];
	*paddr = (vm_paddr_t)vtophys(page_address(page));
	return 0;
}

/**
 * match_one: - Determines if a string matches a simple pattern
 * @s: the string to examine for presense of the pattern
 * @p: the string containing the pattern
 * @args: array of %MAX_OPT_ARGS &substring_t elements. Used to return match
 * locations.
 *
 * Description: Determines if the pattern @p is present in string @s. Can only
 * match extremely simple token=arg style patterns. If the pattern is found,
 * the location(s) of the arguments will be returned in the @args array.
 */
static int match_one(char *s, char *p, substring_t args[])
{
	char *meta;
	int argc = 0;

	if (!p)
		return 1;

	while(1) {
		int len = -1;
		meta = strchr(p, '%');
		if (!meta)
			return strcmp(p, s) == 0;

		if (strncmp(p, s, meta-p))
			return 0;

		s += meta - p;
		p = meta + 1;

		if (isdigit(*p))
			len = simple_strtoul(p, &p, 10);
		else if (*p == '%') {
			if (*s++ != '%')
				return 0;
			p++;
			continue;
		}

		if (argc >= MAX_OPT_ARGS)
			return 0;

		args[argc].from = s;
		switch (*p++) {
		case 's':
			if (strlen(s) == 0)
				return 0;
			else if (len == -1 || len > strlen(s))
				len = strlen(s);
			args[argc].to = s + len;
			break;
		case 'd':
			simple_strtol(s, &args[argc].to, 0);
			goto num;
		case 'u':
			simple_strtoul(s, &args[argc].to, 0);
			goto num;
		case 'o':
			simple_strtoul(s, &args[argc].to, 8);
			goto num;
		case 'x':
			simple_strtoul(s, &args[argc].to, 16);
		num:
			if (args[argc].to == args[argc].from)
				return 0;
			break;
		default:
			return 0;
		}
		s = args[argc].to;
		argc++;
	}
}

/**
 * match_token: - Find a token (and optional args) in a string
 * @s: the string to examine for token/argument pairs
 * @table: match_table_t describing the set of allowed option tokens and the
 * arguments that may be associated with them. Must be terminated with a
 * &struct match_token whose pattern is set to the NULL pointer.
 * @args: array of %MAX_OPT_ARGS &substring_t elements. Used to return match
 * locations.
 *
 * Description: Detects which if any of a set of token strings has been passed
 * to it. Tokens can include up to MAX_OPT_ARGS instances of basic c-style
 * format identifiers which will be taken into account when matching the
 * tokens, and whose locations will be returned in the @args array.
 */
int match_token(char *s, match_table_t table, substring_t args[])
{
	struct match_token *p;

	for (p = table; !match_one(s, p->pattern, args) ; p++)
		;

	return p->token;
}

/**
 * match_strcpy: - copies the characters from a substring_t to a string
 * @to: string to copy characters to.
 * @s: &substring_t to copy
 *
 * Description: Copies the set of characters represented by the given
 * &substring_t @s to the c-style string @to. Caller guarantees that @to is
 * large enough to hold the characters of @s.
 */
void match_strcpy(char *to, substring_t *s)
{
	memcpy(to, s->from, s->to - s->from);
	to[s->to - s->from] = '\0';
}

/**
 * match_strdup: - allocate a new string with the contents of a substring_t
 * @s: &substring_t to copy
 *
 * Description: Allocates and returns a string filled with the contents of
 * the &substring_t @s. The caller is responsible for freeing the returned
 * string with kfree().
 */
char *match_strdup(substring_t *s)
{
	char *p = kmalloc(s->to - s->from + 1, GFP_KERNEL);
	if (p)
		match_strcpy(p, s);
	return p;
}

