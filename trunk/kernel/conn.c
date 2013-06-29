/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include "iscsi.h"
#include "iscsi_dbg.h"
#include "digest.h"

#ifdef LINUX
static void print_conn_state(char *p, size_t size, unsigned long state)
{
	if (test_bit(CONN_ACTIVE, &state))
		snprintf(p, size, "%s", "active");
	else if (test_bit(CONN_CLOSING, &state))
		snprintf(p, size, "%s", "closing");
	else
		snprintf(p, size, "%s", "unknown");
}

static void print_digest_state(char *p, size_t size, unsigned long flags)
{
	if (DIGEST_NONE & flags)
		snprintf(p, size, "%s", "none");
	else if (DIGEST_CRC32C & flags)
		snprintf(p, size, "%s", "crc32c");
	else
		snprintf(p, size, "%s", "unknown");
}

void conn_info_show(struct seq_file *seq, struct iscsi_session *session)
{
	struct iscsi_conn *conn;
	struct sock *sk;
	char buf[64];

	list_for_each_entry(conn, &session->conn_list, list) {
		sk = conn->sock->sk;
		switch (sk->sk_family) {
		case AF_INET:
			snprintf(buf, sizeof(buf),
				 "%pI4", &inet_sk(sk)->inet_daddr);
			break;
		case AF_INET6:
			snprintf(buf, sizeof(buf), "[%pI6]",
				 &inet6_sk(sk)->daddr);
			break;
		default:
			break;
		}
		seq_printf(seq, "\t\tcid:%u ip:%s ", conn->cid, buf);
		print_conn_state(buf, sizeof(buf), conn->state);
		seq_printf(seq, "state:%s ", buf);
		print_digest_state(buf, sizeof(buf), conn->hdigest_type);
		seq_printf(seq, "hd:%s ", buf);
		print_digest_state(buf, sizeof(buf), conn->ddigest_type);
		seq_printf(seq, "dd:%s\n", buf);
	}
}
#endif

struct iscsi_conn *conn_lookup(struct iscsi_session *session, u16 cid)
{
	struct iscsi_conn *conn;

	list_for_each_entry(conn, &session->conn_list, list) {
		if (conn->cid == cid)
			return conn;
	}
	return NULL;
}

#ifdef FREEBSD
static int iet_data_ready(struct socket *so, void *arg, int waitflag)
{
	struct iscsi_conn *conn = (struct iscsi_conn *)(arg);
	struct iscsi_target *target = conn->session->target;
	struct network_thread_info *info = &target->nthread_info;

	if ((so->so_state & SS_ISDISCONNECTING) ||(so->so_state & SS_ISDISCONNECTED))
		conn_close(conn);
	else if (so->so_rcv.sb_cc || !(so->so_rcv.sb_state & SBS_CANTRCVMORE))
		__nthread_wakeup(info);

	return (SU_OK);
}

static int iet_write_space(struct socket *so, void *arg, int waitflag)
{
	struct iscsi_conn *conn = (struct iscsi_conn *)(arg);
	struct iscsi_target *target = conn->session->target;
	struct network_thread_info *info = &target->nthread_info;

	spin_lock(&info->nthread_lock);

	if (test_and_clear_bit(CONN_WSPACE_WAIT, &conn->state))
		__nthread_wakeup(info);

	spin_unlock(&info->nthread_lock);

	return (SU_OK);
}
#else
static void iet_state_change(struct sock *sk)
{
	struct iscsi_conn *conn = sk->sk_user_data;
	struct iscsi_target *target = conn->session->target;

	if (sk->sk_state != TCP_ESTABLISHED)
		conn_close(conn);
	else
		nthread_wakeup(target);

	target->nthread_info.old_state_change(sk);
}

static void iet_data_ready(struct sock *sk, int len)
{
	struct iscsi_conn *conn = sk->sk_user_data;
	struct iscsi_target *target = conn->session->target;

	nthread_wakeup(target);
	target->nthread_info.old_data_ready(sk, len);
}

/*
 * @locking: grabs the target's nthread_lock to protect it from races with
 * set_conn_wspace_wait()
 */
static void iet_write_space(struct sock *sk)
{
	struct iscsi_conn *conn = sk->sk_user_data;
	struct network_thread_info *info = &conn->session->target->nthread_info;

	spin_lock_bh(&info->nthread_lock);

	if (sk_stream_wspace(sk) >= sk_stream_min_wspace(sk) &&
	    test_bit(CONN_WSPACE_WAIT, &conn->state)) {
		clear_bit(CONN_WSPACE_WAIT, &conn->state);
		__nthread_wakeup(info);
	}

	spin_unlock_bh(&info->nthread_lock);

	info->old_write_space(sk);
}
#endif

static void iet_socket_bind(struct iscsi_conn *conn)
{
	int opt = 1;
	struct iscsi_session *session = conn->session;
#ifdef LINUX
	struct iscsi_target *target = session->target;
	mm_segment_t oldfs;
#else
	struct sockopt sopt;
#endif

	dprintk(D_GENERIC, "%llu\n", (unsigned long long) session->sid);

#ifdef LINUX
	conn->sock = SOCKET_I(conn->file->f_dentry->d_inode);
	conn->sock->sk->sk_user_data = conn;

	write_lock_bh(&conn->sock->sk->sk_callback_lock);
	target->nthread_info.old_state_change = conn->sock->sk->sk_state_change;
	conn->sock->sk->sk_state_change = iet_state_change;

	target->nthread_info.old_data_ready = conn->sock->sk->sk_data_ready;
	conn->sock->sk->sk_data_ready = iet_data_ready;

	target->nthread_info.old_write_space = conn->sock->sk->sk_write_space;
	conn->sock->sk->sk_write_space = iet_write_space;
	write_unlock_bh(&conn->sock->sk->sk_callback_lock);

	oldfs = get_fs();
	set_fs(get_ds());
	conn->sock->ops->setsockopt(conn->sock, SOL_TCP, TCP_NODELAY, (void *)&opt, sizeof(opt));
	set_fs(oldfs);
#else
	/* conn set prior to this call for FreeBSD */
	SOCKBUF_LOCK(&conn->sock->so_rcv);
	soupcall_set(conn->sock, SO_RCV, iet_data_ready, conn);
	SOCKBUF_UNLOCK(&conn->sock->so_rcv);
	SOCKBUF_LOCK(&conn->sock->so_snd);
	soupcall_set(conn->sock, SO_SND, iet_write_space, conn);
	SOCKBUF_UNLOCK(&conn->sock->so_snd);
	sopt.sopt_dir = SOPT_SET;
	sopt.sopt_level = IPPROTO_TCP;
	sopt.sopt_name = TCP_NODELAY;
	sopt.sopt_val = (caddr_t)&opt;
	sopt.sopt_valsize = sizeof(opt);
	sopt.sopt_td = NULL;
	sosetopt(conn->sock, &sopt);
#endif
}

int conn_free(struct iscsi_conn *conn)
{
	dprintk(D_GENERIC, "%p %#Lx %u\n", conn->session,
		(unsigned long long) conn->session->sid, conn->cid);

	assert(atomic_read(&conn->nr_cmnds) == 0);
	assert(list_empty(&conn->pdu_list));
	assert(list_empty(&conn->write_list));

	list_del(&conn->list);
	list_del(&conn->poll_list);

	del_timer_sync(&conn->nop_timer);
	digest_cleanup(conn);
	kfree(conn);

	return 0;
}

static int iet_conn_alloc(struct iscsi_session *session, struct conn_info *info)
{
	struct iscsi_conn *conn;
#ifdef FREEBSD
	int error;
#endif

	dprintk(D_SETUP, "%#Lx:%u\n", (unsigned long long) session->sid, info->cid);

	conn = kzalloc(sizeof(*conn), GFP_KERNEL);
	if (!conn)
		return -ENOMEM;

	conn->session = session;
	conn->cid = info->cid;
	conn->stat_sn = info->stat_sn;
	conn->exp_stat_sn = info->exp_stat_sn;

	conn->hdigest_type = info->header_digest;
	conn->ddigest_type = info->data_digest;
	if (digest_init(conn) < 0) {
		kfree(conn);
		return -ENOMEM;
	}

	spin_lock_init(&conn->list_lock);
	atomic_set(&conn->nr_cmnds, 0);
	atomic_set(&conn->nr_busy_cmnds, 0);
	INIT_LIST_HEAD(&conn->pdu_list);
	INIT_LIST_HEAD(&conn->write_list);
	INIT_LIST_HEAD(&conn->poll_list);
	init_timer(&conn->nop_timer);

#ifdef LINUX
	conn->file = fget(info->fd);
#else
#if __FreeBSD_version < 900041
	error = fget(curthread, info->fd, &conn->file);
#else
	error = fget(curthread, info->fd, 0, &conn->file);
#endif
	if (error != 0) {
		eprintk("failed to get fd %d\n", error);
		kfree(conn);
		return error;
	}

#if __FreeBSD_version < 900041
	error = fgetsock(curthread, info->fd, &conn->sock, 0);
#else
	error = fgetsock(curthread, info->fd, 0, &conn->sock, 0);
#endif
	if (error != 0) {
		eprintk("failed to get sock %d\n", error);
		fdrop(conn->file, curthread);
		kfree(conn);
		return error;
	}
#endif
	list_add(&conn->list, &session->conn_list);

	set_bit(CONN_ACTIVE, &conn->state);

	iet_socket_bind(conn);

	list_add(&conn->poll_list, &session->target->nthread_info.active_conns);

	nthread_wakeup(conn->session->target);

	return 0;
}

void conn_close(struct iscsi_conn *conn)
{
	struct iscsi_cmnd *cmnd;
	struct iscsi_session *session = conn->session;

	if (test_and_clear_bit(CONN_ACTIVE, &conn->state))
		set_bit(CONN_CLOSING, &conn->state);

	spin_lock(&conn->list_lock);
	list_for_each_entry(cmnd, &conn->pdu_list, conn_list) {
		set_cmnd_tmfabort(cmnd);
		if (cmnd->lun) {
			ua_establish_for_session(session, cmnd->lun->lun, 0x47, 0x7f);
			iscsi_cmnd_set_sense(cmnd, UNIT_ATTENTION, 0x6e, 0x0);
		}
	}
	spin_unlock(&conn->list_lock);

	nthread_wakeup(conn->session->target);
}

int conn_add(struct iscsi_session *session, struct conn_info *info)
{
	struct iscsi_conn *conn;
	int err;

	conn = conn_lookup(session, info->cid);
	if (conn)
		conn_close(conn);

	err = iet_conn_alloc(session, info);

	return err;
}

int conn_del(struct iscsi_session *session, struct conn_info *info)
{
	struct iscsi_conn *conn;
	int err = -EEXIST;

	conn = conn_lookup(session, info->cid);
	if (!conn)
		return err;

	conn_close(conn);

	return 0;
}
