/*
 * Target device file I/O.
 * (C) 2004 - 2005 FUJITA Tomonori <tomof@acm.org>
 * This code is licenced under the GPL.
 */

#include "iscsi.h"
#include "iscsi_dbg.h"
#include "iotype.h"

struct fileio_data {
	char *path;
#ifdef LINUX
	struct file *filp;
#else
	struct vnode *filevp;
#endif
};

static int fileio_make_request(struct iet_volume *lu, struct tio *tio, int rw)
{
	struct fileio_data *p = lu->private;
	page_t *page;
#ifdef LINUX
	struct file *filp;
	mm_segment_t oldfs;
#else
	struct vnode *vp;
#if defined(NDHASGIANT)
	int vfslocked;
#endif
	int error;
#if ((__FreeBSD_version < 1000000 && __FreeBSD_version >= 900506) || (__FreeBSD_version >= 1000009))
	ssize_t aresid;
#else
	int aresid;
#endif
#endif
	loff_t ppos;
	char *buf;
	int i, err = 0;
	u32 count, size, ret;

	assert(p);
#ifdef LINUX
	filp = p->filp;
#else
	vp = p->filevp;
#if defined(NDHASGIANT)
	vfslocked = VFS_LOCK_GIANT(vp->v_mount);
#endif
#endif
	size = tio->size;
	ppos = tio->offset;

	for (i = 0; i < tio->pg_cnt && size; i++) {
		page = tio->pvec[i];
		assert(page);
		buf = page_address(page);
		count = min_t(u32, PAGE_CACHE_SIZE, size);

#ifdef LINUX
		oldfs = get_fs();
		set_fs(get_ds());

		if (rw == READ)
			ret = vfs_read(filp, buf, count, &ppos);
		else
			ret = vfs_write(filp, buf, count, &ppos);

		set_fs(oldfs);
#else
		error = vn_rdwr(rw, vp, buf, count, ppos, UIO_SYSSPACE, 0, curthread->td_ucred, NOCRED, &aresid, curthread);
		ppos += count;
		if (error == 0)
			ret = count;
#endif

		if (ret != count) {
			eprintk("I/O error %u, %ld\n", count, (long) ret);
			err = -EIO;
			break;
		}

		size -= count;
	}

	if (!err) {
		assert(!size);
	}

#ifdef FREEBSD
#if defined(NDHASGIANT)
	VFS_UNLOCK_GIANT(vfslocked);
#endif
#endif
	return err;
}

#ifdef LINUX
static int fileio_sync(struct iet_volume *lu, struct tio *tio)
{
	struct fileio_data *p = lu->private;
	struct inode *inode = p->filp->f_dentry->d_inode;
	struct address_space *mapping = inode->i_mapping;
	loff_t ppos, count;
	int res;

	if (tio) {
		ppos = tio->offset;
		count = tio->size;
	} else {
		ppos = 0;
		count = lu->blk_cnt << lu->blk_shift;
	}

	res = filemap_write_and_wait_range(mapping, ppos, ppos + count - 1);
	if (res) {
		eprintk("I/O error: syncing pages failed: %d\n", res);
		return -EIO;
	} else
		return 0;
}

static int open_path(struct iet_volume *volume, const char *path)
{
	int err = 0;
	struct fileio_data *info = volume->private;
	struct file *filp;
	mm_segment_t oldfs;
	int flags;

	info->path = kstrdup(path, GFP_KERNEL);
	if (!info->path)
		return -ENOMEM;

	oldfs = get_fs();
	set_fs(get_ds());
	flags = (LUReadonly(volume) ? O_RDONLY : O_RDWR) | O_LARGEFILE;
	filp = filp_open(path, flags, 0);
	set_fs(oldfs);

	if (IS_ERR(filp)) {
		err = PTR_ERR(filp);
		eprintk("Can't open %s %d\n", path, err);
		info->filp = NULL;
	} else
		info->filp = filp;

	return err;
}
#else
static int fileio_sync(struct iet_volume *lu, struct tio *tio)
{
	struct fileio_data *p = lu->private;
#if defined(NDHASGIANT)
	int vfslocked;
#endif
	int error;
	struct vnode *vp;
	struct mount *mp;

	vp = p->filevp;
#if defined(NDHASGIANT)
	vfslocked = VFS_LOCK_GIANT(vp->v_mount);
#endif
	if ((error = vn_start_write(vp, &mp, V_WAIT | PCATCH)) != 0)
		goto drop;

	vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	error = VOP_FSYNC(vp, MNT_WAIT, curthread);
	VOP_UNLOCK(vp, 0);
	vn_finished_write(mp);
drop:
#if defined(NDHASGIANT)
	VFS_UNLOCK_GIANT(vfslocked);
#endif
	return error;
}

static int open_path(struct iet_volume *volume, const char *path)
{
	int error;
	struct fileio_data *info = volume->private;
	struct nameidata nd;
	struct vnode *filevp;
	struct vattr vattr;
#if defined(NDHASGIANT)
	int vfslocked;
#endif
	int flags = FMODE_READ | (LUReadonly(volume) ? 0 : FMODE_WRITE);

	info->path = kstrdup(path, GFP_KERNEL);
	if (!info->path)
		return -ENOMEM;

#if defined(NDHASGIANT)
	NDINIT(&nd, LOOKUP, NOFOLLOW | MPSAFE, UIO_SYSSPACE, path, curthread);
#else
	NDINIT(&nd, LOOKUP, NOFOLLOW, UIO_SYSSPACE, path, curthread);
#endif
	error = namei(&nd);
#if defined(NDHASGIANT)
	vfslocked = NDHASGIANT(&nd);
#else
#endif
	if (error) {
		eprintk("lookup failed for %s err %d\n", path, error);
		return -(error);
	}

	filevp = nd.ni_vp;
	if (filevp->v_type != VREG) {
		eprintk("path %s not a regular file\n", path);
		NDFREE(&nd, 0);
#if defined(NDHASGIANT)
		VFS_UNLOCK_GIANT(vfslocked);
#endif
		return -(EINVAL);
	}

	error = vn_open_cred(&nd, &flags, 0, 0, curthread->td_ucred, NULL);
	if (error != 0) {
		eprintk("failed to open path %s err %d\n", path, error);
		NDFREE(&nd, 0);
#if defined(NDHASGIANT)
		VFS_UNLOCK_GIANT(vfslocked);
#endif
		return -(error);
	}
	NDFREE(&nd, NDF_ONLY_PNBUF);

	error = VOP_GETATTR(filevp, &vattr, curthread->td_ucred);
	if (error != 0) {
		eprintk("failed to get vattr for path %s error %d\n", path, error);
		VOP_UNLOCK(filevp, 0);
		(void)vn_close(filevp, flags, curthread->td_ucred, curthread);
		vrele(filevp);
#if defined(NDHASGIANT)
		VFS_UNLOCK_GIANT(vfslocked);
#endif
		return -(error);
	}

	if (!volume->blk_shift)
		volume->blk_shift = blksize_bits(IET_DEF_BLOCK_SIZE);
	volume->blk_cnt = vattr.va_size >> volume->blk_shift;

	info->filevp = filevp;
	VOP_UNLOCK(filevp, 0);
	return 0;
}
#endif

enum {
	opt_path, opt_ignore, opt_err,
};

static match_table_t tokens = {
	{opt_path, "path=%s"},
	{opt_ignore, "scsiid=%s"},
	{opt_ignore, "scsisn=%s"},
	{opt_ignore, "type=%s"},
	{opt_ignore, "iomode=%s"},
	{opt_ignore, "blocksize=%s"},
	{opt_err, NULL},
};

static int parse_fileio_params(struct iet_volume *volume, char *params)
{
	struct fileio_data *info = volume->private;
	int err = 0;
	char *p, *q;

	while ((p = strsep(&params, ",")) != NULL) {
		substring_t args[MAX_OPT_ARGS];
		int token;
		if (!*p)
			continue;
		iet_strtolower(p);
		token = match_token(p, tokens, args);
		switch (token) {
		case opt_path:
			if (info->path) {
				iprintk("Target %s, LUN %u: "
					"duplicate \"Path\" param\n",
					volume->target->name, volume->lun);
				err = -EINVAL;
				goto out;
			}
			if (!(q = match_strdup(&args[0]))) {
				err = -ENOMEM;
				goto out;
			}
			err = open_path(volume, q);
			kfree(q);
			if (err < 0)
				goto out;
			break;
		case opt_ignore:
			break;
		default:
			iprintk("Target %s, LUN %u: unknown param %s\n",
				volume->target->name, volume->lun, p);
			return -EINVAL;
		}
	}

	if (!info->path) {
		iprintk("Target %s, LUN %u: missing \"Path\" param\n",
			volume->target->name, volume->lun);
		err = -EINVAL;
	}
out:
	return err;
}

static void fileio_detach(struct iet_volume *lu)
{
	struct fileio_data *p = lu->private;

	kfree(p->path);
#ifdef LINUX
	if (p->filp)
		filp_close(p->filp, NULL);
#else
	if (p->filevp) {
		int flags = FMODE_READ | (LUReadonly(lu) ? 0 : FMODE_WRITE);
#if defined(NDHASGIANT)
		int vfslocked;

		vfslocked = VFS_LOCK_GIANT(p->filevp->v_mount);
#endif
		vn_close(p->filevp, flags, curthread->td_ucred, curthread);
		vrele(p->filevp);
#if defined(NDHASGIANT)
		VFS_UNLOCK_GIANT(vfslocked);
#endif
	}
#endif
	kfree(p);
	lu->private = NULL;
}

static int fileio_attach(struct iet_volume *lu, char *args)
{
	int err = 0;
	struct fileio_data *p;
#ifdef LINUX
	struct inode *inode;
#endif

	if (lu->private) {
		printk("already attached ? %d\n", lu->lun);
		return -EBUSY;
	}

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	lu->private = p;

	if ((err = parse_fileio_params(lu, args)) < 0) {
		eprintk("%d\n", err);
		goto out;
	}

#ifdef LINUX
	inode = p->filp->f_dentry->d_inode;

	if (S_ISREG(inode->i_mode))
		;
	else if (S_ISBLK(inode->i_mode))
		inode = inode->i_bdev->bd_inode;
	else {
		err = -EINVAL;
		goto out;
	}

	if (!lu->blk_shift)
		lu->blk_shift = blksize_bits(IET_DEF_BLOCK_SIZE);

	lu->blk_cnt = inode->i_size >> lu->blk_shift;
#endif

	/* we're using the page cache */
	SetLURCache(lu);
out:
	if (err < 0)
		fileio_detach(lu);
	return err;
}

#ifdef LINUX
static void fileio_show(struct iet_volume *lu, struct seq_file *seq)
{
	struct fileio_data *p = lu->private;
	seq_printf(seq, " path:%s\n", p->path);
}
#endif

struct iotype fileio =
{
	.name = "fileio",
	.attach = fileio_attach,
	.make_request = fileio_make_request,
	.sync = fileio_sync,
#ifdef LINUX
	.show = fileio_show,
#endif
	.detach = fileio_detach,
};
