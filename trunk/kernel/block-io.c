/*
 * Target device block I/O.
 *
 * Based on file I/O driver from FUJITA Tomonori
 * (C) 2004 - 2005 FUJITA Tomonori <tomof@acm.org>
 * (C) 2006 Andre Brinkmann <brinkman at hni dot upb dot de>
 * (C) 2007 Ross Walker <rswwalker at hotmail dot com>
 * (C) 2007 Ming Zhang <blackmagic02881 at gmail dot com>
 * This code is licenced under the GPL.
 */

#include "iscsi.h"
#include "iscsi_dbg.h"
#include "iotype.h"

#ifdef FREEBSD
struct g_class iet_vdev_class = {
        .name = "IET::VDEV",
        .version = G_VERSION,
};
#endif

struct blockio_data {
	char *path;
	iodev_t *bdev;
#ifdef FREEBSD
	struct g_geom *gp;
	struct g_consumer *cp;
#endif
};

struct tio_work {
	atomic_t error;
	atomic_t bios_remaining;
	completion_t tio_complete;
};

#ifdef LINUX
static void blockio_bio_endio(struct bio *bio, int error)
#else
static void blockio_bio_endio(struct bio *bio)
#endif
{
	struct tio_work *tio_work = bio_get_private(bio);

#ifdef FREEBSD
	int error = bio->bio_error;
#else
	error = test_bit(BIO_UPTODATE, &bio->bi_flags) ? error : -EIO;
#endif

	if (error)
		atomic_set(&tio_work->error, error);

	/* If last bio signal completion */
	if (atomic_dec_and_test(&tio_work->bios_remaining))
		complete(&tio_work->tio_complete);

	bio_put(bio);
}

#ifdef FREEBSD
static struct bio *
bio_get_new(int max_pages, iodev_t *bdev, void *end_bio_func, void *private, loff_t ppos)
{
	struct bio *bio;

	bio = g_new_bio();
	if (unlikely(!bio))
	{
		return NULL;
	}

	bio->bio_offset = ppos;
	bio->bio_done = end_bio_func;
	bio->bio_caller2 = private;
	return bio;
}
#else
static struct bio *
bio_get_new(int max_pages, iodev_t *bdev, void *end_bio_func, void *private, loff_t ppos)
{
	struct bio *bio;

	bio = bio_alloc(GFP_KERNEL, max_pages);
	if (!bio)
	{
		return NULL;
	}

	/* bi_sector is ALWAYS in units of 512 bytes */
	bio->bi_sector = ppos >> 9;
	bio->bi_bdev = bdev;
	bio->bi_end_io = blockio_bio_endio;
	bio->bi_private = private;
	return bio;
}
#endif

/*
 * Blockio_make_request(): The function translates an iscsi-request into
 * a number of requests to the corresponding block device.
 */
static int
blockio_make_request(struct iet_volume *volume, struct tio *tio, int rw)
{
	struct blockio_data *bio_data = volume->private;
#ifdef LINUX
	struct request_queue *bdev_q = bdev_get_queue(bio_data->bdev);
	struct bio *tio_bio = NULL, *biotail = NULL;
	struct blk_plug plug;
#else
	struct bio_queue_head bioq;
#endif
	struct tio_work *tio_work;
	struct bio *bio = NULL;

	u32 size = tio->size;
	u32 tio_index = 0;

	int max_pages = 1;
	int err = 0;

	loff_t ppos = tio->offset;

#ifdef LINUX
	/* Calculate max_pages for bio_alloc (memory saver) */
	if (bdev_q)
		max_pages = bio_get_nr_vecs(bio_data->bdev);
#else
	rw = (rw == UIO_READ) ? BIO_READ : BIO_WRITE;
	bioq_init(&bioq);
#endif

	tio_work = kzalloc(sizeof (*tio_work), GFP_KERNEL);
	if (!tio_work)
		return -ENOMEM;

	atomic_set(&tio_work->error, 0);
	atomic_set(&tio_work->bios_remaining, 0);
	init_completion(&tio_work->tio_complete);

	/* Main processing loop, allocate and fill all bios */
	while (tio_index < tio->pg_cnt) {
		bio = bio_get_new(min(max_pages, BIO_MAX_PAGES), bio_data->bdev, blockio_bio_endio, tio_work, ppos);
		if (!bio) {
			err = -ENOMEM;
			goto out;
		}

#ifdef LINUX
		if (tio_bio)
			biotail = biotail->bi_next = bio;
		else
			tio_bio = biotail = bio;
#else
		bioq_insert_tail(&bioq, bio);
#endif

		atomic_inc(&tio_work->bios_remaining);

		/* Loop for filling bio */
		while (tio_index < tio->pg_cnt) {
			unsigned int bytes = IET_PAGE_SIZE;

			if (bytes > size)
				bytes = size;

			if (!bio_add_page(bio, tio->pvec[tio_index], bytes, 0))
				break;

			size -= bytes;
			ppos += bytes;

			tio_index++;
#ifdef FREEBSD
			break; /* one bio per page */
#endif
		}
	}

#ifdef LINUX
	blk_start_plug(&plug);

	/* Walk the list, submitting bios 1 by 1 */
	while (tio_bio) {
		bio = tio_bio;
		tio_bio = tio_bio->bi_next;
		bio->bi_next = NULL;

		submit_bio(rw, bio);
	}

	blk_finish_plug(&plug);
#else
	while((bio = bioq_takefirst(&bioq)) != NULL) {
		bio->bio_cmd = rw;
		g_io_request(bio, bio_data->cp);
	}
#endif

	wait_for_completion(&tio_work->tio_complete);

	err = atomic_read(&tio_work->error);

	kfree(tio_work);

	return err;
out:
#ifdef LINUX
	while (tio_bio) {
		bio = tio_bio;
		tio_bio = tio_bio->bi_next;

		bio_put(bio);
	}
#else
	while((bio = bioq_takefirst(&bioq)) != NULL) {
		bio_put(bio);
	}
#endif

	kfree(tio_work);

	return err;
}

#ifdef LINUX
static int
blockio_open_path(struct iet_volume *volume, const char *path)
{
	struct blockio_data *bio_data = volume->private;
	struct block_device *bdev;
	int flags = FMODE_EXCL | FMODE_READ | (LUReadonly(volume) ? 0 : FMODE_WRITE);
	int err = 0;

	bio_data->path = kstrdup(path, GFP_KERNEL);
	if (!bio_data->path)
		return -ENOMEM;

	bdev = blkdev_get_by_path(path, flags, THIS_MODULE);
	if (IS_ERR(bdev)) {
		err = PTR_ERR(bdev);
		eprintk("Can't open device %s, error %d\n", path, err);
		bio_data->bdev = NULL;
	} else {
		bio_data->bdev = bdev;
		fsync_bdev(bio_data->bdev);
	}

	return err;
}
#else
static int
blockio_open_path(struct iet_volume *volume, const char *path)
{
	struct blockio_data *bio_data = volume->private;
	struct nameidata nd;
	int flags = FMODE_READ | (LUReadonly(volume) ? 0 : FMODE_WRITE);
	int vaccess;
	int error;
#if defined(NDHASGIANT)
	int vfslocked;
#endif
	struct vnode *devvp = NULL;
	struct g_provider *pp;
	struct g_geom *gp;
	struct g_consumer *cp;

	bio_data->path = kstrdup(path, GFP_KERNEL);
	if (!bio_data->path)
		return -(ENOMEM);

#if defined(MPSAFE)
	NDINIT(&nd, LOOKUP, NOFOLLOW | MPSAFE, UIO_SYSSPACE, path, curthread);
#else
	NDINIT(&nd, LOOKUP, NOFOLLOW, UIO_SYSSPACE, path, curthread);
#endif
	error = vn_open(&nd, &flags, 0, NULL);
	if (error) {
		eprintk("failed to open disk %s error %d\n", path, error);
		return -(error);
	}
#if defined(NDHASGIANT)
	vfslocked = NDHASGIANT(&nd);
#endif
	NDFREE(&nd, NDF_ONLY_PNBUF);

	devvp = nd.ni_vp; 
	if (!vn_isdisk(devvp, &error)) {
		eprintk("path %s doesnt correspond to a disk error %d\n", path, error);
		goto failed;
	}

	vaccess = VREAD | (LUReadonly(volume) ? 0 : VWRITE);
	error = VOP_ACCESS(devvp, vaccess, curthread->td_ucred, curthread);
	if (error != 0) {
		eprintk("Access %d failed for path %s error %d\n", vaccess, path, error);
		goto failed;
	}

	g_topology_lock();

	pp = g_dev_getprovider(devvp->v_rdev);
	gp = g_new_geomf(&iet_vdev_class, "iet::vdev");
	cp = g_new_consumer(gp);

	error = g_attach(cp, pp);
	if (error != 0) {
		eprintk("Failed to attached GEOM consumer error %d\n", error);
		goto gcleanup;
	}

	vaccess = (LUReadonly(volume) ? 0 : 1);
	error = g_access(cp, 1, vaccess, 0);
	if (error != 0) {
		eprintk("Failed to set access for GEOM consumer error %d\n", error);
		g_detach(cp);
		goto gcleanup;
	}

	if (!volume->blk_shift)
		volume->blk_shift = blksize_bits(pp->sectorsize);

	volume->blk_cnt = pp->mediasize >> volume->blk_shift;
	bio_data->gp = gp;
	bio_data->cp = cp;
	g_topology_unlock();
	bio_data->bdev = devvp;
	VOP_UNLOCK(devvp, 0);
#if defined(NDHASGIANT)
	VFS_UNLOCK_GIANT(vfslocked);
#endif
	return 0;

gcleanup: /* On geom errors */
	g_destroy_consumer(cp);
	g_destroy_geom(gp);
	g_topology_unlock();
failed:
	VOP_UNLOCK(devvp, 0);
	(void)vn_close(devvp, flags, curthread->td_ucred, curthread);
#if defined(NDHASGIANT)
	VFS_UNLOCK_GIANT(vfslocked);
#endif
	return -(error);
}
#endif

/* Create an enumeration of our accepted actions */
enum
{
	opt_path, opt_ignore, opt_err,
};

/* Create a match table using our action enums and their matching options */
static match_table_t tokens = {
	{opt_path, "path=%s"},
	{opt_ignore, "scsiid=%s"},
	{opt_ignore, "scsisn=%s"},
	{opt_ignore, "type=%s"},
	{opt_ignore, "iomode=%s"},
	{opt_ignore, "blocksize=%s"},
	{opt_err, NULL},
};

static int
parse_blockio_params(struct iet_volume *volume, char *params)
{
	struct blockio_data *info = volume->private;
	int err = 0;
	char *p, *q;

	/* Loop through parameters separated by commas, look up our
	 * parameter in match table, return enumeration and arguments
	 * select case based on the returned enum and run the action */
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
			err = blockio_open_path(volume, q);
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

#ifdef LINUX
static void
blockio_detach(struct iet_volume *volume)
{
	struct blockio_data *bio_data = volume->private;
	int flags = FMODE_EXCL | FMODE_READ | (LUReadonly(volume) ? 0 : FMODE_WRITE);

	if (bio_data->bdev)
		blkdev_put(bio_data->bdev, flags);
	kfree(bio_data->path);

	kfree(volume->private);
}
#else
static void
blockio_detach(struct iet_volume *volume)
{
	int flags = FREAD | (LUReadonly(volume) ? 0 : FWRITE);
	struct blockio_data *bio_data = volume->private;

	if (bio_data->cp) {
		int vaccess = (LUReadonly(volume) ? 0 : -1);

		g_topology_lock();
		g_access(bio_data->cp, -1, vaccess, 0);
		g_detach(bio_data->cp);
		g_destroy_consumer(bio_data->cp);
		g_destroy_geom(bio_data->gp);
		g_topology_unlock();
	}

	if (bio_data->bdev) {
#if defined(NDHASGIANT)
		int vfslocked;

		vfslocked = VFS_LOCK_GIANT(bio_data->bdev->v_mount);
#endif
		(void)vn_close(bio_data->bdev, flags, curthread->td_ucred, curthread);
#if defined(NDHASGIANT)
		VFS_UNLOCK_GIANT(vfslocked);
#endif
	}

	if (bio_data->path)
		kfree(bio_data->path);

	kfree(volume->private);
}
#endif

#ifdef LINUX
static int
blockio_attach(struct iet_volume *volume, char *args)
{
	struct blockio_data *bio_data;
	int err = 0;

	if (volume->private) {
		eprintk("Lun %u already attached on Target %s \n",
			volume->lun, volume->target->name);
		return -EBUSY;
	}

	bio_data = kzalloc(sizeof (*bio_data), GFP_KERNEL);
	if (!bio_data)
		return -ENOMEM;

	volume->private = bio_data;

	err = parse_blockio_params(volume, args);
	if (!err) {
		/* see Documentation/ABI/testing/sysfs-block */
		unsigned bsz = bdev_logical_block_size(bio_data->bdev);
		if (!volume->blk_shift)
			volume->blk_shift = blksize_bits(bsz);
		else if (volume->blk_shift < blksize_bits(bsz)) {
			eprintk("Specified block size (%u) smaller than "
				"device %s logical block size (%u)\n",
				(1 << volume->blk_shift), bio_data->path, bsz);
			err = -EINVAL;
		}
	}
	if (err < 0) {
		eprintk("Error attaching Lun %u to Target %s \n",
			volume->lun, volume->target->name);
		goto out;
	}

	volume->blk_cnt = bio_data->bdev->bd_inode->i_size >> volume->blk_shift;

	/* Offer neither write nor read caching */
	ClearLURCache(volume);
	ClearLUWCache(volume);

  out:
	if (err < 0)
		blockio_detach(volume);

	return err;
}
#else
static int
blockio_attach(struct iet_volume *volume, char *args)
{
	struct blockio_data *bio_data;
	int err = 0;

	if (volume->private) {
		eprintk("Lun %u already attached on Target %s \n",
			volume->lun, volume->target->name);
		return -EBUSY;
	}

	bio_data = kzalloc(sizeof (*bio_data), GFP_KERNEL);
	if (!bio_data)
		return -ENOMEM;

	volume->private = bio_data;

	err = parse_blockio_params(volume, args);
	if (err < 0) {
		eprintk("Error attaching Lun %u to Target %s \n",
			volume->lun, volume->target->name);
		goto out;
	}

	/* Offer neither write nor read caching */
	ClearLURCache(volume);
	ClearLUWCache(volume);

  out:
	if (err != 0)
		blockio_detach(volume);

	return err;
}
#endif

#ifdef LINUX
static void
blockio_show(struct iet_volume *volume, struct seq_file *seq)
{
	struct blockio_data *bio_data = volume->private;

	/* Used to display blockio volume info in /proc/net/iet/volumes */
	seq_printf(seq, " path:%s\n", bio_data->path);
}
#endif

struct iotype blockio = {
	.name = "blockio",
	.attach = blockio_attach,
	.make_request = blockio_make_request,
	.detach = blockio_detach,
#ifdef LINUX
	.show = blockio_show,
#endif
};
