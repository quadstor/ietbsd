/*
 * Target I/O.
 * (C) 2005 FUJITA Tomonori <tomof@acm.org>
 * This code is licenced under the GPL.
 */

#include "iscsi.h"
#include "iscsi_dbg.h"
#include "iotype.h"

static int tio_add_pages(struct tio *tio, int count)
{
	int i;
	page_t *page;

	dprintk(D_GENERIC, "%p %d (%d)\n", tio, count, tio->pg_cnt);

	tio->pg_cnt = count;

	count *= sizeof(page_t *);

	do {
		tio->pvec = kzalloc(count, GFP_KERNEL);
		if (!tio->pvec)
			yield();
	} while (!tio->pvec);

	for (i = 0; i < tio->pg_cnt; i++) {
		do {
			if (!(page = alloc_page(GFP_KERNEL)))
				yield();
		} while (!page);
		tio->pvec[i] = page;
	}
	return 0;
}

static slab_cache_t *tio_cache;

struct tio *tio_alloc(int count)
{
	struct tio *tio;

	tio = kmem_cache_alloc(tio_cache, GFP_KERNEL | __GFP_NOFAIL);

	tio->pg_cnt = 0;
	tio->offset = 0;
	tio->size = 0;
	tio->pvec = NULL;

	atomic_set(&tio->count, 1);

	if (count)
		tio_add_pages(tio, count);

	return tio;
}

void
tio_init_iterator(struct tio *tio,
		  struct tio_iterator *iter)
{
	iter->tio = tio;
	iter->size = 0;
	iter->pg_idx = 0;
	iter->pg_off = 0;
}

size_t
tio_add_data(struct tio_iterator *iter,
	     const u8 *data,
	     size_t len)
{
	struct tio *tio = iter->tio;
	const size_t to_copy = min(tio->pg_cnt * PAGE_SIZE - iter->size, len);
	size_t residual = to_copy;

	BUG_ON(tio->size < iter->size);

	do {
		u8 *ptr = (u8 *)page_address(iter->tio->pvec[iter->pg_idx]) + iter->pg_off;
		size_t chunk = min(PAGE_SIZE - iter->pg_off, residual);
		memcpy(ptr, data, chunk);
		residual -= chunk;
		if (residual ||
		    iter->pg_off + chunk == PAGE_SIZE) {
			++iter->pg_idx;
			iter->pg_off = 0;
		} else
			iter->pg_off += chunk;
	} while (residual);

	return to_copy;
}

static void tio_free(struct tio *tio)
{
	int i;
	for (i = 0; i < tio->pg_cnt; i++) {
		assert(tio->pvec[i]);
		__free_page(tio->pvec[i]);
	}
	kfree(tio->pvec);
	kmem_cache_free(tio_cache, tio);
}

void tio_put(struct tio *tio)
{
	assert(atomic_read(&tio->count));
	if (atomic_dec_and_test(&tio->count))
		tio_free(tio);
}

void tio_get(struct tio *tio)
{
	atomic_inc(&tio->count);
}

void tio_set(struct tio *tio, u32 size, loff_t offset)
{
	tio->offset = offset;
	tio->size = size;
}

int tio_read(struct iet_volume *lu, struct tio *tio)
{
	struct iotype *iot = lu->iotype;
	assert(iot);
	if (!tio->size)
		return 0;
	return iot->make_request ? iot->make_request(lu, tio, READ) : 0;
}

int tio_write(struct iet_volume *lu, struct tio *tio)
{
	struct iotype *iot = lu->iotype;
	assert(iot);
	if (!tio->size)
		return 0;
	return iot->make_request ? iot->make_request(lu, tio, WRITE) : 0;
}

int tio_sync(struct iet_volume *lu, struct tio *tio)
{
	struct iotype *iot = lu->iotype;
	assert(iot);
	return iot->sync ? iot->sync(lu, tio) : 0;
}

int tio_init(void)
{
#ifdef LINUX
	tio_cache = KMEM_CACHE(tio, 0);
#else
	tio_cache = uma_zcreate("iettiocache", sizeof(struct tio), NULL, NULL, NULL, NULL, 0, 0);
#endif
	return  tio_cache ? 0 : -ENOMEM;
}

void tio_exit(void)
{
	if (tio_cache)
		kmem_cache_destroy(tio_cache);
}
