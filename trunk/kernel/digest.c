/*
 * iSCSI digest handling.
 * (C) 2004 - 2006 Xiranet Communications GmbH <arne.redlich@xiranet.com>
 * This code is licensed under the GPL.
 */

#include "iscsi.h"
#include "digest.h"
#include "iscsi_dbg.h"

#ifdef FREEBSD /* CRC32 routines */
static void crc32c_update(struct crc32c_ctx *mctx, const u8 *data,
		   unsigned int length)
{
	u32 mcrc;

	mcrc = calculate_crc32c(mctx->crc, data, (size_t)length);

	mctx->crc = mcrc;
}

static void
crc32c_init(struct crc32c_ctx *mctx)
{
	mctx->crc = ~(u32)0;
}

static void
crc32c_final(struct crc32c_ctx *mctx, uint8_t *out)
{
	u32 mcrc = (mctx->crc ^ ~(u32)0);

	*(u32 *)out = __le32_to_cpu(mcrc);
}
#endif

void digest_alg_available(unsigned int *val)
{
#ifdef LINUX
	if (*val & DIGEST_CRC32C &&
	    !crypto_has_alg("crc32c", 0, CRYPTO_ALG_ASYNC)) {
		printk("CRC32C digest algorithm not available in kernel\n");
		*val |= ~DIGEST_CRC32C;
	}
#endif
}

/**
 * initialize support for digest calculation.
 *
 * digest_init -
 * @conn: ptr to connection to make use of digests
 *
 * @return: 0 on success, < 0 on error
 */
#ifdef LINUX
int digest_init(struct iscsi_conn *conn)
{
	int err = 0;

	if (!(conn->hdigest_type & DIGEST_ALL))
		conn->hdigest_type = DIGEST_NONE;

	if (!(conn->ddigest_type & DIGEST_ALL))
		conn->ddigest_type = DIGEST_NONE;

	if (conn->hdigest_type & DIGEST_CRC32C ||
	    conn->ddigest_type & DIGEST_CRC32C) {
		conn->rx_hash.tfm = crypto_alloc_hash("crc32c", 0,
						      CRYPTO_ALG_ASYNC);
		conn->rx_hash.flags = 0;
		if (IS_ERR(conn->rx_hash.tfm)) {
			conn->rx_hash.tfm = NULL;
			err = -ENOMEM;
			goto out;
		}

		conn->tx_hash.tfm = crypto_alloc_hash("crc32c", 0,
						      CRYPTO_ALG_ASYNC);
		conn->tx_hash.flags = 0;
		if (IS_ERR(conn->tx_hash.tfm)) {
			conn->tx_hash.tfm = NULL;
			err = -ENOMEM;
			goto out;
		}
	}

out:
	if (err)
		digest_cleanup(conn);

	return err;
}
#else
int digest_init(struct iscsi_conn *conn)
{
	if (!(conn->hdigest_type & DIGEST_ALL))
		conn->hdigest_type = DIGEST_NONE;

	if (!(conn->ddigest_type & DIGEST_ALL))
		conn->ddigest_type = DIGEST_NONE;

	return 0;
}
#endif

/**
 * free resources used for digest calculation.
 *
 * digest_cleanup -
 * @conn: ptr to connection that made use of digests
 */
void digest_cleanup(struct iscsi_conn *conn)
{
#ifdef LINUX
	if (conn->tx_hash.tfm)
		crypto_free_hash(conn->tx_hash.tfm);
	if (conn->rx_hash.tfm)
		crypto_free_hash(conn->rx_hash.tfm);
#endif
}

/**
 * debug handling of header digest errors:
 * simulates a digest error after n PDUs / every n-th PDU of type
 * HDIGEST_ERR_CORRUPT_PDU_TYPE.
 */
static inline void __dbg_simulate_header_digest_error(struct iscsi_cmnd *cmnd)
{
#define HDIGEST_ERR_AFTER_N_CMNDS 1000
#define HDIGEST_ERR_ONLY_ONCE     1
#define HDIGEST_ERR_CORRUPT_PDU_TYPE ISCSI_OP_SCSI_CMD
#define HDIGEST_ERR_CORRUPT_PDU_WITH_DATA_ONLY 0

	static int num_cmnds = 0;
	static int num_errs = 0;

	if (cmnd_opcode(cmnd) == HDIGEST_ERR_CORRUPT_PDU_TYPE) {
		if (HDIGEST_ERR_CORRUPT_PDU_WITH_DATA_ONLY) {
			if (cmnd->pdu.datasize)
				num_cmnds++;
		} else
			num_cmnds++;
	}

	if ((num_cmnds == HDIGEST_ERR_AFTER_N_CMNDS)
	    && (!(HDIGEST_ERR_ONLY_ONCE && num_errs))) {
		printk("*** Faking header digest error ***\n");
		printk("\tcmnd: 0x%x, itt 0x%x, sn 0x%x\n",
		       cmnd_opcode(cmnd),
		       be32_to_cpu(cmnd->pdu.bhs.itt),
		       be32_to_cpu(cmnd->pdu.bhs.sn));
		cmnd->hdigest = ~cmnd->hdigest;
		/* make things even worse by manipulating header fields */
		cmnd->pdu.datasize += 8;
		num_errs++;
		num_cmnds = 0;
	}
	return;
}

/**
 * debug handling of data digest errors:
 * simulates a digest error after n PDUs / every n-th PDU of type
 * DDIGEST_ERR_CORRUPT_PDU_TYPE.
 */
static inline void __dbg_simulate_data_digest_error(struct iscsi_cmnd *cmnd)
{
#define DDIGEST_ERR_AFTER_N_CMNDS 50
#define DDIGEST_ERR_ONLY_ONCE     1
#define DDIGEST_ERR_CORRUPT_PDU_TYPE   ISCSI_OP_SCSI_DATA_OUT
#define DDIGEST_ERR_CORRUPT_UNSOL_DATA_ONLY 0

	static int num_cmnds = 0;
	static int num_errs = 0;

	if ((cmnd->pdu.datasize)
	    && (cmnd_opcode(cmnd) == DDIGEST_ERR_CORRUPT_PDU_TYPE)) {
		switch (cmnd_opcode(cmnd)) {
		case ISCSI_OP_SCSI_DATA_OUT:
			if ((DDIGEST_ERR_CORRUPT_UNSOL_DATA_ONLY)
			    && (cmnd->pdu.bhs.ttt != ISCSI_RESERVED_TAG))
				break;
		default:
			num_cmnds++;
		}
	}

	if ((num_cmnds == DDIGEST_ERR_AFTER_N_CMNDS)
	    && (!(DDIGEST_ERR_ONLY_ONCE && num_errs))
	    && (cmnd->pdu.datasize)
	    && (!cmnd->conn->read_overflow)) {
		printk("*** Faking data digest error: ***");
		printk("\tcmnd 0x%x, itt 0x%x, sn 0x%x\n",
		       cmnd_opcode(cmnd),
		       be32_to_cpu(cmnd->pdu.bhs.itt),
		       be32_to_cpu(cmnd->pdu.bhs.sn));
		cmnd->ddigest = ~cmnd->ddigest;
		num_errs++;
		num_cmnds = 0;
	}
}

#ifdef LINUX
static void digest_header(struct hash_desc *hash, struct iscsi_pdu *pdu,
			  u8 *crc)
{
	struct scatterlist sg[2];
	unsigned int nbytes = sizeof(struct iscsi_hdr);

	sg_init_table(sg, pdu->ahssize ? 2 : 1);

	sg_set_buf(&sg[0], &pdu->bhs, nbytes);
	if (pdu->ahssize) {
		sg_set_buf(&sg[1], pdu->ahs, pdu->ahssize);
		nbytes += pdu->ahssize;
	}

	crypto_hash_init(hash);
	crypto_hash_update(hash, sg, nbytes);
	crypto_hash_final(hash, crc);
}
#else
static void digest_header(struct crc32c_ctx *mctx, struct iscsi_pdu *pdu, u8 *crc)
{
	crc32c_init(mctx);

	crc32c_update(mctx, (u8 *)(&pdu->bhs), sizeof(struct iscsi_hdr));
	if (pdu->ahssize)
		crc32c_update(mctx, (u8 *)(pdu->ahs), pdu->ahssize);

	crc32c_final(mctx, crc); 
}
#endif


int digest_rx_header(struct iscsi_cmnd *cmnd)
{
	u32 crc;

	digest_header(&cmnd->conn->rx_hash, &cmnd->pdu, (u8 *) &crc);
	if (crc != cmnd->hdigest)
		return -EIO;

	return 0;
}

void digest_tx_header(struct iscsi_cmnd *cmnd)
{
	digest_header(&cmnd->conn->tx_hash, &cmnd->pdu, (u8 *) &cmnd->hdigest);
}

#ifdef LINUX
static void digest_data(struct hash_desc *hash, struct iscsi_cmnd *cmnd,
			struct tio *tio, u32 offset, u8 *crc)
{
	struct scatterlist *sg = cmnd->conn->hash_sg;
	u32 size, length, npages;
	int i, idx;
	unsigned int nbytes;

	size = cmnd->pdu.datasize;
	nbytes = size = (size + 3) & ~3;
	npages = size >> PAGE_CACHE_SHIFT;

	idx = offset >> PAGE_CACHE_SHIFT;
	offset &= ~PAGE_CACHE_MASK;

	BUG_ON(idx + npages > tio->pg_cnt);
	BUG_ON(npages > ISCSI_CONN_IOV_MAX);

	sg_init_table(sg, ARRAY_SIZE(cmnd->conn->hash_sg));
	crypto_hash_init(hash);

	for (i = 0; size > 0; i++) {
		length = min_t(u32, PAGE_CACHE_SIZE - offset, size);
		sg_set_page(&sg[i], tio->pvec[idx + i], length, offset);
		size -= length;
		offset = 0;
	}

	sg_mark_end(&sg[i - 1]);

	crypto_hash_update(hash, sg, nbytes);
	crypto_hash_final(hash, crc);
}
#else
static void digest_data(struct crc32c_ctx *mctx, struct iscsi_cmnd *cmnd,
			struct tio *tio, u32 offset, u8 *crc)
{
	u32 size, length, npages;
	int i, idx;
	unsigned int nbytes;

	size = cmnd->pdu.datasize;
	nbytes = size = (size + 3) & ~3;
	npages = size >> PAGE_CACHE_SHIFT;

	idx = offset >> PAGE_CACHE_SHIFT;
	offset &= ~PAGE_CACHE_MASK;

	BUG_ON(idx + npages > tio->pg_cnt);
	BUG_ON(npages > ISCSI_CONN_IOV_MAX);

	crc32c_init(mctx);

	for (i = 0; size > 0; i++) {
		length = min_t(u32, PAGE_CACHE_SIZE - offset, size);
		crc32c_update(mctx, (u8*)(page_address(tio->pvec[idx + i])) + offset, length);
		size -= length;
		offset = 0;
	}

	crc32c_final(mctx, crc);
}
#endif

int digest_rx_data(struct iscsi_cmnd *cmnd)
{
	struct tio *tio;
	struct iscsi_cmnd *scsi_cmnd;
	struct iscsi_data_out_hdr *req;
	u32 offset, crc;

	switch (cmnd_opcode(cmnd)) {
	case ISCSI_OP_SCSI_REJECT:
	case ISCSI_OP_PDU_REJECT:
	case ISCSI_OP_DATA_REJECT:
		return 0;
	case ISCSI_OP_SCSI_DATA_OUT:
		scsi_cmnd = cmnd->req;
		req = (struct iscsi_data_out_hdr *) &cmnd->pdu.bhs;
		tio = scsi_cmnd->tio;
		offset = be32_to_cpu(req->buffer_offset);
		break;
	default:
		tio = cmnd->tio;
		offset = 0;
	}

	digest_data(&cmnd->conn->rx_hash, cmnd, tio, offset, (u8 *) &crc);

	if (!cmnd->conn->read_overflow &&
	    (cmnd_opcode(cmnd) != ISCSI_OP_PDU_REJECT)) {
		if (crc != cmnd->ddigest)
			return -EIO;
	}

	return 0;
}

void digest_tx_data(struct iscsi_cmnd *cmnd)
{
	struct tio *tio = cmnd->tio;
	struct iscsi_data_out_hdr *req = (struct iscsi_data_out_hdr *)&cmnd->pdu.bhs;

	assert(tio);
	digest_data(&cmnd->conn->tx_hash, cmnd, tio,
		    be32_to_cpu(req->buffer_offset), (u8 *) &cmnd->ddigest);
}
