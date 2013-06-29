/*
 * Copyright (C) 2011 Shivaram U, shivaram.u@quadstor.com
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include "iscsi.h"
#include "iscsi_dbg.h"
#include "persist.h"

static bool_t
pr_is_reserved_by_sid(const struct reservation *res,
		      const u64 sid)
{
	if (!pr_is_reserved(res))
		return false;

	if (pr_type_is_all_registrants(res)) {
		return pr_initiator_has_registered(res, sid);
	} else {
		return res->sid == sid;
	}
}

bool_t
pr_is_reserved_by_session(const struct reservation *res,
			  const struct iscsi_session *sess)
{
	return pr_is_reserved_by_sid(res, sess->sid);
}

bool_t
pr_initiator_has_registered(const struct reservation *res,
			    u64 sid)
{
	struct registration *reg;

	list_for_each_entry(reg, &res->registration_list, r_list) {
		if (reg->sid == sid)
			return true;
	}

	return false;
}

static const struct pr_in_report_capabilities_data pr_capabilities = {
	.length = cpu_to_be16(8),
	.crh_sip_atp_ptpl_c = 0,
	.tmv_ptpl_a = PR_IN_REPORT_CAP_TMV,
	.type_mask = cpu_to_be16(PR_TYPE_WR_EX|
				 PR_TYPE_EX_AC|
				 PR_TYPE_WR_EX_RO|
				 PR_TYPE_EX_AC_RO|
				 PR_TYPE_WR_EX_AR|
				 PR_TYPE_EX_AC_AR),
};

static void
pr_in_report_capabilities(struct iscsi_cmnd *cmnd,
			  u16 allocation_length)
{
	u8 *data = page_address(cmnd->tio->pvec[0]);
	const u32 min_len = min_t(u16, allocation_length, sizeof(pr_capabilities));

	BUG_ON(!data);

	memcpy(data, &pr_capabilities, min_len);
	tio_set(cmnd->tio, min_len, 0);

	dprintk_pr(cmnd, "ret len %u\n", min_len);
}

static void
pr_in_read_reservation(struct iscsi_cmnd *cmnd,
		       u16 allocation_length)
{
	struct iet_volume *volume = cmnd->lun;
	const struct reservation *reservation = &volume->reservation;
	struct pr_in_read_reservation_data *pin_data =
		(struct pr_in_read_reservation_data *)page_address(cmnd->tio->pvec[0]);
	u32 size;

	BUG_ON(!pin_data);
	memset(pin_data, 0x0, sizeof(*pin_data));

	spin_lock(&volume->reserve_lock);
	pin_data->generation = cpu_to_be32(reservation->generation);

	if (pr_is_reserved(reservation)) {
		if (pr_type_is_all_registrants(reservation))
			pin_data->reservation_key = 0;
		else
			pin_data->reservation_key = reservation->reservation_key;
		pin_data->scope_type = PR_SCOPE_LU | reservation->persistent_type;
		/*
		 * SPC-3, 6.11.3.2
		 * "The ADDITIONAL LENGTH field contains a count of the number of
		 * bytes to follow and shall be set to 16"
		 */
		pin_data->additional_length = cpu_to_be32(16);
		size = sizeof(*pin_data);

		dprintk_pr(cmnd, "key %llx, size %u\n",
			   (unsigned long long)pin_data->reservation_key,
			   size);
	} else {
		size = 8; /* generation + additional length */

		dprintk_pr(cmnd,
			   "size %u\n",
			   size);
	}


	spin_unlock(&volume->reserve_lock);


	tio_set(cmnd->tio, min_t(u32, size, allocation_length), 0);
}

static void
pr_in_read_full_status(struct iscsi_cmnd *cmnd,
		       u16 allocation_length)
{
	struct iet_volume *volume = cmnd->lun;
	const struct reservation *reservation = &volume->reservation;
	struct tio_iterator tio_it;
	struct pr_in_read_full_status_data *pfull =
		(struct pr_in_read_full_status_data *)page_address(cmnd->tio->pvec[0]);
	struct registration *reg;
	u16 left = (allocation_length > sizeof(*pfull)) ?
		allocation_length - sizeof(*pfull) :
		0;
	u32 addl_data_len = 0;

	tio_init_iterator(cmnd->tio, &tio_it);
	tio_it.pg_off += sizeof(*pfull);

	spin_lock(&volume->reserve_lock);

	pfull->generation = cpu_to_be32(reservation->generation);

	list_for_each_entry(reg, &reservation->registration_list, r_list) {
		const size_t init_name_len = PAD_TO_4_BYTES(strlen(reg->init_name));
		const struct iscsi_transport_id tid = {
			.fmt_code_proto_id =
			TRANSPORT_ID_FMT_CODE_ISCSI|TRANSPORT_ID_PROTO_ID_ISCSI,
			.additional_length = cpu_to_be16(init_name_len),
		};
		const struct pr_in_full_status_descriptor desc = {
			.reservation_key = reg->reservation_key,
			.all_tg_pt_r_holder =
			    pr_is_reserved_by_sid(reservation, reg->sid),
			.scope_type = PR_SCOPE_LU|reservation->persistent_type,
			/* only rel_tgt_port_id 1 is supported */
			.rel_tgt_port_id = cpu_to_be16(1),
			.additional_desc_length = cpu_to_be32(sizeof(tid) + init_name_len),
		};

		left -= tio_add_data(&tio_it,
				     (const u8 *)&desc,
				     min_t(u16, left, sizeof(desc)));

		left -= tio_add_data(&tio_it,
				     (const u8 *)&tid,
				     min_t(u16, left, sizeof(tid)));

		left -= tio_add_data(&tio_it,
				     (const u8 *)reg->init_name,
				     min_t(u16, left, init_name_len));

		addl_data_len += sizeof(desc) + sizeof(tid) + init_name_len;

		dprintk_pr(cmnd,
			   "init name %s, sess %llx, key %llx, rtype %d, scope_type %x, all_tg_pt_r_holder %x, desc.addlen %u, tid.addlen %u, addlen %u, left %u\n",
			   reg->init_name,
			   (unsigned long long)reg->sid,
			   (unsigned long long)reg->reservation_key,
			   reservation->reservation_type,
			   desc.scope_type,
			   desc.all_tg_pt_r_holder,
			   be32_to_cpu(desc.additional_desc_length),
			   be16_to_cpu(tid.additional_length),
			   addl_data_len,
			   left);
	}

	spin_unlock(&volume->reserve_lock);

	dprintk_pr(cmnd,
		   "dlen %u, tlen %u\n",
		   addl_data_len,
		   allocation_length - left);

	pfull->additional_length = cpu_to_be32(addl_data_len);
	tio_set(cmnd->tio, allocation_length - left, 0);
}

static void
pr_in_read_keys(struct iscsi_cmnd *cmnd,
		u16 allocation_length)
{
	struct iet_volume *volume = cmnd->lun;
	const struct reservation *reservation = &volume->reservation;
	struct tio_iterator tio_it;
	struct pr_in_read_keys_data *kdata =
		(struct pr_in_read_keys_data *)page_address(cmnd->tio->pvec[0]);
	struct registration *reg;
	u16 left = (allocation_length >= sizeof(*kdata)) ?
		allocation_length - sizeof(*kdata) :
		0;
	u32 addl_data_len = 0;

	tio_init_iterator(cmnd->tio, &tio_it);
	tio_it.pg_off += sizeof(*kdata);

	spin_lock(&volume->reserve_lock);

	kdata->generation = cpu_to_be32(reservation->generation);

	list_for_each_entry(reg, &reservation->registration_list, r_list) {

		left -= tio_add_data(&tio_it,
				     (const u8 *)&reg->reservation_key,
				     min_t(u16,
					   left,
					   sizeof(reg->reservation_key)));

		addl_data_len += sizeof(reg->reservation_key);

		dprintk_pr(cmnd,
			   "found reg, init name %s, sess %llx, key %llx, kdata len %u, left %u\n",
			   reg->init_name,
			   (unsigned long long)reg->sid,
			   (unsigned long long)reg->reservation_key,
			   addl_data_len,
			   left);
	}

	spin_unlock(&volume->reserve_lock);

	dprintk_pr(cmnd,
		   "dlen %u, tlen %u\n",
		   addl_data_len,
		   allocation_length - left);

	kdata->additional_length = cpu_to_be32(addl_data_len);
	tio_set(cmnd->tio, allocation_length - left, 0);

	dprintk_pr(cmnd,
		   "keys[0]: %llx\n", (unsigned long long)kdata->keys[0]);
}

void
build_persistent_reserve_in_response(struct iscsi_cmnd *cmnd)
{
	const struct persistent_reserve_in *pr_in =
		(const struct persistent_reserve_in *)(cmnd_hdr(cmnd)->scb);
	const u16 allocation_length = be16_to_cpu(pr_in->allocation_length);
	const enum pr_in_service_actions action =
		pr_in->service_action & PR_SERVICE_ACTION_MASK;

	dprintk_pr(cmnd,
		   "svc action %x, alloc len %u\n",
		   action,
		   allocation_length);

	switch (action) {
	case SERVICE_ACTION_READ_KEYS:
	case SERVICE_ACTION_READ_RESERVATION:
	case SERVICE_ACTION_REPORT_CAPABILITIES:
	case SERVICE_ACTION_READ_FULL_STATUS:
		if (allocation_length == 0)
			return;
		cmnd->tio = tio_alloc(get_pgcnt(allocation_length));
		break;
	default:
		eprintk("%llx:%hu: invalid PR In Service Action %x\n",
			(unsigned long long)cmnd->conn->session->sid,
			cmnd->conn->cid,
			action);
		iscsi_cmnd_set_sense(cmnd,
				     ILLEGAL_REQUEST,
				     INVALID_FIELD_IN_CDB_ASC,
				     INVALID_FIELD_IN_CDB_ASCQ);
		return;
	}

	switch (action) {
	case SERVICE_ACTION_READ_KEYS:
		pr_in_read_keys(cmnd, allocation_length);
		break;
	case SERVICE_ACTION_READ_RESERVATION:
		pr_in_read_reservation(cmnd, allocation_length);
		break;
	case SERVICE_ACTION_REPORT_CAPABILITIES:
		pr_in_report_capabilities(cmnd, allocation_length);
		break;
	case SERVICE_ACTION_READ_FULL_STATUS:
		pr_in_read_full_status(cmnd, allocation_length);
		break;
	}
}

static void
pr_out_register(struct iscsi_cmnd *cmnd, bool_t ignore)
{
	const struct pr_out_param_list *param =
		(const struct pr_out_param_list *)page_address(cmnd->tio->pvec[0]);
	struct iscsi_session *session = cmnd->conn->session;
	struct iet_volume *volume = cmnd->lun;
	struct reservation *reservation = &volume->reservation;
	struct registration *reg;
	struct registration *new_reg = kzalloc(sizeof(*new_reg), GFP_KERNEL);

	dprintk_pr(cmnd, "rkey %llx, skey %llx, spec_i_pt_all_tg_pt_aptl %x ignore %d\n",
		   (unsigned long long)param->reservation_key,
		   (unsigned long long)param->service_action_key,
		   param->spec_i_pt_all_tg_pt_aptl,
		   ignore);

	if (!new_reg) {
		eprintk("%llx:%hu: failed to alloc new registration\n",
			(unsigned long long)cmnd->conn->session->sid,
			cmnd->conn->cid);

		iscsi_cmnd_set_sense(cmnd,
				     /* TODO: verify sense key / asc / ascq */
				     ILLEGAL_REQUEST,
				     INSUFFICIENT_REGISTRATION_RESOURCES_ASC,
				     INSUFFICIENT_REGISTRATION_RESOURCES_ASCQ);
		return;
	}

	spin_lock(&volume->reserve_lock);

	list_for_each_entry(reg, &reservation->registration_list, r_list) {
		dprintk_pr(cmnd,
			   "found reg, init name %s, sess %llx, key %llx\n",
			   reg->init_name,
			   (unsigned long long)reg->sid,
			   (unsigned long long)reg->reservation_key);

		if (reg->sid != session->sid)
			continue;

		if (!ignore && param->reservation_key != reg->reservation_key) {
			/*
			 * SPC4r33: Table 49: when REGISTER is received on a
			 * registered I_T nexus with a reservation key not
			 * equal to the existing reservation key, we should
			 * return RESERVATION CONFLICT
			 */
			cmnd->status = SAM_STAT_RESERVATION_CONFLICT;
			goto out;
		}

		if ((param->spec_i_pt_all_tg_pt_aptl & PR_OUT_PARAM_SPEC_I_PT)) {
			iscsi_cmnd_set_sense(cmnd,
					     ILLEGAL_REQUEST,
					     INVALID_FIELD_IN_CDB_ASC,
					     INVALID_FIELD_IN_CDB_ASCQ);
			goto out;
		}

		if (!param->service_action_key) {
			if (pr_is_reserved_by_session(reservation, session) &&
			    !pr_type_is_all_registrants(reservation)) {
				reservation->reservation_type = RESERVATION_TYPE_NONE;
				reservation->persistent_type = 0;
				reservation->reservation_key = 0;
				ua_establish_for_other_sessions(session,
								volume->lun,
								RESERVATIONS_RELEASED_ASC,
								RESERVATIONS_RELEASED_ASCQ);
			}
			list_del(&reg->r_list);
			kfree(reg);
			if (list_empty(&reservation->registration_list) &&
			    pr_type_is_all_registrants(reservation)) {
				reservation->reservation_type = RESERVATION_TYPE_NONE;
				reservation->persistent_type = 0;
				reservation->reservation_key = 0;
			}
		} else {
			reg->reservation_key = param->service_action_key;
		}
		reservation->generation++;
		goto out;
	}

	if (!param->reservation_key && !param->service_action_key) {
		reservation->generation++;
		goto out;
	}

	if (param->reservation_key) {
		cmnd->status = SAM_STAT_RESERVATION_CONFLICT;
		goto out;
	}

	new_reg->sid = session->sid;
	new_reg->reservation_key = param->service_action_key;
	strncpy(new_reg->init_name,
		cmnd->conn->session->initiator,
		sizeof(new_reg->init_name));

	INIT_LIST_HEAD(&new_reg->r_list);
	list_add_tail(&new_reg->r_list, &reservation->registration_list);
	reservation->generation++;

	spin_unlock(&volume->reserve_lock);

	dprintk_pr(cmnd,
		   "init_name %s, key %llx, generation %u\n",
		   new_reg->init_name,
		   (unsigned long long)new_reg->reservation_key,
		   reservation->generation);

	return;
out:
	kfree(new_reg);
	spin_unlock(&volume->reserve_lock);
}

static bool_t
persistent_type_valid(int type)
{
	switch (type) {
	case PR_TYPE_WRITE_EXCLUSIVE:
	case PR_TYPE_EXCLUSIVE_ACCESS:
	case PR_TYPE_WRITE_EXCLUSIVE_REGISTRANTS_ONLY:
	case PR_TYPE_EXCLUSIVE_ACCESS_REGISTRANTS_ONLY:
	case PR_TYPE_WRITE_EXCLUSIVE_ALL_REGISTRANTS:
	case PR_TYPE_EXCLUSIVE_ACCESS_ALL_REGISTRANTS:
		return true;
	default:
		return false;
	}
}

static void
pr_out_reserve(struct iscsi_cmnd *cmnd, enum persistent_reservation_type type)
{
	const struct pr_out_param_list *param =
		(const struct pr_out_param_list *)page_address(cmnd->tio->pvec[0]);
	bool_t registered;
	struct iscsi_session *session = cmnd->conn->session;
	struct iet_volume *volume = cmnd->lun;
	struct reservation *reservation = &volume->reservation;

	spin_lock(&volume->reserve_lock);

	registered = pr_initiator_has_registered(reservation, session->sid);
	if (!registered) {
		cmnd->status = SAM_STAT_RESERVATION_CONFLICT;
		goto out;
	}

	if (pr_is_reserved(reservation) && reservation->sid != session->sid) {
		cmnd->status = SAM_STAT_RESERVATION_CONFLICT;
		goto out;
	}

	if (pr_is_reserved(reservation) &&
	    reservation->reservation_key != param->reservation_key) {
		cmnd->status = SAM_STAT_RESERVATION_CONFLICT;
		goto out;
	}

	if (pr_is_reserved(reservation) && reservation->persistent_type != type) {
		cmnd->status = SAM_STAT_RESERVATION_CONFLICT;
		goto out;
	}

	if (pr_is_reserved(reservation))
		goto out;

	if (!persistent_type_valid(type)) {
		iscsi_cmnd_set_sense(cmnd,
				     ILLEGAL_REQUEST,
				     INVALID_FIELD_IN_CDB_ASC,
				     INVALID_FIELD_IN_CDB_ASCQ);
		goto out;
	}

	reservation->reservation_type = RESERVATION_TYPE_PERSISTENT;
	reservation->persistent_type = type;
	reservation->reservation_key = param->reservation_key;
	reservation->sid = session->sid;

	dprintk_pr(cmnd,
		   "key %llx, sess %llx, generation %u, rtype %d, ptype %d\n",
		   (unsigned long long)reservation->reservation_key,
		   (unsigned long long)reservation->sid,
		   reservation->generation,
		   reservation->reservation_type,
		   reservation->persistent_type);

out:
	spin_unlock(&volume->reserve_lock);
}

static void
pr_out_release(struct iscsi_cmnd *cmnd,
	       enum persistent_reservation_type type)
{
	const struct pr_out_param_list *param =
		(const struct pr_out_param_list *)page_address(cmnd->tio->pvec[0]);
	bool_t registered;
	struct iscsi_session *session = cmnd->conn->session;
	struct iet_volume *volume = cmnd->lun;
	struct reservation *reservation = &volume->reservation;
	bool_t send_ua;

	spin_lock(&volume->reserve_lock);
	if (!pr_is_reserved(reservation))
		goto out;

	registered = pr_initiator_has_registered(reservation, session->sid);
	if (!registered) {
		cmnd->status = SAM_STAT_RESERVATION_CONFLICT;
		goto out;
	}

	if (!pr_type_is_all_registrants(reservation)) {
		if (reservation->sid != session->sid)
			goto out;
		if (reservation->reservation_key != param->reservation_key) {
			cmnd->status = SAM_STAT_RESERVATION_CONFLICT;
			goto out;
		}
	}

	switch (reservation->persistent_type) {
	case PR_TYPE_WRITE_EXCLUSIVE_REGISTRANTS_ONLY:
	case PR_TYPE_EXCLUSIVE_ACCESS_REGISTRANTS_ONLY:
	case PR_TYPE_WRITE_EXCLUSIVE_ALL_REGISTRANTS:
	case PR_TYPE_EXCLUSIVE_ACCESS_ALL_REGISTRANTS:
		send_ua = true;
		break;
	default:
		send_ua = false;
	}

	dprintk_pr(cmnd,
		   "key %llx, sess %llx, generation %u, rtype %d, ptype %d, ua %d\n",
		   (unsigned long long)reservation->reservation_key,
		   (unsigned long long)reservation->sid,
		   reservation->generation,
		   reservation->reservation_type,
		   reservation->persistent_type,
		   send_ua);

	reservation->reservation_type = RESERVATION_TYPE_NONE;
	reservation->persistent_type = PR_TYPE_NONE;
	reservation->reservation_key = 0;

	if (send_ua)
		ua_establish_for_other_sessions(session,
						volume->lun,
						RESERVATIONS_RELEASED_ASC,
						RESERVATIONS_RELEASED_ASCQ);
out:
	spin_unlock(&volume->reserve_lock);
}

static void
pr_out_clear(struct iscsi_cmnd *cmnd)
{
	bool_t registered;
	struct iscsi_session *tmp_session, *session = cmnd->conn->session;
	struct iscsi_target *target = session->target;
	struct iet_volume *volume = cmnd->lun;
	struct reservation *reservation = &volume->reservation;
	struct registration *reg, *tmp_reg;

	spin_lock(&volume->reserve_lock);
	registered = pr_initiator_has_registered(reservation, session->sid);
	if (!registered) {
		cmnd->status = SAM_STAT_RESERVATION_CONFLICT;
		goto out;
	}

	list_for_each_entry_safe(reg, tmp_reg, &reservation->registration_list, r_list) {
		if (reg->sid != session->sid) {
			tmp_session = session_lookup(target, reg->sid);
			if (tmp_session)
				ua_establish_for_session(session,
							 volume->lun,
							 RESERVATIONS_PREEMPTED_ASC,
							 RESERVATIONS_PREEMPTED_ASCQ);
		}
		list_del(&reg->r_list);
		kfree(reg);
	}

	dprintk_pr(cmnd,
		   "key %llx, sess %llx, generation %u, rtype %d, ptype %d\n",
		   (unsigned long long)reservation->reservation_key,
		   (unsigned long long)reservation->sid,
		   reservation->generation,
		   reservation->reservation_type,
		   reservation->persistent_type);

	reservation->reservation_type = RESERVATION_TYPE_NONE;
	reservation->persistent_type = PR_TYPE_NONE;
	reservation->reservation_key = 0;
	reservation->generation++;
out:
	spin_unlock(&volume->reserve_lock);
}

static void
pr_out_preempt(struct iscsi_cmnd *cmnd,
	       enum persistent_reservation_type pr_type,
	       bool_t abort)
{
	const struct pr_out_param_list *param =
		(const struct pr_out_param_list *)page_address(cmnd->tio->pvec[0]);
	struct registration *reg, *tmp_reg;
	bool_t registered;
	struct iscsi_session *session = cmnd->conn->session;
	struct iscsi_session *reserv_session;
	struct iscsi_target *target = session->target;
	struct iet_volume *volume = cmnd->lun;
	struct reservation *reservation = &volume->reservation;
	bool_t all = 0;

	spin_lock(&volume->reserve_lock);
	if (!param->service_action_key &&
	    !pr_type_is_all_registrants(reservation)) {
		iscsi_cmnd_set_sense(cmnd,
				     ILLEGAL_REQUEST,
				     INVALID_FIELD_IN_PARAMETER_LIST_ASC,
				     INVALID_FIELD_IN_PARAMETER_LIST_ASCQ);
		goto out;
	}

	registered = pr_initiator_has_registered(reservation, session->sid);
	if (!registered) {
		cmnd->status = SAM_STAT_RESERVATION_CONFLICT;
		goto out;
	}

	if (pr_is_reserved(reservation)) {
		if ((!pr_type_is_all_registrants(reservation) &&
		     reservation->reservation_key == param->service_action_key &&
		     reservation->sid != session->sid) ||
		    (pr_type_is_all_registrants(reservation) &&
		     !param->service_action_key)) {

			reserv_session = session_lookup(target, reservation->sid);
			if (reserv_session) {
				if (abort)
					session_abort_tasks(reserv_session,
					    volume->lun);
				ua_establish_for_session(reserv_session,
							 volume->lun,
							 RESERVATIONS_PREEMPTED_ASC,
							 RESERVATIONS_PREEMPTED_ASCQ);
			}

			reservation->reservation_type = RESERVATION_TYPE_PERSISTENT;
			reservation->sid = session->sid;
			reservation->reservation_key = param->reservation_key;
			reservation->persistent_type = pr_type;
			all = true;
		}
	}

	list_for_each_entry_safe(reg, tmp_reg, &reservation->registration_list, r_list) {
		if (reg->sid == session->sid)
			continue;

		if (!all &&
		    reg->reservation_key != param->service_action_key &&
		    !pr_type_is_all_registrants(reservation))
			continue;

		reserv_session = session_lookup(target, reg->sid);
		if (reserv_session)
			ua_establish_for_session(reserv_session,
						 volume->lun,
						 REGISTRATIONS_PREEMPTED_ASC,
						 REGISTRATIONS_PREEMPTED_ASCQ);

		list_del(&reg->r_list);
		kfree(reg);
	}

	reservation->generation++;
out:
	spin_unlock(&volume->reserve_lock);
}

void
build_persistent_reserve_out_response(struct iscsi_cmnd *cmnd)
{
	const struct persistent_reserve_out *pr_out =
		(const struct persistent_reserve_out *)(cmnd_hdr(cmnd)->scb);
	const enum pr_out_service_actions action =
		pr_out->service_action & PR_SERVICE_ACTION_MASK;
	const u32 param_list_length = be32_to_cpu(pr_out->parameter_list_length);

	dprintk_pr(cmnd,
		   "svc action %x, scope_type %x, param len %u\n",
		   action,
		   pr_out->scope_type,
		   param_list_length);

	switch (action) {
	case SERVICE_ACTION_REGISTER:
	case SERVICE_ACTION_REGISTER_IGNORE:
	case SERVICE_ACTION_RESERVE:
	case SERVICE_ACTION_RELEASE:
	case SERVICE_ACTION_CLEAR:
	case SERVICE_ACTION_PREEMPT:
	case SERVICE_ACTION_PREEMPT_ABORT:
		break;
	case SERVICE_ACTION_REGISTER_MOVE:
		/* not implemented (yet) */
	default:
		eprintk("%llx:%hu: invalid PR Out Service Action %x\n",
			(unsigned long long)cmnd->conn->session->sid,
			cmnd->conn->cid,
			action);
		iscsi_cmnd_set_sense(cmnd,
				     ILLEGAL_REQUEST,
				     INVALID_FIELD_IN_CDB_ASC,
				     INVALID_FIELD_IN_CDB_ASCQ);
		return;
	}

	if ((pr_out->scope_type & PR_SCOPE_MASK) != PR_SCOPE_LU) {
		eprintk("%llx:%hu: invalid PR scope %x\n",
			(unsigned long long)cmnd->conn->session->sid,
			cmnd->conn->cid,
			pr_out->scope_type & PR_SCOPE_MASK);
		iscsi_cmnd_set_sense(cmnd,
				     ILLEGAL_REQUEST,
				     INVALID_FIELD_IN_CDB_ASC,
				     INVALID_FIELD_IN_CDB_ASCQ);
		return;
	}

	if (param_list_length < sizeof(struct pr_out_param_list)) {
		eprintk("%llx:%hu: invalid PR Out parameter list length %d\n",
			(unsigned long long)cmnd->conn->session->sid,
			cmnd->conn->cid,
			param_list_length);
		iscsi_cmnd_set_sense(cmnd,
				     ILLEGAL_REQUEST,
				     PARAMETER_LIST_LENGTH_ERROR_ASC,
				     PARAMETER_LIST_LENGTH_ERROR_ASCQ);
		return;
	}

	switch (action) {
	case SERVICE_ACTION_REGISTER:
		pr_out_register(cmnd, false);
		break;
	case SERVICE_ACTION_REGISTER_IGNORE:
		pr_out_register(cmnd, true);
		break;
	case SERVICE_ACTION_RESERVE:
		pr_out_reserve(cmnd, pr_out->scope_type & PR_TYPE_MASK);
		break;
	case SERVICE_ACTION_RELEASE:
		pr_out_release(cmnd, pr_out->scope_type & PR_TYPE_MASK);
		break;
	case SERVICE_ACTION_CLEAR:
		pr_out_clear(cmnd);
		break;
	case SERVICE_ACTION_PREEMPT:
		pr_out_preempt(cmnd,
			       pr_out->scope_type & PR_TYPE_MASK,
			       false);
		break;
	case SERVICE_ACTION_PREEMPT_ABORT:
		pr_out_preempt(cmnd,
			       pr_out->scope_type & PR_TYPE_MASK,
			       true);
		break;
	case SERVICE_ACTION_REGISTER_MOVE:
		/* not implemented (yet) */
	default:
		/* not reachable due to the earlier switch stmt */
		BUG();
	}
}
