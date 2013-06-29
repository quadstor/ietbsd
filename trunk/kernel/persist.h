/*
 * Copyright (C) 2011 Shivaram U, shivaram.u@quadstor.com
 *
 * Released under the terms of the GNU GPL v2.0.
 */
#ifndef IET_PERSIST_H_
#define IET_PERSIST_H_

struct registration {
	u64 sid;
	__be64 reservation_key;
	char init_name[ISCSI_NAME_LEN];
	struct list_head r_list;
};

#define PARAMETER_LIST_LENGTH_ERROR_ASC			0x1A
#define PARAMETER_LIST_LENGTH_ERROR_ASCQ		0x00

#define INVALID_COMMAND_OPERATION_CODE_ASC		0x20
#define INVALID_COMMAND_OPERATION_CODE_ASCQ		0x00

#define INVALID_FIELD_IN_CDB_ASC			0x24
#define INVALID_FIELD_IN_CDB_ASCQ			0x00

#define INVALID_FIELD_IN_PARAMETER_LIST_ASC		0x26
#define INVALID_FIELD_IN_PARAMETER_LIST_ASCQ		0x00

#define INVALID_RELEASE_OF_PERSISTENT_RESERVATION_ASC	0x26
#define INVALID_RELEASE_OF_PERSISTENT_RESERVATION_ASCQ	0x04

#define RESERVATIONS_PREEMPTED_ASC			0x2A
#define RESERVATIONS_PREEMPTED_ASCQ			0x03

#define RESERVATIONS_RELEASED_ASC			0x2A
#define RESERVATIONS_RELEASED_ASCQ			0x04

#define REGISTRATIONS_PREEMPTED_ASC			0x2A
#define REGISTRATIONS_PREEMPTED_ASCQ			0x05

#define INSUFFICIENT_RESERVATION_RESOURCES_ASC		0x55
#define INSUFFICIENT_RESERVATION_RESOURCES_ASCQ		0x02

#define INSUFFICIENT_REGISTRATION_RESOURCES_ASC		0x55
#define INSUFFICIENT_REGISTRATION_RESOURCES_ASCQ	0x04

enum pr_in_service_actions {
	SERVICE_ACTION_READ_KEYS = 0x0,
	SERVICE_ACTION_READ_RESERVATION = 0x1,
	SERVICE_ACTION_REPORT_CAPABILITIES = 0x2,
	SERVICE_ACTION_READ_FULL_STATUS = 0x3
};

struct persistent_reserve_in {
	u8 opcode; /* PERSISTENT_RESERVE_IN == 0x5e */
	u8 service_action;
	u8 rsvd[5];
	__be16 allocation_length;
	u8 control;
} __packed;


enum pr_type_mask {
	PR_TYPE_WR_EX_AR = 0x8000, /* Write Excl., All Registrants */
	PR_TYPE_EX_AC_RO = 0x4000, /* Excl. Access, Registrants Only */
	PR_TYPE_WR_EX_RO = 0x2000, /* Write Excl., Registrants Only */
	PR_TYPE_EX_AC = 0x800,     /* Excl. Access */
	PR_TYPE_WR_EX = 0x200,     /* Write Excl. */
	PR_TYPE_EX_AC_AR = 0x1,    /* Excl. Access, All Registrants */
};

enum {
	PR_IN_REPORT_CAP_PTPL_C = 1,     /* Persist Through Power Loss Capable */
	PR_IN_REPORT_CAP_ATP_C = 1 << 2, /* All Target Ports Capable */
	PR_IN_REPORT_CAP_SIP_C = 1 << 3, /* Specify Initiator Ports Capable */
	PR_IN_REPORT_CAP_CRH = 1 << 4    /* Compatible Reservation Handling */
};


enum {
	PR_IN_REPORT_CAP_PTPL_A = 1,     /* Persist Through Power Loss Activated */
	PR_IN_REPORT_CAP_TMV = 1 << 7,   /* Type Mask Valid */
};

struct pr_in_report_capabilities_data {
	__be16 length;

	u8 crh_sip_atp_ptpl_c;
	u8 tmv_ptpl_a;	/* SPC-4 has allow_commands here - don't care for now */

	__be16 type_mask;
	u8  rsvd4[2];
} __packed;

enum {
	PR_SERVICE_ACTION_MASK = 0x1f,
	PR_TYPE_MASK = 0xf,
	PR_SCOPE_MASK = 0xf << 4,
};

struct pr_in_read_reservation_data {
	__be32 generation;
	__be32 additional_length;
	__be64 reservation_key;
	u8 obsolete1[4];
	u8 rsvd;
	u8 scope_type;
	u8 obsolete2[2];
} __packed;

enum {
	TRANSPORT_ID_FMT_CODE_MASK = 0xc0,
	TRANSPORT_ID_FMT_CODE_ISCSI = 0x0,
	TRANSPORT_ID_PROTO_ID_MASK = 0xf,
	TRANSPORT_ID_PROTO_ID_ISCSI = 0x5,
};

struct iscsi_transport_id {
	u8 fmt_code_proto_id;
	u8 rsvd;
	__be16 additional_length;
	u8 iscsi_name[0];
} __packed;

enum {
	PR_OUT_STATUS_DESC_R_HOLDER = 1,
	PR_OUT_STATUS_DESC_ALL_TG_PT = 1 << 1,
};

/* this is iscsi specific */
struct pr_in_full_status_descriptor {
	__be64 reservation_key;
	u8 rsvd1[4];

	u8 all_tg_pt_r_holder;
	u8 scope_type;

	u8 rsvd2[4];
	__be16 rel_tgt_port_id;
	__be32 additional_desc_length;
	struct iscsi_transport_id iscsi_transport_id[0];
} __packed;

struct pr_in_read_full_status_data {
	__be32 generation;
	__be32 additional_length;
	struct pr_in_full_status_descriptor descriptors[0];
} __packed;

struct pr_in_read_keys_data {
	__be32 generation;
	__be32 additional_length;
	__be64 keys[0];
} __packed;

enum pr_out_service_actions {
	SERVICE_ACTION_REGISTER = 0x0,
	SERVICE_ACTION_RESERVE = 0x1,
	SERVICE_ACTION_RELEASE = 0x2,
	SERVICE_ACTION_CLEAR = 0x3,
	SERVICE_ACTION_PREEMPT = 0x4,
	SERVICE_ACTION_PREEMPT_ABORT = 0x5,
	SERVICE_ACTION_REGISTER_IGNORE = 0x6,
	SERVICE_ACTION_REGISTER_MOVE = 0x7
};

enum persistent_reservation_scope {
	PR_SCOPE_LU = 0x0,
};

enum persistent_reservation_type {
	PR_TYPE_NONE                              = 0x0, /* "abuse" obsolete value */
	PR_TYPE_WRITE_EXCLUSIVE                   = 0x1,
	PR_TYPE_EXCLUSIVE_ACCESS                  = 0x3,
	PR_TYPE_WRITE_EXCLUSIVE_REGISTRANTS_ONLY  = 0x5,
	PR_TYPE_EXCLUSIVE_ACCESS_REGISTRANTS_ONLY = 0x6,
	PR_TYPE_WRITE_EXCLUSIVE_ALL_REGISTRANTS   = 0x7,
	PR_TYPE_EXCLUSIVE_ACCESS_ALL_REGISTRANTS  = 0x8
};

struct persistent_reserve_out {
	u8 opcode; /* PERSISTENT_RESERVE_OUT == 0x5f */
	u8 service_action;
	u8 scope_type;
	u8 rsvd[2];
	__be32 parameter_list_length;
	u8 control;
} __packed;

enum {
	PR_OUT_PARAM_APTPL = 1,
	PR_OUT_PARAM_ALL_TG_PT = 1 << 2,
	PR_OUT_PARAM_SPEC_I_PT = 1 << 3,
};

struct pr_out_param_list {
	__be64 reservation_key;
	__be64 service_action_key;
	u8 obsolete1[4];
	u8 spec_i_pt_all_tg_pt_aptl;
	u8 rsvd;
	u8 obsolete2[2];
	u8 additional_parameter_data[0];
} __packed;

enum reservation_type {
	RESERVATION_TYPE_NONE,
	RESERVATION_TYPE_RESERVE,
	RESERVATION_TYPE_PERSISTENT
};

struct reservation {
	/* RESERVATION_TYPE_NONE indicates "not reserved" */
	enum reservation_type reservation_type;
	enum persistent_reservation_type persistent_type;
	u32 generation;
	u64 sid;
	__be64 reservation_key;
	struct list_head registration_list;
};

static inline bool_t
pr_is_reserved(const struct reservation* res)
{
	return res->reservation_type != RESERVATION_TYPE_NONE;
}

static inline bool_t
pr_type_is_all_registrants(const struct reservation *res)
{
	return ((res->persistent_type == PR_TYPE_WRITE_EXCLUSIVE_ALL_REGISTRANTS) ||
		(res->persistent_type == PR_TYPE_EXCLUSIVE_ACCESS_ALL_REGISTRANTS));
}

struct iscsi_session;

bool_t
pr_is_reserved_by_session(const struct reservation *res,
			  const struct iscsi_session *sess);

bool_t
pr_initiator_has_registered(const struct reservation *res,
			    u64 sid);

struct iscsi_cmnd;

void
build_persistent_reserve_out_response(struct iscsi_cmnd *cmnd);

void
build_persistent_reserve_in_response(struct iscsi_cmnd *cmnd);

#endif
