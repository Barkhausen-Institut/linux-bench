
#ifndef SIDECALLS_H
#define SIDECALLS_H

#include "tculib.h"
#include "globaddr.h"

#include <linux/types.h>
#include <linux/string.h>
#include <linux/printk.h>

#define SIZE_OF_MSG_HEADER 32

uint8_t *snd_buf = (uint8_t *)NULL;
// for receiving sidecalls from m3 kernel
uint8_t *rcv_buf = (uint8_t *)NULL;
// for receiving replies from m3 kernel
uint8_t *rpl_buf = (uint8_t *)NULL;

typedef enum {
	Sidecall_ACT_INIT = 0x0,
	Sidecall_ACT_CTRL = 0x1,
	Sidecall_TRANSLATE = 0x3,
	Sidecall_DERIVE_QUOTA = 0x6,
	Sidecall_GET_QUOTA = 0x7,
	Sidecall_SET_QUOTA = 0x8,
} Sidecalls;

typedef struct {
	uint64_t op;
	uint64_t act_sel;
	uint64_t time_quota;
	uint64_t pt_quota;
	uint64_t eps_start;
} ActInit;

typedef enum {
	ActivityOp_START = 0,
	ActivityOp_STOP = 1,
} ActivityOp;

typedef struct {
	uint64_t op;
	uint64_t act_sel;
	uint64_t act_op;
} ActivityCtrl;

typedef struct {
	uint64_t op;
	uint64_t act_sel;
	uint64_t virt;
	uint64_t perm;
} Translate;

typedef struct {
	uint64_t op;
	uint64_t time;
	uint64_t pts;
} GetQuota;

typedef enum {
	Sidecall_EXIT = 0,
	Sidecall_LX_ACT = 1,
	Sidecall_NOOP = 2,
} Calls;

typedef struct {
	uint64_t op;
	uint64_t act_sel;
	uint64_t code;
} Exit;

typedef struct {
	uint64_t op;
} LxAct;

// used for finding out opcode of incoming sidecall
typedef struct {
	uint64_t opcode;
} DefaultRequest;

// used as a reply from the m3 kernel
typedef struct {
	uint64_t error;
} DefaultReply;

// used as a reply to the m3 kernel
typedef struct {
	uint64_t error;
	uint64_t val1;
	uint64_t val2;
} Response;

static Error send_response(Response res, size_t request_offset)
{
	size_t len = sizeof(Response);
	BUG_ON(snd_buf == NULL);
	memcpy(snd_buf, &res, len);
	return reply_aligned(TMSIDE_REP, snd_buf, len, request_offset);
}

static void wait_for_get_quota(void)
{
	DefaultRequest *req;
	Response res;
	size_t offset;
	Error e;
	do {
		offset = fetch_msg(TMSIDE_REP);
	} while (offset == ~(size_t)0);
	req = (DefaultRequest *)(rcv_buf + offset + SIZE_OF_MSG_HEADER);
	if (req->opcode != Sidecall_GET_QUOTA) {
		pr_warn("wait_for_get_quota: received different sidecall: %llu\n",
			req->opcode);
		return;
	}
	res = (Response){ .error = 0,
			  .val1 = ((uint64_t)1 << 32) | 1,
			  .val2 = ((uint64_t)1 << 32) | 1 };
	e = send_response(res, offset);
	if (e) {
		pr_warn("wait_for_get_quota: send_response failed: %s\n",
			error_to_str(e));
	}
}

static void wait_for_set_quota(void)
{
	DefaultRequest *req;
	Response res;
	size_t offset;
	Error e;
	do {
		offset = fetch_msg(TMSIDE_REP);
	} while (offset == ~(size_t)0);
	req = (DefaultRequest *)(rcv_buf + offset + SIZE_OF_MSG_HEADER);
	if (req->opcode != Sidecall_SET_QUOTA) {
		pr_warn("wait_for_set_quota: received different sidecall: %llu\n",
			req->opcode);
		return;
	}
	res = (Response){ .error = 0, .val1 = 0, .val2 = 0 };
	e = send_response(res, offset);
	if (e) {
		pr_warn("wait_for_set_quota: send_response failed: %s\n",
			error_to_str(e));
	}
}

static void wait_for_derive_quota(void)
{
	DefaultRequest *req;
	Response res;
	size_t offset;
	Error e;
	do {
		offset = fetch_msg(TMSIDE_REP);
	} while (offset == ~(size_t)0);
	req = (DefaultRequest *)(rcv_buf + offset + SIZE_OF_MSG_HEADER);
	if (req->opcode != Sidecall_DERIVE_QUOTA) {
		pr_warn("wait_for_derive_quota: received different sidecall: %llu\n",
			req->opcode);
		return;
	}
	res = (Response){ .error = 0, .val1 = 1, .val2 = 1 };
	e = send_response(res, offset);
	if (e) {
		pr_warn("wait_for_derive_quota: send_response failed: %s\n",
			error_to_str(e));
	}
}

static ActId wait_for_act_init(void)
{
	DefaultRequest *req;
	ActInit *act_init;
	Response res;
	size_t offset;
	Error e;
	do {
		offset = fetch_msg(TMSIDE_REP);
	} while (offset == ~(size_t)0);
	req = (DefaultRequest *)(rcv_buf + offset + SIZE_OF_MSG_HEADER);
	if (req->opcode != Sidecall_ACT_INIT) {
		pr_warn("wait_for_act_init: received different sidecall: %llu\n",
			req->opcode);
		return INVAL_AID;
	}
	act_init = (ActInit *)(rcv_buf + offset + SIZE_OF_MSG_HEADER);
	pr_info("received act init with act_sel: %llu\n", act_init->act_sel);
	res = (Response){ .error = 0, .val1 = 0, .val2 = 0 };
	e = send_response(res, offset);
	if (e) {
		pr_warn("wait_for_act_init: send_response failed: %s\n",
			error_to_str(e));
	}
	return act_init->act_sel;
}

static void wait_for_translate(void)
{
	DefaultRequest *req;
	Translate *translate;
	Response res;
	size_t offset;
	Error e;
	GlobAddr globaddr;
	Phys physaddr;
	do {
		offset = fetch_msg(TMSIDE_REP);
	} while (offset == ~(size_t)0);
	req = (DefaultRequest *)(rcv_buf + offset + SIZE_OF_MSG_HEADER);
	if (req->opcode != Sidecall_TRANSLATE) {
		pr_warn("wait_for_translate: received different sidecall: %llu\n",
			req->opcode);
	}
	translate = (Translate *)(rcv_buf + offset + SIZE_OF_MSG_HEADER);
	pr_info("translate virt addr %llx\n", translate->virt);
	switch (translate->virt) {
	case ENV_START:
		physaddr = ENV_START;
		break;
	case RBUF_STD_ADDR:
		physaddr = MEM_OFFSET + 2 * PAGE_SIZE;
		break;
	default:
		BUG();
	}
	globaddr = phys_to_glob(physaddr);
	res = (Response){ .error = 0, .val1 = globaddr, .val2 = 0 };
	e = send_response(res, offset);
	if (e) {
		pr_warn("wait_for_translate failed: %s\n", error_to_str(e));
	}
}

static void wait_for_act_start(void)
{
	DefaultRequest *req;
	ActivityCtrl *act_ctrl;
	Response res;
	size_t offset;
	Error e;
	do {
		offset = fetch_msg(TMSIDE_REP);
	} while (offset == ~(size_t)0);
	req = (DefaultRequest *)(rcv_buf + offset + SIZE_OF_MSG_HEADER);
	if (req->opcode != Sidecall_ACT_CTRL) {
		pr_warn("wait_for_act_start: received different sidecall: %llu\n",
			req->opcode);
		return;
	}
	act_ctrl = (ActivityCtrl *)(rcv_buf + offset + SIZE_OF_MSG_HEADER);
	if (act_ctrl->act_op != ActivityOp_START) {
		pr_warn("wait_for_act_start: act_op is not START: %llu\n",
			act_ctrl->act_op);
		return;
	}
	res = (Response){ .error = 0, .val1 = 0, .val2 = 0 };
	e = send_response(res, offset);
	if (e) {
		pr_warn("wait_for_act_start: send_response failed: %s\n",
			error_to_str(e));
	}
}

static Error wait_for_reply(void)
{
	size_t offset;
	Error e;
	DefaultReply *r;
	BUG_ON(rpl_buf == NULL);
	do {
		offset = fetch_msg(KPEX_REP);
	} while (offset == ~(size_t)0);
	e = ack_msg(KPEX_REP, offset);
	if (e != Error_None) {
		return e;
	}
	r = (DefaultReply *)(rpl_buf + offset + SIZE_OF_MSG_HEADER);
	return (Error)r->error;
}

static Error snd_rcv_sidecall_exit(ActId aid, uint64_t code)
{
	Error e;
	Exit msg = {
		.op = Sidecall_EXIT,
		.act_sel = (uint64_t)aid,
		.code = code,
	};
	size_t len = sizeof(Exit);
	BUG_ON(snd_buf == NULL);
	memcpy(snd_buf, &msg, len);
	e = send_aligned(KPEX_SEP, snd_buf, len, 0, KPEX_REP);
	if (e != Error_None) {
		pr_err("exit sidecall failed: %s\n", error_to_str(e));
	};
	e = wait_for_reply();
	if (e != Error_None) {
		pr_err("exit sidecall wait_for_reply failed: %s\n",
		       error_to_str(e));
	}
	return e;
}

static Error snd_rcv_sidecall_lx_act(void)
{
	Error e;
	LxAct msg = { .op = Sidecall_LX_ACT };
	size_t len = sizeof(LxAct);
	BUG_ON(snd_buf == NULL);
	memcpy(snd_buf, &msg, len);
	e = send_aligned(KPEX_SEP, snd_buf, len, 0, KPEX_REP);
	if (e != Error_None) {
		pr_err("lx act sidecall failed: %s\n", error_to_str(e));
		return e;
	}
	e = wait_for_reply();
	if (e != Error_None) {
		pr_err("lx act sidecall wait_for_reply failed: %s\n",
		       error_to_str(e));
	}
	return e;
}

#endif // SIDECALLS_H