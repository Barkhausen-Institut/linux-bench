#include "activity.h"
#include "globaddr.h"
#include "sidecalls.h"
#include "tculib.h"

#include <linux/slab.h>
#include <linux/string.h>
#include <linux/printk.h>

typedef struct {
	Reg cmd;
	Reg arg1;
	Reg addr;
	Reg size;
} TCUState;

static Error send_response(struct tcu_device *tcu, Response res, size_t request_offset)
{
	size_t len = sizeof(Response);
	memcpy(tcu->snd_buf, &res, len);
	return reply_aligned(tcu, TMSIDE_REP, tcu->snd_buf, len, request_offset);
}

static void save_tcu_state(struct tcu_device *tcu, TCUState *state)
{
	Error e;

	// abort the current command, if there is any
	e = abort_command(tcu, &state->cmd);
	BUG_ON(e != Error_None);

	state->arg1 = read_unpriv_reg(tcu, UnprivReg_ARG1);
	state->addr = read_unpriv_reg(tcu, UnprivReg_DATA_ADDR);
	state->size = read_unpriv_reg(tcu, UnprivReg_DATA_SIZE);
}

static void restore_tcu_state(struct tcu_device *tcu, const TCUState *state)
{
	write_unpriv_reg(tcu, UnprivReg_ARG1, state->arg1);
	write_unpriv_reg(tcu, UnprivReg_DATA_ADDR, state->addr);
	write_unpriv_reg(tcu, UnprivReg_DATA_SIZE, state->size);
    // always restore the command register, because the previous activity might have an error code
    // in the command register or similar.
	mb();
	write_unpriv_reg(tcu, UnprivReg_COMMAND, state->cmd);
}

static void sidecall_act_init(struct tcu_device *tcu, const ActInit *req, Response *res)
{
	int err;

	dev_info(tcu->dev,
		"sidecalls: ACT_INIT with act_sel: %llu, time_quota=%llu, pt_quota=%llu, eps_start=%llu\n",
		req->act_sel, req->time_quota, req->pt_quota, req->eps_start);

	err = create_activity(tcu, (ActId)req->act_sel);
	if (err < 0)
		res->error = Error_NoSpace;
}

static void sidecall_act_ctrl(struct tcu_device *tcu, const ActivityCtrl *req, Response *res)
{
	dev_info(tcu->dev,
		"sidecalls: ACT_CTRL with act_sel: %llu, act_op=%llu\n",
		req->act_sel, req->act_op);

	switch(req->act_op) {
		case ActivityOp_START: {
		    if (tcu->waiting_task != NULL) {
		        dev_info(tcu->dev, "sidecalls: waking up starter\n");
		    	wake_up_process(tcu->waiting_task);
		    }

			// switch to it in the handle_sidecalls loop
			if (tcu->cur_act_id == INVAL_AID) {
				tcu->cur_act = id_to_activity(tcu, (ActId)req->act_sel);
				tcu->cur_act_id = req->act_sel;
			}
			break;
		}
		case ActivityOp_STOP:
			// TODO handle ACT_STOP operation
			break;
	}
}

static void sidecall_get_quota(struct tcu_device *tcu, const GetQuota *req, Response *res)
{
	dev_info(tcu->dev,
		"sidecalls: GET_QUOTA with time=%llu, pts=%llu\n",
		req->time, req->pts);

	res->val1 = ((uint64_t)1 << 32) | 1;
	res->val2 = ((uint64_t)1 << 32) | 1;
}

static void sidecall_set_quota(struct tcu_device *tcu, const SetQuota *req, Response *res)
{
	dev_info(tcu->dev,
		"sidecalls: SET_QUOTA with id=%llu, time=%llu, pts=%llu\n",
		req->id, req->time, req->pts);
}

static void sidecall_derive_quota(struct tcu_device *tcu, const DeriveQuota *req, Response *res)
{
	dev_info(tcu->dev,
		"sidecalls: DERIVE_QUOTA with parent_time=%llu, parent_pts=%llu, time=%llu, pts=%llu\n",
		req->parent_time, req->parent_pts, req->time, req->pts);

	res->val1 = 1;
	res->val2 = 1;
}

static void sidecall_translate(struct tcu_device *tcu, const Translate *req, Response *res)
{
	struct m3_activity *act;
	Phys physaddr;

	dev_info(tcu->dev,
		"sidecalls: TRANSLATE with act_sel=%llu, virt=%px, perm=%#llx\n",
		req->act_sel, (void*)req->virt, req->perm);

	act = id_to_activity(tcu, (ActId)req->act_sel);
	if (act == NULL) {
		res->error = Error_InvArgs;
		return;
	}

	switch (req->virt) {
	case ENV_START:
		physaddr = act->env_phys;
		break;
	case RBUF_STD_ADDR:
		physaddr = act->std_app_buf_phys;
		break;
	default:
		BUG();
	}

	res->val1 = phys_to_glob(tcu, physaddr);
}

static void handle_sidecall(struct tcu_device *tcu, const DefaultRequest *req)
{
	size_t offset;
	Error e;
	Response res = (Response) {
		.error = 0,
		.val1 = 0,
		.val2 = 0,
	};

	switch (req->opcode) {
	case Sidecall_ACT_INIT:
		sidecall_act_init(tcu, (ActInit*)req, &res);
		break;
	case Sidecall_ACT_CTRL:
		sidecall_act_ctrl(tcu, (ActivityCtrl*)req, &res);
		break;
	case Sidecall_SET_QUOTA:
		sidecall_set_quota(tcu, (SetQuota*)req, &res);
		break;
	case Sidecall_GET_QUOTA:
		sidecall_get_quota(tcu, (GetQuota*)req, &res);
		break;
	case Sidecall_DERIVE_QUOTA:
		sidecall_derive_quota(tcu, (DeriveQuota*)req, &res);
		break;
	case Sidecall_TRANSLATE:
		sidecall_translate(tcu, (Translate*)req, &res);
		break;
	default:
		dev_info(tcu->dev, "Ignoring side call %llu\n", req->opcode);
		break;
	}

	offset = (uintptr_t)req - (uintptr_t)tcu->rcv_buf - SIZE_OF_MSG_HEADER;
	e = send_response(tcu, res, offset);
	if (e) {
		dev_warn(tcu->dev, "wait_for_get_quota: send_response failed: %s\n",
			error_to_str(e));
	}
}

void init_sidecalls(struct tcu_device *tcu)
{
	Reg our_act;
	size_t offset;

	dev_info(tcu->dev, "initializing sidecalls\n");

	while (1) {
		offset = fetch_msg(tcu, TMSIDE_REP);
		if (offset == ~(size_t)0)
			break;

		dev_info(tcu->dev, "Got message @ %#zx\n", offset);
		handle_sidecall(tcu, (DefaultRequest *)(tcu->rcv_buf + offset +
						   SIZE_OF_MSG_HEADER));
	}

	our_act = xchg_activity(tcu, tcu->cur_act_id);
	// TODO this is racy. As soon as we change the activity, we will get an interrupt for further
	// messages to us (PRIV_AID). However, we might have already got a message between the last
	// fetch and the xchg_activity. These cannot be handled here without risking that we get an
	// interrupt during their handling. Thus, for now we simply panic if we really got a message
	// between fetch and xchg_activity.
	BUG_ON(((our_act >> 16) & 0xFFFF) != 0);
}

void handle_sidecalls(struct tcu_device *tcu, Reg our_act)
{
	TCUState state;
	Reg old_act;
	size_t offset;
	Error e;

	dev_info(tcu->dev, "Saving TCU state\n");
	save_tcu_state(tcu, &state);

	while (1) {
		// change to our activity
		old_act = xchg_activity(tcu, our_act);

		dev_info(tcu->dev, "old_act=%#llx, our_act=%#llx\n", old_act, our_act);

		offset = fetch_msg(tcu, TMSIDE_REP);
		if (offset != ~(size_t)0) {
			dev_info(tcu->dev, "Got message @ %#zx\n", offset);
			handle_sidecall(tcu, (DefaultRequest *)(tcu->rcv_buf + offset +
							   SIZE_OF_MSG_HEADER));
		}

		// check if the kernel answered a request from us
		offset = fetch_msg(tcu, KPEX_REP);
		while (offset != ~(size_t)0) {
			dev_info(tcu->dev, "Acking message @ %#zx\n", offset);
			e = ack_msg(tcu, KPEX_REP, offset);
			BUG_ON(e != Error_None);
			offset = fetch_msg(tcu, KPEX_REP);
		}

		// change back to old activity (or the just started one)
		if(tcu->cur_act_id != INVAL_AID) {
			our_act = xchg_activity(tcu, tcu->cur_act_id);
			dev_info(tcu->dev, "Switched from %#llx to %#x\n", our_act, tcu->cur_act_id);
		}
		else {
			our_act = xchg_activity(tcu, old_act);
			dev_info(tcu->dev, "Switched from %#llx to %#llx\n", our_act, old_act);
		}

		// if no events arrived in the meantime, we're done
		if (((our_act >> 16) & 0xFFFF) == 0)
			break;
	}

	dev_info(tcu->dev, "Restoring TCU state\n");
	restore_tcu_state(tcu, &state);
}

Error snd_rcv_sidecall_exit(struct tcu_device *tcu, ActId aid, uint64_t code)
{
	Error e;
	Exit msg = {
		.op = Sidecall_EXIT,
		.act_sel = (uint64_t)aid,
		.code = code,
	};
	size_t len = sizeof(Exit);

	// switch to our activity
	Reg cur_act;
	cur_act = xchg_activity(tcu, PRIV_AID);

	// send the message
	memcpy(tcu->snd_buf, &msg, len);
	e = send_aligned(tcu, KPEX_SEP, tcu->snd_buf, len, 0, KPEX_REP);
	if (e != Error_None) {
		dev_err(tcu->dev, "exit sidecall failed: %s\n", error_to_str(e));
	};

	// switch to idle
	cur_act = xchg_activity(tcu, INVAL_AID);
	// TODO similar problem as with init_sidecalls. We are not calling this from the TCU interrupt
	// handler (where we would be sure that this interrupt cannot happen again until we're finished)
	// and thus interrupts can occur. We therefore cannot call handle_sidecalls to handle messages
	// for us that arrived between the two xchg_activity calls. Thus, for now we simply panic if
	// we received one.
	BUG_ON(((cur_act >> 16) & 0xFFFF) != 0);

	return e;
}
