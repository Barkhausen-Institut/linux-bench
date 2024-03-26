#include "sidecalls.h"

#include <asm/mman.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "activity.h"
#include "globaddr.h"
#include "tculib.h"

typedef enum {
    Sidecall_INFO = 0x0,
    Sidecall_ACT_INIT = 0x1,
    Sidecall_ACT_CTRL = 0x2,
    Sidecall_MAP = 0x3,
    Sidecall_TRANSLATE = 0x4,
    Sidecall_REQUEST_EP = 0x5,
    Sidecall_DERIVE_QUOTA = 0x8,
    Sidecall_GET_QUOTA = 0x9,
    Sidecall_SET_QUOTA = 0xA,
} Sidecalls;

typedef enum {
    TYPE_NONE = 0,
    TYPE_TILEMUX = 1,
    TYPE_LINUX = 2,
    TYPE_ACCEL = 3,
} TileMuxInfoType;

typedef struct {
    uint64_t op;
} SideCallInfo;

typedef struct {
    uint64_t op;
    uint64_t act_sel;
    uint64_t time_quota;
    uint64_t pt_quota;
    uint64_t eps_start;
} SideCallActInit;

typedef enum {
    ActivityOp_START = 0,
    ActivityOp_STOP = 1,
} SideCallActivityOp;

typedef struct {
    uint64_t op;
    uint64_t act_sel;
    uint64_t act_op;
} SideCallActivityCtrl;

typedef struct {
    uint64_t op;
    uint64_t act_sel;
    uint64_t virt;
    uint64_t global;
    uint64_t pages;
    uint64_t perm;
} SideCallMap;

typedef enum {
    MapFlag_R = 1,
    MapFlag_W = 2,
    MapFlag_X = 4,
    MapFlag_L = 8,
    MapFlag_FIXED = 16,
    MapFlag_U = 32,
} MapFlags;

typedef struct {
    uint64_t op;
    uint64_t act_sel;
    uint64_t virt;
    uint64_t perm;
} SideCallTranslate;

typedef struct {
    uint64_t op;
    uint64_t time;
    uint64_t pts;
} SideCallGetQuota;

typedef struct {
    uint64_t op;
    uint64_t id;
    uint64_t time;
    uint64_t pts;
} SideCallSetQuota;

typedef struct {
    uint64_t parent_time;
    uint64_t parent_pts;
    uint64_t time;
    uint64_t pts;
} SideCallDeriveQuota;

typedef enum {
    Sidecall_EXIT = 0,
} KernelCalls;

typedef struct {
    uint64_t op;
    uint64_t act_sel;
    uint64_t code;
} KernelCallExit;

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

static Error sidecalls_send_resp(struct tcu_device *tcu, Response res, size_t request_offset) {
    size_t len = sizeof(Response);
    memcpy(tcu->snd_buf, &res, len);
    return tcu_reply_aligned(tcu, TMSIDE_REP, tcu->snd_buf, len, request_offset);
}

static void sidecalls_info(struct tcu_device *tcu, const SideCallInfo *, Response *res) {
    tculog(LOG_SCALLS, tcu->dev, "sidecalls: INFO\n");

    res->val1 = TYPE_LINUX;
}

static void sidecalls_act_init(struct tcu_device *tcu, const SideCallActInit *req, Response *res) {
    int err;

    tculog(
        LOG_SCALLS, tcu->dev,
        "sidecalls: ACT_INIT with act_sel: %llu, time_quota=%llu, pt_quota=%llu, eps_start=%llu\n",
        req->act_sel, req->time_quota, req->pt_quota, req->eps_start);

    err = activity_create(tcu, (ActId)req->act_sel);
    if(err < 0)
        res->error = Error_NoSpace;
}

static void sidecalls_act_ctrl(struct tcu_device *tcu, const SideCallActivityCtrl *req,
                               Response *res) {
    struct m3_activity *act;

    tculog(LOG_SCALLS, tcu->dev, "sidecalls: ACT_CTRL with act_sel: %llu, act_op=%llu\n",
           req->act_sel, req->act_op);

    act = activity_from_id(tcu, (ActId)req->act_sel);
    if(act == NULL)
        return;

    switch(req->act_op) {
        case ActivityOp_START: {
            // mark the activity as "ready to pick up"
            act->state = A_READY;

            if(tcu->waiting_task != NULL) {
                tculog(LOG_SCALLS, tcu->dev, "sidecalls: waking up starter\n");
                wake_up_process(tcu->waiting_task);
            }
            break;
        }
        case ActivityOp_STOP: activity_remove(tcu, act); break;
    }
}

static void sidecalls_get_quota(struct tcu_device *tcu, const SideCallGetQuota *req,
                                Response *res) {
    tculog(LOG_SCALLS, tcu->dev, "sidecalls: GET_QUOTA with time=%llu, pts=%llu\n", req->time,
           req->pts);

    res->val1 = ((uint64_t)1 << 32) | 1;
    res->val2 = ((uint64_t)1 << 32) | 1;
}

static void sidecalls_set_quota(struct tcu_device *tcu, const SideCallSetQuota *req,
                                Response *res) {
    tculog(LOG_SCALLS, tcu->dev, "sidecalls: SET_QUOTA with id=%llu, time=%llu, pts=%llu\n",
           req->id, req->time, req->pts);
}

static void sidecalls_derive_quota(struct tcu_device *tcu, const SideCallDeriveQuota *req,
                                   Response *res) {
    tculog(LOG_SCALLS, tcu->dev,
           "sidecalls: DERIVE_QUOTA with parent_time=%llu, parent_pts=%llu, time=%llu, pts=%llu\n",
           req->parent_time, req->parent_pts, req->time, req->pts);

    res->val1 = 1;
    res->val2 = 1;
}

static void sidecalls_map(struct tcu_device *tcu, const SideCallMap *req, Response *res) {
    struct m3_activity *act;

    tculog(LOG_SCALLS, tcu->dev,
           "sidecalls: MAP with act_sel=%llu, virt=%px, global=%px, pages=%llu, perm=%#llx\n",
           req->act_sel, (void *)req->virt, (void *)req->global, req->pages, req->perm);

    act = activity_from_id(tcu, (ActId)req->act_sel);
    if(act == NULL) {
        res->error = Error_InvArgs;
        return;
    }

    act->custom_phys = glob_to_phys(tcu, req->global);
    if(act->custom_phys == 0) {
        res->error = Error_InvArgs;
        return;
    }

    act->custom_len = req->pages * PAGE_SIZE;
    act->custom_prot = 0;
    if(req->perm & MapFlag_R)
        act->custom_prot |= PROT_READ;
    if(req->perm & MapFlag_W)
        act->custom_prot |= PROT_WRITE;
    if(req->perm & MapFlag_X)
        act->custom_prot |= PROT_EXEC;
}

static void sidecalls_translate(struct tcu_device *tcu, const SideCallTranslate *req,
                                Response *res) {
    struct m3_activity *act;
    Phys physaddr;

    tculog(LOG_SCALLS, tcu->dev, "sidecalls: TRANSLATE with act_sel=%llu, virt=%px, perm=%#llx\n",
           req->act_sel, (void *)req->virt, req->perm);

    act = activity_from_id(tcu, (ActId)req->act_sel);
    if(act == NULL) {
        res->error = Error_InvArgs;
        return;
    }

    switch(req->virt) {
        case ENV_START: physaddr = act->env_phys; break;
        case RBUF_STD_ADDR: physaddr = act->std_app_buf_phys; break;
        default: BUG();
    }

    res->val1 = phys_to_glob(tcu, physaddr);
}

static void sidecalls_handle_single(struct tcu_device *tcu, const DefaultRequest *req) {
    size_t offset;
    Error e;
    Response res = (Response){
        .error = 0,
        .val1 = 0,
        .val2 = 0,
    };

    switch(req->opcode) {
        case Sidecall_INFO: sidecalls_info(tcu, (SideCallInfo *)req, &res); break;
        case Sidecall_ACT_INIT: sidecalls_act_init(tcu, (SideCallActInit *)req, &res); break;
        case Sidecall_ACT_CTRL: sidecalls_act_ctrl(tcu, (SideCallActivityCtrl *)req, &res); break;
        case Sidecall_GET_QUOTA: sidecalls_get_quota(tcu, (SideCallGetQuota *)req, &res); break;
        case Sidecall_SET_QUOTA: sidecalls_set_quota(tcu, (SideCallSetQuota *)req, &res); break;
        case Sidecall_DERIVE_QUOTA:
            sidecalls_derive_quota(tcu, (SideCallDeriveQuota *)req, &res);
            break;
        case Sidecall_MAP: sidecalls_map(tcu, (SideCallMap *)req, &res); break;
        case Sidecall_TRANSLATE: sidecalls_translate(tcu, (SideCallTranslate *)req, &res); break;
        default: tculog(LOG_ERR, tcu->dev, "Ignoring side call %llu\n", req->opcode); break;
    }

    offset = (uintptr_t)req - (uintptr_t)tcu->rcv_buf - SIZE_OF_MSG_HEADER;
    e = sidecalls_send_resp(tcu, res, offset);
    if(e) {
        tculog(LOG_ERR, tcu->dev, "wait_for_get_quota: send_response failed: %s\n",
               error_to_str(e));
    }
}

void sidecalls_init(struct tcu_device *tcu) {
    Reg our_act;
    size_t offset;

    tculog(LOG_SCALLS, tcu->dev, "initializing sidecalls\n");

    while(1) {
        while(1) {
            offset = tcu_fetch_msg(tcu, TMSIDE_REP);
            if(offset == ~(size_t)0)
                break;

            tculog(LOG_SCALLS, tcu->dev, "Got message @ %#zx\n", offset);
            sidecalls_handle_single(tcu,
                                    (DefaultRequest *)(tcu->rcv_buf + offset + SIZE_OF_MSG_HEADER));
        }

        // now switch to the first activity
        our_act = tcu_xchg_activity(tcu, tcu->cur_act_id);

        // if no events arrived in the meantime (between the last fetch and xchg_act), we're done
        if(((our_act >> 16) & 0xFFFF) == 0)
            break;

        // switch back to our activity and try again
        tcu->cur_act_id = tcu_xchg_activity(tcu, our_act);
    }
}

void sidecalls_handle(struct tcu_device *tcu, Reg our_act) {
    TCUState state;
    Reg old_act;
    size_t offset;
    Error e;

    tculog(LOG_SCALLS, tcu->dev, "Saving TCU state\n");
    tcu_save_state(tcu, &state);

    while(1) {
        // change to our activity
        old_act = tcu_xchg_activity(tcu, our_act);

        tculog(LOG_SCALLS, tcu->dev, "old_act=%#llx, our_act=%#llx\n", old_act, our_act);

        offset = tcu_fetch_msg(tcu, TMSIDE_REP);
        if(offset != ~(size_t)0) {
            tculog(LOG_SCALLS, tcu->dev, "Got message @ %#zx\n", offset);
            sidecalls_handle_single(tcu,
                                    (DefaultRequest *)(tcu->rcv_buf + offset + SIZE_OF_MSG_HEADER));
        }

        // check if the kernel answered a request from us
        offset = tcu_fetch_msg(tcu, KPEX_REP);
        while(offset != ~(size_t)0) {
            tculog(LOG_SCALLS, tcu->dev, "Acking message @ %#zx\n", offset);
            e = tcu_ack_msg(tcu, KPEX_REP, offset);
            BUG_ON(e != Error_None);
            offset = tcu_fetch_msg(tcu, KPEX_REP);
        }

        // change back to old activity
        if(tcu->cur_act_id != INVAL_AID) {
            our_act = tcu_xchg_activity(tcu, tcu->cur_act_id);
            tculog(LOG_SCALLS, tcu->dev, "Switched from %#llx to %#x\n", our_act, tcu->cur_act_id);
        }
        else {
            our_act = tcu_xchg_activity(tcu, old_act);
            tculog(LOG_SCALLS, tcu->dev, "Switched from %#llx to %#llx\n", our_act, old_act);
        }

        // if no events arrived in the meantime, we're done
        if(((our_act >> 16) & 0xFFFF) == 0)
            break;
    }

    tculog(LOG_SCALLS, tcu->dev, "Restoring TCU state\n");
    tcu_restore_state(tcu, &state);
}

Error sidecalls_send_exit(struct tcu_device *tcu, ActId aid, uint64_t code) {
    Error e;
    KernelCallExit msg = {
        .op = Sidecall_EXIT,
        .act_sel = (uint64_t)aid,
        .code = code,
    };
    size_t len = sizeof(msg);

    // switch to our activity
    Reg cur_act;
    cur_act = tcu_xchg_activity(tcu, PRIV_AID);

    // send the message
    memcpy(tcu->snd_buf, &msg, len);
    e = tcu_send_aligned(tcu, KPEX_SEP, tcu->snd_buf, len, 0, KPEX_REP);
    if(e != Error_None)
        tculog(LOG_ERR, tcu->dev, "exit sidecall failed: %s\n", error_to_str(e));

    // switch to idle
    cur_act = tcu_xchg_activity(tcu, INVAL_AID);
    // if we received messages in the meantime, handle them before we leave
    if(((cur_act >> 16) & 0xFFFF) != 0)
        sidecalls_handle(tcu, cur_act);

    return e;
}
