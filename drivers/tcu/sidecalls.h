#ifndef TCU_SIDECALLS_H
#define TCU_SIDECALLS_H

#include <linux/types.h>

#include "tculib.h"

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

typedef struct {
	uint64_t op;
	uint64_t id;
	uint64_t time;
	uint64_t pts;
} SetQuota;

typedef struct {
	uint64_t parent_time;
	uint64_t parent_pts;
	uint64_t time;
	uint64_t pts;
} DeriveQuota;

typedef enum {
	Sidecall_EXIT = 0,
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

void init_sidecalls(struct tcu_device *tcu);
void handle_sidecalls(struct tcu_device *tcu, Reg our_act);
Error snd_rcv_sidecall_exit(struct tcu_device *tcu, ActId aid, uint64_t code);
Error snd_rcv_sidecall_lx_act(struct tcu_device *tcu);

#endif // TCU_SIDECALLS_H
