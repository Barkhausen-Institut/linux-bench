#ifndef SIDECALLS_H
#define SIDECALLS_H

#include <linux/types.h>

#include "tculib.h"

#define SIZE_OF_MSG_HEADER 32

extern uint8_t *snd_buf;
// for receiving sidecalls from m3 kernel
extern uint8_t *rcv_buf;
// for receiving replies from m3 kernel
extern uint8_t *rpl_buf;

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

Error send_response(Response res, size_t request_offset);

void wait_for_get_quota(void);
void wait_for_set_quota(void);
void wait_for_derive_quota(void);
ActId wait_for_act_init(void);
void wait_for_translate(void);
void wait_for_act_start(void);
Error wait_for_reply(void);
Error snd_rcv_sidecall_exit(ActId aid, uint64_t code);
Error snd_rcv_sidecall_lx_act(void);

#endif // SIDECALLS_H