#ifndef TCULIB_H
#define TCULIB_H

#include "envdata.h"
#include "tcuerr.h"

#include <asm/barrier.h>
#include <linux/cdev.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/sched.h>

enum {
	LOG_INFO = 1,
	LOG_ERR = 2,
	LOG_ACT = 4,
	LOG_ACTSW = 8,
	LOG_MEM = 16,
	LOG_POLL = 32,
	LOG_IRQ = 64,
	LOG_SCALLS = 128,
};

static int tcu_log_level = LOG_INFO | LOG_ERR | LOG_ACT;

#define tculog(lvl, dev, fmt, ...)	do {			 \
	if (tcu_log_level & (lvl)) 						 \
		_dev_info(dev, dev_fmt(fmt), ##__VA_ARGS__); \
} while(0)

#define MIN(a, b) ((a) < (b) ? (a) : (b))

// privileged activity id
#define PRIV_AID 0xffff
// invalid activity id
#define INVAL_AID 0xfffe

#define INVALID_EP 0xffff

#define MMIO_UNPRIV_ADDR 0xf0000000
#define MMIO_UNPRIV_SIZE PAGE_SIZE
#define MMIO_PRIV_ADDR 0xf0001000
#define MMIO_PRIV_SIZE (1 * PAGE_SIZE)
#define MMIO_EPS_ADDR 0xf0002000
#define MMIO_EPS_MAXSIZE ((1 << 16) * EP_REGS * sizeof(Reg))
#define MMIO_ADDR MMIO_UNPRIV_ADDR
#define MMIO_SIZE (MMIO_UNPRIV_SIZE + MMIO_PRIV_SIZE + MMIO_EPS_MAXSIZE)

#define LPAGE_SIZE (1 << 21)

#define PMEM_PROT_EPS ((EpId)4)
/// The send EP for kernel calls from TileMux
#define KPEX_SEP (PMEM_PROT_EPS + 0)
/// The receive EP for kernel calls from TileMux
#define KPEX_REP (PMEM_PROT_EPS + 1)
/// The receive EP for sidecalls from the kernel for TileMux
#define TMSIDE_REP (PMEM_PROT_EPS + 2)

#define TOTAL_EPS(tcu) (tcu_is_gem5(tcu) ? 192 : 128)
/// The number of external registers
#define EXT_REGS 5
/// The number of unprivileged registers
#define UNPRIV_REGS 6
/// The number of registers per EP
#define EP_REGS 4
/// The number of print registers
#define PRINT_REGS 32

#define MAX_MSG_SIZE 512

#define SIZE_OF_MSG_HEADER 32

typedef uint64_t Reg;
typedef uint64_t EpId;
typedef uint64_t Label;
typedef uint16_t ActId;
typedef uint16_t TileId;
typedef uint32_t Perm;

struct m3_activity;

enum PageFlags {
	PAGE_R = 1,
	PAGE_W = 2,
	PAGE_X = 4,
	PAGE_L = 8,
	PAGE_FIXED = 16,
	PAGE_U = 32,
};

struct tcu_device {
	struct device *dev;
	unsigned int major;
	struct cdev cdev;
	struct class *dev_class;
	struct device *char_dev;
	int irq;
	spinlock_t lock;

	// start address of the unprivileged und privileged tcu mmio region
	Reg *unpriv_base;
	Reg *priv_base;

	uint8_t *snd_buf;
	// for receiving sidecalls from m3 kernel
	uint8_t *rcv_buf;
	// for receiving replies from m3 kernel
	uint8_t *rpl_buf;

	uint64_t tile_id;
	uint64_t platform;
	uint16_t tile_ids[MAX_CHIPS * MAX_TILES];

	struct task_struct *waiting_task;
	struct m3_activity *wake_act;
	int pending_wakeups;

	struct m3_activity *wait_list;
	struct m3_activity *run_list;
	struct m3_activity *cur_act;
	ActId cur_act_id;
};

typedef struct {
	TileId tid;
	uint64_t addr;
	uint64_t size;
	Perm perm;
} EpInfo;

typedef struct {
	Reg cmd;
	Reg arg1;
	Reg addr;
	Reg size;
} TCUState;

struct cureq_foreign_msg {
	ActId act;
	EpId ep;
};

static inline bool tcu_is_gem5(struct tcu_device *tcu)
{
	return tcu->platform == 0;
}

size_t tcu_endpoints_size(struct tcu_device *tcu);
Error tcu_tlb_insert(struct tcu_device *tcu, uint16_t asid, uint64_t virt, uint64_t phys, uint8_t perm);
Error tcu_tlb_invalidate(struct tcu_device *tcu);
Error tcu_abort_cmd(struct tcu_device *tcu, Reg *cmd);
Reg tcu_xchg_activity(struct tcu_device *tcu, Reg new_act);
bool tcu_get_cu_req(struct tcu_device *tcu, struct cureq_foreign_msg *core_req);
void tcu_set_cu_resp(struct tcu_device *tcu);
Error tcu_send_aligned(struct tcu_device *tcu, EpId ep, uint8_t *msg, size_t len, Label reply_lbl,
 					   EpId reply_ep);
Error tcu_reply_aligned(struct tcu_device *tcu, EpId ep, uint8_t *reply, size_t len, size_t msg_off);
// returns ~(size_t)0 if there is no message or there was an error
size_t tcu_fetch_msg(struct tcu_device *tcu, EpId ep);
bool tcu_has_msgs(struct tcu_device *tcu);
Error tcu_ack_msg(struct tcu_device *tcu, EpId ep, size_t msg_off);
void tcu_ack_irq(struct tcu_device *tcu, int irq);

void tcu_print_ep_info(struct tcu_device *tcu, int flag, EpId ep, EpInfo i);
EpInfo tcu_unpack_mem_ep(struct tcu_device *tcu, EpId ep);

void tcu_save_state(struct tcu_device *tcu, TCUState *state);
void tcu_restore_state(struct tcu_device *tcu, const TCUState *state);

void tcu_print(struct tcu_device *tcu, const char *str);
void tcu_printf(struct tcu_device *tcu, const char *fmt, ...);

#endif // TCULIB_H
