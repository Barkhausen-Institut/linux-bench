
#ifndef TCULIB_H
#define TCULIB_H

#include "tcu_error.h"

#include <linux/kernel.h>
#include <linux/io.h>
#include <asm/barrier.h>
#include <linux/printk.h>
#include <linux/sched.h>

typedef uint64_t Reg;
typedef uint64_t EpId;
typedef uint64_t Label;
typedef uint16_t ActId;
typedef uint8_t TileId;
typedef uint32_t Perm;

// privileged activity id
#define PRIV_AID 0xffff
// invalid activity id
#define INVAL_AID 0xfffe

#define MMIO_UNPRIV_ADDR 0xf0000000
#define MMIO_UNPRIV_SIZE (2 * PAGE_SIZE)
#define MMIO_PRIV_ADDR 0xf0002000
#define MMIO_PRIV_SIZE (2 * PAGE_SIZE)
#define MMIO_ADDR MMIO_UNPRIV_ADDR
#define MMIO_SIZE (MMIO_UNPRIV_SIZE + MMIO_PRIV_SIZE)

#define LPAGE_SIZE (1 << 21)

#define PMEM_PROT_EPS ((EpId)4)
/// The send EP for kernel calls from TileMux
#define KPEX_SEP (PMEM_PROT_EPS + 0)
/// The receive EP for kernel calls from TileMux
#define KPEX_REP (PMEM_PROT_EPS + 1)
/// The receive EP for sidecalls from the kernel for TileMux
#define TMSIDE_REP (PMEM_PROT_EPS + 2)

/// The number of external registers
#define EXT_REGS 2
/// The number of unprivileged registers
#define UNPRIV_REGS 6
/// The number of registers per EP
#define EP_REGS 3

#define MAX_MSG_SIZE 512

// start address of the unprivileged und privileged tcu mmio region
static Reg *unpriv_base = (Reg *)NULL;
static Reg *priv_base = (Reg *)NULL;

typedef enum PrivReg {
	/// For core requests
	PrivReg_CORE_REQ = 0x0,
	/// For privileged commands
	PrivReg_PRIV_CMD = 0x1,
	/// The argument for privileged commands
	PrivReg_PRIV_CMD_ARG = 0x2,
	/// The current activity
	PrivReg_CUR_ACT = 0x3,
	/// Used to ack IRQ requests
	PrivReg_CLEAR_IRQ = 0x4,
} PrivReg;

typedef enum {
	/// The idle command has no effect
	PrivCmdOpCode_IDLE = 0,
	/// Invalidate a single TLB entry
	PrivCmdOpCode_INV_PAGE = 1,
	/// Invalidate all TLB entries
	PrivCmdOpCode_INV_TLB = 2,
	/// Insert an entry into the TLB
	PrivCmdOpCode_INS_TLB = 3,
	/// Changes the activity
	PrivCmdOpCode_XCHG_ACT = 4,
	/// Sets the timer
	PrivCmdOpCode_SET_TIMER = 5,
	/// Abort the current command
	PrivCmdOpCode_ABORT_CMD = 6,
	/// Flushes and invalidates the cache
	PrivCmdOpCode_FLUSH_CACHE = 7,
} PrivCmdOpCode;

typedef enum {
	/// The idle command has no effect
	CmdOpCode_IDLE = 0x0,
	/// Sends a message
	CmdOpCode_SEND = 0x1,
	/// Replies to a message
	CmdOpCode_REPLY = 0x2,
	/// Reads from external memory
	CmdOpCode_READ = 0x3,
	/// Writes to external memory
	CmdOpCode_WRITE = 0x4,
	/// Fetches a message
	CmdOpCode_FETCH_MSG = 0x5,
	/// Acknowledges a message
	CmdOpCode_ACK_MSG = 0x6,
	/// Puts the CU to sleep
	CmdOpCode_SLEEP = 0x7,
} CmdOpCode;

typedef enum {
	/// Starts commands and signals their completion
	UnprivReg_COMMAND = 0x0,
	/// Specifies the data address
	UnprivReg_DATA_ADDR = 0x1,
	/// Specifies the data size
	UnprivReg_DATA_SIZE = 0x2,
	/// Specifies an additional argument
	UnprivReg_ARG1 = 0x3,
	/// The current time in nanoseconds
	UnprivReg_CUR_TIME = 0x4,
	/// Prints a line into the gem5 log
	UnprivReg_PRINT = 0x5,
} UnprivReg;

static void write_unpriv_reg(unsigned int index, Reg val)
{
	BUG_ON(unpriv_base == NULL);
	iowrite64(val, unpriv_base + EXT_REGS + index);
}

static Reg read_unpriv_reg(unsigned int index)
{
	BUG_ON(unpriv_base == NULL);
	return ioread64(unpriv_base + EXT_REGS + index);
}

static Reg read_ep_reg(EpId ep, size_t reg)
{
	BUG_ON(unpriv_base == NULL);
	return ioread64(unpriv_base + EXT_REGS + UNPRIV_REGS + EP_REGS * ep +
			reg);
}

static void write_priv_reg(unsigned int index, Reg val)
{
	BUG_ON(priv_base == NULL);
	iowrite64(val, priv_base + index);
}

static Reg read_priv_reg(unsigned int index)
{
	BUG_ON(priv_base == NULL);
	return ioread64(priv_base + index);
}

static Error get_unpriv_error(void)
{
	Reg cmd;
	while (true) {
		cmd = read_unpriv_reg(UnprivReg_COMMAND);
		if ((cmd & 0xf) == CmdOpCode_IDLE) {
			return (Error)((cmd >> 20) & 0x1f);
		}
	}
}

static Error get_priv_error(void)
{
	Reg cmd;
	while (true) {
		cmd = read_priv_reg(PrivReg_PRIV_CMD);
		if ((cmd & 0xf) == PrivCmdOpCode_IDLE) {
			return (Error)((cmd >> 4) & 0xf);
		}
	}
}

static Error insert_tlb(uint16_t asid, uint64_t virt, uint64_t phys,
			uint8_t perm)
{
	Reg cmd;
	Error e;
	uint32_t tcu_flags = 0;
	if(perm & 1)
		tcu_flags |= 1;
	if(perm & 2)
		tcu_flags |= 2;
	if(perm & 16)
		tcu_flags |= 4;

	if(perm & 8)
		phys = phys | ((virt & (LPAGE_SIZE - 1)) & ~(uint64_t)PAGE_MASK);

	// pr_info("tlb insert: asid: %#hx, virt: %#llx, phys: %#llx, perm: %#x\n",
	// 	asid, virt, phys, perm);
	BUG_ON(phys >> 32 != 0);
	write_priv_reg(PrivReg_PRIV_CMD_ARG, virt & PAGE_MASK);
	mb();
	cmd = ((Reg)asid << 41) | ((phys & PAGE_MASK) << 9) |
	      (tcu_flags << 9) | PrivCmdOpCode_INS_TLB;
	write_priv_reg(PrivReg_PRIV_CMD, cmd);
	e = get_priv_error();
	if (e) {
		pr_err("failed to insert tlb entry, got error %s\n",
		       error_to_str(e));
	}
	return e;
}

static Error xchg_activity(Reg actid)
{
	Error e;
	write_priv_reg(PrivReg_PRIV_CMD, (actid << 9) | PrivCmdOpCode_XCHG_ACT);
	e = get_priv_error();
	if (e) {
		pr_err("failed to exchange activities, got error: %s\n",
		       error_to_str(e));
	}
	// read_priv_reg(PrivReg_PRIV_CMD_ARG);
	return e;
}

#define READ_PERM 0x1

static Error perform_send_reply(uint64_t msg_addr, Reg cmd)
{
	Error e;
	while (true) {
		write_unpriv_reg(UnprivReg_COMMAND, cmd);
		e = get_unpriv_error();
		if (e == Error_TranslationFault) {
			// messages sent from the device driver are always sidecalls
			insert_tlb(0xffff, msg_addr, __pa(msg_addr), READ_PERM);
			continue;
		}
		return e;
	}
}

static Reg build_cmd(EpId ep, CmdOpCode cmd, Reg arg)
{
	return (arg << 25) | ((Reg)ep << 4) | cmd;
}

static Error send_aligned(EpId ep, uint8_t *msg, size_t len, Label reply_lbl,
			  EpId reply_ep)
{
	Reg msg_addr = (Reg)msg;
	write_unpriv_reg(UnprivReg_DATA_ADDR, msg_addr);
	write_unpriv_reg(UnprivReg_DATA_SIZE, (Reg)len);
	if (reply_lbl != 0) {
		write_unpriv_reg(UnprivReg_ARG1, (Reg)reply_lbl);
	}
	return perform_send_reply(msg_addr,
				  build_cmd(ep, CmdOpCode_SEND, (Reg)reply_ep));
}

static Error reply_aligned(EpId ep, uint8_t *reply, size_t len, size_t msg_off)
{
	Reg reply_addr = (Reg)reply;
	write_unpriv_reg(UnprivReg_DATA_ADDR, reply_addr);
	write_unpriv_reg(UnprivReg_DATA_SIZE, (Reg)len);
	return perform_send_reply(reply_addr,
				  build_cmd(ep, CmdOpCode_REPLY, (Reg)msg_off));
}

// returns ~(size_t)0 if there is no message or there was an error
static size_t fetch_msg(EpId ep)
{
	Error e;
	write_unpriv_reg(UnprivReg_COMMAND,
			 build_cmd(ep, CmdOpCode_FETCH_MSG, 0));
	e = get_unpriv_error();
	if (e != Error_None) {
		pr_err("fetch_msg: got error %s\n", error_to_str(e));
		return ~(size_t)0;
	}
	return read_unpriv_reg(UnprivReg_ARG1);
}

static Error ack_msg(EpId ep, size_t msg_off)
{
	mb();
	write_unpriv_reg(UnprivReg_COMMAND,
			 build_cmd(ep, CmdOpCode_ACK_MSG, (Reg)msg_off));
	return get_unpriv_error();
}

typedef struct {
	TileId tid;
	uint64_t addr;
	uint64_t size;
	Perm perm;
} EpInfo;

static void print_ep_info(EpId ep, EpInfo i)
{
	pr_info("PMP EP %llu (offset: %#llx, size: %#llx, perm: %#x)\n", ep,
		i.addr, i.size, i.perm);
}

static EpInfo unpack_mem_ep(EpId ep)
{
	Reg r0 = read_ep_reg(ep, 0);
	Reg r1 = read_ep_reg(ep, 1);
	Reg r2 = read_ep_reg(ep, 2);
	TileId tid = (r0 >> 23) & 0xff; // TODO: this only works on gem5
	Perm perm = (r0 >> 19) & 0x3;
	BUG_ON((r0 & 0x7) != 0x3); // ep must be a memory ep
	return (EpInfo){ .tid = tid, .addr = r1, .size = r2, .perm = perm };
}

#endif // TCULIB_H