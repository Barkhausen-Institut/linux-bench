#include "tculib.h"

Error insert_tlb(struct tcu_device *tcu, uint16_t asid, uint64_t virt,
				 uint64_t phys, uint8_t perm)
{
	Reg cmd;
	Error e;
	uint32_t tcu_flags = 0;
	if (perm & 1)
		tcu_flags |= 1;
	if (perm & 2)
		tcu_flags |= 2;
	if (perm & 16)
		tcu_flags |= 4;

	if (perm & 8)
		phys = phys |
		       ((virt & (LPAGE_SIZE - 1)) & ~(uint64_t)PAGE_MASK);

	// pr_info("tlb insert: asid: %#hx, virt: %#llx, phys: %#llx, perm: %#x\n",
	//  asid, virt, phys, perm);
	BUG_ON(phys >> 32 != 0);
	write_priv_reg(tcu, PrivReg_PRIV_CMD_ARG, virt & PAGE_MASK);
	mb();
	cmd = ((Reg)asid << 41) | ((phys & PAGE_MASK) << 9) | (tcu_flags << 9) |
	      PrivCmdOpCode_INS_TLB;
	write_priv_reg(tcu, PrivReg_PRIV_CMD, cmd);
	e = get_priv_error(tcu);
	if (e) {
		dev_err(tcu->dev, "failed to insert tlb entry, got error %s\n",
		       error_to_str(e));
	}
	return e;
}

Error abort_command(struct tcu_device *tcu, Reg *cmd) {
	Reg priv_cmd;
	Error err;

    // save the old value before aborting
	*cmd = read_unpriv_reg(tcu, UnprivReg_COMMAND);
    // ensure that we read the command register before the abort has been executed
	mb();
    write_priv_reg(tcu, PrivReg_PRIV_CMD, PrivCmdOpCode_ABORT_CMD);

    while(1) {
        priv_cmd = read_priv_reg(tcu, PrivReg_PRIV_CMD);
        if((priv_cmd & 0xF) == PrivCmdOpCode_IDLE) {
            err = (priv_cmd >> 4) & 0x1F;
            if(err != 0)
            	return err;

            if((priv_cmd >> 9) == 0) {
                // if the command was finished successfully, use the current command register
                // to ensure that we don't forget the error code
                *cmd = read_unpriv_reg(tcu, UnprivReg_COMMAND);
                return Error_None;
            }

            // otherwise use the old one to repeat it later
            return Error_None;
        }
    }
}

Reg xchg_activity(struct tcu_device *tcu, Reg new_act)
{
	Error e;
	write_priv_reg(tcu, PrivReg_PRIV_CMD, (new_act << 9) | PrivCmdOpCode_XCHG_ACT);
	e = get_priv_error(tcu);
	BUG_ON(e != Error_None);
	return read_priv_reg(tcu, PrivReg_PRIV_CMD_ARG);
}

bool get_core_req(struct tcu_device *tcu, struct corereq_foreign_msg *core_req)
{
	Reg req = read_priv_reg(tcu, PrivReg_CORE_REQ);
	if((req & 0x7) == 0x2) {
		core_req->act = req >> 48;
		core_req->ep = (req >> 3) & 0xFFFF;
		return true;
	}
	return false;
}

void set_foreign_resp(struct tcu_device *tcu)
{
    write_priv_reg(tcu, PrivReg_CORE_REQ, 0x1);
}

#define READ_PERM 0x1

Error perform_send_reply(struct tcu_device *tcu, uint64_t msg_addr, Reg cmd)
{
	Error e;
	while (true) {
		write_unpriv_reg(tcu, UnprivReg_COMMAND, cmd);
		e = get_unpriv_error(tcu);
		if (e == Error_TranslationFault) {
			// messages sent from the device driver are always sidecalls
			insert_tlb(tcu, PRIV_AID, msg_addr, __pa(msg_addr), READ_PERM);
			continue;
		}
		return e;
	}
}

Error send_aligned(struct tcu_device *tcu, EpId ep, uint8_t *msg, size_t len,
				   Label reply_lbl, EpId reply_ep)
{
	Reg msg_addr = (Reg)msg;
	write_unpriv_reg(tcu, UnprivReg_DATA_ADDR, msg_addr);
	write_unpriv_reg(tcu, UnprivReg_DATA_SIZE, (Reg)len);
	if (reply_lbl != 0) {
		write_unpriv_reg(tcu, UnprivReg_ARG1, (Reg)reply_lbl);
	}
	return perform_send_reply(tcu, msg_addr,
				  build_cmd(ep, CmdOpCode_SEND, (Reg)reply_ep));
}

Error reply_aligned(struct tcu_device *tcu, EpId ep, uint8_t *reply, size_t len, size_t msg_off)
{
	Reg reply_addr = (Reg)reply;
	write_unpriv_reg(tcu, UnprivReg_DATA_ADDR, reply_addr);
	write_unpriv_reg(tcu, UnprivReg_DATA_SIZE, (Reg)len);
	return perform_send_reply(tcu, reply_addr,
				  build_cmd(ep, CmdOpCode_REPLY, (Reg)msg_off));
}

// returns ~(size_t)0 if there is no message or there was an error
size_t fetch_msg(struct tcu_device *tcu, EpId ep)
{
	Error e;
	write_unpriv_reg(tcu, UnprivReg_COMMAND,
			 build_cmd(ep, CmdOpCode_FETCH_MSG, 0));
	e = get_unpriv_error(tcu);
	if (e != Error_None) {
		dev_err(tcu->dev, "fetch_msg: got error %s\n", error_to_str(e));
		return ~(size_t)0;
	}
	return read_unpriv_reg(tcu, UnprivReg_ARG1);
}

Error ack_msg(struct tcu_device *tcu, EpId ep, size_t msg_off)
{
	mb();
	write_unpriv_reg(tcu, UnprivReg_COMMAND,
			 build_cmd(ep, CmdOpCode_ACK_MSG, (Reg)msg_off));
	return get_unpriv_error(tcu);
}

void ack_irq(struct tcu_device *tcu, int irq)
{
	if(!is_gem5(tcu)) {
	    // TODO: temporary (add to spec and make gem5 behave the same)
		write_priv_reg(tcu, (0x1030 + (irq - 1)) / sizeof(Reg), 0);
	}
	else {
		Reg irq = read_priv_reg(tcu, PrivReg_CLEAR_IRQ);
		write_priv_reg(tcu, PrivReg_CLEAR_IRQ, irq);
	}
}

void print_ep_info(struct tcu_device *tcu, EpId ep, EpInfo i)
{
	dev_info(tcu->dev, "PMP EP %llu (offset: %#llx, size: %#llx, perm: %#x)\n", ep,
		i.addr, i.size, i.perm);
}

EpInfo unpack_mem_ep(struct tcu_device *tcu, EpId ep)
{
	Reg r0 = read_ep_reg(tcu, ep, 0);
	Reg r1 = read_ep_reg(tcu, ep, 1);
	Reg r2 = read_ep_reg(tcu, ep, 2);
	TileId tid = nocid_to_tileid(tcu, (r0 >> 23) & 0x3fff);
	Perm perm = (r0 >> 19) & 0x3;
	BUG_ON((r0 & 0x7) != 0x3); // ep must be a memory ep
	return (EpInfo){ .tid = tid, .addr = r1, .size = r2, .perm = perm };
}

void tcu_print(struct tcu_device *tcu, const char *str)
{
	// make sure the string is aligned for the 8-byte accesses below
	static __attribute__((
		aligned(8))) char aligned_buf[PRINT_REGS * sizeof(Reg)];

	const char *aligned_str;
	size_t regCount;
	Reg *buffer;
	const Reg *rstr, *end;
	size_t len;

	len = strlen(str);
	len = MIN(len, PRINT_REGS * sizeof(Reg) - 1);

	aligned_str = str;
	if ((uintptr_t)aligned_str & 7) {
		memcpy(aligned_buf, str, len);
		aligned_str = aligned_buf;
	}

	regCount = EXT_REGS + UNPRIV_REGS + TOTAL_EPS(tcu) * EP_REGS;
	buffer = tcu->unpriv_base + regCount;
	rstr = (const Reg *)(aligned_str);
	end = (const Reg *)(aligned_str + len);
	while (rstr < end) {
		iowrite64(*rstr, buffer);
		buffer++;
		rstr++;
	}

	write_unpriv_reg(tcu, UnprivReg_PRINT, len);
	// wait until the print was carried out
	while (read_unpriv_reg(tcu, UnprivReg_PRINT) != 0)
		;
}

void tcu_printf(struct tcu_device *tcu, const char *fmt, ...)
{
	__attribute__((aligned(8))) char buffer[PRINT_REGS * sizeof(Reg)];
	va_list args;
	va_start(args, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, args);
	tcu_print(tcu, buffer);
	va_end(args);
}
