#include "tculib.h"

Error insert_tlb(uint16_t asid, uint64_t virt, uint64_t phys, uint8_t perm)
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
    //  asid, virt, phys, perm);
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

Error xchg_activity(Reg actid)
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

Error perform_send_reply(uint64_t msg_addr, Reg cmd)
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

Error send_aligned(EpId ep, uint8_t *msg, size_t len, Label reply_lbl, EpId reply_ep)
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

Error reply_aligned(EpId ep, uint8_t *reply, size_t len, size_t msg_off)
{
    Reg reply_addr = (Reg)reply;
    write_unpriv_reg(UnprivReg_DATA_ADDR, reply_addr);
    write_unpriv_reg(UnprivReg_DATA_SIZE, (Reg)len);
    return perform_send_reply(reply_addr,
                  build_cmd(ep, CmdOpCode_REPLY, (Reg)msg_off));
}

// returns ~(size_t)0 if there is no message or there was an error
size_t fetch_msg(EpId ep)
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

Error ack_msg(EpId ep, size_t msg_off)
{
    mb();
    write_unpriv_reg(UnprivReg_COMMAND,
             build_cmd(ep, CmdOpCode_ACK_MSG, (Reg)msg_off));
    return get_unpriv_error();
}

void print_ep_info(EpId ep, EpInfo i)
{
    pr_info("PMP EP %llu (offset: %#llx, size: %#llx, perm: %#x)\n", ep,
        i.addr, i.size, i.perm);
}

EpInfo unpack_mem_ep(EpId ep)
{
    Reg r0 = read_ep_reg(ep, 0);
    Reg r1 = read_ep_reg(ep, 1);
    Reg r2 = read_ep_reg(ep, 2);
    TileId tid = (r0 >> 23) & 0xff; // TODO: this only works on gem5
    Perm perm = (r0 >> 19) & 0x3;
    BUG_ON((r0 & 0x7) != 0x3); // ep must be a memory ep
    return (EpInfo){ .tid = tid, .addr = r1, .size = r2, .perm = perm };
}
