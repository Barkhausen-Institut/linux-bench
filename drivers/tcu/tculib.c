#include "tculib.h"

typedef enum {
    /// Stores the privileged flag (for now)
    ExtReg_FEATURES = 0x0,
    /// Stores the tile description
    ExtReg_TILE_DESC = 0x1,
    /// For external commands
    ExtReg_CMD = 0x2,
    /// The global address of the EP region
    ExtReg_EPS_ADDR = 0x3,
    /// The size of the EP region in bytes
    ExtReg_EPS_SIZE = 0x4,
} ExtReg;

typedef enum {
    /// For core requests
    PrivReg_CORE_REQ = 0x0,
    /// Controls the privileged interface
    PrivReg_PRIV_CTRL = 0x1,
    /// For privileged commands
    PrivReg_PRIV_CMD = 0x2,
    /// The argument for privileged commands
    PrivReg_PRIV_CMD_ARG = 0x3,
    /// The current activity
    PrivReg_CUR_ACT = 0x4,
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
    /// Used to fetch IRQ requests
    PrivCmdOpCode_FETCH_IRQ = 7,
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

static inline TileId tcu_nocid_to_tileid(struct tcu_device *tcu, uint16_t tile) {
    size_t i;
    for(i = 0; i < MAX_CHIPS * MAX_TILES; ++i) {
        if(tcu->tile_ids[i] == tile) {
            uint8_t chip = i / MAX_TILES;
            uint8_t tile = i % MAX_TILES;
            return (chip << 8) | tile;
        }
    }
    BUG_ON(true);
}

static inline Reg tcu_read_ep_reg(struct tcu_device *tcu, EpId ep, size_t reg) {
    if(tcu->tcu_version.major < 3)
        return ioread64(tcu->unpriv_base + EXT_REGS(tcu) + UNPRIV_REGS + EP_REGS(tcu) * ep + reg);
    return ioread64((tcu->unpriv_base + (MMIO_EPS_ADDR - MMIO_UNPRIV_ADDR) / sizeof(Reg)) +
                    EP_REGS(tcu) * ep + reg);
}

static inline Reg tcu_read_ext_reg(struct tcu_device *tcu, unsigned int index) {
    return ioread64(tcu->unpriv_base + index);
}

static inline void tcu_write_unpriv_reg(struct tcu_device *tcu, unsigned int index, Reg val) {
    iowrite64(val, tcu->unpriv_base + EXT_REGS(tcu) + index);
}

static inline Reg tcu_read_unpriv_reg(struct tcu_device *tcu, unsigned int index) {
    return ioread64(tcu->unpriv_base + EXT_REGS(tcu) + index);
}

static inline void tcu_write_priv_reg(struct tcu_device *tcu, unsigned int index, Reg val) {
    iowrite64(val, tcu->priv_base + index);
}

static inline Reg tcu_read_priv_reg(struct tcu_device *tcu, unsigned int index) {
    return ioread64(tcu->priv_base + index);
}

static inline Error tcu_get_unpriv_error(struct tcu_device *tcu) {
    Reg cmd;
    while(true) {
        cmd = tcu_read_unpriv_reg(tcu, UnprivReg_COMMAND);
        if((cmd & 0xf) == CmdOpCode_IDLE) {
            return (Error)((cmd >> 20) & 0x1f);
        }
    }
}

static inline Error tcu_get_priv_error(struct tcu_device *tcu) {
    Reg cmd;
    while(true) {
        cmd = tcu_read_priv_reg(tcu, PrivReg_PRIV_CMD);
        if((cmd & 0xf) == PrivCmdOpCode_IDLE) {
            return (Error)((cmd >> 4) & 0xf);
        }
    }
}

static inline Reg tcu_build_cmd(EpId ep, CmdOpCode cmd, Reg arg) {
    return (arg << 25) | ((Reg)ep << 4) | cmd;
}

struct tcu_version tcu_version(struct tcu_device *tcu) {
    Reg features = tcu_read_ext_reg(tcu, ExtReg_FEATURES);
    return (struct tcu_version){
        .major = (features >> 32) & 0xFFFF,
        .minor = (features >> 48) & 0xFF,
        .patch = (features >> 56) & 0xFF,
    };
}

size_t tcu_endpoints_size(struct tcu_device *tcu) {
    if(tcu->tcu_version.major < 3)
        return tcu_is_gem5(tcu) ? 192 : 128;
    return tcu_read_ext_reg(tcu, ExtReg_EPS_SIZE);
}

Error tcu_tlb_insert(struct tcu_device *tcu, uint16_t asid, uint64_t virt, uint64_t phys,
                     uint8_t perm) {
    Reg cmd;
    Error e;
    uint32_t tcu_flags = 0;
    if(perm & PAGE_R)
        tcu_flags |= 1;
    if(perm & PAGE_W)
        tcu_flags |= 2;
    if(perm & PAGE_FIXED)
        tcu_flags |= 4;

    if(perm & PAGE_L) {
        phys = phys | ((virt & (LPAGE_SIZE - 1)) & ~(uint64_t)PAGE_MASK);
    }

    tculog(LOG_MEM, tcu->dev, "TLB insert: asid=%#hx, virt=%#llx, phys=%#llx, perm=%#x\n", asid,
           virt, phys, perm);

    BUG_ON(phys >> 32 != 0);
    tcu_write_priv_reg(tcu, PrivReg_PRIV_CMD_ARG, virt & PAGE_MASK);
    mb();
    cmd = ((Reg)asid << 41) | ((phys & PAGE_MASK) << 9) | (tcu_flags << 9) | PrivCmdOpCode_INS_TLB;
    tcu_write_priv_reg(tcu, PrivReg_PRIV_CMD, cmd);
    e = tcu_get_priv_error(tcu);
    if(e)
        tculog(LOG_ERR, tcu->dev, "failed to insert tlb entry, got error %s\n", error_to_str(e));
    return e;
}

Error tcu_tlb_invalidate(struct tcu_device *tcu) {
    Error e;
    tcu_write_priv_reg(tcu, PrivReg_PRIV_CMD, PrivCmdOpCode_INV_TLB);
    e = tcu_get_priv_error(tcu);
    if(e)
        tculog(LOG_ERR, tcu->dev, "failed to invalidate TLB, got error %s\n", error_to_str(e));
    return e;
}

Error tcu_abort_cmd(struct tcu_device *tcu, Reg *cmd) {
    Reg priv_cmd;
    Error err;

    // save the old value before aborting
    *cmd = tcu_read_unpriv_reg(tcu, UnprivReg_COMMAND);
    // ensure that we read the command register before the abort has been executed
    mb();
    tcu_write_priv_reg(tcu, PrivReg_PRIV_CMD, PrivCmdOpCode_ABORT_CMD);

    while(1) {
        priv_cmd = tcu_read_priv_reg(tcu, PrivReg_PRIV_CMD);
        if((priv_cmd & 0xF) == PrivCmdOpCode_IDLE) {
            err = (priv_cmd >> 4) & 0x1F;
            if(err != 0)
                return err;

            if((priv_cmd >> 9) == 0) {
                // if the command was finished successfully, use the current command register
                // to ensure that we don't forget the error code
                *cmd = tcu_read_unpriv_reg(tcu, UnprivReg_COMMAND);
                return Error_None;
            }

            // otherwise use the old one to repeat it later
            return Error_None;
        }
    }
}

Reg tcu_xchg_activity(struct tcu_device *tcu, Reg new_act) {
    Error e;
    tcu_write_priv_reg(tcu, PrivReg_PRIV_CMD, (new_act << 9) | PrivCmdOpCode_XCHG_ACT);
    e = tcu_get_priv_error(tcu);
    BUG_ON(e != Error_None);
    return tcu_read_priv_reg(tcu, PrivReg_PRIV_CMD_ARG) & 0xFFFFFFFF;
}

bool tcu_get_cu_req(struct tcu_device *tcu, struct cureq_foreign_msg *core_req) {
    Reg req = tcu_read_priv_reg(tcu, PrivReg_CORE_REQ);
    if((req & 0x7) == 0x2) {
        core_req->act = req >> 48;
        core_req->ep = (req >> 3) & 0xFFFF;
        return true;
    }
    return false;
}

void tcu_set_cu_resp(struct tcu_device *tcu) {
    tcu_write_priv_reg(tcu, PrivReg_CORE_REQ, 0x1);
}

#define READ_PERM 0x1

static Error tcu_send_reply(struct tcu_device *tcu, uint64_t msg_addr, Reg cmd) {
    Error e;
    while(true) {
        tcu_write_unpriv_reg(tcu, UnprivReg_COMMAND, cmd);
        e = tcu_get_unpriv_error(tcu);
        if(e == Error_TranslationFault) {
            // messages sent from the device driver are always sidecalls
            tcu_tlb_insert(tcu, PRIV_AID, msg_addr, __pa(msg_addr), READ_PERM);
            continue;
        }
        return e;
    }
}

Error tcu_send_aligned(struct tcu_device *tcu, EpId ep, uint8_t *msg, size_t len, Label reply_lbl,
                       EpId reply_ep) {
    Reg msg_addr = (Reg)msg;
    tcu_write_unpriv_reg(tcu, UnprivReg_DATA_ADDR, msg_addr);
    tcu_write_unpriv_reg(tcu, UnprivReg_DATA_SIZE, (Reg)len);
    if(reply_lbl != 0) {
        tcu_write_unpriv_reg(tcu, UnprivReg_ARG1, (Reg)reply_lbl);
    }
    return tcu_send_reply(tcu, msg_addr, tcu_build_cmd(ep, CmdOpCode_SEND, (Reg)reply_ep));
}

Error tcu_reply_aligned(struct tcu_device *tcu, EpId ep, uint8_t *reply, size_t len,
                        size_t msg_off) {
    Reg reply_addr = (Reg)reply;
    tcu_write_unpriv_reg(tcu, UnprivReg_DATA_ADDR, reply_addr);
    tcu_write_unpriv_reg(tcu, UnprivReg_DATA_SIZE, (Reg)len);
    return tcu_send_reply(tcu, reply_addr, tcu_build_cmd(ep, CmdOpCode_REPLY, (Reg)msg_off));
}

// returns ~(size_t)0 if there is no message or there was an error
size_t tcu_fetch_msg(struct tcu_device *tcu, EpId ep) {
    Error e;
    tcu_write_unpriv_reg(tcu, UnprivReg_COMMAND, tcu_build_cmd(ep, CmdOpCode_FETCH_MSG, 0));
    e = tcu_get_unpriv_error(tcu);
    if(e != Error_None) {
        tculog(LOG_ERR, tcu->dev, "tcu_fetch_msg: got error %s\n", error_to_str(e));
        return ~(size_t)0;
    }
    return tcu_read_unpriv_reg(tcu, UnprivReg_ARG1);
}

bool tcu_has_msgs(struct tcu_device *tcu) {
    Reg cur_act = tcu_read_priv_reg(tcu, PrivReg_CUR_ACT);
    return (cur_act >> 16) != 0;
}

Error tcu_ack_msg(struct tcu_device *tcu, EpId ep, size_t msg_off) {
    mb();
    tcu_write_unpriv_reg(tcu, UnprivReg_COMMAND,
                         tcu_build_cmd(ep, CmdOpCode_ACK_MSG, (Reg)msg_off));
    return tcu_get_unpriv_error(tcu);
}

void tcu_ack_irq(struct tcu_device *tcu, int irq) {
    if(!tcu_is_gem5(tcu)) {
        // TODO: temporary (add to spec and make gem5 behave the same)
        tcu_write_priv_reg(tcu, (0x1030 + (irq - 1)) / sizeof(Reg), 0);
    }
    else {
        Error e;
        tcu_write_priv_reg(tcu, PrivReg_PRIV_CMD, PrivCmdOpCode_FETCH_IRQ);
        e = tcu_get_priv_error(tcu);
        BUG_ON(e != Error_None);
    }
}

void tcu_print_ep_info(struct tcu_device *tcu, int flag, EpId ep, EpInfo i) {
    tculog(flag, tcu->dev, "PMP EP %llu (offset: %#llx, size: %#llx, perm: %#x)\n", ep, i.addr,
           i.size, i.perm);
}

EpInfo tcu_unpack_mem_ep(struct tcu_device *tcu, EpId ep) {
    EpInfo info;
    Reg r0 = tcu_read_ep_reg(tcu, ep, 0);
    Reg r1 = tcu_read_ep_reg(tcu, ep, 1);
    Reg r2 = tcu_read_ep_reg(tcu, ep, 2);
    if((r0 & 0x7) != 0x3)
        info.size = 0;
    else {
        info.tid = tcu_nocid_to_tileid(tcu, (r0 >> 23) & 0x3fff);
        info.perm = (r0 >> 19) & 0x3;
        info.addr = r1;
        info.size = r2;
    }
    return info;
}

void tcu_save_state(struct tcu_device *tcu, TCUState *state) {
    Error e;

    // abort the current command, if there is any
    e = tcu_abort_cmd(tcu, &state->cmd);
    BUG_ON(e != Error_None);

    state->arg1 = tcu_read_unpriv_reg(tcu, UnprivReg_ARG1);
    state->addr = tcu_read_unpriv_reg(tcu, UnprivReg_DATA_ADDR);
    state->size = tcu_read_unpriv_reg(tcu, UnprivReg_DATA_SIZE);
}

void tcu_restore_state(struct tcu_device *tcu, const TCUState *state) {
    tcu_write_unpriv_reg(tcu, UnprivReg_ARG1, state->arg1);
    tcu_write_unpriv_reg(tcu, UnprivReg_DATA_ADDR, state->addr);
    tcu_write_unpriv_reg(tcu, UnprivReg_DATA_SIZE, state->size);
    // always restore the command register, because the previous activity might have an error code
    // in the command register or similar.
    mb();
    tcu_write_unpriv_reg(tcu, UnprivReg_COMMAND, state->cmd);
}

void tcu_print(struct tcu_device *tcu, const char *str) {
    // make sure the string is aligned for the 8-byte accesses below
    static __attribute__((aligned(8))) char aligned_buf[PRINT_REGS * sizeof(Reg)];

    const char *aligned_str;
    size_t regCount;
    Reg *buffer;
    const Reg *rstr, *end;
    size_t len;

    len = strlen(str);
    len = MIN(len, PRINT_REGS * sizeof(Reg) - 1);

    aligned_str = str;
    if((uintptr_t)aligned_str & 7) {
        memcpy(aligned_buf, str, len);
        aligned_str = aligned_buf;
    }

    if(tcu->tcu_version.major < 3)
        regCount = EXT_REGS(tcu) + UNPRIV_REGS + TOTAL_EPS(tcu) * EP_REGS(tcu);
    else
        regCount = EXT_REGS(tcu) + UNPRIV_REGS;
    buffer = tcu->unpriv_base + regCount;
    rstr = (const Reg *)(aligned_str);
    end = (const Reg *)(aligned_str + len);
    while(rstr < end) {
        iowrite64(*rstr, buffer);
        buffer++;
        rstr++;
    }

    tcu_write_unpriv_reg(tcu, UnprivReg_PRINT, len);
    // wait until the print was carried out
    while(tcu_read_unpriv_reg(tcu, UnprivReg_PRINT) != 0)
        ;
}

void tcu_printf(struct tcu_device *tcu, const char *fmt, ...) {
    __attribute__((aligned(8))) char buffer[PRINT_REGS * sizeof(Reg)];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    tcu_print(tcu, buffer);
    va_end(args);
}
