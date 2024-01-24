#ifndef TCU_GLOBADDR_H
#define TCU_GLOBADDR_H

#include <linux/types.h>

#include "cfg.h"
#include "tculib.h"

typedef uint64_t Phys;
typedef uint64_t GlobAddr;

#define TILE_SHIFT  49
#define TILE_OFFSET 0x4000

static inline GlobAddr phys_to_glob(struct tcu_device *tcu, Phys addr) {
    EpId ep;
    EpInfo info;
    uint64_t offset;
    GlobAddr res;
    BUG_ON(addr > 0xffffffff);
    addr -= MEM_OFFSET;
    ep = (addr >> 30) & 0x3;
    offset = addr & 0x3fffffff;
    info = tcu_unpack_mem_ep(tcu, ep);
    BUG_ON(info.size == 0); // must be a memory EP
    tcu_print_ep_info(tcu, LOG_MEM, ep, info);
    res = ((TILE_OFFSET + (GlobAddr)info.tid) << TILE_SHIFT) | (offset + info.addr);
    tculog(LOG_MEM, tcu->dev, "Translated %#llx to %#llx\n", addr, res);
    return res;
}

static inline Phys glob_to_phys(struct tcu_device *tcu, GlobAddr glob) {
    EpId ep;
    EpInfo info;
    TileId tile;
    uint64_t offset;

    if(glob < ((GlobAddr)TILE_OFFSET << TILE_SHIFT)) {
        tculog(LOG_MEM, tcu->dev, "Translated %#llx to %#llx\n", glob, glob);
        return glob;
    }

    tile = (glob >> TILE_SHIFT) - TILE_OFFSET;
    offset = glob & (((GlobAddr)1 << TILE_SHIFT) - 1);

    // find memory EP that contains the address
    for(ep = 0; ep < PMEM_PROT_EPS; ++ep) {
        info = tcu_unpack_mem_ep(tcu, ep);

        // ignore non-memory EPs
        if(info.size == 0)
            continue;

        if(info.tid == tile && offset >= info.addr && offset < info.addr + info.size) {
            // TODO validate access permissions?
            Phys phys = ep << 30 | (MEM_OFFSET + (offset - info.addr));
            tculog(LOG_MEM, tcu->dev, "Translated %#llx to %#llx\n", glob, phys);
            return phys;
        }
    }

    tculog(LOG_MEM, tcu->dev, "Translation of %#llx failed\n", glob);
    return 0;
}

#endif // TCU_GLOBADDR_H
