#ifndef TCU_GLOBADDR_H
#define TCU_GLOBADDR_H

#include "tculib.h"
#include "cfg.h"

#include <linux/types.h>

typedef uint64_t Phys;
typedef uint64_t GlobAddr;

#define TILE_SHIFT 49
#define TILE_OFFSET 0x4000

static inline GlobAddr phys_to_glob(Phys addr)
{
	EpId ep;
	EpInfo info;
	uint64_t offset;
	GlobAddr res;
	BUG_ON(addr > 0xffffffff);
	addr -= MEM_OFFSET;
	ep = (addr >> 30) & 0x3;
	offset = addr & 0x3fffffff;
	info = unpack_mem_ep(ep);
	print_ep_info(ep, info);
	res = ((TILE_OFFSET + (GlobAddr)info.tid) << TILE_SHIFT) |
	      (offset + info.addr);
	pr_info("Translated %#llx to %#llx\n", addr, res);
	return res;
}

#endif // TCU_GLOBADDR_H
