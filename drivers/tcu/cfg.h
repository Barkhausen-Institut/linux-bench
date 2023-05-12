#ifndef TCU_CFG_H
#define TCU_CFG_H

#include "tculib.h"

#define MAX_TILES 64
#define MAX_CHIPS 2

#define RBUF_STD_ADDR 0xd0000000

#define MEM_OFFSET 0x10000000
#define ENV_START (MEM_OFFSET + 0x8)

#define STD_RBUF_ADDR (MEM_OFFSET + 2 * PAGE_SIZE)
#define STD_RBUF_SIZE PAGE_SIZE

#define TILEMUX_START(tcu) (is_gem5(tcu) ? (MEM_OFFSET + 0x200000) : MEM_OFFSET)
#define TILEMUX_RBUF_SPACE(tcu) (TILEMUX_START(tcu) + 0xd00000)
#define TMUP_RBUF_ADDR(tcu) (TILEMUX_RBUF_SPACE(tcu) + KPEX_RBUF_SIZE)

#define KPEX_RBUF_ORD 6
#define KPEX_RBUF_SIZE (1 << KPEX_RBUF_ORD)

#define TMUP_RBUF_ORD 7
#define TMUP_RBUF_SIZE (1 << TMUP_RBUF_ORD)

#endif // TCU_CFG_H
