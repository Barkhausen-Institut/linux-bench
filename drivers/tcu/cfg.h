#ifndef TCU_CFG_H
#define TCU_CFG_H

#include "tculib.h"

#define MAX_TILES          64
#define MAX_CHIPS          2

#define RBUF_STD_ADDR      0xd0000000

#define MEM_OFFSET         0x10000000
#define ENV_START          (MEM_OFFSET + 0x1000)

#define TILEMUX_START      (MEM_OFFSET + 0x3000)
#define TILEMUX_RBUF_SPACE (MEM_OFFSET + 0x2000)
#define TMUP_RBUF_ADDR     (TILEMUX_RBUF_SPACE + KPEX_RBUF_SIZE)

#define KPEX_RBUF_ORD      6
#define KPEX_RBUF_SIZE     (1 << KPEX_RBUF_ORD)

#define TMUP_RBUF_ORD      7
#define TMUP_RBUF_SIZE     (1 << TMUP_RBUF_ORD)

#endif // TCU_CFG_H
