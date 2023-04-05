#ifndef CFG_H
#define CFG_H

#define MAX_TILES          64
#define MAX_CHIPS          2

#define RBUF_STD_ADDR      0xd0000000

#define MEM_OFFSET         0x10000000
#define ENV_START          (MEM_OFFSET + 0x8)

#define TILEMUX_START      (MEM_OFFSET + 0x200000)
#define TILEMUX_RBUF_SPACE (TILEMUX_START + 0xd00000)

#define KPEX_RBUF_ORD      6
#define KPEX_RBUF_SIZE     (1 << KPEX_RBUF_ORD)

#define SIDE_RBUF_ADDR     (TILEMUX_RBUF_SPACE + KPEX_RBUF_SIZE)

#endif // CFG_H