#ifndef TCU_ENVDATA_H
#define TCU_ENVDATA_H

#include <linux/types.h>

#include "cfg.h"

typedef struct {
    // boot env
    uint64_t platform;
    uint64_t tile_id;
    uint64_t tile_desc;
    uint64_t argc;
    uint64_t argv;
    uint64_t envp;
    uint64_t kenv;
    uint64_t raw_tile_count;
    uint64_t raw_tile_ids[MAX_TILES * MAX_CHIPS];

    // set by TileMux
    uint64_t shared;

    // m3 env
    uint64_t sp;
    uint64_t entry;
    uint64_t lambda;
    uint64_t heap_size;
    uint64_t first_std_ep;
    uint64_t first_sel;
    uint64_t act_id;

    uint64_t rmng_sel;
    uint64_t pager_sess;
    uint64_t pager_sgate;

    uint64_t mounts_addr;
    uint64_t mounts_len;

    uint64_t fds_addr;
    uint64_t fds_len;

    uint64_t data_addr;
    uint64_t data_len;
} EnvData;

#endif // TCU_ENVDATA_H
