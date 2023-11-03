#ifndef TCU_SIDECALLS_H
#define TCU_SIDECALLS_H

#include <linux/types.h>

#include "tculib.h"

void sidecalls_init(struct tcu_device *tcu);
void sidecalls_handle(struct tcu_device *tcu, Reg our_act);
Error sidecalls_send_exit(struct tcu_device *tcu, ActId aid, uint64_t code);

#endif // TCU_SIDECALLS_H
