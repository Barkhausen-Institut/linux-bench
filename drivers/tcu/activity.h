#ifndef ACTIVITY_H
#define ACTIVITY_H

#include "tculib.h"

struct m3_activity {
    ActId id;
    pid_t pid;
    struct m3_activity *next;

    void *env;
    phys_addr_t env_phys;

    void *std_app_buf;
    phys_addr_t std_app_buf_phys;

    Reg cur_act;
    Reg tcu_regs[4];
};

int create_activity(struct tcu_device *tcu, ActId id);
struct m3_activity *id_to_activity(struct tcu_device *tcu, ActId id);
struct m3_activity *pid_to_activity(struct tcu_device *tcu, pid_t pid);
struct m3_activity *wait_activity(struct tcu_device *tcu);
void start_activity(struct tcu_device *tcu, struct m3_activity *act, pid_t pid);
void switch_activity(struct tcu_device *tcu, struct m3_activity *p_act, struct m3_activity *n_act);
void save_activity(struct tcu_device *tcu, struct m3_activity *act);
void restore_activity(struct tcu_device *tcu, struct m3_activity *act);
void remove_activity(struct tcu_device *tcu, struct m3_activity *act);

#endif
