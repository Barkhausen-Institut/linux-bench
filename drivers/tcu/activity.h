#ifndef ACTIVITY_H
#define ACTIVITY_H

#include <linux/wait.h>

#include "tculib.h"

enum ActivityState {
    A_STOPPED,
    A_READY,
    A_RUNNING,
};

struct m3_activity {
    ActId id;
    pid_t pid;
    int state;
    struct m3_activity *next;

    void *env;
    phys_addr_t env_phys;

    void *std_app_buf;
    phys_addr_t std_app_buf_phys;

    unsigned long custom_len;
    phys_addr_t custom_phys;
    unsigned long custom_prot;

    int wakeup;
    wait_queue_head_t wait_queue;

    Reg cur_act;
    TCUState tcu_state;
};

int activity_create(struct tcu_device *tcu, ActId id);
struct m3_activity *activity_from_id(struct tcu_device *tcu, ActId id);
struct m3_activity *activity_from_pid(struct tcu_device *tcu, pid_t pid);
struct m3_activity *activity_wait(struct tcu_device *tcu);
void activity_start(struct tcu_device *tcu, struct m3_activity *act, pid_t pid);
void activity_switch(struct tcu_device *tcu, struct m3_activity *p_act, struct m3_activity *n_act);
void activity_remove(struct tcu_device *tcu, struct m3_activity *act);

#endif
