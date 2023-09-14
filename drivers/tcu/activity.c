#include "activity.h"

#include <linux/slab.h>

int create_activity(struct tcu_device *tcu, ActId id)
{
    size_t i;
    struct m3_activity *act = kmalloc(sizeof(struct m3_activity), GFP_ATOMIC);

    if (!act) {
        dev_err(tcu->dev, "kmalloc for new activity");
        return -ENOMEM;
    }

    act->id = id;
    act->pid = 0;
    act->cur_act = id;
    for(i = 0; i < sizeof(act->tcu_regs) / sizeof(act->tcu_regs[0]); ++i)
        act->tcu_regs[i] = 0;

    act->custom_phys = 0;
    act->custom_len = 0;
    act->custom_prot = 0;

    // allocate environment for application
    act->env = kmalloc(PAGE_SIZE, GFP_ATOMIC);
    if (!act->env) {
        dev_err(tcu->dev, "kmalloc for environment failed");
        kfree(act);
        return -ENOMEM;
    }
    act->env_phys = virt_to_phys(act->env);

    // allocate buffer for standard application endpoints
    act->std_app_buf = kmalloc(PAGE_SIZE, GFP_ATOMIC);
    if (!act->std_app_buf) {
        dev_err(tcu->dev, "kmalloc for std buffer failed");
        kfree(act->env);
        kfree(act);
        return -ENOMEM;
    }
    act->std_app_buf_phys = virt_to_phys(act->std_app_buf);

    dev_info(tcu->dev, "Created activity (%d)\n", id);

    // enqueue in wait list
    act->next = tcu->wait_list;
    tcu->wait_list = act;
    return 0;
}

struct m3_activity *id_to_activity(struct tcu_device *tcu, ActId id)
{
    struct m3_activity *act;

    act = tcu->wait_list;
    while (act != NULL) {
        if (act->id == id)
            return act;
        act = act->next;
    }

    act = tcu->run_list;
    while (act != NULL) {
        if (act->id == id)
            return act;
        act = act->next;
    }

    return NULL;
}

struct m3_activity *pid_to_activity(struct tcu_device *tcu, pid_t pid)
{
    struct m3_activity *act;

    // activities in run_list do not necessarily have a valid pid, but the activities in wait_list
    // never do.
    act = tcu->run_list;
    while (act != NULL) {
        if (act->pid == pid)
            return act;
        act = act->next;
    }

    return NULL;
}

struct m3_activity *wait_activity(struct tcu_device *tcu)
{
    unsigned long flags;
    struct m3_activity *act;
    ActId id;

    spin_lock_irqsave(&tcu->lock, flags);

    if (tcu->waiting_task != NULL) {
        spin_unlock_irqrestore(&tcu->lock, flags);
        return NULL;
    }

    while (tcu->wait_list == NULL) {
        dev_info(tcu->dev, "waiting for new activity\n");
        tcu->waiting_task = get_current();
        spin_unlock_irqrestore(&tcu->lock, flags);
        set_current_state(TASK_INTERRUPTIBLE);
        schedule();
        spin_lock_irqsave(&tcu->lock, flags);
        dev_info(tcu->dev, "woke up from waiting for new activity\n");
        tcu->waiting_task = NULL;
    }

    act = tcu->wait_list;
    id = act->id;

    dev_info(tcu->dev, "got new activity (%d)\n", id);

    // move from wait_list to run_list
    tcu->wait_list = act->next;
    act->next = tcu->run_list;
    tcu->run_list = act;

    spin_unlock_irqrestore(&tcu->lock, flags);

    return act;
}

void start_activity(struct tcu_device *tcu, struct m3_activity *act, pid_t pid)
{
    EnvData *env;

    act->pid = pid;
    dev_info(tcu->dev, "Started activity %d (pid %d)\n", act->id, pid);

    // set our tile to shared to make apps yield instead of use the TCU sleep
    // TODO improve that
    env = (EnvData*)act->env;
    env->shared = 1;
}

void save_activity(struct tcu_device *tcu, struct m3_activity *act)
{
    Reg old_cmd;
    Error err;

    dev_info(tcu->dev, "Saving state of activity %d (pid %d)\n", act->id, act->pid);

    // abort the current command, if there is any
    err = abort_command(tcu, &old_cmd);
    BUG_ON(err != Error_None);

    act->tcu_regs[0] = old_cmd;
    act->tcu_regs[1] = read_unpriv_reg(tcu, UnprivReg_ARG1);
    act->tcu_regs[2] = read_unpriv_reg(tcu, UnprivReg_DATA_ADDR);
    act->tcu_regs[3] = read_unpriv_reg(tcu, UnprivReg_DATA_SIZE);
}

void switch_activity(struct tcu_device *tcu, struct m3_activity *p_act, struct m3_activity *n_act)
{
    Reg prev_reg, next_reg;

    if (p_act) {
        save_activity(tcu, p_act);
    }

    next_reg = n_act ? n_act->cur_act : INVAL_AID;
    prev_reg = xchg_activity(tcu, next_reg);

    dev_info(tcu->dev, "TCU-activity: %#llx\n", next_reg);

    if (p_act)
        p_act->cur_act = prev_reg;

    if (n_act) {
        restore_activity(tcu, n_act);
    }

    tcu->cur_act = n_act;
    tcu->cur_act_id = next_reg & 0xFFFF;
}

void restore_activity(struct tcu_device *tcu, struct m3_activity *act)
{
    dev_info(tcu->dev, "Restoring state of activity %d (pid %d)\n", act->id, act->pid);

    write_unpriv_reg(tcu, UnprivReg_ARG1, act->tcu_regs[1]);
    write_unpriv_reg(tcu, UnprivReg_DATA_ADDR, act->tcu_regs[2]);
    write_unpriv_reg(tcu, UnprivReg_DATA_SIZE, act->tcu_regs[3]);
    // always restore the command register, because the previous activity might have an error code
    // in the command register or similar.
    mb();
    write_unpriv_reg(tcu, UnprivReg_COMMAND, act->tcu_regs[0]);
}

void remove_activity(struct tcu_device *tcu, struct m3_activity *act)
{
    struct m3_activity *pact;

    dev_info(tcu->dev, "Removing activity %d (pid %d)\n", act->id, act->pid);

    // find previous activity
    pact = tcu->run_list;
    while (pact) {
        if (pact->next == act)
            break;
        pact = pact->next;
    }

    // remove from list
    if (pact)
        pact->next = act->next;
    else
        tcu->run_list = act->next;
    kfree(act->env);
    kfree(act->std_app_buf);
    kfree(act);
}
