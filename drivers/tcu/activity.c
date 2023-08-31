#include "activity.h"

#include <linux/slab.h>

int create_activity(struct tcu_device *tcu, ActId id)
{
    struct m3_activity *act = kmalloc(sizeof(struct m3_activity), GFP_ATOMIC);
    if (!act) {
        dev_err(tcu->dev, "kmalloc for new activity");
        return -ENOMEM;
    }

    act->id = id;
    act->pid = 0;

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
    struct m3_activity *act;
    ActId id;

    if (tcu->waiting_task != NULL)
        return NULL;

    while (tcu->wait_list == NULL) {
        dev_info(tcu->dev, "waiting for new activity\n");
        tcu->waiting_task = get_current();
        set_current_state(TASK_INTERRUPTIBLE);
        schedule();
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

    return act;
}

void start_activity(struct m3_activity *act, pid_t pid)
{
    act->pid = pid;
}

void remove_activity(struct tcu_device *tcu, struct m3_activity *act)
{
    struct m3_activity *pact;

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
