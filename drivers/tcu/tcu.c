#include "activity.h"
#include "sidecalls.h"
#include "tculib.h"
#include "cfg.h"
#include "envdata.h"

// PROT_READ etc.
#include <asm/mman.h>

// module_init, module_exit
#include <linux/module.h>

// mmap_mem_ops
#include <linux/mm.h>

// request_irq
#include <linux/interrupt.h>

// platform device stuff
#include <linux/of.h>
#include <linux/platform_device.h>

// ioremap, iounmap
#include <linux/io.h>

// kmalloc
#include <linux/slab.h>
#include <linux/delay.h>

// wait for a new activity to start
#define IOCTL_WAIT_FOR_ACT _IOR('q', 1, ActId*)
// register an activity
#define IOCTL_REG_ACT _IOW('q', 2, unsigned long)
// inserts an entry in tcu tlb, uses current activity id
#define IOCTL_TLB_INSRT _IOW('q', 3, unsigned long)
// forgets about an activity
#define IOCTL_UNREG_ACT _IOW('q', 4, unsigned long)
// noop
#define IOCTL_NOOP _IO('q', 5)

typedef struct {
	uint64_t arg1;
	uint64_t arg2;
} NoopArg;

enum {
	MemType_TCU,
	MemType_Environment,
	MemType_StdRecvBuf,
	MemType_Custom,
};

static struct tcu_device *tcu = NULL;

// source: https://github.com/davidhcefx/Translate-Virtual-Address-To-Physical-Address-in-Linux-Kernel
static unsigned long vaddr2paddr(unsigned long address)
{
	uint64_t phys = 0;
	pgd_t *pgd = pgd_offset(current->mm, address);
	if (!pgd_none(*pgd) && !pgd_bad(*pgd)) {
		p4d_t *p4d = p4d_offset(pgd, address);
		if (!p4d_none(*p4d) && !p4d_bad(*p4d)) {
			pud_t *pud = pud_offset(p4d, address);
			if (!pud_none(*pud) && !pud_bad(*pud)) {
				pmd_t *pmd = pmd_offset(pud, address);
				if (!pmd_none(*pmd) && !pmd_bad(*pmd)) {
					pte_t *pte =
						pte_offset_map(pmd, address);
					if (!pte_none(*pte)) {
						struct page *pg =
							pte_page(*pte);
						phys = page_to_phys(pg);
					}
					pte_unmap(pte);
				}
			}
		}
	}
	return phys;
}

static int ioctl_wait_for_activity(struct tcu_device *tcu, unsigned long arg)
{
	struct m3_activity *act = wait_activity(tcu);
	if (!act)
		return -EBUSY;

	if (copy_to_user((void*)arg, &act->id, sizeof(act->id)))
		return -EINVAL;

	return 0;
}

static int ioctl_reg_activity(struct tcu_device *tcu, unsigned long arg)
{
	struct m3_activity *act;

	act = id_to_activity(tcu, (ActId)arg);
	if (act == NULL || act->pid != 0)
		return -EINVAL;

	start_activity(tcu, act, get_current()->pid);
	BUG_ON(tcu->cur_act == act);
    switch_activity(tcu, tcu->cur_act, act);

	return 0;
}

static int ioctl_insert_tlb(struct tcu_device *tcu, unsigned long arg)
{
	uint64_t phys;
	uint64_t virt;
	uint8_t perm;

	if (tcu->cur_act_id == INVAL_AID) {
		tculog(LOG_ERR, tcu->dev, "there is no activity registered\n");
		return -EINVAL;
	}

	virt = arg & PAGE_MASK;
	perm = (uint8_t)(arg & 0xf);
	phys = vaddr2paddr(virt);
	if (phys == 0) {
		tculog(LOG_ERR, tcu->dev, "TLB insert: virtual address is not mapped\n");
		return -EINVAL;
	}

	return (int)insert_tlb(tcu, tcu->cur_act_id, virt, phys, perm);
}

static int ioctl_unreg_activity(struct tcu_device *tcu, unsigned long arg)
{
	struct m3_activity *act;
	Error e;

	act = id_to_activity(tcu, (ActId)arg);
	if (act == NULL || act->pid == 0) {
		tculog(LOG_ERR, tcu->dev, "activity %d not found\n", (ActId)arg);
		return -EINVAL;
	}

	// send exit sidecall
	e = send_kernelcall_exit(tcu, act->id, 0);
	if (e != Error_None) {
		tculog(LOG_ERR, tcu->dev, "exit sidecall for %d failed: %d", act->id, e);
		return -EINVAL;
	}

	remove_activity(tcu, act);
	return 0;
}

static int ioctl_noop(struct tcu_device *tcu)
{
	return 0;
}

static long int tcu_ioctl(struct file *f,
						  unsigned int cmd, unsigned long arg)
{
	unsigned long flags;
	long int res = -EINVAL;

	if (cmd != IOCTL_WAIT_FOR_ACT)
    	spin_lock_irqsave(&tcu->lock, flags);

	switch (cmd) {
	case IOCTL_WAIT_FOR_ACT:
		res = ioctl_wait_for_activity(tcu, arg);
		break;
	case IOCTL_REG_ACT:
		res = ioctl_reg_activity(tcu, arg);
		break;
	case IOCTL_TLB_INSRT:
		res = ioctl_insert_tlb(tcu, arg);
		break;
	case IOCTL_UNREG_ACT:
		res = ioctl_unreg_activity(tcu, arg);
		break;
	case IOCTL_NOOP:
		res = ioctl_noop(tcu);
		break;
	default:
		tculog(LOG_ERR, tcu->dev, "received ioctl call without unknown magic number\n");
		break;
	}

	if (cmd != IOCTL_WAIT_FOR_ACT)
		spin_unlock_irqrestore(&tcu->lock, flags);

	return res;
}

static int tcu_dev_mmap(struct file *file, struct vm_area_struct *vma)
{
	int res, io = 0;
	unsigned long expected_prot;
	size_t expected_size, size = vma->vm_end - vma->vm_start;
	unsigned long pfn, flags;
	int ty = vma->vm_pgoff;
	struct m3_activity *act;

    spin_lock_irqsave(&tcu->lock, flags);

	act = pid_to_activity(tcu, get_current()->pid);
	if (act == NULL) {
    	spin_unlock_irqrestore(&tcu->lock, flags);
		return -EINVAL;
	}

	switch (ty) {
	case MemType_TCU:
		pfn = MMIO_UNPRIV_ADDR >> PAGE_SHIFT;
		expected_size = MMIO_UNPRIV_SIZE;
		expected_prot = PROT_READ | PROT_WRITE;
		io = 1;
		break;
	case MemType_Environment:
		pfn = act->env_phys >> PAGE_SHIFT;
		expected_size = PAGE_SIZE;
		expected_prot = PROT_READ | PROT_WRITE;
		break;
	case MemType_StdRecvBuf:
		pfn = act->std_app_buf_phys >> PAGE_SHIFT;
		expected_size = PAGE_SIZE;
		expected_prot = PROT_READ;
		break;
	case MemType_Custom:
		if (!act->custom_len) {
	    	spin_unlock_irqrestore(&tcu->lock, flags);
			return -EINVAL;
		}
		pfn = act->custom_phys >> PAGE_SHIFT;
		expected_size = act->custom_len;
		expected_prot = PROT_READ;
		act->custom_len = 0;
		break;
	default:
		tculog(LOG_ERR, tcu->dev, "mmap invalid type: %d\n", ty);
    	spin_unlock_irqrestore(&tcu->lock, flags);
		return -EINVAL;
	}

	spin_unlock_irqrestore(&tcu->lock, flags);

	// check if the size and protection is as expected
	if (size != expected_size) {
		tculog(LOG_ERR, tcu->dev, "mmap unexpected size: %zu vs. %zu\n", size,
		       expected_size);
		return -EINVAL;
	}
	if ((vma->vm_flags & (PROT_READ | PROT_WRITE)) != expected_prot) {
		tculog(LOG_ERR, tcu->dev, "mmap unexpected protection: %#lx vs. %#lx\n",
			vma->vm_flags & (PROT_READ | PROT_WRITE), expected_prot);
		return -EINVAL;
	}

	tculog(LOG_MEM, tcu->dev, "mmap %#lx to %#lx (%zu pages)\n",
		vma->vm_start, pfn << PAGE_SHIFT, expected_size / PAGE_SIZE);

	if (io) {
		// Remap-pfn-range will mark the range VM_IO
		res = io_remap_pfn_range(vma, vma->vm_start, pfn, size,
					 vma->vm_page_prot);
	} else {
		res = remap_pfn_range(vma, vma->vm_start, pfn, size,
				      vma->vm_page_prot);
	}

	if (res) {
		tculog(LOG_ERR, tcu->dev, "mmap - remap_pfn_range failed\n");
		return -EAGAIN;
	}

	return 0;
}

static irqreturn_t __maybe_unused tcu_irq_handler(int irq, void *ndev)
{
	struct corereq_foreign_msg core_req;
	struct m3_activity *act;
	Reg old_act;

	spin_lock(&tcu->lock);

	tculog(LOG_IRQ, tcu->dev, "Got TCU irq %d\n", irq);

	if(get_core_req(tcu, &core_req)) {
		tculog(LOG_IRQ, tcu->dev, "Got foreign message core request (act=%u, ep=%llu)\n",
			core_req.act, core_req.ep);

		// if it's for us, handle side calls
		if(core_req.act == PRIV_AID) {
			// we know that we're received a message and the TCU hasn't increased the counter. we
			// also know that we always handle all messages before we switch back to another
			// activity. therefore, we can just set one message here.
			// TODO maybe we want to execute that in process ctx rather than in interrupt ctx?
			handle_sidecalls(tcu, PRIV_AID | (1 << 16));
		}
		// if it's for the current app, increase message counter
		else if(core_req.act == tcu->cur_act_id) {
			// switch to idle to get the current message count
			old_act = xchg_activity(tcu, INVAL_AID);
			// add message
			old_act += 1 << 16;
			// we know that idle never receives messages, therefore there is nothing else to do
			xchg_activity(tcu, old_act);
		}
		else {
			act = id_to_activity(tcu, core_req.act);
			if (act == NULL)
				tculog(LOG_ERR, tcu->dev, "Received message for unknown activity %u\n",
					core_req.act);
			else
				act->cur_act += 1 << 16;
			// TODO switch to the task
		}

		set_foreign_resp(tcu);
	}
	else
		tculog(LOG_ERR, tcu->dev, "Unknown cause for TCU irq\n");

	ack_irq(tcu, irq);

    spin_unlock(&tcu->lock);

	return IRQ_HANDLED;
}

void tcu_task_switch(bool preempt, struct task_struct *prev, struct task_struct *next)
{
	struct m3_activity *p_act, *n_act;
    unsigned long flags;

	// module not initialized yet?
	if (!tcu)
		return;

    spin_lock_irqsave(&tcu->lock, flags);

	p_act = tcu->cur_act;
	BUG_ON(p_act != NULL && p_act->pid != prev->pid);
	n_act = pid_to_activity(tcu, next->pid);

	if (p_act != NULL || n_act != NULL)
	    switch_activity(tcu, p_act, n_act);

    spin_unlock_irqrestore(&tcu->lock, flags);
}

#define DEV_COUNT 1
#define TCU_MINOR 0

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.mmap = tcu_dev_mmap,
	.unlocked_ioctl = tcu_ioctl,
};

static void init_tileid_translation(struct tcu_device *tcu,
									uint64_t *raw_tile_ids, size_t raw_tile_count)
{
	size_t i, count = raw_tile_count;

	uint8_t log_chip = 0;
	uint8_t log_tile = 0;
	int phys_chip = -1;

	for (i = 0; i < count; ++i) {
		TileId tid = raw_tile_ids[i];
		uint8_t cid = tid >> 8;

		if (phys_chip != -1) {
			if (phys_chip != cid) {
				phys_chip = cid;
				log_chip += 1;
				log_tile = 0;
			} else
				log_tile += 1;
		} else {
			phys_chip = cid;
		}

		tcu->tile_ids[log_chip * MAX_TILES + log_tile] = tid;
	}
}

static dev_t create_tcu_dev(struct tcu_device *tcu, struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	dev_t dev_no = 0;
	int retval;

	retval = alloc_chrdev_region(&dev_no, TCU_MINOR, DEV_COUNT, "tcu");
	if (retval < 0) {
		tculog(LOG_ERR, dev, "failed to allocate major number for TCU device\n");
		goto error;
	}

	tcu->major = MAJOR(dev_no);
	cdev_init(&tcu->cdev, &fops);
	retval = cdev_add(&tcu->cdev, dev_no, DEV_COUNT);
	if (retval < 0) {
		tculog(LOG_ERR, dev, "failed to add TCU device\n");
		goto error_add;
	}

	tcu->dev_class = class_create(THIS_MODULE, "tcu");
	if (IS_ERR(tcu->dev_class)) {
		tculog(LOG_ERR, dev, "failed to create device class for TCU device\n");
		goto error_add;
	}

	tcu->char_dev = device_create(tcu->dev_class, NULL, MKDEV(tcu->major, TCU_MINOR),
				   NULL, "tcu");
	if (IS_ERR(tcu->char_dev)) {
		tculog(LOG_ERR, dev, "failed to create TCU device\n");
		goto error_create;
	}

	tcu->irq = platform_get_irq(pdev, 0);
	if (tcu->irq < 0) {
		tculog(LOG_ERR, dev, "failed to get TCU IRQ\n");
		goto error_irq;
	}

	tculog(LOG_INFO, tcu->dev, "using IRQ %d\n", tcu->irq);

	return dev_no;

error_irq:
	device_destroy(tcu->dev_class, dev_no);
error_create:
	class_destroy(tcu->dev_class);
error_add:
	unregister_chrdev_region(dev_no, DEV_COUNT);
error:
	return -1;
}

static void destroy_tcu_dev(struct tcu_device *tcu)
{
	dev_t tcu_dev = MKDEV(tcu->major, TCU_MINOR);
	device_destroy(tcu->dev_class, tcu_dev);
	unregister_chrdev_region(tcu_dev, DEV_COUNT);
	class_destroy(tcu->dev_class);
}

static int tcu_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	EnvData *m3_env;
	dev_t dev_no;
	int retval;

	tcu = kmalloc(sizeof(struct tcu_device), GFP_KERNEL);
	if (!tcu) {
		tculog(LOG_ERR, dev, "kmalloc for tcu_device failed\n");
		goto error;
	}
	tcu->dev = dev;
	tcu->waiting_task = NULL;
	tcu->wait_list = NULL;
	tcu->run_list = NULL;
	tcu->cur_act = NULL;
	tcu->cur_act_id = INVAL_AID;
	spin_lock_init(&tcu->lock);

	// map the environment to know the platform we're running on (some macros depend on it)
	m3_env = (EnvData *)memremap(ENV_START, PAGE_SIZE, MEMREMAP_WB);
	if (!m3_env) {
		tculog(LOG_ERR, dev, "memremap for environment failed\n");
		goto error_env;
	}

	tcu->platform = m3_env->platform;
	tculog(LOG_INFO, tcu->dev, "initializing TCU driver on platform %d\n", (int)tcu->platform);

	init_tileid_translation(tcu, m3_env->raw_tile_ids, m3_env->raw_tile_count);
	memunmap(m3_env);

	dev_no = create_tcu_dev(tcu, pdev);
	if (dev_no == (dev_t)-1)
		goto error_env;

	// map MMIO region; both unprivileged and privileged interface
	tcu->unpriv_base = (uint64_t *)ioremap(MMIO_ADDR, MMIO_SIZE);
	if (!tcu->unpriv_base) {
		tculog(LOG_ERR, dev, "ioremap for the TCU's MMIO region failed\n");
		goto error_mmio;
	}
	tcu->priv_base = tcu->unpriv_base + (MMIO_UNPRIV_SIZE / sizeof(uint64_t));

	// map receive buffer for side calls
	tcu->rcv_buf = (uint8_t *)memremap(TMUP_RBUF_ADDR, TMUP_RBUF_SIZE, MEMREMAP_WB);
	if (!tcu->rcv_buf) {
		tculog(LOG_ERR, dev, "memremap for side call receive buffer failed\n");
		goto error_sidebuf;
	}

	// map receive buffer for replies from the M³ kernel
	tcu->rpl_buf = (uint8_t *)memremap(TILEMUX_RBUF_SPACE, KPEX_RBUF_SIZE, MEMREMAP_WB);
	if (!tcu->rpl_buf) {
		tculog(LOG_ERR, dev, "memremap for TileMux receive buffer failed\n");
		goto error_tmbuf;
	}

	// map send buffer for our messages to the M³ kernel
	tcu->snd_buf = (uint8_t *)kmalloc(MAX_MSG_SIZE, GFP_KERNEL);
	if (!tcu->snd_buf) {
		tculog(LOG_ERR, dev, "kmalloc for send buffer failed");
		goto error_sndbuf;
	}
	// messages need to be 16 byte aligned
	BUG_ON(((uintptr_t)tcu->snd_buf) % 16 != 0);

	platform_set_drvdata(pdev, tcu);

	init_sidecalls(tcu);

	retval = request_irq(tcu->irq, tcu_irq_handler, IRQF_SHARED, dev_name(dev), dev);
	if (retval) {
		tculog(LOG_ERR, dev, "failed to request TCU IRQ\n");
		goto error_irq;
	}

	tculog(LOG_INFO, tcu->dev, "initialization done\n");

	return 0;

error_irq:
	kfree(tcu->snd_buf);
error_sndbuf:
	memunmap(tcu->rpl_buf);
error_tmbuf:
	memunmap(tcu->rcv_buf);
error_sidebuf:
	iounmap(tcu->unpriv_base);
error_mmio:
	destroy_tcu_dev(tcu);
error_env:
	kfree(tcu);
error:
	return -1;
}

static int tcu_remove(struct platform_device *pdev)
{
	struct tcu_device *tcu = platform_get_drvdata(pdev);

	kfree(tcu->snd_buf);
	memunmap(tcu->rpl_buf);
	memunmap(tcu->rcv_buf);
	iounmap(tcu->unpriv_base);
	destroy_tcu_dev(tcu);
	kfree(tcu);

	return 0;
}

static const struct of_device_id tcu_match[] = {
	{ .compatible = "tcu" },
	{},
};
MODULE_DEVICE_TABLE(of, tcu_match);

static struct platform_driver tcu_platform_driver = {
	.probe		= tcu_probe,
	.remove		= tcu_remove,
	.driver		= {
		.name	= "tcu",
		.of_match_table = of_match_ptr(tcu_match),
	},
};

static int __init tcu_init(void)
{
	return platform_driver_register(&tcu_platform_driver);
}

static void __exit tcu_exit(void)
{
	platform_driver_unregister(&tcu_platform_driver);
}

module_init(tcu_init);
module_exit(tcu_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Driver for the trusted communication unit (TCU)");
