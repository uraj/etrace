#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kernel.h>
#include <linux/elogk.h>
#include <linux/string.h>
#include <linux/time.h>

/*
 * Our key idea: list every important syscall and instrument their
 * core rountines (i.e., do_vfs_read). By parsing the registers dumped
 * when kretprobes (in some cases we will use jprobes only, because
 * there is no need to know how the syscall returns, e.g., fd_install)
 * sucessfully intercept the routine at the entry, according to our
 * knowledge to the ABI of the architecture we are working on (ARM).
 */

static unsigned int counter[10];
static struct timespec timestat;

#define regs_arg(regs,no,type)     ((type)((regs)->ARM_r ## no))

#define STR_BUF_SIZE          256
#define EBUF_SIZE             (STR_BUF_SIZE + sizeof(struct eevent_t))
#define SBUF_SIZE             32

#define EEVENT_MMC_READ       2
#define EEVENT_MMC_WRITE      3

#include <linux/mmc/host.h>
#include <linux/mmc/core.h>

/**
 * func: @mmc_wait_for_req(struct mmc_host *, struct mmc_request *);
 * in drivers/mmc/host/msm_sdcc.c
 */
static void mmc_handler(struct mmc_host *host, struct mmc_request* req)
{
    static __s16 id = 0;
    static char buf[EBUF_SIZE];
    struct eevent_t *eevent = (struct eevent_t *)buf;
    struct mmc_data *data = req->data;
    __u16 type;
        
    if (!data)
        jprobe_return();
    
    if (data->flags & MMC_DATA_WRITE)
        type = EEVENT_MMC_WRITE;
    else if (data->flags & MMC_DATA_READ)
        type = EEVENT_MMC_READ;
    else
        goto out;
    
    eevent->id = id++;
    eevent->type = type;
    eevent->len =
        sprintf(eevent->params, "%d", data->blocks * data->blksz);
    
    elogk(eevent, ELOG_MMC, 0);
    
    ++counter[type];

  out:
    jprobe_return();
    
    return;
}

static struct jprobe mmc_probe = {
    .entry = mmc_handler,
    .kp = {
        .symbol_name = "mmc_wait_for_req",
    },
};

static int __init etrace_init(void)
{
    int ret;

    ret = register_jprobe(&mmc_probe);
    if (ret < 0)
        goto err;

    ktime_get_ts(&timestat);
    
    return 0;
    
  err:
    printk(KERN_INFO "etrace init failed\n");
    return -1;
}

static void __exit etrace_exit(void)
{
    long s = timestat.tv_sec;
    
    unregister_jprobe(&mmc_probe);

    ktime_get_ts(&timestat);
    
    printk(KERN_INFO "%d read, %d write in %ld seconds!\n",
           counter[EEVENT_MMC_READ],
           counter[EEVENT_MMC_WRITE],
           timestat.tv_sec - s);
    return;
}

module_init(etrace_init)
module_exit(etrace_exit)
MODULE_LICENSE("GPL");
