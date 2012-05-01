#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kernel.h>
#include <linux/elogk.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/mmc/host.h>
#include <linux/mmc/core.h>
#include <linux/mmc/card.h>

/*
 * Our key idea: list every important syscall/drivers and instrument
 * their core rountines. By parsing the registers dumped when
 * kretprobes (in some cases we will use jprobes only, because there
 * is no need to know how the syscall returns) sucessfully intercept
 * the routine at the entry, according to our knowledge to the ABI
 * of the architecture we are working on (ARM).
 */

static unsigned int counter[10];
static struct timespec timestat;

#define regs_arg(regs,no,type)     ((type)((regs)->ARM_r ## no))

#define LBUF_SIZE          128
#define SBUF_SIZE          4 

enum {
    EEVENT_VFS_READ = 0,
    EEVENT_VFS_WRITE,
    EEVENT_MMC_READ,
    EEVENT_MMC_WRITE,
};

#define ERR_FILENAME "(.)"

struct elog_probe_data
{
    __u32 hook_ret;
    struct eevent_t eevent;
    __u8 payload[SBUF_SIZE];
} __attribute__((packed));

/*
static inline int fpath_filter(char *path, size_t length)
{
    return 0;
}
*/

static inline int fpath_filter(char *path, size_t length)
{
    static const struct {
        size_t length;
        char *path;
    } paths[2] = {
        { .length = 11, .path = "/mnt/sdcard" },
        { .length = 7, .path = "/sdcard", },
    };

    int i;
    
    for (i = 0; i < sizeof(paths); ++i)
        if ((length >= paths[i].length) &&
            (!strncmp(path, paths[i].path, paths[i].length)))
            return 0;
    
    return 1;
}


static int read_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    static __s32 id = 1;
    char buf[LBUF_SIZE];
    struct file *arg0 = regs_arg(regs, 0, struct file *);
    struct elog_probe_data *data = (struct elog_probe_data *)ri->data;
    struct eevent_t *eevent = &(data->eevent);
    char *fpath = d_path(&arg0->f_path, buf, LBUF_SIZE);
    
    if (IS_ERR(fpath) || fpath_filter(fpath, strlen(fpath))) {
        data->hook_ret = 0;
        return 0;
    } else {
        data->hook_ret = 1;
    }
    
    eevent->id = id++;
    eevent->type = EEVENT_VFS_READ;
    eevent->belong = task_uid(current);
    ktime_get_ts(&eevent->etime);
    
    return 0;
}

static int read_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct elog_probe_data *data = (struct elog_probe_data *)ri->data;
    struct eevent_t *eevent = &(data->eevent);
    ssize_t retvalue;
    
    if (data->hook_ret == 0)
        return 0;
    
    retvalue = (ssize_t)regs_return_value(regs);
    
    if (retvalue < 512)
        return 0;
    
    memcpy(eevent->payload, &retvalue, sizeof(ssize_t));
    eevent->len = sizeof(ssize_t);
    
    counter[EEVENT_VFS_READ]++;

    elogk(eevent, ELOG_VFS, ELOGK_WITHOUT_TIME);
    
    return 0;
}

static struct kretprobe read_kretprobe = {
    .handler = read_ret_handler,
    .entry_handler = read_entry_handler,
    .data_size = sizeof(struct elog_probe_data),
    .kp = {
        .symbol_name = "__ee_read_core",
    },
    .maxactive = 10,
};

static int write_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    static __s32 id = 1;
    char buf[LBUF_SIZE];
    struct file *arg0 = regs_arg(regs, 0, struct file *);
    struct elog_probe_data *data = (struct elog_probe_data *)ri->data;
    struct eevent_t *eevent = &(data->eevent);
    char *fpath = d_path(&arg0->f_path, buf, LBUF_SIZE);
    
    if (IS_ERR(fpath) || fpath_filter(fpath, strlen(fpath))) {    
        data->hook_ret = 0;
        return 0;
    } else {
        data->hook_ret = 1;
    }

    eevent->id = id++;
    eevent->type = EEVENT_VFS_WRITE;
    eevent->belong = task_uid(current);
    ktime_get_ts(&eevent->etime);
    
    return 0;
}

static int write_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct elog_probe_data *data = (struct elog_probe_data *)ri->data;
    struct eevent_t *eevent = &(data->eevent);
    ssize_t retvalue;
    
    if (data->hook_ret == 0)
        return 0;
    
    retvalue = (ssize_t)regs_return_value(regs);

    if (retvalue < 512)
        return 0;
    
    memcpy(eevent->payload, &retvalue, sizeof(ssize_t));
    eevent->len = sizeof(ssize_t);

    counter[EEVENT_VFS_WRITE]++;
    
    elogk(eevent, ELOG_VFS, ELOGK_WITHOUT_TIME);
    
    return 0;
}

static struct kretprobe write_kretprobe = {
    .handler = write_ret_handler,
    .entry_handler = write_entry_handler,
    .data_size = sizeof(struct elog_probe_data),
    .kp = {
        .symbol_name = "__ee_write_core",
    },
    .maxactive = 10,
};

/**
 * func: @mmc_wait_for_req(struct mmc_host *, struct mmc_request *);
 * in drivers/mmc/core/core.c
 */
static void mmc_handler(struct mmc_host *host, struct mmc_request* req)
{
    static __s16 id = 0;
    static char buf[LBUF_SIZE];
    struct eevent_t *eevent = (struct eevent_t *)buf;
    struct mmc_data *data = req->data;
    __u16 type;
    unsigned int workload;
    
    if (!data)
        jprobe_return();

    if (!mmc_card_sd(host->card))
        goto out;
    
    if (data->flags & MMC_DATA_WRITE)
        type = EEVENT_MMC_WRITE;
    else if (data->flags & MMC_DATA_READ)
        type = EEVENT_MMC_READ;
    else
        goto out;
    
    eevent->id = id++;
    eevent->type = type;
    workload = data->blocks * data->blksz;
    memcpy(eevent->payload, &workload, sizeof(unsigned int));
    eevent->len = sizeof(unsigned int);
    
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

    ret = register_kretprobe(&read_kretprobe);
    if (ret < 0)
        goto err1;
    ret = register_kretprobe(&write_kretprobe);
    if (ret < 0)
        goto err2;
    ret = register_jprobe(&mmc_probe);
    if (ret < 0)
        goto err3;
    
    ktime_get_ts(&timestat);
    
    return 0;
    
  err3:
    unregister_kretprobe(&write_kretprobe);
  err2:
    unregister_kretprobe(&read_kretprobe);
  err1:
    printk(KERN_INFO "etrace init failed\n");
    return -1;
}

static void __exit etrace_exit(void)
{
    long s = timestat.tv_sec;
    
    unregister_kretprobe(&read_kretprobe);
    unregister_kretprobe(&write_kretprobe);
    unregister_jprobe(&mmc_probe);
    
    ktime_get_ts(&timestat);
     
    printk("%d vfs read, %d vfs write\n%d mmc read, %d mmc write\nin %ld seconds!\n",
           counter[EEVENT_VFS_READ],
           counter[EEVENT_VFS_WRITE],
           counter[EEVENT_MMC_READ],
           counter[EEVENT_MMC_WRITE],
           
           timestat.tv_sec - s);
    
    return;
}

module_init(etrace_init)
module_exit(etrace_exit)
MODULE_LICENSE("GPL");
