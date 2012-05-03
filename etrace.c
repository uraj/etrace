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

#define UID_APP(uid)       ((uid) >= 10000)

enum {
    EEVENT_VFS_READ = 0,
    EEVENT_VFS_WRITE,
    EEVENT_MMC_READ,
    EEVENT_MMC_WRITE,
};

#define ERR_FILENAME "(.)"

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

struct vfs_probe_data
{
    __u32 hook_ret;
    struct eevent_t eevent;
    __u8 payload[sizeof(ssize_t)];
} __attribute__((packed));

static int read_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    static __s32 id = 1;
    char buf[LBUF_SIZE];
    struct file *arg0 = regs_arg(regs, 0, struct file *);
    struct vfs_probe_data *data = (struct vfs_probe_data *)ri->data;
    struct eevent_t *eevent = &(data->eevent);
    char *fpath = d_path(&arg0->f_path, buf, LBUF_SIZE);
    unsigned int uid = task_uid(current);
    
    if (!UID_APP(uid) || IS_ERR(fpath) || fpath_filter(fpath, strlen(fpath))) {
        data->hook_ret = 0;
        return 0;
    } else {
        data->hook_ret = 1;
    }
    
    eevent->id = id++;
    eevent->type = EEVENT_VFS_READ;
    eevent->belong = uid;
    ktime_get_ts(&eevent->etime);
    
    return 0;
}

static int read_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct vfs_probe_data *data = (struct vfs_probe_data *)ri->data;
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
    .data_size = sizeof(struct vfs_probe_data),
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
    struct vfs_probe_data *data = (struct vfs_probe_data *)ri->data;
    struct eevent_t *eevent = &(data->eevent);
    char *fpath = d_path(&arg0->f_path, buf, LBUF_SIZE);
    unsigned int uid = task_uid(current);
    
    if (!UID_APP(uid) || IS_ERR(fpath) || fpath_filter(fpath, strlen(fpath))) {    
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
    struct vfs_probe_data *data = (struct vfs_probe_data *)ri->data;
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
    .data_size = sizeof(struct vfs_probe_data),
    .kp = {
        .symbol_name = "__ee_write_core",
    },
    .maxactive = 10,
};

struct mmc_probe_data
{
    __u32 hook_ret;
    struct eevent_t eevent;
    __u8 payload[2*sizeof(unsigned int)];
} __attribute__((packed));

/**
 * func: @mmc_wait_for_req(struct mmc_host *, struct mmc_request *);
 * in drivers/mmc/core/core.c
 */
static int mmc_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    static __s32 id = 1;
    struct mmc_host *host = regs_arg(regs, 0, struct mmc_host *);
    struct mmc_request *req = regs_arg(regs, 1, struct mmc_request *);
    struct mmc_probe_data *probe_data = (struct mmc_probe_data *)ri->data;
    struct eevent_t *eevent = &(probe_data->eevent);
    struct mmc_data *data = req->data;
    __u16 type;
    unsigned int workload;
    
    if (!data)
        goto discard;

    if (!mmc_card_sd(host->card))
        goto discard;
    
    if (data->flags & MMC_DATA_WRITE)
        type = EEVENT_MMC_WRITE;
    else if (data->flags & MMC_DATA_READ)
        type = EEVENT_MMC_READ;
    else
        goto discard;

    probe_data->hook_ret = 1;
    
    eevent->id = id++;
    eevent->type = type;
    workload = data->blocks * data->blksz;
    memcpy(eevent->payload, &workload, sizeof(unsigned int));
    eevent->len = sizeof(unsigned int);
    ktime_get_ts(&eevent->etime);

    ++counter[type];

    return 0;
    
  discard:
    return 0;
}

static int mmc_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct mmc_probe_data *probe_data = (struct mmc_probe_data *)ri->data;
    struct eevent_t *eevent = &(probe_data->eevent);
    unsigned int duration;
    struct timespec rtime;
    
    if (probe_data->hook_ret == 0)
        return 0;

    ktime_get_ts(&rtime);
    duration = (rtime.tv_sec - eevent->etime.tv_sec) * 1000;
    duration += (rtime.tv_sec - eevent->etime.tv_sec) / 1000000;
    
    memcpy(eevent->payload + eevent->len, &duration, sizeof(unsigned int));
    eevent->len += sizeof(unsigned int);

    elogk(eevent, ELOG_MMC, ELOGK_WITHOUT_TIME);
    
    return 0;
}

static struct kretprobe mmc_kretprobe = {
    .handler = mmc_ret_handler,
    .entry_handler = mmc_entry_handler,
    .data_size = sizeof(struct mmc_probe_data),
    .kp = {
        .symbol_name = "mmc_wait_for_req",
    },
    .maxactive = 5,
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
    ret = register_kretprobe(&mmc_kretprobe);
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
    unregister_kretprobe(&mmc_kretprobe);
    
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
