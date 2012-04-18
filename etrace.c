#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kernel.h>
#include <linux/elogk.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/net.h>

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
    EEVENT_NET_SEND,
    EEVENT_NET_RECV,
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
        { .length = 5, .path = "/data", },
        { .length = 11, .path = "/mnt/sdcard" },
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

/*
// sys_sendto(int fd, void *buf, size_t len, unsigned flags, struct sockaddr *addr, int addr_len)

int send_entry_handler(int fd, void *ubuf, size_t len, unsigned flags, struct sockaddr *addr, int addr_len)
{
    static __s32 id = 1;
    char buf[SBUF_SIZE];
    struct eevent_t *eevent = (struct eevent_t *)buf;
    
    eevent = (struct eevent_t *)buf;
    eevent->id = id;
    eevent->type = EEVENT_NET_SEND;
    eevent->reserved = task_uid(current);
    eevent->len =
        sprintf(eevent->params, "%u", len > INT_MAX ? INT_MAX : len);
    
    elogk(eevent, ELOG_NET, 0);
    
    return 0;
}

static struct kretprobe send_kretprobe = {
    .handler = send_ret_handler,
    .entry_handler = send_entry_handler,
    .data_size = sizeof(struct elog_probe_data),
    .kp = {
        .symbol_name = "sys_sendto",
    },
    .maxactive = 10,
};


// sys_recvfrom(int fd, void *buf, size_t size, unsigned flags, struct sockaddr *addr, int *addr_len)

int net_recv_handler(int fd, void *ubuf, size_t len, unsigned flags, struct sockaddr *addr, int *addr_len)
{
    char buf[SBUF_SIZE];
    struct eevent_t *eevent;

    eevent = (struct eevent_t *)buf;
    eevent->id = 0;
    eevent->type = EEVENT_NET_RECV;
    eevent->reserved = task_uid(current);
    eevent->len =
        sprintf(eevent->params, "%u", len > INT_MAX ? INT_MAX : len);
    
    elogk(eevent, ELOG_NET, 0);
    
    jprobe_return();
    return 0;
}


static struct kretprobe recv_kretprobe = {
    .handler = recv_ret_handler,
    .entry_handler = recv_entry_handler,
    .data_size = sizeof(struct elog_probe_data),
    .kp = {
        .symbol_name = "sys_sendto",
    },
    .maxactive = 10,
};
*/
static int __init etrace_init(void)
{
    int ret;

    ret = register_kretprobe(&read_kretprobe);
    if (ret < 0)
        goto err;
    ret = register_kretprobe(&write_kretprobe);
    if (ret < 0)
        goto err;
/*    ret = register_kretprobe(&send_kretprobe);
    if (ret < 0)
        goto err;
    ret = register_kretprobe(&recv_kretprobe);
    if (ret < 0)
        goto err;
*/  
    ktime_get_ts(&timestat);
    
    return 0;
    
  err:
    printk(KERN_INFO "etrace init failed\n");
    return -1;
}

static void __exit etrace_exit(void)
{
    long s = timestat.tv_sec;
    
    unregister_kretprobe(&read_kretprobe);
    unregister_kretprobe(&write_kretprobe);
//    unregister_kretprobe(&send_kretprobe);
//    unregister_kretprobe(&recv_kretprobe);
    
    ktime_get_ts(&timestat);
     
    printk(KERN_INFO "%d read, %d write, %d send, %d recv in %ld seconds!\n",
           counter[EEVENT_VFS_READ],
           counter[EEVENT_VFS_WRITE],
           counter[EEVENT_NET_SEND],
           counter[EEVENT_NET_RECV],
           
           timestat.tv_sec - s);
    
    return;
}

module_init(etrace_init)
module_exit(etrace_exit)
MODULE_LICENSE("GPL");
