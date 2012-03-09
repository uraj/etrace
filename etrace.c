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
 *
 * We choose 3 syscalls to begin with:
 *   1. open
 *   2. read
 *   3. write
 * Corresponding core subroutines are:
 *   1. do_sys_open
 *   2. vfs_read
 *   3. vfs_write
 *
 * Note: do_sys_open is not an exported symbol, while vfs_read and
 * vfs_write are. What symbols are elected to be exported may be
 * an interesting question. Figure it out.
 */

static unsigned int counter[10];
static struct timespec timestat;

#define regs_arg(regs,no,type)     ((type)((regs)->ARM_r ## no))

#define STR_BUF_SIZE          256
#define EBUF_SIZE             (STR_BUF_SIZE + sizeof(struct eevent_t))
#define SBUF_SIZE             32
#define ERR_FILENAME          ("(.)")

static char __buf[STR_BUF_SIZE];
    
/* needed by hooking open, read, write */
#include <linux/fs.h>

struct fs_kretprobe_data
{
    __s16 id;
    __u16 hook_ret;
};

#define EEVENT_OPEN_NO       1
#define EEVENT_READ_NO       2
#define EEVENT_WRITE_NO      3

static inline int __file_filter(char * path, size_t length)
{
    if (length < 5)
        return 0;
    
    if (strncmp(path, "/proc", 5) == 0)
        return 1;
    
    if (strncmp(path, "pipe:", 5) == 0)
        return 1;
    
    return 0;
}

#define file_filter(x,y) __file_filter(x,y)
//#define file_filter(x,y) 0

/*
 * hooked func:
 * ssize_t vfs_read(struct file *file, char *buf, size_t count, loff_t *pos)
 */
static int read_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    static __s16 id = 0;
    static char buf[EBUF_SIZE];
    struct eevent_t *eevent = (struct eevent_t *)buf;

    struct file *arg0 = regs_arg(regs, 0, struct file *);
    
    char *fpath;
    int fpath_len;

    struct fs_kretprobe_data *data = (struct fs_kretprobe_data *)ri->data;
    
    fpath = d_path(&arg0->f_path, __buf, STR_BUF_SIZE);
    if (IS_ERR(fpath))
        fpath = ERR_FILENAME;
    fpath_len = strlen(fpath);
    
    if (file_filter(fpath, fpath_len))
    {
        data->hook_ret = 0;
        return 0;
    }

    data->hook_ret = 1;
    data->id = id;
    eevent->syscall_no = EEVENT_READ_NO;
    eevent->id = id++;
    eevent->len =
        sprintf(eevent->params, "\"%.*s\"", fpath_len, fpath);
    
    elogk(eevent);
    
    ++counter[EEVENT_READ_NO];
    
    return 0;
}

static int read_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    static char buf[SBUF_SIZE];
    struct eevent_t *eevent;

    struct fs_kretprobe_data *data = (struct fs_kretprobe_data *)ri->data;

    if (data->hook_ret == 0)
        return 0;
    
    /* negative id for return entry */
    eevent = (struct eevent_t *)buf;
    eevent->id = -*((__s16 *)ri->data);
    eevent->syscall_no = EEVENT_READ_NO;
    eevent->len = sprintf(eevent->params, "%d", (ssize_t)regs_return_value(regs));
    
    elogk(eevent);
    
    return 0;
}

static struct kretprobe read_kretprobe =
{
    .handler = read_ret_handler,
    .entry_handler = read_entry_handler,
    .data_size = sizeof(struct fs_kretprobe_data),
    .kp =
    {
        .symbol_name = "__ee_read_core",
    },
    .maxactive = 10,
};

/*
 * hooked func:
 * ssize_t vfs_write(struct file *file, char *buf, size_t count, loff_t *pos)
 */
static int write_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    static __s16 id = 0;
    static char buf[EBUF_SIZE];
    struct eevent_t *eevent = (struct eevent_t *)buf;

    struct file *arg0 = regs_arg(regs, 0, struct file *);

    char *fpath;
    int fpath_len;

    struct fs_kretprobe_data *data = (struct fs_kretprobe_data *)ri->data;
    
    fpath = d_path(&arg0->f_path, __buf, STR_BUF_SIZE);
    if (IS_ERR(fpath))
        fpath = ERR_FILENAME;
    fpath_len = strlen(fpath);
    
    if (file_filter(fpath, fpath_len))
    {
        data->hook_ret = 0;
        return 0;
    }
    
    data->hook_ret = 1;
    data->id = id;
    eevent->syscall_no = EEVENT_WRITE_NO;
    eevent->id = id++;    
    eevent->len =
        sprintf(eevent->params, "\"%.*s\"", fpath_len, fpath);
    
    elogk(eevent);
    
    ++counter[EEVENT_WRITE_NO];
    
    return 0;
}

static int write_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    static char buf[SBUF_SIZE];
    struct eevent_t *eevent;
    struct fs_kretprobe_data *data = (struct fs_kretprobe_data *)ri->data;

    if (data->hook_ret == 0)
        return 0;
    
    /* negative id for return entry */
    eevent = (struct eevent_t *)buf;
    eevent->id = - data->id;
    eevent->syscall_no = EEVENT_WRITE_NO;
    eevent->len = sprintf(eevent->params, "%d", (ssize_t)regs_return_value(regs));
    
    elogk(eevent);
    
    return 0;
}

static struct kretprobe write_kretprobe =
{
    .handler = write_ret_handler,
    .entry_handler = write_entry_handler,
    .data_size = sizeof(struct fs_kretprobe_data),
    .kp =
    {
        .symbol_name = "vfs_write",
    },
    .maxactive = 10,
};

static int __init etrace_init(void)
{
    int ret;

    ret = register_kretprobe(&read_kretprobe);
    if (ret < 0)
        goto err;

    ret = register_kretprobe(&write_kretprobe);
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
    
    unregister_kretprobe(&read_kretprobe);
    unregister_kretprobe(&write_kretprobe);

    ktime_get_ts(&timestat);
    
    printk(KERN_INFO "%d read, %d write in %ld seconds!\n",
           counter[EEVENT_READ_NO],
           counter[EEVENT_WRITE_NO],
           timestat.tv_sec - s);
    return;
}

module_init(etrace_init)
module_exit(etrace_exit)
MODULE_LICENSE("GPL");

