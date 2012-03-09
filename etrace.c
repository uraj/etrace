#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kernel.h>
#include <linux/elogk.h>
#include <linux/string.h>

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

static inline int file_filter(char * path, size_t length)
{
    if (length < 5)
        return 0;
    
    if (strncmp(path, "/proc", 5) == 0)
        return 1;
    
    return 0;
}

/*
 * hooked func:
 * void fd_install(unsgined int fd, struct file *file)
 */
static void open_handler(unsigned int fd, struct file *file)
{
    static __s16 id = 0;
    static char buf[EBUF_SIZE];
    char *fpath;
    int fpath_len;
    
    struct eevent_t *eevent = (struct eevent_t *)buf;
    
    fpath = d_path(&file->f_path, __buf, STR_BUF_SIZE);
    if (IS_ERR(fpath))
        fpath = ERR_FILENAME;
    fpath_len = strlen(fpath);

    if (file_filter(fpath, fpath_len))
        jprobe_return();

    eevent->syscall_no = EEVENT_OPEN_NO;
    eevent->id = id++;
    eevent->len =
        sprintf(eevent->params, "%u,\"%.*s\"", fd, fpath_len, fpath);

    elogk(eevent);

    jprobe_return();
}

static struct jprobe open_jprobe =
{
    .entry = open_handler,
    .kp =
    {
        .symbol_name = "fd_install",
    },
};

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
    char *arg1        = regs_arg(regs, 1, char *);
    size_t arg2       = regs_arg(regs, 2, size_t);
    loff_t *arg3      = regs_arg(regs, 3, loff_t *);
    
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
    eevent->len = sprintf(eevent->params, "\"%.*s\",%p,%u,%p",
                          fpath_len, fpath, arg1, arg2, arg3);
    
    elogk(eevent);
    
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
        .symbol_name = "vfs_read",
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
    char *arg1        = regs_arg(regs, 1, char *);
    size_t arg2       = regs_arg(regs, 2, size_t);
    loff_t *arg3      = regs_arg(regs, 3, loff_t *);

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
        sprintf(eevent->params, "\"%.*s\",%p,%u,%p",
                fpath_len, fpath, arg1, arg2, arg3);
    
    elogk(eevent);
    
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

    ret = register_jprobe(&open_jprobe);
    if (ret < 0)
        goto err;

    ret = register_kretprobe(&read_kretprobe);
    if (ret < 0)
        goto err;

    ret = register_kretprobe(&write_kretprobe);
    if (ret < 0)
        goto err;
    
    return 0;
    
  err:
    printk(KERN_INFO "etrace init failed\n");
    return -1;
}

static void __exit etrace_exit(void)
{
    unregister_jprobe(&open_jprobe);
    unregister_kretprobe(&read_kretprobe);
    unregister_kretprobe(&write_kretprobe);
    return;
}

module_init(etrace_init)
module_exit(etrace_exit)
MODULE_LICENSE("GPL");

