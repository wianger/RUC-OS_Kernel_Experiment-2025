// SPDX-License-Identifier: GPL-2.0
/*
 * StatPlus (assignment skeleton)
 * Goal: On module load, print information for a given PID's file descriptor
 * (default: fd=3).
 *
 * Keep the printing block unchanged. Implement the TODOs to make it work.
 */
#include <linux/dcache.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kdev_t.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/path.h>
#include <linux/pid.h>
#include <linux/sched/signal.h>
#include <linux/time64.h>
#include <linux/uidgid.h>

static int pid = -1;
module_param(pid, int, 0644);
MODULE_PARM_DESC(pid, "Target PID");

static int fd = 3; /* default: 3 */
module_param(fd, int, 0644);
MODULE_PARM_DESC(fd, "Target FD (default 3)");

char path_buf[PATH_MAX];

static int __init stat_plus_init(void) {
  struct task_struct *task; /* Process resolution is provided (not graded). */
  struct files_struct *files __maybe_unused;
  struct file *file = NULL;

  if (pid <= 0) {
    pr_err("StatPlus: please set pid (>0)\n");
    return -EINVAL;
  }
  if (fd < 0) {
    pr_err("StatPlus: fd must be >= 0\n");
    return -EINVAL;
  }

  /* Process lookup is provided (not part of grading). */
  task = get_pid_task(find_vpid(pid), PIDTYPE_PID);
  if (!task) {
    pr_err("StatPlus: pid %d not found\n", pid);
    return -ESRCH;
  }

  /* TODO: From task->files, locate the file corresponding to the given fd
   * under the correct synchronization. Hold a safe reference to the file
   * while printing its information, and release it afterwards.
   */
  rcu_read_lock();
  files = task->files;
  if (files) {
    struct fdtable *fdt = files_fdtable(files);
    if (fd < fdt->max_fds)
      file = fdt->fd[fd];
    if (file)
      get_file(file);
  }
  rcu_read_unlock();

  /* TODO (optional): Use an RCU-friendly approach for walking the fd table
   * and briefly justify the synchronization choice.
   */
  // Justification: Using RCU for reading the file descriptor table is
  // efficient as it allows concurrent access without locking for readers.
  // It's safe because modifications to the fd table (like closing or duping
  // fds) use mechanisms like call_rcu() to ensure data structures are not
  // freed until all readers have finished. get_file() is used to safely
  // increment the file's reference count, ensuring it won't be deallocated
  // while we are using it.

  /* Drop the task reference here to avoid leaks in the skeleton.
   * When you implement the TODOs above, adjust the placement accordingly.
   */
  put_task_struct(task);

  if (!file) {
    pr_err("StatPlus: pid %d has no open file at fd=%d\n", pid, fd);
    return -EBADF;
  }

  /* Gather and print information. NOTE: keep the block below unchanged. */
  {
    char *path = path_buf;
    struct inode *inode = file_inode(file);
    umode_t mode = inode->i_mode;
    const char *type;
    kuid_t kuid = inode->i_uid;
    kgid_t kgid = inode->i_gid;
    unsigned int uid = from_kuid_munged(current_user_ns(), kuid);
    unsigned int gid = from_kgid_munged(current_user_ns(), kgid);
    loff_t size = inode_get_bytes(inode);
    loff_t pos = file->f_pos;
    struct timespec64 at = inode->i_atime;
    struct timespec64 mt = inode->i_mtime;
    struct timespec64 ct = inode->__i_ctime;
    dev_t sdev = inode->i_sb->s_dev;

    /* TODO: Fill all fields from file/inode under proper sync; get path via
     * d_path (handle IS_ERR). */
    path = d_path(&file->f_path, path_buf, PATH_MAX);
    if (IS_ERR(path)) {
      path = "(error)";
    }

    if (S_ISREG(mode))
      type = "regular";
    else if (S_ISDIR(mode))
      type = "directory";
    else if (S_ISLNK(mode))
      type = "symlink";
    else if (S_ISCHR(mode))
      type = "char device";
    else if (S_ISBLK(mode))
      type = "block device";
    else if (S_ISFIFO(mode))
      type = "fifo";
    else if (S_ISSOCK(mode))
      type = "socket";
    else
      type = "unknown";

    pr_info("StatPlus: PID=%d FD=%d\n", pid, fd);
    pr_info("  path: %s\n", path);
    pr_info("  type: %s\n", type);
    pr_info("  mode: %#o (perm=%#o)\n", mode, mode & 07777);
    pr_info("  uid: %u  gid: %u\n", uid, gid);
    pr_info("  size: %lld  pos: %lld\n", (long long)size, (long long)pos);
    pr_info("  inode: %lu  nlink: %lu\n", (unsigned long)inode->i_ino,
            (unsigned long)inode->i_nlink);
    pr_info("  flags: %#x  fmode: %#x\n", file->f_flags, file->f_mode);
    pr_info("  superblock: %s  sb_dev: %u:%u\n",
            inode->i_sb ? inode->i_sb->s_id : "?", MAJOR(sdev), MINOR(sdev));
    pr_info("  atime: %lld.%09lu\n  mtime: %lld.%09lu\n  ctime: %lld.%09lu\n",
            (long long)at.tv_sec, (unsigned long)at.tv_nsec,
            (long long)mt.tv_sec, (unsigned long)mt.tv_nsec,
            (long long)ct.tv_sec, (unsigned long)ct.tv_nsec);
  }

  /* Balance get_file() once the TODOs are implemented. */
  fput(file);
  return 0;
}

static void __exit stat_plus_exit(void) { pr_info("StatPlus: unloaded\n"); }

MODULE_LICENSE("GPL");
MODULE_AUTHOR("StatPlus");
MODULE_DESCRIPTION("Print specified PID's fd (default 3) info - stat plus");
MODULE_VERSION("1.0");

module_init(stat_plus_init);
module_exit(stat_plus_exit);
