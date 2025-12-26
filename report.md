# 操作系统内核分析及安全实验报告

## 实验概述

本实验报告涵盖了操作系统内核实验的各个章节，包括进程管理、系统调用、存储管理、文件系统、进程间通信、内核同步、中断机制以及安全相关实验。所有实验基于 Linux 6.6 内核版本，通过编写内核模块来深入理解操作系统的核心机制。

---

## 一、Linux 内核概述

### 1.1 DebugKernel - 内核调试

**实验目标**：学习如何使用 GDB 调试 Linux 内核。

**实验方法**：
1. 使用 QEMU 启动内核时添加 `-s -S` 参数：
   - `-s`：在 TCP 端口 1234 上启动 GDB 服务器
   - `-S`：启动时暂停虚拟机 CPU，等待 GDB 连接
2. 在另一个终端使用 GDB 远程连接：
   ```bash
   gdb vmlinux -ex "target remote:1234" -ex "b {target_function}" -ex "c"
   ```
3. 为获取调试信息，需要在内核编译时启用 `CONFIG_DEBUG_INFO` 选项，并选择 DWARF5 格式。

**关键知识点**：GDB 远程调试、内核编译选项配置、断点设置。

---

## 二、进程管理与调度

### 2.1 ProcessShow - 进程信息展示

**实验目标**：编写内核模块遍历并打印所有进程的状态信息。

**实验方法**：
1. 使用 `for_each_process(task)` 宏遍历系统中所有进程
2. 通过 `task_struct` 结构体获取进程信息：
   - `task->pid`：进程 PID
   - `task->__state`：进程状态（RUNNING、INTERRUPTIBLE 等）
   - `task->comm`：进程命令名
   - `task->cred->euid/egid`：有效用户/组 ID
   - `task->parent->pid`：父进程 PID
3. 使用 `task_thread_info(task)` 获取线程信息结构

**核心代码**：
```c
rcu_read_lock();
for_each_process(task) {
    printk(KERN_INFO "PID: %-6d | State: %-16s | Command: %-16s\n", 
           task->pid, get_task_state(task->__state), task->comm);
}
rcu_read_unlock();
```

---

### 2.2 ScheduleObserver - 调度观察器

**实验目标**：创建内核线程观察 CFS 调度器行为，比较不同优先级线程的调度次数。

**实验方法**：
1. 使用 `kthread_run()` 创建多个内核线程
2. 线程函数中调用 `schedule()` 主动让出 CPU，并使用原子变量记录调度次数
3. 使用 `set_user_nice(task, -20)` 设置线程的 nice 值来调整优先级
4. 卸载模块时打印各线程的调度次数

**关键发现**：nice 值越低（优先级越高）的线程获得更多的调度机会。

---

### 2.3 HideProcess - 进程隐藏（RootKit）

**实验目标**：通过内核模块将指定进程从进程链表中摘除，使其对 `for_each_process` 遍历不可见。

**实验方法**：
1. 遍历进程链表找到目标进程（如 "malware"）
2. 使用 `list_del_init(&task->tasks)` 将进程从 `tasks` 链表中删除
3. 保存删除位置以便模块卸载时恢复

**核心代码**：
```c
for_each_process(task) {
    if (strcmp(task->comm, target_process) == 0) {
        saved_prev = task->tasks.prev;
        list_del_init(&task->tasks);
        hidden_task = task;
        break;
    }
}
```

**安全意义**：展示了 RootKit 如何通过操纵内核数据结构隐藏恶意进程。

---

## 三、系统调用

### 3.1 SyscallShow - 系统调用表展示

**实验目标**：打印内核中所有系统调用的地址和符号名称。

**实验方法**：
1. 使用 `kallsyms_lookup_name("sys_call_table")` 获取系统调用表地址
2. 遍历系统调用表，使用 `sprint_symbol()` 解析函数符号名
3. 需要在内核中导出 `kallsyms_lookup_name` 符号

**核心代码**：
```c
syscall_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
for (i = 0; i < NR_syscalls; i++) {
    sprint_symbol(symbuf, syscall_table[i]);
    pr_info("syscall[%3d] = %lx -> %s\n", i, syscall_table[i], symbuf);
}
```

---

### 3.2 AddSyscall - 添加系统调用

**实验目标**：通过内核模块动态添加自定义系统调用。

**实验方法**：
1. 获取系统调用表地址
2. 清除 CR0 寄存器的 WP（写保护）位以允许修改只读页面
3. 替换指定位置的系统调用处理函数
4. 自定义系统调用返回当前进程的 PID

**核心代码**：
```c
unsigned int clear_and_return_cr0(void) {
    unsigned int cr0 = 0;
    asm volatile("movq %%cr0, %%rax" : "=a"(cr0));
    cr0 &= 0xfffeffff;  // 清除 WP 位
    asm volatile("movq %%rax, %%cr0" ::"a"(cr0));
    return ret;
}

static int sys_mycall(void) { 
    return task_tgid_vnr(current); 
}
```

---

### 3.3 HookSyscall - 系统调用 Hook（RootKit）

**实验目标**：Hook `setuid` 系统调用实现恶意进程提权。

**实验方法**：
1. 找到目标进程（通过 PID 或进程名）
2. 替换 `setuid` 系统调用为自定义函数
3. 当目标进程调用时，使用 `prepare_creds()` 和 `commit_creds()` 将 UID/GID 设为 0（root）

**核心代码**：
```c
static long sys_mycall(uid_t uid) {
    if (target_task && current == target_task) {
        struct cred *new_cred = prepare_creds();
        new_cred->uid.val = 0;
        new_cred->euid.val = 0;
        commit_creds(new_cred);
        return 0;
    }
    return anything_saved(uid);
}
```

---

## 四、存储管理

### 4.1 MemoryStatus - 内存状态统计

**实验目标**：遍历物理页面统计内存使用情况，并展示进程的 VMA 和页表信息。

**实验方法**：
1. **物理内存遍历**：
   - 使用 `for_each_online_node()` 遍历所有 NUMA 节点
   - 通过 `pfn_to_page()` 获取页面结构
   - 使用 `PageBuddy/PageAnon/PageSlab` 等宏分类页面

2. **VMA 遍历**：
   - 使用 `VMA_ITERATOR` 和 `for_each_vma` 遍历进程的虚拟内存区域
   - 打印每个 VMA 的起始地址、结束地址、标志和关联文件

3. **页表遍历**：
   - 使用四级页表结构（PGD→P4D→PUD→PMD→PTE）逐层遍历
   - 处理大页（Huge Page）情况
   - 需要导出 `__pte_offset_map` 符号

---

### 4.2 TraverseVMA - VMA 写位翻转

**实验目标**：遍历指定进程的 VMA 并翻转 `VM_WRITE` 标志位。

**实验方法**：
1. 使用 `vma_iter_init()` 和 `vma_next()` 遍历进程 VMA
2. 使用 `vm_flags_set/vm_flags_clear` 安全地修改 VMA 标志
3. 跳过特殊 VMA（`VM_IO`、`VM_PFNMAP`、`VM_SPECIAL`）

**核心代码**：
```c
mmap_write_lock(mm);
while ((vma = vma_next(&vmi)) != NULL) {
    if (old_flags & VM_WRITE)
        vm_flags_clear(vma, VM_WRITE);
    else
        vm_flags_set(vma, VM_WRITE);
}
mmap_write_unlock(mm);
```

---

### 4.3 HideVMA - VMA 隐藏（RootKit）

**实验目标**：从进程的 VMA maple tree 中删除指定 VMA，使其在 `/proc/<pid>/maps` 中不可见。

**实验方法**：
1. 使用 `MA_STATE` 和 `mas_for_each` 遍历 maple tree
2. 找到可执行 VMA（代码段）后使用 `mas_erase()` 删除

**核心代码**：
```c
MA_STATE(mas, &mm->mm_mt, 0, 0);
mas_for_each(&mas, vma, ULONG_MAX) {
    if (vma->vm_flags & VM_EXEC) {
        mas_erase(&mas);
        break;
    }
}
```

---

## 五、文件系统

### 5.1 StatPlus - 文件详细信息

**实验目标**：打印指定进程指定文件描述符对应文件的详细信息。

**实验方法**：
1. 通过 `task->files` 获取文件描述符表
2. 使用 RCU 保护访问 `files_fdtable()`
3. 从 `struct file` 获取 inode 信息
4. 使用 `d_path()` 获取文件完整路径

**打印信息包括**：路径、类型、权限、UID/GID、大小、inode 号、时间戳等。

---

### 5.2 ProcMirror - Proc 文件系统镜像

**实验目标**：在 `/proc` 下创建目录，用符号链接映射目标进程打开的文件。

**实验方法**：
1. 使用 `proc_mkdir()` 创建目录
2. 遍历目标进程的文件描述符表
3. 使用 `d_path()` 解析文件路径
4. 使用 `proc_symlink()` 创建符号链接

---

### 5.3 RedirectFile - 文件重定向（RootKit）

**实验目标**：将恶意进程打开的文件重定向到 `/etc/passwd`。

**实验方法**：
1. 遍历目标进程的文件描述符表
2. 找到目标文件后，使用 `filp_open()` 打开 `/etc/passwd`
3. 使用 `rcu_assign_pointer()` 替换文件描述符指向的文件

**安全意义**：展示了如何通过操纵文件描述符表实现文件内容篡改。

---

## 六、进程间通信

### 6.1 MutiIPC - 多 IPC 协作 Fuzz 框架

**实验目标**：实现一个结合消息队列、共享内存和信号量的 Fuzz 测试框架。

**需要实现的接口**：
1. **消息队列**（msgqueue.c）：
   - `msgqueue_init()`：创建/获取消息队列
   - `msgqueue_send/recv()`：发送/接收任务
   - `msgqueue_cleanup()`：清理资源

2. **共享内存+信号量**（shm_sem.c）：
   - `shmsem_init()`：创建共享内存和信号量
   - `shm_write/read_sample()`：读写样本数据
   - `shmsem_cleanup()`：清理资源

---

### 6.2 CheatIPC - IPC 消息篡改

**实验目标**：在内核中篡改 System V 消息队列中的消息内容。

**实验方法**：
1. 找到目标进程（sender）
2. 获取其 IPC 命名空间
3. 使用 `ipc_obtain_object_check()` 获取消息队列
4. 遍历 `q_messages` 链表修改消息内容

**核心代码**：
```c
msq = container_of(ipcp, struct msg_queue, q_perm);
list_for_each_entry_safe(msg, t, &msq->q_messages, m_list) {
    str = (char *)(msg + 1);
    if (strncmp(str, "good", 4) == 0) {
        strcpy(str, "bad");
    }
}
```

---

### 6.3 SignalBlocker - 信号拦截（RootKit）

**实验目标**：让指定进程忽略特定信号（如 SIGINT）。

**实验方法**：
1. 找到目标进程
2. 修改 `task->sighand->action[BLOCKED_SIG-1]`
3. 设置 `sa_handler = SIG_IGN`

**核心代码**：
```c
struct k_sigaction *ksa = &task->sighand->action[BLOCKED_SIG - 1];
ksa->sa.sa_handler = SIG_IGN;
sigemptyset(&ksa->sa.sa_mask);
```

---

## 七、内核同步

### 7.1 RaceCondition - 竞态条件演示

**实验目标**：演示在不实施内核同步控制时共享变量的不一致问题。

**实验方法**：
1. 实现两个系统调用（454、455）对共享变量进行不同的操作
2. 多线程并发调用时，由于缺少同步机制导致结果不一致
3. 实现系统调用 456 读取共享变量的值

---

### 7.2 VisitShared - 共享变量同步

**实验目标**：使用互斥锁消除竞态条件。

**实验方法**：
1. 定义 `DEFINE_MUTEX(vs_lock)` 创建互斥锁
2. 在访问共享变量前后使用 `mutex_lock/mutex_unlock`
3. 通过字符设备 ioctl 接口提供 `INC1`、`INC2`、`GET` 操作

**核心代码**：
```c
case VS_INC1:
    mutex_lock(&vs_lock);
    tmp = shared_val;
    schedule();  // 模拟竞态窗口
    shared_val = tmp + 1;
    mutex_unlock(&vs_lock);
    return 0;
```

**实验效果**：加锁后 `Expected=Observed`，消除了竞态条件。

---

## 八、中断机制

### 8.1 IDTHook - 键盘监控（RootKit）

**实验目标**：注册键盘中断处理函数，记录每个按键。

**实验方法**：
1. Hook 键盘中断处理程序
2. 在自定义处理函数中记录按键信息
3. 调用原始处理函数保持正常功能

---

## 九、其他实验

### 9.1 StudentList - 学生链表管理

**实验目标**：实现内核模块管理学生数据结构，支持增删查操作。

**实验方法**：
1. 使用 `list_head` 实现链表
2. 使用 `hlist_head` 实现年级和学院的哈希表索引
3. 通过字符设备 ioctl 接口与用户空间交互
4. 实现汇编版本的 `strcmp` 函数

**数据结构**：
```c
struct student {
    int id;
    char name[16];
    struct list_head list;           // 主链表
    struct hlist_node hnode_grade;   // 年级哈希表
    struct hlist_node hnode_college; // 学院哈希表
};
```

---

## 十、安全实验

### 10.1 CodeQL 漏洞挖掘

**实验目标**：使用 CodeQL 静态分析工具检测内核代码中预埋的漏洞。

**漏洞类型**：
1. **栈越界访问（Stack OOB）**
2. **堆越界访问（Heap OOB）**
3. **释放后使用（UAF）**
4. **双重释放（Double Free）**

**实验方法**：
1. 创建 CodeQL 数据库：`codeql database create`
2. 编写 QL 查询规则匹配漏洞模式
3. 运行分析：`codeql database analyze`

**QL 查询示例**（栈 OOB）：
```ql
from ArrayExpr access, LocalVariable arr, Literal bound
where
  arr.getType().(ArrayType).getArraySize() = size and
  bound.getValue().toInt() > size
select access, "Array of size " + size + " may be indexed beyond bounds"
```

---

## 实验总结

本系列实验通过编写内核模块深入了解了 Linux 内核的核心机制：

1. **进程管理**：理解了 `task_struct` 结构和进程遍历机制
2. **系统调用**：掌握了系统调用表的结构和 Hook 技术
3. **内存管理**：学习了物理页面、VMA、页表的组织方式
4. **文件系统**：了解了文件描述符表和 inode 结构
5. **进程间通信**：实践了消息队列、共享内存、信号量的内核实现
6. **内核同步**：理解了竞态条件的危害和互斥锁的使用
7. **安全实验**：了解了 RootKit 技术和静态代码分析

这些实验不仅加深了对操作系统原理的理解，也提高了内核编程和安全分析的实践能力。

