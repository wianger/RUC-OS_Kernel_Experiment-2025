// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/mmzone.h>
#include <linux/module.h>
#include <linux/nodemask.h>
#include <linux/page_ref.h>
#include <linux/pgtable.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sysinfo.h>

#ifndef pud_devmap
#define pud_devmap(pud) 0
#endif

#ifndef pmd_devmap
#define pmd_devmap(pmd) 0
#endif

#ifndef pud_huge
#define pud_huge(pud) 0
#endif

#ifndef pmd_huge
#define pmd_huge(pmd) 0
#endif

#ifndef pmd_trans_huge
#define pmd_trans_huge(pmd) 0
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CheUhxg");
MODULE_DESCRIPTION("Show memory statistics and process memory map");
MODULE_VERSION("2.0");

static int pid = -1;
module_param(pid, int, 0644);
MODULE_PARM_DESC(pid, "Target process PID");

static void traverse_all_pages(void) {
  unsigned long total_pages = 0;
  unsigned long valid_pages = 0;
  unsigned long free_pages = 0;
  unsigned long anon_pages = 0;
  unsigned long file_pages = 0;
  unsigned long slab_pages = 0;
  unsigned long dirty_pages = 0;
  unsigned long writeback_pages = 0;
  unsigned long lru_pages = 0;
  int nid;

  pr_info("[memory_status] ===== Page Frame Traversal =====\n");

  for_each_online_node(nid) {
    unsigned long start_pfn = node_start_pfn(nid);
    unsigned long end_pfn = node_end_pfn(nid);
    unsigned long pfn;

    for (pfn = start_pfn; pfn < end_pfn; pfn++) {
      struct page *page;

      total_pages++;

      if (!pfn_valid(pfn))
        continue;

      valid_pages++;
      page = pfn_to_page(pfn);

      /* TODO: classify page and update relevant counters */
      if (PageBuddy(page))
        free_pages++;
      if (PageAnon(page))
        anon_pages++;
      if (page->mapping != NULL && !PageAnon(page))
        file_pages++;
      if (PageSlab(page))
        slab_pages++;
      if (PageDirty(page))
        dirty_pages++;
      if (PageWriteback(page))
        writeback_pages++;
      if (PageLRU(page))
        lru_pages++;
    }
  }

  pr_info("[memory_status] ===== Page Type Summary =====\n");
  pr_info("[memory_status] total_pfn         = %lu\n", total_pages);
  pr_info("[memory_status] valid_pfn         = %lu\n", valid_pages);
  pr_info("[memory_status] free_pages        = %lu\n", free_pages);
  pr_info("[memory_status] anon_pages        = %lu\n", anon_pages);
  pr_info("[memory_status] file_pages        = %lu\n", file_pages);
  pr_info("[memory_status] slab_pages        = %lu\n", slab_pages);
  pr_info("[memory_status] dirty_pages       = %lu\n", dirty_pages);
  pr_info("[memory_status] writeback_pages   = %lu\n", writeback_pages);
  pr_info("[memory_status] lru_pages         = %lu\n", lru_pages);
  pr_info("[memory_status] PAGE_SIZE         = %lu bytes\n", PAGE_SIZE);
}

static void show_vmas(struct mm_struct *mm) {
  struct vm_area_struct *vma;
  VMA_ITERATOR(vmi, mm, 0);

  pr_info("[memory_status] ===== Traverse VMA (Maple Tree) =====\n");

  /* TODO: iterate VMAs and print basic info */
  const char *file_name;
  mmap_read_lock(mm);
  for_each_vma(vmi, vma) {
    if (vma->vm_file)
      file_name = vma->vm_file->f_path.dentry->d_name.name;
    else
      file_name = "(null)";
    pr_info("VMA: 0x%lx - 0x%lx, flags=0x%lx, anon=%d, file=%s\n",
            vma->vm_start, vma->vm_end, vma->vm_flags, !vma->vm_file,
            file_name);
  }
  mmap_read_unlock(mm);
}

static void traverse_page_table(struct mm_struct *mm) {
  unsigned long addr;
  unsigned long mapped_pages = 0;
  const unsigned long end = mm->task_size;

  pr_info("[memory_status] ===== Page Table Walk (partial) =====\n");

  mmap_read_lock(mm);
  /* Descend the page table hierarchy while skipping empty ranges fast. */
  for (addr = 0; addr < end;) {
    /* TODO: walk the page table and count mapped pages
     * Reminder: use pte_offset_map() to access PTEs safely
     */
    pgd_t *pgd = pgd_offset(mm, addr);
    unsigned long pgd_end = pgd_addr_end(addr, end);

    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
      addr = pgd_end;
      continue;
    }

    unsigned long p4d_addr;
    for (p4d_addr = addr; p4d_addr < pgd_end;) {
      p4d_t *p4d = p4d_offset(pgd, p4d_addr);
      unsigned long p4d_end = p4d_addr_end(p4d_addr, pgd_end);

      if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        p4d_addr = p4d_end;
        continue;
      }

      unsigned long pud_addr;
      for (pud_addr = p4d_addr; pud_addr < p4d_end;) {
        pud_t *pud = pud_offset(p4d, pud_addr);
        unsigned long pud_end = pud_addr_end(pud_addr, p4d_end);

        if (pud_none(*pud) || pud_bad(*pud)) {
          pud_addr = pud_end;
          continue;
        }

        if (pud_huge(*pud) || pud_devmap(*pud)) {
          unsigned long base_pfn = pud_pfn(*pud);
          unsigned long pages = (pud_end - pud_addr) >> PAGE_SHIFT;
          unsigned long i;

          for (i = 0; i < pages; i++) {
            unsigned long vaddr = pud_addr + (i << PAGE_SHIFT);
            unsigned long pfn = base_pfn + i;
            phys_addr_t pa = (phys_addr_t)pfn << PAGE_SHIFT;

            pr_info("VA 0x%lx -> PFN 0x%lx (PA 0x%llx)\n", vaddr, pfn,
                    (unsigned long long)pa);
          }
          mapped_pages += pages;
          pud_addr = pud_end;
          continue;
        }

        unsigned long pmd_addr;
        for (pmd_addr = pud_addr; pmd_addr < pud_end;) {
          pmd_t *pmd = pmd_offset(pud, pmd_addr);
          unsigned long pmd_end = pmd_addr_end(pmd_addr, pud_end);

          if (pmd_none(*pmd) || pmd_bad(*pmd)) {
            pmd_addr = pmd_end;
            continue;
          }

          if (pmd_trans_huge(*pmd) || pmd_huge(*pmd) || pmd_devmap(*pmd)) {
            unsigned long base_pfn = pmd_pfn(*pmd);
            unsigned long pages = (pmd_end - pmd_addr) >> PAGE_SHIFT;
            unsigned long i;

            for (i = 0; i < pages; i++) {
              unsigned long vaddr = pmd_addr + (i << PAGE_SHIFT);
              unsigned long pfn = base_pfn + i;
              phys_addr_t pa = (phys_addr_t)pfn << PAGE_SHIFT;

              pr_info("VA 0x%lx -> PFN 0x%lx (PA 0x%llx)\n", vaddr, pfn,
                      (unsigned long long)pa);
            }
            mapped_pages += pages;
            pmd_addr = pmd_end;
            continue;
          }

          pte_t *pte_base = pte_offset_map(pmd, pmd_addr);
          pte_t *pte = pte_base;
          unsigned long pte_addr;

          if (!pte_base) {
            pmd_addr = pmd_end;
            continue;
          }

          for (pte_addr = pmd_addr; pte_addr < pmd_end;
               pte_addr += PAGE_SIZE, pte++) {
            if (!pte_present(*pte)) {
              pr_info("VA 0x%lx -> PFN 0x0 (PA 0x0)\n", pte_addr);
              continue;
            }

            unsigned long pfn = pte_pfn(*pte);
            phys_addr_t pa = (phys_addr_t)pfn << PAGE_SHIFT;

            pr_info("VA 0x%lx -> PFN 0x%lx (PA 0x%llx)\n", pte_addr, pfn,
                    (unsigned long long)pa);
            mapped_pages++;
          }

          pte_unmap(pte_base);
          pmd_addr = pmd_end;
        }
        pud_addr = pud_end;
      }
      p4d_addr = p4d_end;
    }
    addr = pgd_end;
  }

  mmap_read_unlock(mm);

  pr_info("[memory_status] Mapped pages: %lu\n", mapped_pages);
}

static int __init memory_status_init(void) {
  traverse_all_pages();

  if (pid < 0) {
    return 0;
  }

  struct task_struct *task = pid_task(find_vpid(pid), PIDTYPE_PID);
  struct mm_struct *mm;

  if (!task) {
    pr_err("[memory_status] PID %d not found\n", pid);
    return -ESRCH;
  }

  mm = get_task_mm(task);
  if (!mm) {
    pr_err("[memory_status] PID %d has no mm_struct (kernel thread?)\n", pid);
    return -EINVAL;
  }

  pr_info("[memory_status] ===== Target process: %s (pid=%d) =====\n",
          task->comm, pid);

  show_vmas(mm);
  traverse_page_table(mm);

  mmput(mm);
  return 0;
}

static void __exit memory_status_exit(void) {
  pr_info("[memory_status] Module unloaded.\n");
}

module_init(memory_status_init);
module_exit(memory_status_exit);
