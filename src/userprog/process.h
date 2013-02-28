#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "lib/user/syscall.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/mmap.h"

struct file_handle
{
	struct file* f;
	int fd;
	struct list_elem elem;
};
struct lock filesys_lock;

struct process {
  tid_t tid;
  mapid_t mapid;
  int num_children;
  int waiting_thread; // init -1
  int waiting_status; // init whateva
  bool exited;
  int exit_status;
  struct process* parent;
  struct process** children;
  struct lock wait_lock;
  struct condition wait_cond;
  struct file* execFile;
  struct list_elem elem;
  int process_fd;           
  struct list file_list;
  int num_stack_pages;
};

/* Root process */
struct list process_list;
struct process root_process;
struct lock root_lock;


tid_t process_execute (const char *cmdline);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
struct process* get_process(tid_t tid);
struct process* process_current(void);
struct process* get_parent(struct process* process);
struct process* get_process_recursive(tid_t tid, struct process* process);
struct process* add_process(tid_t parent_tid, tid_t child_tid); 
void remove_process(tid_t parent_tid, tid_t child_tid);
void lazy_load_segment(struct page* fault_page, struct file* file);
void grow_stack(void* fault_addr, struct intr_frame* f);
struct file_handle* find_file_handle(int fd);
void null_children(struct process* parent);
bool install_page (void *upage, void *kpage, bool writable);

#ifdef THREADS_H_H
void cleanup_mmap(struct intr_frame* f);
void cleanup_process(uint32_t status, struct intr_frame *f);
#endif

#endif /* userprog/process.h */
