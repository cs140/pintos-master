#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <list.h>
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "vm/frame.h"
#include "vm/page.h"


static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
void setup_arguments(void **esp, char* filename, char* save_ptr);
void cleanup_process(uint32_t status, struct intr_frame *f);

#define MAX_CMD_LENGTH 128

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *cmdline) 
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of cmdline.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  // fn_copy = frame_get_page (0, NULL);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, cmdline, PGSIZE);

  char *filename, *save_ptr;
  int len = strlen(cmdline) + 1;
  char cmd_copy[len];

  strlcpy(cmd_copy, cmdline, len);
  filename = strtok_r(cmd_copy, " ", &save_ptr);

  /* Create a new thread to execute cmdline. */
  tid = thread_create (filename, PRI_DEFAULT, start_process, fn_copy);

  if (tid == TID_ERROR) 
  {
    palloc_free_page (fn_copy); 
    // frame_free_page(0, fn_copy, NULL);
    thread_current()->success = false;  
  }

  /* If the thread is created succesfully */
  if (tid != TID_ERROR) 
  {
    struct process* new_process = add_process(thread_current()->tid, tid);
    if(new_process == NULL) thread_current()->success = false;
  }

  thread_current()->success = true;
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *cmdline_)
{
  char *cmdline = cmdline_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  struct thread* t = thread_current();
  supplementary_page_table_init(&t->supplementary_page_table);
  success = load (cmdline, &if_.eip, &if_.esp);


  /* If load failed, quit. */
  struct process* parent = get_parent(get_process(thread_current()->tid));
  struct thread* parent_thread = thread_get(parent->tid);
  lock_acquire(&(parent_thread->process_init_lock));
  palloc_free_page (cmdline);
  // frame_free_page(PAL_USER, cmdline);

  if(parent_thread->success) parent_thread->success = success;

  cond_signal(&(parent_thread->process_init_cond), 
    &(parent_thread->process_init_lock));

  lock_release(&(parent_thread->process_init_lock));

  if (!success) 
  {
    remove_process(parent->tid,thread_current()->tid);
    thread_exit ();
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Get struct process given thread id */
struct process*
get_process (tid_t tid) 
{
  struct list_elem *e;
  for (e=list_begin(&process_list); e!=list_end(&process_list);
    e=list_next(e))
  {
    struct process* p = list_entry(e, struct process, elem);
    if (p->tid == tid) 
    {
      return p;
    }
  }

  return NULL;
}

/* Recursive function to find process given thread id */
struct process*
get_process_recursive (tid_t tid, struct process* process)
{
  if (process->tid == tid) 
    return process;
  int num_children = process->num_children;
  /* Deep first search */
  int i = 0;
  for (i = 0; i < num_children; i++) 
  {
    struct process* cur_process = get_process_recursive(tid, 
                                      process->children[i]);
    if (cur_process != NULL) 
    {
      return cur_process;
    }
  }
  /* Return NULL if don't find process with given tid */
  return NULL;
}

struct process*
get_parent (struct process* process) 
{
  if (process == NULL || process->parent == NULL) {
    return NULL;
  }
  return process->parent;
}

struct process*
add_process (tid_t parent_tid, tid_t child_tid) 
{
  lock_acquire(&root_lock);
  struct process* parent = get_process(parent_tid);
  /* Create the child struct */
  struct process* child = malloc(sizeof(struct process));
  if (child == NULL)
  {
    //MALLOC FAILED
    return NULL;
  }

  child->tid = child_tid;
  child->num_children = 0;
  child->waiting_thread = -1;
  child->exited = false;
  child->parent = parent;
  child->children = NULL;
  lock_init (&child->wait_lock);
  cond_init (&child->wait_cond);
  list_init (&child->file_list);
  child->process_fd = 2;
  /* Add the child in the tree */
  parent->num_children++;
  if (parent->children == NULL) 
  {
    parent->children = malloc(parent->num_children*sizeof(struct process*));
    if (parent->children == NULL) 
    {
      free(child);
      return NULL;
    }
  } else
  {
    parent->children = realloc(parent->children, 
                                parent->num_children*sizeof(struct process*));
  }
  parent->children[parent->num_children-1] = child;
  list_push_back(&process_list, &child->elem);

  lock_release(&root_lock);

  return child;
}

void 
remove_process (tid_t parent_tid, tid_t child_tid)
{
  lock_acquire(&root_lock);
  /* Remove the child from parent */
  struct process* parent = get_process(parent_tid);
  struct process* child = NULL;

  if (parent != NULL) 
  {
    int num_children = parent->num_children;
    int i = 0;
    for (i = 0; i < num_children; i++) {
      if (parent->children[i]->tid == child_tid) {
        child = parent->children[i];
        parent->children[i] = parent->children[num_children-1];
        break;
      }
    }
    parent->num_children--;
  }


  /* Remove from list and free process */

  if (child != NULL) 
  {
    list_remove(&child->elem);
    free(child->children);
    free(child);
  }

  lock_release(&root_lock);
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
  struct process* cur_process = get_process(thread_current()->tid);
  lock_acquire(&cur_process->wait_lock);
  
  //thread is not child of current thread
  struct process* child = get_process(child_tid);

  if (child == NULL || child->parent == NULL || 
      child->parent->tid != cur_process->tid) 
  {
    lock_release(&cur_process->wait_lock);
    return -1;
  }

  if(child->exited)
  {
    int status = child->exit_status;
    remove_process(cur_process->tid,child->tid);
    lock_release(&cur_process->wait_lock);
    return status;
  }

  cur_process->waiting_thread = child_tid;

  cond_wait(&cur_process->wait_cond,&cur_process->wait_lock);

  int status = get_process(thread_current()->tid)->waiting_status;
  remove_process(cur_process->tid,child->tid);
  lock_release(&cur_process->wait_lock);

  return status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp,char* filename,char* save_ptr);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from CMDLINE into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *cmdline, void (**eip) (void), void **esp) 
{
  struct thread* t = thread_current ();
  struct process* p =  get_process(t->tid);

  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  
  process_activate ();

  /* Parse cmdline into executable and arguments */
  char *filename, *save_ptr;
  int cmdlen = strlen(cmdline);

  /* Verify that the cmdline will not overflow stack*/
  if (cmdlen > MAX_CMD_LENGTH) 
  {
    printf ("command line too long\n");
    goto done;
  }

  char cmd_copy[MAX_CMD_LENGTH + 1];
  strlcpy(cmd_copy,cmdline,strlen(cmdline) + 1);
  filename = strtok_r(cmd_copy, " ", &save_ptr);


  /* Open executable file. */
  lock_acquire(&filesys_lock);
  file = filesys_open (filename);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", filename);
      goto done; 
    }
  p->execFile = file;
  file_deny_write(p->execFile);


  /* Read and verify executable header. */

  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", filename);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, filename, save_ptr))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;
  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  if(!success) file_close(file);
  lock_release(&filesys_lock);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  // printf("in load segment\n");
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
      // printf("page_read_bytes:%d\n", page_read_bytes);
      /* Get a page of memory. */ 
      // uint8_t *kpage = palloc_get_page (PAL_USER);
      uint8_t *kpage = frame_get_page (PAL_USER, upage);
      // printf("kpage:%p\n", kpage);
      // printf("upage:%p\n", upage);
      if (kpage == NULL)
        return false;

      struct thread* t = thread_current();
      struct hash* spt = &t->supplementary_page_table;
      // printf("\nWW\n");
      struct page* spt_entry = supplementary_page_table_lookup(spt, upage);
      spt_entry->executable = true;
      spt_entry->page_read_bytes = page_read_bytes;
      spt_entry->kpage = kpage;
      spt_entry->writable = writable;
      spt_entry->ofs = file_tell(file);
      file_seek(file,file_tell(file) + page_read_bytes);
      // printf("\nXX\n");
      /* Load this page. */
            // printf("DIFF: %d %d\n",spt_entry->ofs,file_tell(file));
      // file_read (file, kpage, page_read_bytes);
      // if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
      //   {
      //     // palloc_free_page (kpage);
      //     frame_free_page(kpage);
      //    return false; 
      //  }
      // memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      // if (!install_page (upage, kpage, writable)) 
      //  {
      //    palloc_free_page (kpage);
      //    frame_free_page(kpage);
      //    return false; 
      //  }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

void
setup_arguments(void **esp, char* filename, char* save_ptr)
{
  int num_tokens = 0; //total number of input arguments
  int total_size = 0; //total length of the input arguments without delimeters
  char* argv[64]; //array for the pointers to the arg strings
  char* token;
  for(token = strtok_r(NULL," ",&save_ptr) ; token != NULL ; 
     token = strtok_r(NULL," ",&save_ptr)) //loop over the cmdline arguments, 
      //assumes filename already parsed out
  {
    int size = strlen(token) + 1; //+1 for null terminator
    total_size += size;
    *esp -= size;
    memcpy(*esp,token,size);

    num_tokens++;
    //sets the value in our pointer array to the current token
    argv[num_tokens] = *esp; 
  }

  //write filename
  int size = strlen(filename) + 1;
  *esp -= size;
  memcpy(*esp,filename,size);
  argv[0] = *esp;

  //write null argument
  argv[num_tokens + 1] = NULL;

  //write padding to align to 4 bytes
  int padding = 4 * ((total_size + 3) / 4) - total_size;
  *esp -= padding;
  memset(*esp,0,padding);

  //write pointer array
  *esp -= 4*(num_tokens + 2);
  memcpy(*esp,argv,4*(num_tokens + 2));


  *esp -= sizeof(char**);
  *((int*)*esp) = (int)(*esp + sizeof(char**));

  //argc
  *esp -= sizeof(int);
  *((int*)*esp) = num_tokens + 1;

  //junk return addr
  *esp -= sizeof(void*);
  *((int*)*esp) = 0;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, char* filename, char* save_ptr) 
{
  uint8_t *kpage;
  bool success = false;

  // kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  uint8_t* uaddr = ((uint8_t *) PHYS_BASE) - PGSIZE;
  // printf("before get page\n");
  kpage = frame_get_page (PAL_USER | PAL_ZERO, (void*)uaddr);
  // printf("after get page\n");
  if (kpage != NULL) 
    {
      success = install_page (uaddr, kpage, true);
      if (success)
      {
        *esp = PHYS_BASE;
        setup_arguments(esp, filename, save_ptr);
      }
      else
        // palloc_free_page (kpage);
        frame_free_page(kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

void lazy_load_segment(struct page* fault_page)
{
    install_page(fault_page->vaddr,fault_page->kpage,fault_page->writable);
  struct process* process = get_process(thread_current()->tid);
   file_seek (process->execFile, fault_page->ofs);
  int page_read_bytes = fault_page->page_read_bytes;
  if(page_read_bytes > 0)
  {
    // printf("LAZY: %p %d\n",fault_page->kpage,file_tell(process->execFile));
    // printf("S: %s\n",fault_page->kpage);
    file_read(process->execFile,fault_page->kpage,page_read_bytes);
  }
  memset(fault_page->kpage + page_read_bytes,0,PGSIZE - page_read_bytes);
  // printf("E: %s\n",fault_page->kpage);

  // printf("\nABC\n");
}

// if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
      //   {
      //     // palloc_free_page (kpage);
      //     frame_free_page(kpage);
      //    return false; 
      //  }
      // memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      // if (!install_page (upage, kpage, writable)) 
      //  {
      //    palloc_free_page (kpage);
      //    frame_free_page(kpage);
      //    return false; 
      //  }

struct file_handle*
find_file_handle (int fd) 
{
  struct thread* t = thread_current();
  struct process* p = get_process(t->tid);

  struct list_elem *e;
  for (e=list_begin(&p->file_list); e!=list_end(&p->file_list);
    e = list_next(e))
  {
    struct file_handle* fh = list_entry(e, struct file_handle, elem);
    if (fd==fh->fd) 
    {
      return fh;
    }
  }

  return NULL;
}

void null_children (struct process* parent)
{
  int i = 0;
  for(i = 0; i < parent->num_children; i++)
  {
    if(parent->children[i]->exited)
      remove_process(parent->tid,parent->children[i]->tid);
    else parent->children[i]->parent = NULL;
  }
}

void free_filehandles() 
{
  struct process* p = get_process(thread_current()->tid);
   
  while (!list_empty (&p->file_list))
  {
    struct list_elem* e = list_pop_front(&p->file_list);
    struct file_handle* fh = list_entry(e, struct file_handle, elem);
    //list_remove(e);
    file_close(fh->f);
    free(fh);
  }
}

void cleanup_process (uint32_t status, struct intr_frame *f)
{
  struct process* cur_process = get_process(thread_current()->tid);
  struct process* parent = get_parent(cur_process);

  lock_acquire(&filesys_lock);
  file_close(cur_process->execFile);
  free_filehandles();
  lock_release(&filesys_lock);

  if(parent != NULL && !parent->exited) 
  {
    lock_acquire(&parent->wait_lock);

    null_children(cur_process);

    if(cur_process->tid == parent->waiting_thread)
    {
      parent->waiting_status = status;

      cond_signal(&parent->wait_cond,&parent->wait_lock);
    }  

    cur_process->exit_status = status;
    cur_process->exited = true;
    lock_release(&parent->wait_lock);
  } else 
  {
    remove_process(parent->tid, cur_process->tid);
  }
  
  char name[strlen(thread_current()->name) + 1];
  memcpy(name,thread_current()->name,strlen(thread_current()->name) + 1);

  printf("%s: exit(%d)\n",name, status);
  f->eax = status;
}
