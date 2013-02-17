#include "userprog/syscall.h"
#include <stdio.h>
#include "lib/user/syscall.h"
#include "lib/string.h"
#include "devices/input.h"
#include <syscall-nr.h> 
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

static void syscall_handler (struct intr_frame *);
const void *check_valid_uaddr(const void * uaddr, int size);
int get_arg(int i, void* esp);
static void sys_halt(void);
static void sys_exit(uint32_t status, struct intr_frame *f);
static void sys_write(int fd, const void *buffer, 
	unsigned length, struct intr_frame *f);
static void sys_create(const char* file, unsigned initial_size,
  struct intr_frame *f); 
static void sys_wait(pid_t pid, struct intr_frame *f) ;
static void sys_read (int fd, void *buffer, unsigned size, 
  struct intr_frame *f);
static void sys_open (const char *file, struct intr_frame *f);
static void sys_filesize(int fd, struct intr_frame *f);
static void sys_exec(const char* cmd_line, struct intr_frame *f);
static void sys_seek(int fd, int position);
static void sys_tell(int fd,struct intr_frame* f);
static void sys_close(int fd, struct intr_frame *f);
static int num_args(enum SYSCALL_NUMBER number);
static bool check_args(void* esp,int num_args);
static bool check_string(const char* file);

const void*
check_valid_uaddr(const void * uaddr, int size) 
{
	if (uaddr == NULL) 
  {
    return NULL;
  }

  const void *usaddr = uaddr; //user start addr 
	void *ueaddr = (void*)((char*)uaddr + size - 1); //user end addr

	uint32_t *pd = thread_current()->pagedir; //WHAT THREAD IS THIS?!

	//validate both the start and end addresses
	//TODO NEED TO VALIDATE ALL PAGES IN BETWEEN
  const void* cur;
	for (cur=usaddr; cur<ueaddr; cur+=4096) {
	  if (!is_user_vaddr(cur))	return NULL;

    void* page = pagedir_get_page (pd, cur);
    if (page == NULL) return NULL;
	}

  if(!is_user_vaddr(ueaddr)) return NULL;
  
  void *keaddr = pagedir_get_page (pd, ueaddr);


	//one of these is out of the bounds 
	if (keaddr==NULL) 
	{	
		return NULL;
	}

	return uaddr;
}


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}

int
get_arg (int i, void* esp) {

	int arg = *(int*)((char*)(esp + 4*i));
	return arg;
}

/*
 * This method returns the number of arguments given a particular
 * system call.
*/
int num_args (enum SYSCALL_NUMBER number)
{
  switch (number) {
    case SYS_HALT:
      return 0;
    case SYS_EXIT:
      return 1;
    case SYS_EXEC:
      return 1;
    case SYS_WAIT:
      return 1;
    case SYS_CREATE:
      return 2;
    case SYS_REMOVE:
      return 1;
    case SYS_OPEN:
      return 1;
    case SYS_FILESIZE:
      return 1;
    case SYS_READ:
      return 3;
    case SYS_WRITE:
      return 3;
    case SYS_SEEK:
      return 2;
    case SYS_TELL:
      return 1;
    case SYS_CLOSE:
      return 1;
    default:
      return 0;
    }
}

/*
 * This method validates the arguments passed into a particular function.
*/
bool check_args (void* esp,int num_args)
{
  int i;
  for(i = 1; i <= num_args; i++)
  {
    void* arg_addr = (void*)((char*)esp + i*sizeof(void*));
    if(check_valid_uaddr(arg_addr,sizeof(void*)) == NULL)
    {
      return false;
    }
  }
  return true;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  if (check_valid_uaddr(f->esp, sizeof(enum SYSCALL_NUMBER)) == NULL) 
  {
    sys_exit(-1, f);
    return;
  }

  enum SYSCALL_NUMBER number = *(int*)f->esp; //get the syscall number

  if(!check_args(f->esp,num_args(number)))
  {
    sys_exit(-1,f);
    return;
  }

  switch (number) {
  	case SYS_HALT:
  		sys_halt();
  		break;
  	case SYS_EXIT:
  		sys_exit((int)get_arg(1, f->esp), f);
  		break;
  	case SYS_EXEC:
      sys_exec((const char*)get_arg(1, f->esp), f);
  		break;
  	case SYS_WAIT:
  	  {
  			pid_t pid = (pid_t)get_arg(1, f->esp);
  			sys_wait(pid, f);
  			break;	
  	  }
  	case SYS_CREATE:
      {
        char* file = (char*)get_arg(1,f->esp);
        unsigned initial_size = (unsigned)get_arg(2,f->esp);
        sys_create(file, initial_size, f); 
  		  break;
      }
  	case SYS_REMOVE:
  		break;
  	case SYS_OPEN:
      {
        char* file = (char*)get_arg(1,f->esp);
        sys_open (file, f);
  		  break;
      }
  	case SYS_FILESIZE:
      {
        int fd = (int)get_arg(1,f->esp);
        sys_filesize (fd, f);
        break;
      }
  	case SYS_READ:
      {
        int fd = (int)get_arg(1,f->esp);
        void* buffer = (void*)get_arg(2,f->esp);
        unsigned size = (unsigned)get_arg(3,f->esp);
        sys_read (fd, buffer, size, f);
  		  break;
      }
  	case SYS_WRITE:
  		// TODO verify address
  	{
  		int fd = get_arg(1,f->esp);
  		void* buffer = (void*)get_arg(2,f->esp);
  		unsigned length = (int)get_arg(3,f->esp);
  		sys_write(fd,buffer,length,f);
  		break;
  	}
  	case SYS_SEEK:
    {
  	  int fd = get_arg(1,f->esp);
      int position = get_arg(2,f->esp);
      sys_seek(fd, position);
    	break;
    }
  	case SYS_TELL:
    {
  	  int fd = get_arg(1,f->esp);
      sys_tell(fd,f);
    	break;
    }
  	case SYS_CLOSE:
    {
      int fd = get_arg(1,f->esp);
      sys_close(fd, f);
  		break;
    }
  	default:
  		break;
  }

  // thread_exit ();
}

static void 
sys_halt () 
{
  shutdown_power_off();
}

static void 
sys_exit (uint32_t status, struct intr_frame *f) 
{
  cleanup_process(status, f);
  thread_exit();
}

/*
 * This method validates a string passed in as an argument.
*/
static bool 
check_string (const char* file)
{
  if (file == NULL) 
  {
    return false;
  }

  const char* cur = file;

  if(check_valid_uaddr(cur,sizeof(char)) == NULL) return false;
  while(*cur != '\0')
  {
    cur = cur + 1;
    if(check_valid_uaddr(cur,sizeof(char)) == NULL) return false;
  }
  if(check_valid_uaddr(cur,sizeof(char)) == NULL) return false;

  return true;
}

static void 
sys_exec (const char* cmd_line, struct intr_frame *f) 
{
  if(!check_string(cmd_line))
  {
    sys_exit(-1,f);
    return;
  }
  
  lock_acquire(&(thread_current()->process_init_lock));

  tid_t tid = process_execute(cmd_line);

  if(tid == TID_ERROR)
  {
    f->eax = -1;
    lock_release(&(thread_current()->process_init_lock));
    return;
  }
  
  cond_wait(&(thread_current()->process_init_cond),
   &(thread_current()->process_init_lock)); //waits for process_start to finish loading

  /* Return the id of the new process */
  if (thread_current()->success == true) {
    f->eax = tid;
  } else {
    f->eax = -1;
  }
  lock_release(&(thread_current()->process_init_lock));
}

static void
sys_wait (pid_t pid, struct intr_frame *f) 
{
  f->eax = process_wait(pid);
}

static void
sys_create (const char* file, unsigned initial_size,
              struct intr_frame *f) 
{
  lock_acquire(&filesys_lock);
  if(!check_string(file))
  {
    lock_release(&filesys_lock);
    sys_exit(-1,f);
    return;
  }
  bool check = false;

  check = filesys_create(file, initial_size);

  f->eax = check;
  lock_release(&filesys_lock);
}

static void 
sys_open (const char *file, struct intr_frame *f)
{
  lock_acquire(&filesys_lock);
  if(!check_string(file))
  {
    lock_release(&filesys_lock);
    sys_exit(-1,f);
    return;
  }

  struct thread* t = thread_current();
  struct process* p = get_process(t->tid);
  struct file* fi = filesys_open(file);
  struct file_handle* fh = malloc(sizeof(struct file_handle));
  if (fh == NULL || fi == NULL)
  {
    f->eax = -1;
    lock_release(&filesys_lock);
    return;
  }
  
  fh->f = fi;
  fh->fd = p->process_fd;

  list_push_back(&p->file_list, &fh->elem);
  p->process_fd++;

  f->eax = fh->fd;
  lock_release(&filesys_lock);
  return;
}

static void 
sys_filesize (int fd, struct intr_frame *f) 
{
  lock_acquire(&filesys_lock);
  struct file_handle* fh = find_file_handle(fd);
  if(fh == NULL)
  {
    f->eax = -1;
    lock_release(&filesys_lock);
    return;
  }
  off_t size = file_length(fh->f);

  f->eax = size;
  lock_release(&filesys_lock);
  return;
}

static void
sys_read (int fd, void *buffer, unsigned size, 
        struct intr_frame *f)
{
  lock_acquire(&filesys_lock);
  if (check_valid_uaddr(buffer,size) == NULL)
  {
    lock_release(&filesys_lock);
    sys_exit(-1,f);
    return;
  }

  int sizeRead = 0;
  /* Read from console */
  if (fd == 0) {
    sizeRead = input_getc();
  } else {
    struct file_handle* fh = find_file_handle(fd);
    if (fh == NULL || buffer == NULL)  {
      f->eax = -1;
      lock_release(&filesys_lock);
      return;
    }
    struct file* fi = fh->f;
    sizeRead = file_read(fi, buffer, size);
  }

  f->eax = sizeRead;
  lock_release(&filesys_lock);
  return;
}

static void 
sys_write (int fd, const void *buffer, unsigned length, 
            struct intr_frame *f)
{
	/* Protect against race condition */
  lock_acquire(&filesys_lock);
  if (check_valid_uaddr(buffer,length) == NULL) 
  {
    lock_release(&filesys_lock);
    sys_exit(-1,f);
    return;   
  }

  /* Write to console */
  if (buffer == NULL) {
    f->eax = 0;
    lock_release(&filesys_lock);
    return;
  }

  int sizeWrite = 0;
	if (fd == 1) {
		putbuf(buffer,length);
		/* Return the number of written byte */
    	sizeWrite = length;
	} else {
		/* Write to file */
		struct file_handle* fh = find_file_handle(fd);
    if (fh == NULL) {
      f->eax = 0;
      lock_release(&filesys_lock);
      return; 
    }
    struct file* fi = fh->f;
    sizeWrite = file_write(fi, buffer, length);
	}

  f->eax = sizeWrite;
  lock_release(&filesys_lock);
  return;
}

static void
sys_seek (int fd, int position)
{
  //printf("S: %d %d\n",fd,thread_current()->tid);
  lock_acquire(&filesys_lock);
  struct file_handle* fh = find_file_handle(fd);

   if(fh == NULL)
  {
    //printf("HERE %d %d\n",fd,thread_current()->tid);
    lock_release(&filesys_lock);
    return;
  }
  file_seek(fh->f, position);
  lock_release(&filesys_lock);
  return;
}

static void
sys_tell (int fd,struct intr_frame* f)
{
  lock_acquire(&filesys_lock);
  struct file_handle* fh = find_file_handle(fd);
   if(fh == NULL)
  {
    f->eax = -1;
    lock_release(&filesys_lock);
    return;
  }
  f->eax = file_tell(fh->f);
  lock_release(&filesys_lock);
  return;
}


static void
sys_close (int fd, struct intr_frame *f) 
{
  lock_acquire(&filesys_lock);
  struct file_handle* fh = find_file_handle(fd);

  if (fh == NULL) 
  {
    f->eax = -1;
    lock_release(&filesys_lock);
    return;
  }

  list_remove(&fh->elem);
  file_close(fh->f);
  free(fh); 
  lock_release(&filesys_lock);
  return;
}
