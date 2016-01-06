#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "threads/vaddr.h"
#include "threads/init.h"
#include "userprog/process.h"
#include <list.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "devices/input.h"
#include "threads/synch.h"

typedef int pid_t;

static void syscall_handler (struct intr_frame *);

static int read (int fd, void *buffer, unsigned size);
static int write (int fd, const void *buffer, unsigned length);
static void halt (void);
static void close (int filedesc);
static bool create (const char *file, unsigned initial_size);
static int open (const char *file);
static pid_t exec (const char *cmd);
static int wait(pid_t pid);
static int filesize (int fd);
static void seek(int filedesc, int pos);
static int tell(int filedesc);
static bool remove (const char *file);

/* Syscall handler function */
typedef int (*handler) (uint32_t, uint32_t, uint32_t);

/* Vector that associates each handler function with its enum defined in syscall-nr.h*/
static handler syscall_vec[128];

/* Lock for currently accessed file*/
static struct lock file_lock;

/* Filedescriptor element for a file. 
It stores the file descriptor for the file, the file and a list_elem so 
that the file can be associated with the thread that opened or created it */
struct filedescriptor_elem {
    int filedesc;
    struct file *file;
    struct list_elem thread_elem;
  };

/* Retrieves a file given a filedesc */
static struct file *find_file_by_filedesc (int filedesc);

/* Returns filedescriptor_elem of the passed filedesc */
static struct filedescriptor_elem *find_fde_by_filedesc_thread (int filedesc);

/* For allocating new fids during 'create'*/
static int fid=2;

/* Lock for fid */
static struct lock fid_lock;

void
syscall_init (void)  {
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  syscall_vec[SYS_EXIT] = (handler)exit;
  syscall_vec[SYS_HALT] = (handler)halt;
  syscall_vec[SYS_CREATE] = (handler)create;
  syscall_vec[SYS_OPEN] = (handler)open;
  syscall_vec[SYS_CLOSE] = (handler)close;
  syscall_vec[SYS_READ] = (handler)read;
  syscall_vec[SYS_WRITE] = (handler)write;
  syscall_vec[SYS_EXEC] = (handler)exec;
  syscall_vec[SYS_WAIT] = (handler)wait;
  syscall_vec[SYS_FILESIZE] = (handler)filesize;
  syscall_vec[SYS_SEEK] = (handler)seek;
  syscall_vec[SYS_TELL] = (handler)tell;
  syscall_vec[SYS_REMOVE] = (handler)remove;
  
  lock_init (&file_lock);

}

static void syscall_handler (struct intr_frame *f UNUSED)  {
  
  handler h;
  int *stack_position;
  int return_value;
  
  stack_position = f->esp;
  
  if (!is_user_vaddr (stack_position))
    goto end;
  
  if (*stack_position < SYS_HALT || *stack_position > SYS_INUMBER)
    goto end;
  
  h = syscall_vec[*stack_position];

  if (!(is_user_vaddr (stack_position + 1) && is_user_vaddr (stack_position + 2) && is_user_vaddr (stack_position + 3)))
    goto end;

  return_value = h (*(stack_position + 1), *(stack_position + 2), *(stack_position + 3));

  f->eax = return_value;
  
  return;
  
end:
  exit (-1);
}

/* Reads size bytes from the file open as fd into buffer */
static int read (int filedesc, void *buffer, unsigned size) {
  struct file * f;
  int ret=-1;

  lock_acquire(&file_lock);
  if(filedesc==STDIN_FILENO)
  {
    uint16_t i;
    for(i=0;i<size;i++)
      *(uint8_t *)(buffer + i)= input_getc();
    ret=size;
    goto end;
  }
  else if(filedesc==STDOUT_FILENO)
   {
    lock_release (&file_lock);
   return ret;
   }
  else if(!is_user_vaddr(buffer) || !is_user_vaddr(buffer + size))
  {
    lock_release(&file_lock);
    exit(-1);
  }
  else
  {
    f=find_file_by_filedesc(filedesc);
    if(f)
      ret=file_read(f,buffer,size);
    else  
      goto end;
  }

  end:
  lock_release (&file_lock);
  return ret;
}

/* Writes size bytes from buffer to the open file fd*/
static int write (int filedesc, const void *buffer, unsigned length) {
  struct file * f;
  int ret;
  //ASSERT(0);
  ret = -1;
  lock_acquire (&file_lock);
  if (filedesc == STDOUT_FILENO) /* stdout */
    putbuf (buffer, length);
  
  else if (filedesc == STDIN_FILENO)  
    goto end;
  else if (!is_user_vaddr (buffer) || !is_user_vaddr (buffer + length))
    {
      lock_release (&file_lock);
      exit (-1);
    }
  else
    {
      f = find_file_by_filedesc (filedesc);
      if (!f)
        goto end;
        
      ret = file_write (f, buffer, length);
    }
    
end:
  lock_release (&file_lock);
  return ret;
}


/* Terminates the current user program, returning status to the kernel */
void exit(int status)
{
  struct thread *cur;
  cur=thread_current();

  if (lock_held_by_current_thread(&file_lock))
    lock_release(&file_lock);

  if(list_empty(&cur->all_files))
    goto end;
  else
  {
    struct list_elem *elem;
    while(!list_empty(&cur->all_files))
    {
      elem=list_begin(&cur->all_files);
      close((list_entry(elem, struct filedescriptor_elem, thread_elem))->filedesc);
    }
  }

end:
  cur->return_status=status;
  thread_exit();
}
 
/* Closes file descriptor fd */
static void close(int filedesc) {

  struct filedescriptor_elem *fde;
  fde=find_fde_by_filedesc_thread(filedesc);

  if(fde!=NULL)
  { 
  file_close(fde->file);
  list_remove(&fde->thread_elem);
  free(fde);
  }
  
  return;
}

/* Creates a new file called ‘file’ initially initial_size bytes in size. 
  Returns true if successful, false otherwise */
static bool create (const char *file, unsigned initial_size)
{
 
  if(!file)
    exit(-1);
  
  int return_value;
  lock_acquire(&file_lock);
  return_value = filesys_create (file, initial_size);
  lock_release(&file_lock);

  return return_value;
}

/* Opens the file called `file’ */
static int open (const char *file)
{
  struct file *f;
  struct filedescriptor_elem *fde;
  
  if (file == NULL) 
     return -1;
  if (!is_user_vaddr (file))
      exit (-1);
  f = filesys_open (file);
  if (!f) 
    return -1;
    
  fde = (struct filedescriptor_elem *)malloc (sizeof (struct filedescriptor_elem));
  if (!fde) 
    {
      file_close (f);
      goto done;
    }
  else
  {
    
    fde->file = f;
    fde->filedesc = fid++;
    list_push_back (&thread_current ()->all_files, &fde->thread_elem);
    return fde->filedesc;
  }
done:
  return -1;
}

/* Terminates Pintos by calling shutdown_power_off() */
static void halt (void) {
  shutdown_power_off ();  
}


/* Runs the executable whose name is given in cmd line, passing any given arguments, and returns the new process's program id */
static pid_t exec (const char *cmd) {
  int ret;
  if (!cmd || !is_user_vaddr(cmd))
    return -1;

  lock_acquire(&file_lock);
  ret = process_execute(cmd);
  lock_release(&file_lock);
  return ret;
}

/* Waits for a child process pid and retrieves the child's exit status */
static int wait (pid_t pid) {
  return process_wait(pid);
}

static struct file *find_file_by_filedesc (int filedesc) {
  struct filedescriptor_elem *fd;
  struct list_elem *el;
  struct thread *cur;

  cur=thread_current();
  //for (el = list_begin (&open_file_list); el != list_end (&open_file_list); el = list_next (el))
  for (el = list_begin (&cur->all_files); el != list_end (&cur->all_files); el = list_next (el))
  
    {
      fd = list_entry (el, struct filedescriptor_elem, thread_elem);
      if (fd->filedesc == filedesc)
        return fd->file;
    }
    
  return NULL;
}

/* Returns the size, in bytes, of the file open as fd */
static int filesize (int filedesc) {
  struct file *file_size;
  file_size = find_file_by_filedesc(filedesc);
  if (!file_size)
    return -1;

  return file_length(file_size);
}

/* Returns the position of the next byte to be read or written in open file fd, 
expressed in bytes from the beginning of the file*/
static int tell(int filedesc) {
  struct file *f;
  f = find_file_by_filedesc(filedesc);

  if(!f)
    return -1;
  
  return file_tell(f);

}

/* Changes the next byte to be read or written in open file fd to position, 
expressed in bytes from the beginning of the file*/
static void seek(int filedesc, int pos) {
  struct file *f;
  f = find_file_by_filedesc(filedesc);
  if(!f)
    return ;
  
  file_seek(f, pos);
  
}

/* Deletes the file called `file’. Returns true if successful, false otherwise */
static bool remove (const char *file) {
  if (!file)
    return false;

  if (!is_user_vaddr (file))
      exit (-1);

  int return_value;
  lock_acquire(&file_lock);
  return_value = filesys_remove (file);
  lock_release(&file_lock);

  return return_value;
}

/* Returns an instance of filedescriptor_elem from the given filedescriptor value
  This is done to retrieve the file opened by a thread and its corresponding filedesc_elem
  in 'close', and to close the file and remove the memory allocated to the filedescriptor_elem */
static struct filedescriptor_elem *find_fde_by_filedesc_thread (int filedesc) {
  struct filedescriptor_elem *fd;
  struct list_elem *el;
  struct thread *cur;

  cur=thread_current();
  
  for (el = list_begin (&cur->all_files); el != list_end (&cur->all_files); el = list_next (el))
    {
      fd = list_entry (el, struct filedescriptor_elem, thread_elem);
      if (fd->filedesc == filedesc)
        return fd;
    }
    
  return NULL;
}
