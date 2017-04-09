#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/init.h"
#include "devices/input.h"
#include "userprog/process.h"

/* Simulating cloning arguments from user to kernel. */
#define CLONE_ARG(TYPE, VAR) TYPE VAR; pop_arg (&args, (void *)(&VAR), sizeof (TYPE))
/* Simulating returning to user system call. */
#define RETURN(N) {f->eax = (uint32_t) (N); return;}

/* System call handler function type. */
typedef void syscall_handler_func (struct intr_frame *f, void *args);

/* Syscall handlers. */
static syscall_handler_func *handlers[SYSCALL_CNT];

/* System call handler functions. */
static intr_handler_func syscall_handler;

static syscall_handler_func sys_halt;
static syscall_handler_func sys_exit;
static syscall_handler_func sys_exec;
static syscall_handler_func sys_wait;
static syscall_handler_func sys_create;
static syscall_handler_func sys_remove;
static syscall_handler_func sys_open;
static syscall_handler_func sys_filesize;
static syscall_handler_func sys_read;
static syscall_handler_func sys_write;
static syscall_handler_func sys_seek;
static syscall_handler_func sys_tell;
static syscall_handler_func sys_close;
static syscall_handler_func sys_mmap;
static syscall_handler_func sys_munmap;
static syscall_handler_func sys_chdir;
static syscall_handler_func sys_mkdir;
static syscall_handler_func sys_readdir;
static syscall_handler_func sys_isdir;
static syscall_handler_func sys_inumber;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  handlers[0] = sys_halt;
  handlers[1] = sys_exit;
  handlers[2] = sys_exec;
  handlers[3] = sys_wait;
  handlers[4] = sys_create;
  handlers[5] = sys_remove;
  handlers[6] = sys_open;
  handlers[7] = sys_filesize;
  handlers[8] = sys_read;
  handlers[9] = sys_write;
  handlers[10] = sys_seek;
  handlers[11] = sys_tell;
  handlers[12] = sys_close;
  handlers[13] = sys_mmap;
  handlers[14] = sys_munmap;
  handlers[15] = sys_chdir;
  handlers[16] = sys_mkdir;
  handlers[17] = sys_readdir;
  handlers[18] = sys_isdir;
  handlers[19] = sys_inumber;
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
        : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
        : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

/* Get the user string. Result is -1 if segfault occured, 0 if file length
   exceeded, 1 if successed. */
static int
get_user_string (char *ustr, char *str, unsigned size)
{
  uint8_t *uaddr = (uint8_t *) ustr;
  int med = 0;
  while (size-- > 0)
  {
    if (is_kernel_vaddr (uaddr) || (med = get_user (uaddr)) == -1)
      return -1;
    *str = med;
    if (med == 0)
      break;
    str++;
    uaddr++;
  }
  return med == 0 ? 1 : 0;
}

/* Copy the user buffer to BUF. */
static bool
get_user_buffer (void *ubuf, void *buf, unsigned size)
{
  int med;
  while (size-- > 0)
  {
    if (is_kernel_vaddr (ubuf) || (med = get_user (ubuf)) == -1)
      return false;
    ASSIGN (buf, uint8_t, med);
    MOVE_ADDR (ubuf, uint8_t, 1);
    MOVE_ADDR (buf, uint8_t, 1);
  }
  return true;
}

/* Copy BUF to the user buffer. */
static bool
put_user_buffer (void *ubuf, void *buf, unsigned size)
{
  while (size-- > 0)
  {
    if (is_kernel_vaddr (ubuf) || !put_user (ubuf, POINTER (buf, uint8_t)))
      return false;
    MOVE_ADDR (ubuf, uint8_t, 1);
    MOVE_ADDR (buf, uint8_t, 1);
  }
  return true;
}

/* Get the keyboard input to the user buffer. -1 if segfault
   occurred. */
static int
put_user_input (void *ubuf, unsigned size)
{
  int res_size = 0;
  while (size-- > 0)
  {
    if (!put_user (ubuf, input_getc ()))
      return -1;
    if (POINTER (ubuf, uint8_t) == 0)
      break;
    MOVE_ADDR (ubuf, uint8_t, 1);
    res_size++;
  }
  return res_size;
}


/* Get the arguments with SIZE bytes from the ESP. If it fails,
   immediately terminate the process. */
static void
pop_arg (void **args, void *dst, unsigned size)
{
  void *src = *args;
  int med;    /* Intermediate value for get_user (). */
  while (size-- > 0)
  {
    if (is_kernel_vaddr (src) || (med = get_user (src)) == -1)
      thread_exit ();
    ASSIGN (dst, uint8_t, med);
    MOVE_ADDR (src, uint8_t, 1);
    MOVE_ADDR (dst, uint8_t, 1);
  }
  *args = src;
}

/* Main system call handler function. */
static void
syscall_handler (struct intr_frame *f)
{
  void *args = f->esp;
  CLONE_ARG (int, opt);  /* Syscall option. */

  /* Unknown system call. */
  if (opt < 0 || opt >= SYSCALL_CNT)
    thread_exit ();

  syscall_handler_func *handler = handlers[opt];
  handler (f, args);
}

/* Halt Pintos. */
static void
sys_halt (struct intr_frame *f UNUSED, void *args UNUSED)
{
  power_off ();
  NOT_REACHED ();
}

/* Exit the current process. */
static void
sys_exit (struct intr_frame *f UNUSED, void *args)
{
  /* User provided argument. */
  CLONE_ARG (int, code);

  thread_current ()->info->exit_code = code;
  thread_exit ();
}

/* Execute new process with given filename. */
static void
sys_exec (struct intr_frame *f, void *args)
{
  /* User provided argument. */
  CLONE_ARG (char *, cmd_line);

  char *str;
  int success;
  tid_t tid;
  struct process_info *pi;

  str = palloc_get_page (0);
  if (str == NULL)
    RETURN (-1);

  success = get_user_string (cmd_line, str, PGSIZE);
  if (success == -1)
  {
    palloc_free_page (str);
    thread_exit ();
  }
  else if (success == 0)
  {
    palloc_free_page (str);
    RETURN (-1);
  }

  tid = process_execute (str);
  palloc_free_page (str);
  if (tid == TID_ERROR)
    RETURN (-1);

  pi = get_info_by_tid (tid);
  if (pi == NULL)
    RETURN (-1);

  sema_down (&pi->executed);
  if (pi->exec_success)
    RETURN (tid);

  sema_down (&pi->exited);
  remove_info (pi);
  RETURN (-1);
}

/* Wait for a child process. If it is not a child, it fails. */
static void
sys_wait (struct intr_frame *f, void *args)
{
  /* User provided argument. */
  CLONE_ARG (tid_t, tid);

  f->eax = process_wait (tid);
}

/* Create a new file. */
static void
sys_create (struct intr_frame *f, void *args)
{
  /* User provided arguments. */
  CLONE_ARG (char *, file);
  CLONE_ARG (unsigned, initial_size);

  char *str;
  int success;

  str = palloc_get_page (0);
  if (str == NULL)
    RETURN (0);

  success = get_user_string (file, str, PGSIZE);
  if (success == -1)
  {
    palloc_free_page (str);
    thread_exit ();
  }
  else if (success == 0)
  {
    palloc_free_page (str);
    RETURN (0);
  }

  lock_acquire (&filesys_lock);
  f->eax = filesys_create (str, initial_size);
  lock_release (&filesys_lock);

  palloc_free_page (str);
}

/* Remove a file or a directory. */
static void
sys_remove (struct intr_frame *f, void *args)
{
  /* User provided argument. */
  CLONE_ARG (char *, file);

  char *str;
  int success;

  str = palloc_get_page (0);
  if (str == NULL)
    RETURN (0);

  success = get_user_string (file, str, PGSIZE);
  if (success == -1)
  {
    palloc_free_page (str);
    thread_exit ();
  }
  else if (success == 0)
  {
    palloc_free_page (str);
    RETURN (0);
  }

  lock_acquire (&filesys_lock);
  f->eax = filesys_remove (str);
  lock_release (&filesys_lock);

  palloc_free_page (str);
}

/* Open a file and return its file descriptor. */
static void
sys_open (struct intr_frame *f, void *args)
{
  /* User provided argument. */
  CLONE_ARG (char *, file);

  char *str;
  int success;
  struct file *new_file;
  int fd;

  str = palloc_get_page (0);
  if (str == NULL)
    RETURN (-1);

  success = get_user_string (file, str, PGSIZE);
  if (success == -1)
  {
    palloc_free_page (str);
    thread_exit ();
  }
  else if (success == 0)
  {
    palloc_free_page (str);
    RETURN (-1);
  }

  lock_acquire (&filesys_lock);
  new_file = filesys_open (str);
  lock_release (&filesys_lock);
  
  palloc_free_page (str);
  if (new_file == NULL)
    RETURN (-1);

  if ((fd = process_add_fd (new_file)) == FD_ERROR)
  {
    lock_acquire (&filesys_lock);
  	file_close (new_file);
    lock_release (&filesys_lock);
    RETURN (-1);
  }

  f->eax = fd;
}

/* Return the file size of given file descriptor. */
static void
sys_filesize (struct intr_frame *f, void *args)
{
  /* User provided argument. */
  CLONE_ARG (int, fd);

  struct file *file = get_file_by_fd (fd);
  if (file == NULL)
    RETURN (-1);

  lock_acquire (&filesys_lock);
  f->eax = file_length (file);
  lock_release (&filesys_lock);
}

/* Read the file given file descriptor, SIZE bytes. */
static void
sys_read (struct intr_frame *f, void *args)
{
  /* User provided arguments. */
  CLONE_ARG (int, fd);
  CLONE_ARG (void *, buffer);
  CLONE_ARG (unsigned, size);

  struct file *file;
  void *kbuf;
  bool success;
  int tot_size;

  if (fd == 0)
  {
    int res = put_user_input (buffer, size);
    if (res == -1)
      thread_exit ();
    RETURN (res);
  }

  file = get_file_by_fd (fd);
  if (file == NULL)
    RETURN (-1);

  /* SIZE might be too large, so just allocate a single page. */
  kbuf = palloc_get_page (0);
  if (kbuf == NULL)
    RETURN (-1);

  /* Read the content of the file repeatedly in one page. */
  tot_size = 0;

  while (size > 0)
  {
    int read_size = size < PGSIZE ? size : PGSIZE;

    lock_acquire (&filesys_lock);
    int res = file_read (file, kbuf, read_size);
    lock_release (&filesys_lock);

    success = put_user_buffer (buffer + tot_size, kbuf, res);
    if (!success)
    {
      palloc_free_page (kbuf);
      thread_exit ();
    }

    tot_size += res;
    size -= res;

    if (res < read_size)
    {
      palloc_free_page (kbuf);
      RETURN (tot_size);
    }
  }

  palloc_free_page (kbuf);
  f->eax = tot_size;
}

/* Write to the file of given file descriptor. */
static void
sys_write (struct intr_frame *f, void *args)
{
  /* User provided arguments. */
  CLONE_ARG (int, fd);
  CLONE_ARG (void *, buffer);
  CLONE_ARG (unsigned, size);

  void *kbuf;
  bool success;
  int tot_size;
  int real_size;
  struct file *file = NULL;

  if (fd != 1)
  {
    file = get_file_by_fd (fd);
    if (file == NULL)
      RETURN (-1);
  }

  kbuf = palloc_get_page (0);
  if (kbuf == NULL)
    RETURN (0);

  tot_size = 0;
  real_size = 0;

  while (size > 0)
  {
    int write_size = size < PGSIZE ? size : PGSIZE;

    success = get_user_buffer (buffer + tot_size, kbuf, write_size);
    if (!success)
    {
      palloc_free_page (kbuf);
      thread_exit ();
    }

    tot_size += write_size;
    size -= write_size;

    if (fd == 1)
    {
      putbuf (kbuf, write_size);
      real_size += write_size;
    }
    else
    {
      lock_acquire (&filesys_lock);
      real_size += file_write (file, kbuf, write_size);
      lock_release (&filesys_lock);

      if (real_size < tot_size)
      {
        palloc_free_page (kbuf);
        RETURN (real_size);
      }
    }
  }

  palloc_free_page (kbuf);
  f->eax = real_size;
}

static void
sys_seek (struct intr_frame *f UNUSED, void *args)
{
  /* User provided arguments. */
  CLONE_ARG (int, fd);
  CLONE_ARG (unsigned, position);

  struct file *file = get_file_by_fd (fd);
  if (file != NULL)
  {
    lock_acquire (&filesys_lock);
    file_seek (file, position);
    lock_release (&filesys_lock);
  }
}

static void
sys_tell (struct intr_frame *f, void *args)
{
  /* User provided argument. */
  CLONE_ARG (int, fd);

  struct file *file = get_file_by_fd (fd);
  if (file == NULL)
    RETURN (0);

  lock_acquire (&filesys_lock);
  f->eax = file_tell (file);
  lock_release (&filesys_lock);
}

/* Close the open file, given file descriptor. */
static void
sys_close (struct intr_frame *f UNUSED, void *args)
{
  /* User provided argument. */
  CLONE_ARG (int, fd);

  process_remove_fd (fd);
}

/* Not yet implemented. */
static void
sys_mmap (struct intr_frame *f, void *args)
{
  /* User provided arguments. */
  CLONE_ARG (int, fd);
  CLONE_ARG (void *, addr);

  f->eax = 0xffffffff;
}

/* Not yet implemented. */
static void
sys_munmap (struct intr_frame *f UNUSED, void *args)
{
  /* User provided argument. */
  CLONE_ARG (int, mapid);
}

/* Not yet implemented. */
static void
sys_chdir (struct intr_frame *f, void *args)
{
  /* User provided argument. */
  CLONE_ARG (char *, dir);

  f->eax = 0;
}

/* Not yet implemented. */
static void
sys_mkdir (struct intr_frame *f, void *args)
{
  /* User provided argument. */
  CLONE_ARG (char *, dir);

  f->eax = 0;
}

/* Not yet implemented. */
static void
sys_readdir (struct intr_frame *f, void *args)
{
  /* User provided arguments. */
  CLONE_ARG (int, fd);
  CLONE_ARG (char *, name);

  f->eax = 0;
}

/* Not yet implemented. */
static void
sys_isdir (struct intr_frame *f, void *args)
{
  /* User provided argument. */
  CLONE_ARG (int, fd);

  f->eax = 0;
}

/* Not yet implemented. */
static void
sys_inumber (struct intr_frame *f, void *args)
{
  /* User provided argument. */
  CLONE_ARG (int, fd);

  f->eax = 0xffffffff;
}
