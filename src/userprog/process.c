#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Process table. */
static struct list process_table;
static struct lock table_lock;

/* Initialize process management system. */
void
process_init (void)
{
  lock_init (&filesys_lock);
  lock_init (&table_lock);
  list_init (&process_table);
}

/* File descriptor structure managed independently by each process. */
struct fd_info
  {
    struct list_elem elem;
    int fd;
    bool isdir;
    struct file *file;
    struct dir *dir;
  };

/* Register a new process to the process table. */
void
process_register (struct process_info *pi)
{
  lock_acquire (&table_lock);
  list_push_back (&process_table, &pi->elem);
  lock_release (&table_lock);
}

/* Allocate a new file descriptor to FILE. */
int
process_add_fd (struct file *file)
{
  struct thread *cur = thread_current ();
  struct fd_info *fd_info = malloc (sizeof *fd_info);
  if (fd_info == NULL)
    return FD_ERROR;
  fd_info->fd = cur->next_fd++;
  fd_info->file = file;
  list_push_back (&cur->fd_list, &fd_info->elem);
  return fd_info->fd;
}

/* Get process info by TID. If there is no matching info, return NULL. */
struct process_info *
get_info_by_tid (tid_t tid)
{
  struct process_info *pi = NULL;
  struct list_elem *e;
  lock_acquire (&table_lock);
  for (e = list_begin (&process_table); e != list_end (&process_table); e = list_next (e))
  {
    if (list_entry (e, struct process_info, elem)->tid == tid)
    {
      pi = list_entry (e, struct process_info, elem);
      break;
    }
  }
  lock_release (&table_lock);
  return pi;
}

/* Get file descriptor entry by FD. */
static struct fd_info *
get_info_by_fd (int fd)
{
  struct thread *cur = thread_current ();
  struct list_elem *e;
  struct fd_info *fd_info = NULL;

  for (e = list_begin (&cur->fd_list); e != list_end (&cur->fd_list); e = list_next (e))
  {
    if (list_entry (e, struct fd_info, elem)->fd == fd)
    {
      fd_info = list_entry (e, struct fd_info, elem);
      break;
    }
  }

  return fd_info;
}

/* Get the file pointer by FD. */
struct file *
get_file_by_fd (int fd)
{
  struct fd_info *fd_info = get_info_by_fd (fd);
  if (fd_info == NULL)
    return NULL;
  return fd_info->file;
}

/* Remove file descriptor entry from the table. */
void
process_remove_fd (int fd)
{
  struct fd_info *fd_info = get_info_by_fd (fd);
  if (fd_info != NULL)
  {
    lock_acquire (&filesys_lock);
    file_close (fd_info->file);
    lock_release (&filesys_lock);
    list_remove (&fd_info->elem);
    free (fd_info);
  }
}

/* Remove process information from the table. */
void
remove_info (struct process_info *pi)
{
  if (pi != NULL)
  {
    lock_acquire (&table_lock);
    list_remove (&pi->elem);
    lock_release (&table_lock);
    free (pi);
  }
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  char *arg_copy;
  char *name;
  char *save_ptr;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  arg_copy = palloc_get_page (0);
  if (fn_copy == NULL || arg_copy == NULL)
  {
    palloc_free_page (fn_copy);
    palloc_free_page (arg_copy);
    return TID_ERROR;
  }
  strlcpy (fn_copy, file_name, PGSIZE);
  strlcpy (arg_copy, file_name, PGSIZE);
  name = strtok_r (fn_copy, " ", &save_ptr);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (name, PRI_DEFAULT, start_process, arg_copy);
  palloc_free_page (fn_copy);
  if (tid == TID_ERROR)
  {
    palloc_free_page (arg_copy); 
  }
  return tid;
}

static void setup_arguments (char *filename, char **save_ptr, void **esp);

/* A thread function that loads a user process and makes it start
   running. */
static void
start_process (void *f_name)
{
  char *save_ptr;
  char *file_name = strtok_r ((char *) f_name, " ", &save_ptr);
  struct intr_frame if_;
  struct thread *cur = thread_current ();
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  lock_acquire (&filesys_lock);
  success = load (file_name, &if_.eip, &if_.esp);
  lock_release (&filesys_lock);

  if (success)
  {
    setup_arguments (file_name, &save_ptr, &if_.esp);
    cur->info->exec_success = true;
  }
  /* If load failed, quit. */
  palloc_free_page (f_name);
  sema_up (&cur->info->executed);
  if (!success) 
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
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
process_wait (tid_t child_tid) 
{
  struct process_info *pi = get_info_by_tid (child_tid);
  int exit_code;

  if (pi == NULL || pi->parent_id != thread_current ()->tid)
    return -1;
  sema_down (&pi->exited);
  exit_code = pi->exit_code;
  remove_info (pi);
  return exit_code;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *curr = thread_current ();
  uint32_t *pd;

  lock_acquire (&filesys_lock);
  if (curr->file != NULL)
    file_close (curr->file);

  /* Destroy the current process's file descriptor table, and
     child process list. */
  struct list_elem *e;
  struct fd_info *fd_info;
  while (!list_empty (&curr->fd_list))
    {
      e = list_pop_front (&curr->fd_list);
      fd_info = list_entry (e, struct fd_info, elem);
      file_close (fd_info->file);
      free (fd_info);
    }
  lock_release (&filesys_lock);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = curr->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      curr->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

  /* Exit message. */
  if (curr->info->exec_success)
    printf ("%s: exit(%d)\n", curr->name, curr->info->exit_code);
  sema_up (&curr->info->exited);
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

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
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

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
  /* Prevent writes to an open executable. */
  t->file = file;
  file_deny_write (file);


  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
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
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
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
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Do calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Setup the stack with argument for user program. It should
   only be called by start_process (). Note that the file name has
   already been tokenized. */
static void
setup_arguments (char *file_name, char **save_ptr, void **esp)
{
  void *ptr = *esp;
  char *str_ptr = NULL;
  char *token = file_name;  /* The first argument is the filename. - JHS */
  int len;
  int tot_len = 0;
  int argc = 0;
  int i;

  /* Store the arguments in the stack in reverse order. - JHS */
  while (token != NULL)
  {
    len = strnlen (token, PGSIZE - tot_len);
    str_ptr = ptr;
    MOVE_ADDR (ptr, char, -(len+1));
    for (i = 0; i <= len; i++)
    {
      str_ptr--;
      *str_ptr = token[i];
    }
    argc++;
    tot_len += len+1;
    token = strtok_r (NULL, " ", save_ptr);
  }

  /* Round down to the multiple of 4. - JHS */
  ptr = SP_ROUND_DOWN (ptr);

  /* ARGV[ARGC] should be 0. */
  PUSH_DOWN (ptr, char *, NULL);

  /* Again reverse the stack and update the pointer. 
     Step 1 : Reversing + pointer update
     Step 2 : Pointer update - JHS */

  char *rev_ptr = *esp;
  char temp;    /* This is a temporary value for swapping. */
  bool new_arg = true;

  /* Here, starts the Step 1. - JHS */
  MOVE_ADDR (ptr, char *, -argc);
  rev_ptr--;
  for (i = 0; i < tot_len/2; i++)
  {
    /* Swap. */
    temp = *str_ptr;
    *str_ptr = *rev_ptr;
    *rev_ptr = temp;
    if (new_arg)
    {
      new_arg = false;
      PUSH_UP (ptr, char *, str_ptr);
    }
    if (*str_ptr == 0)
      new_arg = true;

    str_ptr++;
    rev_ptr--;
  }

  /* Here, starts the Step 2. - JHS */
  for (i = tot_len/2; i < tot_len; i++)
  {
    if (new_arg)
    {
      new_arg = false;
      PUSH_UP (ptr, char *, str_ptr);
    }
    if (*str_ptr == 0)
      new_arg = true;

    str_ptr++;
  }

  ASSERT (POINTER(ptr, char *) == NULL);

  MOVE_ADDR (ptr, char *, -argc);

  /* Push ARGV. - JHS */
  PUSH_DOWN (ptr, char **, ptr);

  /* Push ARGC. - JHS */
  PUSH_DOWN (ptr, int, argc);

  /* Push fake return address. - JHS */
  PUSH_DOWN (ptr, void *, NULL);

  /* For debug, uncomment the following function call. (I am not sure
     what the first argument of hex_dump() means, but anyway it works.) - JHS */
  //hex_dump (0, ptr, *esp - ptr, true);

  *esp = ptr;
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
