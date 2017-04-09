#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include <stdint.h>
#include <list.h>
#include "threads/synch.h"
#include "threads/thread.h"

#define FD_ERROR -1

struct lock filesys_lock;

/* Process information about exit status. */
struct process_info
  {
    struct list_elem elem;
    tid_t tid;
    tid_t parent_id;
    struct semaphore executed;
    struct semaphore exited;
    bool exec_success;
    int exit_code;
  };

struct file;
struct fd_info;

void process_init (void);
tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
void process_register (struct process_info *);
int process_add_fd (struct file *file);
void process_remove_fd (int fd);

/* Helper functions for managing information list. */
struct process_info *get_info_by_tid (tid_t tid);
void remove_info (struct process_info *pi);

/* Helper functions for managing fd table per process. */
struct file *get_file_by_fd (int fd);

/* Helper macro functions for user arguments setup.
   1. INCREMENT_ADDR (ADDR, TYPE, N) : incremented address by N casting to type TYPE.
   2. MOVE_ADDR (ADDR, TYPE, N) : move ADDR to INCREMENT_ADDR (ADDR, TYPE, N). ADDR should be an lvalue.
   3. POINTER (ADDR, TYPE) : a reference to the TYPE address ADDR. (It can be an lvalue.)
   4. ASSIGN (ADDR, TYPE, V) : Assign a value V to address ADDR.
   5. PUSH_UP (ADDR, TYPE, V) :
    Low             High
     +-------+-------+                    +-------+-------+
     |       |       |        ====>       |   V   |       |
     +-------+-------+                    +-------+-------+
     ^       <------->                            ^
    ADDR   size of TYPE

   6. PUSH_DOWN (ADDR, TYPE, V) :
     +-------+-------+                    +-------+-------+
     |       |       |        ====>       |   V   |       |
     +-------+-------+                    +-------+-------+
             ^                            ^

   7. POP_UP (ADDR, TYPE) :
     +-------+-------+                    +-------+-------+
     |   V   |       |        ====>       |       |       |   return V
     +-------+-------+                    +-------+-------+
     ^                                            ^
   
   8. POP_DOWN (ADDR, TYPE) :
     +-------+-------+                    +-------+-------+
     |   V   |       |        ====>       |       |       |   return V
     +-------+-------+                    +-------+-------+
             ^                            ^

   9. SP_ROUND_DOWN(ADDR) : round down ADDR to the multiple of 4.
   10. SWAP(PTR1, PTR2, T) : swap the values of each pointer, exploiting the temporary storage T. */

#define INCREMENT_ADDR(ADDR, TYPE, N) ((void *) (((TYPE *) (ADDR)) + (N)))
#define MOVE_ADDR(ADDR, TYPE, N) ((ADDR) = INCREMENT_ADDR(ADDR, TYPE, N))
#define POINTER(ADDR, TYPE) (*((TYPE *) (ADDR)))
#define ASSIGN(ADDR, TYPE, V) (POINTER(ADDR, TYPE) = ((TYPE) (V)))
#define PUSH_UP(ADDR, TYPE, V) ASSIGN(ADDR, TYPE, V), MOVE_ADDR(ADDR, TYPE, 1)
#define PUSH_DOWN(ADDR, TYPE, V) ASSIGN(INCREMENT_ADDR(ADDR, TYPE, -1), TYPE, V), MOVE_ADDR(ADDR, TYPE, -1)
#define POP_UP(ADDR, TYPE) POINTER(INCREMENT_ADDR(MOVE_ADDR(ADDR, TYPE, 1), TYPE, -1), TYPE)
#define POP_DOWN(ADDR, TYPE) POINTER(MOVE_ADDR(ADDR, TYPE, -1), TYPE)

#define SP_ROUND_DOWN(ADDR) ((void *) (((intptr_t) (ADDR)) & -4))

#endif /* userprog/process.h */
