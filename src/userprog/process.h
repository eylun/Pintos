#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/synch.h"
#include "threads/thread.h"

#include "lib/kernel/hash.h"

typedef int pid_t;

tid_t process_execute(const char *file_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(void);

struct argument
{
  struct list_elem elem; /* List element for argv list in struct setup_data */
  char *arg;             /* String argument */
  void *stack_addr;      /* Memory of where the argument is stored for stack */
};
struct setup_data
{
  int argc;          /* Number of arguments */
  struct list argv;  /* List of arguments */
  struct process *p; /* Pointer to calloc'd process memory */
};

/* Structure of a process, each thread will have one of these if a process is
   ran on it */
struct process
{
  pid_t pid;                   /* Process identification */
  int exit_code;               /* Exit code of process */
  struct semaphore wait_sema;  /* Semaphore for process waiting */
  struct semaphore exec_sema;  /* Semaphore for process execution */
  bool load_success;           /* Set to True if this process has been successfully loaded */
  bool is_waited_on;           /* Set to True if this process is being waited on */
  bool has_parent;             /* Set to True if this process has a parent */
  bool terminated;             /* Set to True if the process is dead */
  struct list_elem child_elem; /* List elem for list of thread's children */
  struct hash fd_table;        /* Hash table to store file descriptors */
  int next_fd;                 /* Stores the next number to use for the file descriptor */
};

bool install_page(void *, void *, bool);

#endif /* userprog/process.h */
