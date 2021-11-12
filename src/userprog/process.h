#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/synch.h"
#include "threads/thread.h"

typedef int pid_t;

tid_t process_execute(const char *file_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(void);

struct argument
{
  struct list_elem elem; /* List element for argv list in struct setup_data */
  char *arg;             /* string argument */
  void *stack_addr;      /* memory of where the argument is stored for stack */
};
struct setup_data
{
  int argc;         /* number of arguments */
  struct list argv; /* list of arguments */
};

/* Structure of a process, each thread will have one of these if a process is
   ran on it */
struct process
{
  pid_t pid;                   /* Process identification */
  int exit_code;               /* Exit code of process */
  struct semaphore wait_sema;  /* Semaphore for process */
  bool load_success;           /* Set to True if this process has been successfully loaded */
  bool is_waited_on;           /* Set to True if this process is being waited on */
  bool has_parent;             /* Set to True if this process has a parent */
  bool terminated;             /* Set to True if the process is dead */
  bool has_children;           /* Set to True if the thread has any children */
  struct list_elem child_elem; /* List elem for list of thread's children */
  struct thread *thread;       /* Pointer to thread */
};
#endif /* userprog/process.h */
