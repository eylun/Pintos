#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

typedef int pid_t;

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct argument {
  struct list_elem elem; /* List element for argv list in struct setup_data */
  char *arg;             /* string argument */
  void *stack_addr;      /* memory of where the argument is stored for stack */
};
struct setup_data {
  int argc;              /* number of arguments */
  struct list argv;      /* list of arguments */
};

/* Structure of a process, each thread will have one of these if a process is 
   ran on it */
struct process {
  pid_t pid;           /* Process identification */
  int exit_code;       /* Exit code of process */
};
#endif /* userprog/process.h */
