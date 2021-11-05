#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct argument {
  struct list_elem elem; /* List element for argv list in struct setup_data */
  char *arg;             /* string argument */
  void *stack_addr;      /* memory of where the argument is stored for stack */
}

struct setup_data {
  struct list argv;       /* list of arguments */
  int argc;               /* number of arguments */
}
#endif /* userprog/process.h */
