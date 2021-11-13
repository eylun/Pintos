#include "userprog/syscall.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

typedef void (*handler)(struct intr_frame *);

static void syscall_handler(struct intr_frame *);
static bool validate_memory(void *, int);

static void sys_halt(struct intr_frame *UNUSED);
static void sys_exit(struct intr_frame *);
static void exit(int status);
static void sys_exec(struct intr_frame *);
static void sys_wait(struct intr_frame *);
static void sys_create(struct intr_frame *);
static void sys_remove(struct intr_frame *);
static void sys_open(struct intr_frame *);
static void sys_filesize(struct intr_frame *);
static void sys_read(struct intr_frame *);
static void sys_write(struct intr_frame *);
static void sys_seek(struct intr_frame *);
static void sys_tell(struct intr_frame *);
static void sys_close(struct intr_frame *);

/* List of function pointers to syscalls, handler is defined in syscall.h.
   Each function is appropriately positioned at the syscall value which it is
   associated to, so that syscall_handler can directly access it */
static const handler syscalls[] = {
    &sys_halt,     /* Halt the operating system. */
    &sys_exit,     /* Terminate this process. */
    &sys_exec,     /* Start another process. */
    &sys_wait,     /* Wait for a child process to die. */
    &sys_create,   /* Create a file. */
    &sys_remove,   /* Delete a file. */
    &sys_open,     /* Open a file. */
    &sys_filesize, /* Obtain a file's size. */
    &sys_read,     /* Read from a file. */
    &sys_write,    /* Write to a file. */
    &sys_seek,     /* Change position in a file. */
    &sys_tell,     /* Report current position in a file. */
    &sys_close,    /* Close a file. */
};

/* List of number of arguments for each system call. The values are
   appropriately positioned to line up with the functions inside the syscalls
   list of function pointers */
static const int sysarguments[] = {
    0, 1, 1, 1, 2, 1, 1, 1, 3, 3, 2, 1, 1};

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f)
{
  int *esp = f->esp;
  if (!validate_memory(esp, 1))
  {
    exit(EXIT_CODE);
  }
  int arguments = sysarguments[*esp];
  if (!validate_memory(esp + 1, arguments))
  {
    exit(EXIT_CODE);
  }
  /* All syscall handlers work under the assumption that the
     arguments have been validated. This is safe to assume because validation
     occurs right before the calling of the handlers */
  syscalls[*esp](f);
}

static bool validate_memory(void *pointer, int arguments)
{
  /* If 0 arguments, then there is no need to check */
  if (arguments == 0)
  {
    return true;
  }
  /* Check if pointer provided is null */
  if (!pointer)
  {
    return false;
  }
  for (int count = 0; count < arguments; ++count)
  {
    /* Check if pointers are user vaddrs,
       and are on the page of the current thread */
    if (!is_user_vaddr(pointer + count) ||
        !pagedir_get_page(thread_current()->pagedir, pointer + count))
    {
      return false;
    }
  }
  return true;
}

static void sys_halt(struct intr_frame *f UNUSED)
{
  shutdown_power_off();
}

static void sys_exit(struct intr_frame *f)
{
  int *esp = f->esp;
  int status = *(esp + 1);
  exit(status);
  /* Exit returns nothing */
}

static void exit(int status)
{
  thread_current()->process->exit_code = status;
  thread_exit();
}

static void sys_exec(struct intr_frame *f)
{
  /* Exec returns a pid_t value */
  int *esp = f->esp;
  const char *cmd_line = *(const char**) (esp + 1);
  /* Check if cmd_line string pointer is:
     1. A valid pointer (using validate_memory)
     2. Has a size less than or equal to a page (4,096kb)
        Check this using strnlen(cmd_line, 4096), and use validate_memory
        on the end of the buffer */

  /* TODO: Make a buffer check function (reuse for file read/write) */
  if (!validate_memory((void *)cmd_line, 1))
  {
    exit(EXIT_CODE);
  }
  size_t cmd_line_size = strnlen(cmd_line, PGSIZE);
  if (!validate_memory((void *)(cmd_line + cmd_line_size), 1))
  {
    exit(EXIT_CODE);
  }
  f->eax = process_execute(cmd_line);
}

static void sys_wait(struct intr_frame *f)
{
  /* Wait returns an int value */
  int *esp = f->esp;
  pid_t pid = *(esp + 1);
  f->eax = process_wait(pid);
}

static void sys_create(struct intr_frame *f)
{
  printf("Create Call\n");
  /* Create returns a bool value */
  f->eax = true;
}

static void sys_remove(struct intr_frame *f)
{
  printf("Remove Call\n");
  /* Remove returns a bool value */
  f->eax = true;
}

static void sys_open(struct intr_frame *f)
{
  printf("Open Call\n");
  /* Open returns an int value */
  f->eax = 1;
}

static void sys_filesize(struct intr_frame *f)
{
  printf("Open Filesize\n");
  /* Filesize returns an int value */
  f->eax = 1;
}

static void sys_read(struct intr_frame *f)
{
  printf("Open Read\n");
  /* Read returns an int value */
  f->eax = 1;
}

static void sys_write(struct intr_frame *f)
{
  /* Write returns an int value */
  int *esp = f->esp;
  int fd = *(esp + 1);
  const void *buffer = (void *)*(esp + 2);
  unsigned size = *(esp + 3);
  int ret;
  if (fd == 1)
  {
    putbuf(buffer, size);
    ret = size;
  }
  f->eax = ret;
}

static void sys_seek(struct intr_frame *f)
{
  printf("Open Seek\n");
  /* Seek returns nothing */
}

static void sys_tell(struct intr_frame *f)
{
  printf("Open Tell\n");
  /* Tell returns an unsigned value */
  f->eax = 1;
}

static void sys_close(struct intr_frame *f)
{
  printf("Open Close\n");
  /* Close returns nothing */
}