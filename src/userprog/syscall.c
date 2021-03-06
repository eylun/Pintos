#include "userprog/syscall.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "lib/kernel/hash.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "vm/vm.h"
#include "vm/frame.h"
#include "vm/mmap.h"
#include "vm/page.h"

typedef void (*handler)(struct intr_frame *);

static void syscall_handler(struct intr_frame *);
static void validate_memory(void *, int);

void exit(int status);
static void sys_halt(struct intr_frame *UNUSED);
static void sys_exit(struct intr_frame *);
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
static void sys_mmap(struct intr_frame *);
static void sys_munmap(struct intr_frame *);

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
    &sys_mmap,     /* Maps the file to virtual pages. */
    &sys_munmap    /* Unmaps the file from the virtual pages. */
};

/* List of number of arguments for each system call. The values are
   appropriately positioned to line up with the functions inside the syscalls
   list of function pointers */
static const int sysarguments[] = {
    0, 1, 1, 1, 2, 1, 1, 1, 3, 3, 2, 1, 1, 2, 1};

static struct lock filesys_lock;

void start_filesys_access(void)
{
  lock_acquire(&filesys_lock);
}

void end_filesys_access(void)
{
  lock_release(&filesys_lock);
}

void check_and_end_filesys_access(void)
{
  if (filesys_lock.holder && thread_current()->tid == filesys_lock.holder->tid)
  {
    end_filesys_access();
  }
}

void syscall_init(void)
{
  lock_init(&filesys_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f)
{
  int *esp = f->esp;
  /* First, validate the pointer to esp .*/
  validate_memory(esp, 1);
  /* Retrieve number of arguments using the sysarguments array */
  int arguments = sysarguments[*esp];
  /* Next, validate the pointers to the arguments for this system call */
  validate_memory(esp + 1, arguments);
  /* All syscall handlers work under the assumption that the
     arguments have been validated. This is safe to assume because validation
     occurs right before the calling of the handlers */
  syscalls[*esp](f);
}

/* Check if a buffer is writable. */
static bool check_buffer_writable(void *buffer)
{
  struct page_info *page_info = sp_search_page_info(thread_current(), pg_round_down(buffer));
  if (page_info && !page_info->writable)
  {
    return false;
  }
  return true;
}

/* validate_memory takes in a pointer and an arguments parameter.
   If arguments is 0, there is nothing to validate
   If arguments is non-zero, validate this amount of pointers
   At any point if validation fails, terminate immediately */
static void validate_memory(void *pointer, int arguments)
{
  /* If 0 arguments, then there is no need to check */
  if (arguments == 0)
  {
    return;
  }
  /* Check if pointer provided is null */
  if (!pointer)
  {
    exit(EXIT_CODE);
  }
  for (int count = 0; count < arguments; ++count)
  {
    /* Check if pointers are user vaddrs,
       and are on the page of the current thread */
    if (!is_user_vaddr(pointer + count) ||
        !pagedir_get_page(thread_current()->pagedir, pointer + count))
    {
      if (!vm_page_fault(pointer, NULL))
      {
        exit(EXIT_CODE);
      }
    }
  }
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

void exit(int status)
{
  thread_current()->process->exit_code = status;
  thread_exit();
}

static void sys_exec(struct intr_frame *f)
{
  /* Exec returns a pid_t value */
  int *esp = f->esp;
  const char *cmd_line = *(const char **)(esp + 1);
  /* Check if cmd_line string pointer is:
     1. A valid pointer (using validate_memory)
     2. Has a size less than or equal to a page (4,096kb)
        Check this using strnlen(cmd_line, 4096), and use validate_memory
        on the end of the buffer */

  /* A command line can only contain PGSIZE worth of bytes.
     Validate the starting pointer first, then retrieve the length of the
     string. Note that it is possible that while cmd_line points to user
     memory, it might not point to an actual string. */
  validate_memory((void *)cmd_line, 1);

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
  /* Create returns a bool value */
  int *esp = f->esp;
  const char *file = *(const char **)(esp + 1);
  unsigned initial_size = *(unsigned *)(esp + 2);

  validate_memory((void *)file, 1);

  start_filesys_access();

  f->eax = filesys_create(file, initial_size);

  end_filesys_access();
}

static void sys_remove(struct intr_frame *f)
{
  /* Remove returns a bool value */
  int *esp = f->esp;
  const char *file = *(const char **)(esp + 1);

  validate_memory((void *)file, 1);

  start_filesys_access();

  f->eax = filesys_remove(file);

  end_filesys_access();
}

static void sys_open(struct intr_frame *f)
{
  /* Open returns an int value */
  int *esp = f->esp;
  const char *filename = *(const char **)(esp + 1);
  validate_memory((void *)filename, 1);

  start_filesys_access();

  struct file *file = filesys_open(filename);

  end_filesys_access();

  int fd = EXIT_CODE;

  if (file != NULL)
  {
    struct thread *current_thread = thread_current();

    struct file_descriptor *descriptor = malloc(sizeof(struct file_descriptor));
    if (!descriptor)
    {
      end_filesys_access();
      exit(EXIT_CODE);
    }

    descriptor->fd = (current_thread->process->next_fd)++;
    descriptor->file = file;

    hash_insert(&current_thread->process->fd_table, &descriptor->hash_elem);
    fd = descriptor->fd;
  }

  f->eax = fd;
}

/* Returns a hash_elem equal to the file_descriptor's hash_elem (fd) from
  the current process's fd_table or null pointer if no such element exists */
struct hash_elem *get_elem(int fd)
{
  struct file_descriptor descriptor;
  struct thread *current_thread = thread_current();
  descriptor.fd = fd;

  return hash_find(&current_thread->process->fd_table, &descriptor.hash_elem);
}

static void sys_filesize(struct intr_frame *f)
{
  /* Filesize returns an int value */
  int *esp = f->esp;
  int fd = *(esp + 1);

  int file_size = 0;

  struct hash_elem *elem = get_elem(fd);

  if (elem != NULL)
  {
    struct file_descriptor *open_descriptor = hash_entry(elem, struct file_descriptor, hash_elem);
    if (open_descriptor != NULL)
    {
      start_filesys_access();
      file_size = file_length(open_descriptor->file);
      end_filesys_access();
    }
  }

  f->eax = file_size;
}

static void sys_read(struct intr_frame *f)
{
  /* Read returns an int value */
  int *esp = f->esp;
  int fd = *(esp + 1);
  const void *buffer = *(const void **)(esp + 2);
  unsigned size = *(unsigned *)(esp + 3);

  validate_memory((void *)buffer, 1);

  int ret = EXIT_CODE;
  if (!check_buffer_writable((void *)buffer))
  {
    exit(-1);
  }

  if (fd == STDIN_FILENO)
  {
    ret = input_getc();
  }
  else
  {
    struct hash_elem *elem = get_elem(fd);

    if (elem != NULL)
    {
      struct file_descriptor *open_descriptor = hash_entry(elem, struct file_descriptor, hash_elem);
      if (open_descriptor != NULL)
      {
        void *upage = pg_round_down(buffer);
        struct page_info *page_info = sp_search_page_info(thread_current(), upage);
        /* Acquire the frame lock before reading to the buffer (page) */
        lock_acquire(&page_info->frame->lock);
        start_filesys_access();
        ret = file_read(open_descriptor->file, (void *)buffer, size);
        end_filesys_access();
        lock_release(&page_info->frame->lock);
      }
    }
  }

  f->eax = ret;
}

static void sys_write(struct intr_frame *f)
{
  /* Write returns an int value */
  int *esp = f->esp;
  int fd = *(esp + 1);
  const void *buffer = *(const void **)(esp + 2);
  unsigned size = *(unsigned *)(esp + 3);

  validate_memory((void *)buffer, 1);

  int ret = 0;

  if (fd == 1)
  {
    putbuf(buffer, size);
    ret = size;
  }
  else
  {
    struct hash_elem *elem = get_elem(fd);

    if (elem != NULL)
    {
      struct file_descriptor *open_descriptor = hash_entry(elem, struct file_descriptor, hash_elem);
      if (open_descriptor != NULL)
      {
        void *upage = pg_round_down(buffer);
        struct page_info *page_info = sp_search_page_info(thread_current(), upage);
        /* Acquire the frame lock before reading from the buffer (page) */
        lock_acquire(&page_info->frame->lock);
        start_filesys_access();
        ret = file_write(open_descriptor->file, buffer, size);
        end_filesys_access();
        lock_release(&page_info->frame->lock);
      }
    }
  }

  /* Return result by setting eax value in interrupt frame */
  f->eax = ret;
}

static void sys_seek(struct intr_frame *f)
{
  /* Seek returns nothing */
  int *esp = f->esp;
  int fd = *(esp + 1);
  unsigned position = (unsigned)*(esp + 2);

  struct hash_elem *elem = get_elem(fd);

  if (elem != NULL)
  {
    struct file_descriptor *open_descriptor = hash_entry(elem, struct file_descriptor, hash_elem);
    if (open_descriptor != NULL)
    {
      start_filesys_access();
      file_seek(open_descriptor->file, position);
      end_filesys_access();
    }
  }
}

static void sys_tell(struct intr_frame *f)
{
  /* Tell returns an unsigned value */
  int *esp = f->esp;
  int fd = *(esp + 1);

  unsigned pos = 0;

  struct hash_elem *elem = get_elem(fd);

  if (elem != NULL)
  {
    struct file_descriptor *open_descriptor = hash_entry(elem, struct file_descriptor, hash_elem);
    if (open_descriptor != NULL)
    {
      start_filesys_access();
      pos = file_tell(open_descriptor->file);
      end_filesys_access();
    }
  }

  f->eax = pos;
}

static void sys_close(struct intr_frame *f)
{
  /* Close returns nothing */
  int *esp = f->esp;
  int fd = *(esp + 1);

  struct file_descriptor descriptor;
  struct thread *current_thread = thread_current();
  descriptor.fd = fd;

  struct hash_elem *elem = hash_find(&current_thread->process->fd_table, &descriptor.hash_elem);

  if (elem != NULL)
  {
    struct file_descriptor *open_descriptor = hash_entry(elem, struct file_descriptor, hash_elem);

    if (open_descriptor != NULL)
    {
      start_filesys_access();
      file_close(open_descriptor->file);
      end_filesys_access();

      struct file_descriptor close_descriptor;
      close_descriptor.fd = open_descriptor->fd;
      hash_delete(&current_thread->process->fd_table, &close_descriptor.hash_elem);
      free(open_descriptor);
    }
  }
}

/* Maps the entire file open as fd into the process's virtual address space */
/* Failure cases:
  - fd has length of zero bytes
  - addr is not page aligned
  - range of pages mapped overlaps an existing set of mapped pages (incld. stack and pages mapped during load)
  - addr == 0, fd == 0, fd == 1 */

static void sys_mmap(struct intr_frame *f)
{
  int *esp = f->esp;
  int fd = *(esp + 1);
  void *addr = (void *)*(esp + 2);

  f->eax = mmap_map(fd, addr);
}

static void sys_munmap(struct intr_frame *f)
{
  int *esp = f->esp;
  mapid_t mapid = *(esp + 1);

  mmap_unmap(mapid);
}
