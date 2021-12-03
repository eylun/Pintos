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
  // printf("syscall: %d\n", *esp);
  syscalls[*esp](f);
}

/* Check if a buffer is writable. */
static void check_buffer_writable(void *buffer)
{
  struct page_info *page_info = sp_search_page_info(thread_current(), pg_round_down(buffer));
  if (page_info && !page_info->writable)
  {
    exit(EXIT_CODE);
  }
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
/* validate_buffer validates the memory that an entire buffer occupies.
   This function usually validates pointers which are passed in, not
   pointers from the interrupt frame.
   It takes in the pointer itself, as well as a size limit.
   For every 4096 bytes, there is a need to recheck the pagedir.
   THIS FUNCTION WILL BE CALLED ONLY AFTER validate_memory. This is for
   the sys_exec handler to not double-validate */
static void validate_buffer(void *pointer, unsigned size)
{
  /* The start of the pointer has already been validated, no need to
     validate again. */
  unsigned page_checker = PGSIZE;
  for (; page_checker < size; page_checker += PGSIZE)
  {
    /* Revalidate the pointer for every PGSIZE bytes */
    validate_memory(pointer + page_checker, 1);
  }
  /* Validate the end of the buffer IF the starting pointer lies on a page
     boundary. When the starting pointer lies on a page boundary, there is no
     need to validate the pointer of the end of the buffer, since the start of
     the last page is validated in the for loop
      */
  if (pointer != pg_round_down(pointer))
  {
    /* Validate the end of the buffer */
    validate_memory(pointer + size, 1);
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
  // validate_buffer((void *)cmd_line, strnlen(cmd_line, PGSIZE));

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
  // validate_buffer((void *)file, FILE_MAX);

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
  // validate_buffer((void *)file, FILE_MAX);

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
  // validate_buffer((void *)filename, FILE_MAX);

  start_filesys_access();

  struct file *file = filesys_open(filename);

  end_filesys_access();

  int fd = EXIT_CODE;

  if (file != NULL)
  {
    struct thread *current_thread = thread_current();

    struct file_descriptor *descriptor = malloc(sizeof(struct file_descriptor));
    if (descriptor == NULL)
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
static struct hash_elem *get_elem(struct file_descriptor *descriptor, int fd)
{
  struct thread *current_thread = thread_current();
  descriptor->fd = fd;

  return hash_find(&current_thread->process->fd_table, &descriptor->hash_elem);
}

static void sys_filesize(struct intr_frame *f)
{
  /* Filesize returns an int value */
  int *esp = f->esp;
  int fd = *(esp + 1);

  int file_size = 0;
  struct file_descriptor descriptor;

  struct hash_elem *elem = get_elem(&descriptor, fd);

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
  check_buffer_writable((void *)buffer);
  // validate_buffer((void *)buffer, size);

  int ret = EXIT_CODE;

  if (fd == STDIN_FILENO)
  {
    ret = input_getc();
  }
  else
  {
    struct file_descriptor descriptor;
    struct hash_elem *elem = get_elem(&descriptor, fd);

    if (elem != NULL)
    {
      struct file_descriptor *open_descriptor = hash_entry(elem, struct file_descriptor, hash_elem);
      if (open_descriptor != NULL)
      {
        start_filesys_access();
        ret = file_read(open_descriptor->file, (void *)buffer, size);
        end_filesys_access();
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
  check_buffer_writable((void *)buffer);
  // validate_buffer((void *)buffer, size);

  int ret = 0;
  if (fd == 1)
  {
    putbuf(buffer, size);
    ret = size;
  }
  else
  {
    struct file_descriptor descriptor;

    struct hash_elem *elem = get_elem(&descriptor, fd);

    if (elem != NULL)
    {
      struct file_descriptor *open_descriptor = hash_entry(elem, struct file_descriptor, hash_elem);
      if (open_descriptor != NULL)
      {
        start_filesys_access();
        ret = file_write(open_descriptor->file, buffer, size);
        end_filesys_access();
      }
    }
  }

  f->eax = ret;
}

static void sys_seek(struct intr_frame *f)
{
  /* Seek returns nothing */
  int *esp = f->esp;
  int fd = *(esp + 1);
  unsigned position = (unsigned)*(esp + 2);

  struct file_descriptor descriptor;

  struct hash_elem *elem = get_elem(&descriptor, fd);

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
  struct file_descriptor descriptor;

  struct hash_elem *elem = get_elem(&descriptor, fd);

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

  /* Pintos assumes virtual page 0 is not mapped and fd = 0 and fd = 1 is not mappable */
  if (addr == 0 || fd == 0 || fd == 1)
  {
    // PANIC("help");
    f->eax = MMAP_ERROR;
    return;
  }

  /* Checks that addr is a user virtual address */
  if (!is_user_vaddr(addr))
  {
    // PANIC("help me");
    exit(EXIT_CODE);
  }

  if (pg_ofs(addr) != 0)
  {
    // PANIC("help me please");
    f->eax = MMAP_ERROR;
    return;
  }

  /* Access file corresponding to the given fd */
  /* Returns -1 if the given file_descriptor is not found in the process's fd_table */
  struct file_descriptor descriptor;
  struct hash_elem *elem = get_elem(&descriptor, fd);

  if (elem == NULL)
  {
    f->eax = MMAP_ERROR;
    return;
  }
  /* TODO: Create a function to retrieve file_descriptor given fd */

  struct file_descriptor *open_descriptor = hash_entry(elem, struct file_descriptor, hash_elem);
  if (open_descriptor == NULL)
  {
    f->eax = MMAP_ERROR;
    return;
  }

  /* Memory map stays even when original file is closed or removed. */

  start_filesys_access();
  struct file *file = file_reopen(open_descriptor->file);
  off_t length = file_length(file);
  end_filesys_access();

  /* Returns -1 if file has length of zero bytes */
  if (length == 0)
  {
    f->eax = MMAP_ERROR;
    return;
  }

  int pages_to_map = length / PGSIZE;
  if (length % PGSIZE)
  {
    pages_to_map++;
  }

  for (int i = 0; i < pages_to_map; i++)
  {
    if (sp_search_page_info(addr + i * PGSIZE))
    {
      // PANIC("help ,");
      f->eax = MMAP_ERROR;
      return;
    }
  }
  struct thread *cur = thread_current();

  struct mmap_entry *entry = malloc(sizeof(struct mmap_entry));
  if (!entry)
  {
    exit(EXIT_CODE);
  }

  entry->mapid = cur->next_mmapid++;
  entry->file = file;
  entry->uaddr = addr;

  size_t bytes_into_file = 0;
  void *uaddr = addr;

  for (int i = 0; i < pages_to_map; i++)
  {
    length = length - bytes_into_file < PGSIZE ? length - bytes_into_file : PGSIZE;

    start_sp_access();
    struct page_info *page_info = malloc(sizeof(struct page_info));
    if (!page_info)
    {
      exit(EXIT_CODE);
    }
    page_info->page_status = PAGE_MMAP;
    page_info->upage = uaddr;
    page_info->page_read_bytes = length;
    page_info->start = bytes_into_file;
    page_info->mapid = entry->mapid;
    sp_insert_page_info(page_info);
    end_sp_access();
    bytes_into_file += PGSIZE;
    uaddr += PGSIZE;
  }

  hash_insert(&cur->mmap_table, &entry->hash_elem);

  f->eax = entry->mapid;
}

/* TODO: Implement sys_munmap and create helper functions */
static void sys_munmap(struct intr_frame *f)
{
  int *esp = f->esp;
  mapid_t mapid = *(esp + 1);

  struct hash *mmap_table = &thread_current()->mmap_table;
  struct mmap_entry *entry = mmap_search_mapping(mmap_table, mapid);

  if (!entry)
  {
    return;
  }

  start_filesys_access();
  size_t file_size = file_length(entry->file);
  end_filesys_access();

  int num_pages = file_size / PGSIZE;
  if (file_size % PGSIZE != 0)
  {
    num_pages++;
  }

  void *uaddr = entry->uaddr;

  struct hash *sp_table = &thread_current()->sp_table;

  for (int i = 0; i < num_pages; i++)
  {

    struct page_info *page_info = sp_search_page_info(uaddr);

    if (!page_info)
    {
      return;
    }
    if (page_info->page_status == PAGE_MMAP)
    {
      void *kaddr = pagedir_get_page(thread_current()->pagedir, uaddr);
      if (pagedir_is_dirty(thread_current()->pagedir, page_info->upage))
      {
        mmap_write_back_data(entry, kaddr, page_info->start, page_info->page_read_bytes);
      }
    }

    struct page_info temp_page_info;
    temp_page_info.upage = uaddr;
    hash_delete(sp_table, &temp_page_info.elem);

    uaddr += PGSIZE;
  }

  struct mmap_entry temp_entry;
  temp_entry.mapid = entry->mapid;
  hash_delete(&thread_current()->mmap_table, &temp_entry.hash_elem);

  start_filesys_access();
  file_close(entry->file);
  end_filesys_access();

  free(entry);
}