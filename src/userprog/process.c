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
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static thread_func start_process NO_RETURN;
static bool load(const char *cmdline, void (**eip)(void), void **esp);
static void *increment_page_ptr(void *, int);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t process_execute(const char *file_name)
{
  void *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy(fn_copy, file_name, PGSIZE);

  /* Begin building setup_data for setting up the stack in start_process().
     At any point where fn_copy is changed to point outside of the page, the
     program will free the page and terminate */

  /* Save the pointer to the start of the page as page_start,
     it also happens to point to the file_name stored in the page */
  char *page_start = fn_copy;
  /* Increment the fn_copy pointer to move past the file_name in the page */
  if (!(fn_copy = increment_page_ptr(fn_copy, strlen(file_name) + 1)))
  {
    palloc_free_page(page_start);
    return TID_ERROR;
  }
  /* Set the memory of the page at pointer 'fn_copy' to point to
     a struct setup_data */
  struct setup_data *setup = fn_copy;

  /* Increment the fn_copy pointer to move past setup_data in the page */
  list_init(&setup->argv);
  setup->argc = 0;

  if (!(fn_copy = increment_page_ptr(fn_copy, sizeof(struct setup_data))))
  {
    palloc_free_page(page_start);
    return TID_ERROR;
  }
  /* Convert the command arguments into tokens using strtok_r */
  char *token, *save_ptr;
  struct argument *arg;
  for (token = strtok_r(page_start, " ", &save_ptr); token;
       token = strtok_r(NULL, " ", &save_ptr))
  {
    /* Set current value of fn_copy to point to a instance of struct argument */
    arg = fn_copy;
    arg->arg = token;
    /* Push the argument to the front of setup_data's argv, stack-style */
    list_push_front(&setup->argv, &arg->elem);
    /* Increment the fn_copy pointer to move past argument in the page */
    if (!(fn_copy = increment_page_ptr(fn_copy, sizeof(struct argument))))
    {
      palloc_free_page(page_start);
      return TID_ERROR;
    }
    setup->argc++;
  }
  /* At this point, file_name is still intact with no changes.
     However, the copy of file_name in the page has all the spaces replaced
     with '\0' characters because of strtok_r. */
  /* Create process struct
     Process structure is created here because we need to know what is
     the parent id. */
  struct process *p = calloc(1, sizeof(struct process));
  struct process **process_ptr = fn_copy;

  /* Initialize process semaphore */
  sema_init(&p->wait_sema, 0);

  /* Push the pointer of this process onto the page so it can be
     deferenced in start_process(). */
  *process_ptr = p;
  if (!(fn_copy = increment_page_ptr(fn_copy, sizeof(void *))))
  {
    palloc_free_page(page_start);
    return TID_ERROR;
  }

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(page_start, PRI_DEFAULT, start_process, setup);

  /* Check for error, if none, cond_wait */
  if (tid == TID_ERROR)
  {
    palloc_free_page(page_start);
  }
  else
  {
    sema_down(&p->wait_sema);

    /* If process not loaded, free process and return TID_ERROR */
    if (!p->load_success)
    {
      free(p);
      return TID_ERROR;
    }

    p->pid = tid;

    /* Add process child_elem to thread's list of child_elems */
    list_push_back(&thread_current()->child_elems, &p->child_elem);
  }
  return tid;
}

/* Check if newly added pointer will be within limits of page boundary.
   This is to catch situations where there is overflow in the page,
   (or underflow, somehow) */
void *increment_page_ptr(void *curr, int size)
{
  void *incremented = curr + size;
  /* IF new pointer is within limits of page boundary, return pointer,
     otherwise, return NULL. */
  return incremented <= pg_round_down(curr) + PGSIZE
             ? incremented
             : NULL;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process(void *page)
{
  /* page is a page that points to a struct setup_data.
     After struct setup_data, the page stores the list elements
     of setup_data's argv list
      ___________________________
     | file_name  ...........\0  |
     |___________________________|
     | struct setup_data         | <- page points here
     | ..........                |
     |___________________________|
     | struct argument           |
     |___________________________|
     | struct argument           |
     |___________________________|
     |...                        |
     |...                        |
     |___________________________|
     Cast file_name into a struct setup_data */

  /* Retrieve file_name from the top of page */
  char *file_name = pg_round_down(page);
  /* Retrieve setup data from new page location */
  struct setup_data *setup = page;
  struct intr_frame if_;
  bool success;
  /* Initialize interrupt frame and load executable. */
  memset(&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  /* Signal the parent process if properly executed */
  success = load(file_name, &if_.eip, &if_.esp);

  /* Acquire struct process after pushing everything onto the stack */
  struct process **p = page +
                       sizeof(struct setup_data) + setup->argc * sizeof(struct argument);

  // TODO: HOW TO CHECK IF PROCESS IS VALID (exec-missing.c)
  struct process *process_check = *p;
  process_check->load_success = success;
  sema_up(&process_check->wait_sema);

  /* If load failed, quit. */
  if (!success)
  {
    /* Set thread's child process exit code to TID_ERROR */
    palloc_free_page(file_name);
    thread_exit();
  }

  thread_current()->process = process_check;

  int arg_len;
  struct list_elem *e;
  struct argument *arg;

  /* Begin setting up stack
     Loop through the argv list from start to end
     Since arguments were pushed from the front, the last argument
     will be the first list element */
  for (e = list_begin(&setup->argv);
       e != list_end(&setup->argv); e = list_next(e))
  {
    arg = list_entry(e, struct argument, elem);
    arg_len = strlen(arg->arg) + 1;
    if_.esp -= arg_len;
    strlcpy(if_.esp, arg->arg, arg_len);
    /* Store the stack address for pushing up later */
    arg->stack_addr = if_.esp;
  }

  /* Null Pointer Sentinel */
  if_.esp -= sizeof(void *);
  memset(if_.esp, 0, sizeof(void *));
  /* Push argument pointers */
  /* Reset index back to argc - 1 for iteration */

  /* Push up argument stack addresses */
  for (e = list_begin(&setup->argv);
       e != list_end(&setup->argv); e = list_next(e))
  {
    arg = list_entry(e, struct argument, elem);
    if_.esp -= sizeof(void *);
    memcpy(if_.esp, &arg->stack_addr, sizeof(void *));
  }

  /* Push up argv */
  void *prev_esp = if_.esp;
  if_.esp -= sizeof(void *);
  memcpy(if_.esp, &prev_esp, sizeof(void *));

  /* Push up argc */
  if_.esp -= sizeof(int);
  memcpy(if_.esp, &setup->argc, sizeof(int));

  /* Push up fake return address */
  if_.esp -= sizeof(void *);
  memset(if_.esp, 0, sizeof(void *));

  palloc_free_page(file_name);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit"
               :
               : "g"(&if_)
               : "memory");
  NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.
 * If it was terminated by the kernel (i.e. killed due to an exception),
 * returns -1.
 * If TID is invalid or if it was not a child of the calling process, or if
 * process_wait() has already been successfully called for the given TID,
 * returns -1 immediately, without waiting.
 *
 * This function will be implemented in task 2.
 * For now, it does nothing. */
int process_wait(tid_t child_tid UNUSED)
{
  struct process *process = thread_current()->process;
  struct list_elem *child_elem = list_begin(&thread_current()->child_elems);

  /* Locate child_tid in thread's children */
  for (child_elem; child_elem != list_end(&thread_current()->child_elems); child_elem = list_next(child_elem))
  {
    struct process *child_process = list_entry(child_elem, struct process, child_elem);

    /* Child process acquires lock */
    if (child_process->pid == child_tid && !child_process->is_waited_on)
    {

      /* Store exit_status on the stack */
      int child_exit_code = child_process->exit_code;

      if (child_process->terminated)
      {
        /* Note: may need a custom function for freeing child_process */
        list_remove(child_elem);
        free(child_process);
        return child_exit_code;
      }

      sema_down(&child_process->wait_sema);
      /* Set child_process is_waited_on to True */
      child_process->is_waited_on = true;

      /* Remove child_process from process's children list */
      list_remove(child_elem);

      /* Free up memory */
      free(child_process);

      return child_exit_code;
    }
  }
  return -1;
}

/* Free the current process's resources. */
void process_exit(void)
{
  struct thread *cur = thread_current();
  uint32_t *pd;

  /* Check if thread_exitting is running a user process
     If thread->process is NULL, it means there is no user process */
  if (cur->process)
  {
    printf("%s: exit(%d)\n", cur->name, cur->process->exit_code);
    cur->process->terminated = true;
    sema_up(&cur->process->wait_sema);
  }

  // Somewhere here we cond_signal

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
  {
    /* Correct ordering here is crucial.  We must set
       cur->pagedir to NULL before switching page directories,
       so that a timer interrupt can't switch back to the
       process page directory.  We must activate the base page
       directory before destroying the process's page
       directory, or our active page directory will be one
       that's been freed (and cleared). */
    cur->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void process_activate(void)
{
  struct thread *t = thread_current();

  /* Activate thread's page tables. */
  pagedir_activate(t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void **esp);
static bool validate_segment(const struct Elf32_Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char *file_name, void (**eip)(void), void **esp)
{
  struct thread *t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create();
  if (t->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  file = filesys_open(file_name);
  if (file == NULL)
  {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr || memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024)
  {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
  {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
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
      if (validate_segment(&phdr, file))
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
          zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
        }
        else
        {
          /* Entirely zero.
             Don't read anything from disk. */
          read_bytes = 0;
          zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
        }
        if (!load_segment(file, file_page, (void *)mem_page,
                          read_bytes, zero_bytes, writable))
          goto done;
      }
      else
        goto done;
      break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp))
    goto done;

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  file_close(file);
  return success;
}

/* load() helpers. */

static bool install_page(void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment(const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void *)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
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
load_segment(struct file *file, off_t ofs, uint8_t *upage,
             uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
  {
    /* Calculate how to fill this page.
       We will read PAGE_READ_BYTES bytes from FILE
       and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Check if virtual page already allocated */
    struct thread *t = thread_current();
    uint8_t *kpage = pagedir_get_page(t->pagedir, upage);

    if (kpage == NULL)
    {

      /* Get a new page of memory. */
      kpage = palloc_get_page(PAL_USER);
      if (kpage == NULL)
      {
        return false;
      }

      /* Add the page to the process's address space. */
      if (!install_page(upage, kpage, writable))
      {
        palloc_free_page(kpage);
        return false;
      }
    }

    /* Load data into the page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes)
    {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

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
setup_stack(void **esp)
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL)
  {
    success = install_page(((uint8_t *)PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
      *esp = PHYS_BASE;
    else
      palloc_free_page(kpage);
  }
  return success;
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
install_page(void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pagedir, upage) == NULL && pagedir_set_page(t->pagedir, upage, kpage, writable));
}
