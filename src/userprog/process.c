#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
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
#include "lib/kernel/hash.h"
#include "vm/frame.h"
#include "vm/vm.h"
#include "vm/page.h"

static thread_func start_process NO_RETURN;
static bool load(const char *cmdline, void (**eip)(void), void **esp);
static void free_setup(struct setup_data *);
static void free_hash_file(struct hash_elem *, void *UNUSED);

bool install_page(void *upage, void *kpage, bool writable);
unsigned fd_table_hash_func(const struct hash_elem *e, void *aux);
bool fd_table_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t process_execute(const char *file_name)
{
  void *fn_copy;
  tid_t tid;

  /* Before doing anything, ensure the file_name passed in fits within a page */
  /* strnlen is used here because file_name might not be a string, and hence
     might never terminate. Using strnlen allows the code to have a limit and
     if the length passes this limit (4096), we return an error */
  if (strnlen(file_name, PGSIZE + 1) > PGSIZE)
  {
    return TID_ERROR;
  }

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  /* VM NOTE: There is no need to vm alloc this because this is for
     argument parsing purposes. It will be freed once parsing is over. */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy(fn_copy, file_name, PGSIZE);

  /* Begin building setup_data for setting up the stack in start_process().
     At any point where fn_copy is changed to point outside of the page, the
     program will free the page and terminate */

  struct setup_data *setup = calloc(1, sizeof(struct setup_data));
  if (!setup)
  {
    palloc_free_page(fn_copy);
    return TID_ERROR;
  }

  /* Increment the fn_copy pointer to move past setup_data in the page */
  list_init(&setup->argv);
  setup->argc = 0;

  /* Convert the command arguments into tokens using strtok_r */
  char *token, *save_ptr;
  struct argument *arg;
  for (token = strtok_r(fn_copy, " ", &save_ptr); token;
       token = strtok_r(NULL, " ", &save_ptr))
  {
    /* Set current value of fn_copy to point to a instance of struct argument */
    arg = calloc(1, sizeof(struct argument));
    if (!arg)
    {
      palloc_free_page(fn_copy);
      free_setup(setup);
      return TID_ERROR;
    }
    arg->arg = token;
    /* Push the argument to the front of setup_data's argv, stack-style */
    list_push_front(&setup->argv, &arg->elem);
    setup->argc++;
  }
  /* At this point, file_name is still intact with no changes.
     However, the copy of file_name in the page has all the spaces replaced
     with '\0' characters because of strtok_r. */

  /* Create process struct
     Process structure is created here because we need to know what is
     the parent id. */
  struct process *p = calloc(1, sizeof(struct process));
  if (!p)
  {
    free_setup(setup);
    palloc_free_page(fn_copy);
    return TID_ERROR;
  }
  /* Store the pointer in the setup so it can be referenced later during
     start_process */
  setup->p = p;

  /* Initialize process semaphore */
  sema_init(&p->wait_sema, 0);
  sema_init(&p->exec_sema, 0);

  /* Initialize process hash table of file descriptors */
  hash_init(&p->fd_table, &fd_table_hash_func, &fd_table_less_func, NULL);

  /* Sets the first fd to 2 since 0 and 1 are reserved for the console. */
  p->next_fd = MIN_FD;

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(fn_copy, PRI_DEFAULT, start_process, setup);

  /* SYNCHRONIZATION - When child has loaded it will sema_up and allow this
     parent to continue */
  sema_down(&p->exec_sema);

  /* Free the page and setup data, they are no longer needed */
  palloc_free_page(fn_copy);
  free_setup(setup);

  if (tid != TID_ERROR)
  {
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

void free_setup(struct setup_data *setup)
{
  struct list_elem *e;
  /* Using method provided in list.c for freeing list elements */
  while (!list_empty(&setup->argv))
  {
    e = list_pop_front(&setup->argv);
    free(list_entry(e, struct argument, elem));
  }
  free(setup);
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process(void *_setup)
{
  /* setup is a struct setup_data. It contains the arguments in a list (argv),
     the process pointer and argument count (argc) */

  struct intr_frame if_;
  bool success;

  struct setup_data *setup = _setup;

  /* Initialize supplemental page table */
  sp_init();

  /* Initialize mmap_table */
  mmap_init();

  /* Initialize interrupt frame and load executable. */
  memset(&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  /* Signal the parent process if properly executed */
  success = load(thread_current()->name, &if_.eip, &if_.esp);

  /* Acquire struct process from the setup data*/
  struct process *p = setup->p;
  p->has_parent = true;
  p->is_waited_on = false;
  p->terminated = false;
  p->load_success = success;
  /* SYNCHRONIZATION - Child process runs sema_up in order to notify parent
     that it has loaded */
  sema_up(&p->exec_sema);

  /* If load failed, quit. */
  if (!success)
  {
    /* Set thread's child process exit code to TID_ERROR */
    thread_exit();
  }

  /* Set thread's process, only do this is load is successful */
  thread_current()->process = p;

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
 * returns -1 immediately, without waiting. */
int process_wait(tid_t child_tid)
{
  struct list_elem *child_elem = list_begin(&thread_current()->child_elems);

  /* Locate child_tid in thread's list of children */
  for (; child_elem != list_end(&thread_current()->child_elems); child_elem = list_next(child_elem))
  {
    struct process *child_process = list_entry(child_elem, struct process, child_elem);
    if (child_process->pid == child_tid)
    {
      /* Check if child is already being waited on, return
         an error if it is */
      if (child_process->is_waited_on)
      {
        return TID_ERROR;
      }
      /* Check if child has already terminated. If it has, there is no need
         to invoke synchronization */
      if (!child_process->terminated)
      {
        /* Set child_process is_waited_on to True */
        child_process->is_waited_on = true;

        /* SYNCRHONIZATION - Parent waits for child to call sema_up
           when it exits */
        sema_down(&child_process->wait_sema);
      }

      /* Store exit_status separately as the process is going to be freed */
      int child_exit_code = child_process->exit_code;

      /* Remove child_process from process's children list */
      list_remove(child_elem);

      /* Free up memory */
      free(child_process);

      return child_exit_code;
    }
  }
  return TID_ERROR;
}

/* Free the current process's resources. */
void process_exit(void)
{
  struct thread *cur = thread_current();
  uint32_t *pd;

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

  /* Loop through this thread's list of child processes.
     If a child has died, free its process
     If a child is still alive, set its has_parent flag to false */
  struct list_elem *e = list_begin(&cur->child_elems);
  struct process *child_process;

  while (e != list_end(&cur->child_elems))
  {
    struct list_elem *next_child = list_next(e);

    child_process = list_entry(e, struct process, child_elem);
    if (child_process->terminated)
    {
      /* There is no need to free the contents of the child_process, because it
         has already done so when it's thread called process_exit() */
      list_remove(e);
      free(child_process);
    }
    else
    {
      child_process->has_parent = false;
    }

    e = next_child;
  }

  /* Check if thread_exit is running a user process.
     If thread->process is NULL, it means there is no user process */
  struct process *p = cur->process;
  if (p)
  {
    /* Attempt to end filesys access. It is possible that the exitting thread
       might still hold onto the filesys lock here */
    check_and_end_filesys_access();
    /* Run sema_up the exec_sema, the thread can terminate before it
       calls for that, and the parent will end up stuck in process_execute.
       If program has already sema_up'd successfully, running sema_up() again
       here will not change anything */
    sema_up(&p->exec_sema);
    printf("%s: exit(%d)\n", cur->name, p->exit_code);
    p->terminated = true;
    sema_up(&p->wait_sema);

    /* Clear up process file hash table */
    start_filesys_access();
    hash_destroy(&p->fd_table, free_hash_file);
    end_filesys_access();
    /* If this process no longer has a parent, free it */
    if (!p->has_parent)
    {
      free(p);
    }
  }

  /* Completely destroy the thread's supplemental page table, freeing all
     pages associated IF there are any */
  sp_destroy_complete();

  /* If the thread also holds onto a file, free it */
  if (cur->file)
  {
    start_filesys_access();
    file_close(cur->file);
    end_filesys_access();
  }
}

/* Hash file freeing, can be used as a function for completely
   destroying a hash table storing file descriptors */
void free_hash_file(struct hash_elem *e, void *aux UNUSED)
{
  struct file_descriptor *fd = hash_entry(e, struct file_descriptor, hash_elem);
  file_close(fd->file);
  hash_delete(&thread_current()->process->fd_table, e);
  free(fd);
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
  start_filesys_access();
  file = filesys_open(file_name);
  end_filesys_access();
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
    start_filesys_access();
    file_seek(file, file_ofs);

    off_t file_read_result = file_read(file, &phdr, sizeof phdr);
    end_filesys_access();
    if (file_read_result != sizeof phdr)
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
  start_filesys_access();
  file_deny_write(file);
  end_filesys_access();
done:
  /* We arrive here whether the load is successful or not. */

  t->file = file;

  return success;
}

/* load() helpers. */

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment(const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  start_filesys_access();
  if (phdr->p_offset > (Elf32_Off)file_length(file))
  {
    end_filesys_access();
    return false;
  }
  end_filesys_access();
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
  start_filesys_access();
  file_seek(file, ofs);
  off_t start = ofs;
  end_filesys_access();
  // printf("loading...\n");
  while (read_bytes > 0 || zero_bytes > 0)
  {
    /* Calculate how to fill this page.
       We will read PAGE_READ_BYTES bytes from FILE
       and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    struct thread *t = thread_current();
    /*Malloc new page_info
      Fill in page_info
      Things to fill:
      1. upage
      2. page_read_bytes -- page_zero_bytes = PGSIZE - page_read_bytes
      3. writable */
    struct page_info *page_info = calloc(1, sizeof(struct page_info));
    page_info->file = file;
    page_info->page_status = PAGE_FILESYS;
    page_info->upage = upage;
    page_info->writable = writable;
    page_info->page_read_bytes = page_read_bytes;
    page_info->start = start;
    sp_insert_page_info(page_info);
    /* Advance. */
    start += page_read_bytes;
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
  uint8_t *kpage, *upage = (uint8_t *)PHYS_BASE - PGSIZE;
  if (vm_grow_stack(upage))
  {
    *esp = PHYS_BASE;
    return true;
  }
  return false;
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
bool install_page(void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pagedir, upage) == NULL && pagedir_set_page(t->pagedir, upage, kpage, writable));
}

unsigned fd_table_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
  const struct file_descriptor *file_descriptor = hash_entry(e, struct file_descriptor, hash_elem);
  return file_descriptor->fd;
};

bool fd_table_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  const struct file_descriptor *file_descriptor_a = hash_entry(a, struct file_descriptor, hash_elem);
  const struct file_descriptor *file_descriptor_b = hash_entry(b, struct file_descriptor, hash_elem);

  return file_descriptor_a->fd < file_descriptor_b->fd;
};