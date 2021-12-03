#ifndef VM_VM_H
#define VM_VM_H

#include <hash.h>
#include <threads/palloc.h>

#define ZERO 0
#define NO_ZERO 1

#define STACK_MAX_SPACE 1024 * 8000 /* 1kb * 8000 = 8MB */

/* Initialize the VM controller */
void vm_init(void);

/* Function to call when a new page needs to be retrieved */
void *vm_alloc_get_page(enum palloc_flags, void *);

/* Function to call upon a virtual memory page fault */
void *vm_page_fault(void *, void *);

/* Function to call for freeing a VM page */
void vm_free_page(void *);

/* Stack growing */
void *vm_grow_stack(void *);

#endif /* vm/vm.h */