#include <string.h>
#include "vm/page.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "lib/kernel/hash.h"

void sp_init(struct process *p)
{
    hash_init(&p->sp_table, sp_table_hash_func, sp_table_less_func, NULL);
    lock_init(&p->sp_lock);
}

unsigned sp_table_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
    return (unsigned)hash_entry(e, struct page_info, elem)->upage;
}

bool sp_table_less_func(const struct hash_elem *e1,
                        const struct hash_elem *e2, void *aux UNUSED)
{
    return hash_entry(e1, struct page_info, elem)->upage <
           hash_entry(e2, struct page_info, elem)->upage;
}