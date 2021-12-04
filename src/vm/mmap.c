#include "vm/mmap.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "lib/kernel/hash.h"

static unsigned mmap_table_hash_func(const struct hash_elem *, void *UNUSED);
bool mmap_table_less_func(const struct hash_elem *,
                          const struct hash_elem *, void *UNUSED);

void mmap_init(void)
{
    struct thread *cur = thread_current();
    hash_init(&cur->mmap_table, mmap_table_hash_func, mmap_table_less_func, NULL);
}

/* TODO: Implement Controller Functions
struct mmap_entry *mmap_search_mapping(void *);
void mmap_insert_mapping(struct mmap_entry *);
void mmap_destroy_complete(void); */

static unsigned mmap_table_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
    const struct mmap_entry *mapping = hash_entry(e, struct mmap_entry, hash_elem);
    return hash_int((unsigned)mapping->mapid);
}

bool mmap_table_less_func(const struct hash_elem *e1,
                          const struct hash_elem *e2, void *aux UNUSED)
{
    return hash_entry(e1, struct mmap_entry, hash_elem)->mapid <
           hash_entry(e2, struct mmap_entry, hash_elem)->mapid;
}
