#include "vm/mmap.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "lib/kernel/hash.h"
#include "userprog/syscall.h"

static unsigned
mmap_table_hash_func(const struct hash_elem *, void *UNUSED);
bool mmap_table_less_func(const struct hash_elem *,
                          const struct hash_elem *, void *UNUSED);

void mmap_init(void)
{
    struct thread *cur = thread_current();
    hash_init(&cur->mmap_table, mmap_table_hash_func, mmap_table_less_func, NULL);
    cur->next_mmapid = 0;
}

/* TODO: Implement Controller Functions
void mmap_insert_mapping(struct mmap_entry *);
void mmap_destroy_complete(void); */

struct mmap_entry *mmap_search_mapping(struct hash *mmap_table, mapid_t mapid)
{
    struct mmap_entry entry;
    entry.mapid = mapid;

    struct hash_elem *e = hash_find(mmap_table, &entry.hash_elem);

    if (!e)
    {
        return NULL;
    }

    return hash_entry(e, struct mmap_entry, hash_elem);
};

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

void mmap_write_back_data(struct mmap_entry *entry, void *src, size_t offset, size_t length)
{
    start_filesys_access();
    file_seek(entry->file, offset);
    file_write(entry->file, src, length);
    end_filesys_access();
}
