#include "vm/mmap.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "lib/kernel/hash.h"
#include "userprog/syscall.h"

static unsigned mmap_table_hash_func(const struct hash_elem *, void *UNUSED);
bool mmap_table_less_func(const struct hash_elem *,
                          const struct hash_elem *, void *UNUSED);

void mmap_init(void)
{
    struct thread *cur = thread_current();
    hash_init(&cur->mmap_table, mmap_table_hash_func, mmap_table_less_func, NULL);
    cur->next_mmapid = 0;
}

void mmap_unmap(mapid_t mapid)
{
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
        struct page_info *page_info = sp_search_page_info(thread_current(), uaddr);

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

        /* Free user page in sp_table */
        struct page_info temp_page_info;
        temp_page_info.upage = uaddr;
        hash_delete(sp_table, &temp_page_info.elem);

        uaddr += PGSIZE;
    }

    /* Finds and deletes the mmap_entry*/
    struct mmap_entry temp_entry;
    temp_entry.mapid = entry->mapid;
    hash_delete(&thread_current()->mmap_table, &temp_entry.hash_elem);

    start_filesys_access();
    file_close(entry->file);
    end_filesys_access();

    free(entry);
}

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
