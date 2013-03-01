#include "filesys/file.h"
#include "vm/mmap.h"
#include "threads/malloc.h"


unsigned 
mmap_page_hash (const struct hash_elem *p_, void *aux UNUSED)
{
  const struct mmap_entry *p = hash_entry(p_, struct mmap_entry, helem);
  return hash_bytes (&p->mapid, sizeof(p->mapid));
}

bool 
mmap_page_less(const struct hash_elem *a, const struct hash_elem *b, void *aux)
{
  struct mmap_entry *pa = hash_entry(a, struct mmap_entry, helem);
  struct mmap_entry *pb = hash_entry(b, struct mmap_entry, helem);

  return pa->mapid < pb->mapid;
}

bool 
mmap_table_init(struct hash* mpt)
{
  lock_init(&thread_current()->mmap_lock);
  return hash_init(mpt, mmap_page_hash, mmap_page_less, NULL);
}

struct mmap_entry* 
mmap_table_put(struct hash* mpt, mapid_t mapid, int array_size,struct file* fi)
{
  struct mmap_entry* p = malloc(sizeof(struct mmap_entry)); 

  if(p == NULL) return NULL;

  p->mapid = mapid;
  p->size = array_size;
  p->pages = malloc(array_size*sizeof(struct page *));
  p->backup_file = file_reopen(fi);

  if(p->pages == NULL) return NULL;

  return hash_insert(mpt, &(p->helem)) == NULL ? p : NULL;
}

struct mmap_entry* 
mmap_table_lookup(struct hash* mpt, mapid_t mapid)
{
  struct mmap_entry p;
  struct hash_elem *e;
  p.mapid = mapid;
  e = hash_find(mpt, &p.helem);

  return e != NULL ? hash_entry (e, struct mmap_entry, helem) : NULL;
}

struct mmap_entry* 
mmap_table_remove(struct hash* mpt, mapid_t mapid)
{
  struct mmap_entry p;
  struct hash_elem *e;

  p.mapid = mapid;
  e = hash_delete(mpt, &p.helem);
  return e != NULL ? hash_entry (e, struct mmap_entry, helem) : NULL;
}


void 
mmap_cleanup(struct intr_frame* f,struct thread* t)
{
  struct hash_iterator i;
  struct process* p = get_process(t->tid);
  struct hash* mpt = &t->mmap_page_table;

  hash_first(&i, mpt);
  while (hash_next(&i))
  {
    struct mmap_entry* entry = hash_entry(hash_cur(&i), 
      struct mmap_entry, helem);

    mmap_unmap_file(entry->mapid, f, t);  
  }
}

void
mmap_unmap_file(mapid_t mapid, struct intr_frame* f,struct thread* t)
{
  struct hash* mpt = &t->mmap_page_table;
  struct mmap_entry* mpt_entry = mmap_table_lookup(mpt, mapid);
  /* If the mapid doesn't exist for this process */
  if (mpt_entry == NULL)
  {
    f->eax = -1;
    return;
  }
  
  struct file* fi = mpt_entry->backup_file;
  
  uint32_t *pd = t->pagedir;

  int i = 0;
  for (i = 0; i < mpt_entry->size; i++) 
  {
    struct page* page = mpt_entry->pages[i];
    void* addr = page->vaddr;

    if (pagedir_get_page(pd, addr) != NULL && 
        pagedir_is_dirty(pd, addr) == true) 
    {
      lock_acquire(&filesys_lock);
      file_write_at(fi, addr, page->page_read_bytes, page->ofs);
      lock_release(&filesys_lock);
    }

    if (pagedir_get_page(pd, addr) != NULL) pagedir_clear_page(pd, addr);

    struct page* p = supplementary_page_table_remove(
        &(thread_current()->supplementary_page_table), addr);

    if (p != NULL) free(p);
  }

  free(mpt_entry->backup_file);
  mmap_table_remove(mpt, mapid);
}

bool 
mmap_unmap_page(struct frame* frame)
{
  uint32_t *pd = frame->supplementary_page->pd;
  struct mmap_entry* mpt_entry = frame->supplementary_page->mmentry;
  struct file* fi = mpt_entry->backup_file;
  int index = ((uint64_t)frame->uaddr - (uint64_t)mpt_entry->pages[0]->vaddr) / 4096;

  struct page* page = mpt_entry->pages[index];

  if (pagedir_get_page(pd, frame->uaddr) != NULL && 
      pagedir_is_dirty(pd, frame->uaddr) == true) 
    {
      lock_acquire(&filesys_lock);
      file_write_at(fi, frame->paddr, page->page_read_bytes, page->ofs);
      lock_release(&filesys_lock);
    }

  if (pagedir_get_page(pd, frame->uaddr) != NULL) pagedir_clear_page(pd, frame->uaddr);
  
  return true;
}
