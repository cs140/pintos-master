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

struct hash_elem* 
mmap_table_put(struct hash* mpt, mapid_t mapid, int array_size)
{
  struct mmap_entry* p = malloc(sizeof(struct mmap_entry)); 
  p->mapid = mapid;
  p->size = array_size;
  p->pages = malloc(array_size*sizeof(struct page *));
    //printf("put in %d\n", (int)p->mapid);
  return hash_insert(mpt, &(p->helem));
}

struct mmap_entry* 
mmap_table_lookup(struct hash* mpt, mapid_t mapid)
{
  struct mmap_entry p;
  struct hash_elem *e;
  p.mapid = mapid;
  e = hash_find(mpt, &p.helem);
  //printf("lookup in %d\n", (int)p.mapid);
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
mmap_cleanup(struct intr_frame* f)
{
  struct hash_iterator i;
  struct thread* t = thread_current();
  struct process* p = get_process(t->tid);
  struct hash* mpt = &t->mmap_page_table;

  hash_first(&i, mpt);
  while (hash_next(&i))
  {
    struct mmap_entry* entry = hash_entry(hash_cur(&i), 
      struct mmap_entry, helem);

    mmap_unmap(entry->mapid, f);  
  }
}

void
mmap_unmap(mapid_t mapid, struct intr_frame* f)
{
    //printf("In munmap\n");
  //lock_acquire(&filesys_lock);
  struct thread* t = thread_current();
  struct hash* mpt = &t->mmap_page_table;
  struct mmap_entry* mpt_entry = mmap_table_lookup(mpt, mapid);
  /* If the mapid doesn't exist for this process */
  if (mpt_entry == NULL)
  {
    f->eax = -1;
    return;
  }
  
  struct file* fi = mpt_entry->backup_file;
  int i = 0;
  
  uint32_t *pd = thread_current()->pagedir;

  for (i = 0; i < mpt_entry->size; i++) 
  {
    struct page* page = mpt_entry->pages[i];
    void* addr = page->vaddr;
    /* Write the database back to the file */
    /*if (write_byte < PGSIZE) 
    {

    } else 
    {

    }*/
    if (pagedir_get_page(pd, addr) != NULL && 
      pagedir_is_dirty(pd, addr) == true) 
    {
      //printf("here %d %d %s\n", page->page_read_bytes, page->ofs, addr);
      //if (fi->deny_write) printf("deny write\n");
      file_write_at(fi, addr, page->page_read_bytes, page->ofs);
    }
    //cur_write += ;
    //printf("there\n");
    /* Remove from frame page */
    //frame_free_page(page->kpage);
    pagedir_clear_page(pd, addr);
    struct page* p = supplementary_page_table_remove(
      &(thread_current()->supplementary_page_table), addr);
    if (p != NULL) free(p);
  }
  

  free(mpt_entry->backup_file);
  mmap_table_remove(mpt, mapid);
  //lock_release(&filesys_lock);
}
