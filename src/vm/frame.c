#include <debug.h>
#include "frame.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "vm/page.h"
#include "vm/swap.h"

#define PAGE_SIZE 4096

struct frame* frame_table_put(void *paddr, void *uaddr);
unsigned frame_hash (const struct hash_elem *f_, void *aux UNUSED);
bool frame_less(const struct hash_elem *a, const struct hash_elem *b, 
	void *aux);
struct process* frame_get_process(struct hash_elem* e);

unsigned
frame_hash (const struct hash_elem *f_, void *aux UNUSED)
{
	const struct frame *f = hash_entry(f_, struct frame, helem);
	return hash_bytes (&f->paddr, sizeof(f->paddr));
}

bool 
frame_less(const struct hash_elem *a, const struct hash_elem *b, 
	void *aux)
{
	struct frame *fa = hash_entry(a, struct frame, helem);
	struct frame *fb = hash_entry(b, struct frame, helem);

	return fa->paddr < fb->paddr;
}

bool 
frame_table_init(void) 
{
	lock_init(&frame_lock);
	return hash_init(&frame_table, frame_hash, frame_less, NULL);
}

/*
 * Assumes that the user addresses are page alligned.
 * paddr = physical address
 * uaddr = user address
*/
struct frame*
frame_table_put(void *paddr, void *uaddr)
{
	// printf("frame table size:%d \n", hash_size(&frame_table));
	ASSERT ((int)uaddr % PAGE_SIZE == 0);
	// if (frame_table_lookup(paddr) != NULL)
	// {
	// 	// printf("FACK\n");
	// 	return NULL;
	// }

	struct frame* f = malloc(sizeof(struct frame));
	if (f == NULL) {
		PANIC("MALLOC FAIL?!\n");
	}
	f->paddr = paddr;
	f->uaddr = uaddr;
	f->locked = false;

	struct hash_elem* helem = hash_insert(&frame_table, &f->helem);
	if(helem == NULL) 
		{
			// if(paddr == 0xc0286000) PANIC("BACKTRACE %p %d\n",paddr,thread_current()->tid);
			return f;
		}
	else 
	{
		// PANIC("paddr: %p %d\n",paddr,thread_current()->tid);
		return NULL;
	}	
}

struct frame*
frame_table_lookup(void* paddr)
{
	lock_acquire(&frame_lock);
	//allign user address to page boundaries
	void* page = (void*)(((int)paddr/PAGE_SIZE) * PAGE_SIZE);
	struct frame f;
	struct hash_elem *e;

	f.paddr = page;
	e = hash_find(&frame_table, &f.helem);

	struct frame* lookup_frame = e != NULL ? hash_entry (e, struct frame, helem) : NULL;

	lock_release(&frame_lock);

	return lookup_frame;
}

struct frame*
frame_table_remove(void *paddr)
{
	// lock_acquire(&frame_lock);
	struct frame f;
	struct hash_elem *e;

	f.paddr = paddr;
	e = hash_delete(&frame_table, &f.helem);

	struct frame* removed = e != NULL ? hash_entry (e, struct frame, helem) : NULL;

	// lock_release(&frame_lock);

	return removed; 
}

void get_lock()
{
	lock_acquire(&frame_lock);
}

void release_lock()
{
	lock_release(&frame_lock);
}

void*
uframe_get_page(enum palloc_flags flags, void *uaddr) 
{
	ASSERT ((flags & PAL_USER) != 0);
	// lock_acquire(&frame_lock);

	void* page = palloc_get_page(flags);

	if (page == NULL)
	{
		struct frame* evict = frame_get_evict();
		page = swap_get_frame(evict);
	}

	struct hash* spt = &thread_current()->supplementary_page_table;
	struct page* supp_page = supplementary_page_table_put(spt, uaddr);
	
	struct frame* frame = frame_table_put(page, uaddr);
	frame->supplementary_page = supp_page;
	// lock_release(&frame_lock);
	return page;
}

void*
frame_get_page(enum palloc_flags flags, void *uaddr) 
{
	ASSERT ((flags & PAL_USER) != 0);
	lock_acquire(&frame_lock);

	void* page = palloc_get_page(flags);

	if (page == NULL)
	{
		struct frame* evict = frame_get_evict();
		page = swap_get_frame(evict);
	}

	struct hash* spt = &thread_current()->supplementary_page_table;
	struct page* supp_page = supplementary_page_table_put(spt, uaddr);
	
	struct frame* frame = frame_table_put(page, uaddr);
	frame->supplementary_page = supp_page;
	lock_release(&frame_lock);
	return page;
}

struct frame*
frame_get_evict()
{
  // lock_acquire(&frame_lock);
  int i;
  for (i=0; i<2; i++) {
	  struct hash_iterator i;
	  hash_first(&i, &frame_table);
	  while (hash_next(&i))
	  {
	    struct frame* f = hash_entry(hash_cur(&i), 
	      struct frame, helem);

	    if(!f->locked) 
	    {
	    	if (pagedir_is_accessed(f->supplementary_page->pd, f->uaddr))
	    	{
	    		pagedir_set_accessed(f->supplementary_page->pd, f->uaddr, false);
	    	} else 
	    	{
	    		if (pagedir_is_dirty(f->supplementary_page->pd, f->uaddr))
	    		{
	    			pagedir_set_dirty(f->supplementary_page->pd, f->uaddr, false);
					//clear dirty bit and write page to disk, TODO SYNCHRONIZATION
	    		}
	    		// lock_release(&frame_lock);
	    		return f;
	    	}
	    }
	  }
  }

  // lock_release(&frame_lock);
  return NULL;
}

void
frame_free_page(void *page)
{

	ASSERT ((int)page % PAGE_SIZE == 0);
	lock_acquire(&frame_lock);
	palloc_free_page(page);
	
	struct frame* f = frame_table_remove(page);
	if (f != NULL) 
	{
		free(f); //free if not null
		struct hash* spt = &thread_current()->supplementary_page_table;
		struct page* p = supplementary_page_table_remove(spt, f->uaddr);
		if (p != NULL) free(p);	
	}
	
	lock_release(&frame_lock);
	return;
}

struct process*
frame_get_process(struct hash_elem* e)
{
	// lock_acquire(&frame_lock);

	struct frame* f = hash_entry(e, struct frame, helem);
	struct page* page = f->supplementary_page;
	struct process* p = page->process;

	// lock_release(&frame_lock);

	return p;
}

void
frame_cleanup(void)
{
	lock_acquire(&frame_lock);

	struct process* p = process_current();
	struct hash_elem* removeElems[hash_size(&frame_table)]; //list of frames to remove

	int count = 0;
	struct hash_iterator i;
	hash_first(&i, &frame_table);
	while (hash_next(&i))
	{
		struct hash_elem* e = hash_cur(&i);

		if (frame_get_process(e) == p)
		{
			// add to list
			removeElems[count] = e;
			count++;
		}
	}

	int c;
	for (c=0; c<count; c++)
	{
		hash_delete(&frame_table, removeElems[c]);
	}

	lock_release(&frame_lock);
}
