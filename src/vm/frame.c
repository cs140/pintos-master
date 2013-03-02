#include <debug.h>
#include "frame.h"
#include "lib/round.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "vm/page.h"
#include "vm/swap.h"

#define PAGE_SIZE 4096

static struct frame* frame_table_put(void *paddr, void *uaddr,struct page* supp_page);
unsigned frame_hash (const struct hash_elem *f_, void *aux UNUSED);
bool frame_less(const struct hash_elem *a, const struct hash_elem *b, 
	void *aux);
static struct process* frame_get_process(struct hash_elem* e);
static struct frame* frame_get_page_core(enum palloc_flags,void* uaddr);

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
static struct frame*
frame_table_put(void *paddr, void *uaddr,struct page* supp_page)
{
	ASSERT ((int)uaddr % PAGE_SIZE == 0);

	struct frame* f = malloc(sizeof(struct frame));
	if (f == NULL) 
	{
		return NULL;
	}
	f->paddr = paddr;
	f->uaddr = uaddr;
	f->locked = false;
	f->supplementary_page = supp_page;

	struct hash_elem* helem = hash_insert(&frame_table, &f->helem);

	return helem == NULL ? f : NULL;
}

static struct frame*
frame_table_lookup_core(void *paddr)
{
	//allign user address to page boundaries
	void* page = (void*)ROUND_DOWN((uint64_t)paddr, (uint64_t)PAGE_SIZE);
	struct frame f;
	struct hash_elem *e;

	f.paddr = page;
	e = hash_find(&frame_table, &f.helem);

	struct frame* lookup_frame = e != NULL ? hash_entry (e, struct frame, helem) : NULL;
	return lookup_frame;
}

struct frame*
frame_table_lookup(void* paddr)
{
	lock_acquire(&frame_lock);
	
	struct frame* lookup_frame = frame_table_lookup_core(paddr);

	lock_release(&frame_lock);

	return lookup_frame;
}

struct frame*
frame_table_remove(void *paddr)
{
	struct frame f;
	struct hash_elem *e;

	f.paddr = paddr;
	e = hash_delete(&frame_table, &f.helem);

	struct frame* removed = e != NULL ? hash_entry (e, struct frame, helem) : NULL;

	return removed; 
}

void* frame_get_locked_page(enum palloc_flags flags,void* uaddr)
{
	lock_acquire(&frame_lock);

	struct frame* frame = frame_get_page_core(flags,uaddr);

	frame->locked = true;
	
	lock_release(&frame_lock);
	return frame->paddr;
}

static bool unmodified_executable(struct page* page)
{
	return page->executable && !page->executable_modified;
}

static struct frame* frame_get_page_core(enum palloc_flags flags,void* uaddr)
{
	ASSERT ((flags & PAL_USER) != 0);

	void* page = palloc_get_page(flags);

	if (page == NULL)
	{
		struct frame* evict = frame_get_evict();
		page = swap_get_frame(evict);

		if(evict->supplementary_page->mmentry == NULL &&
			!unmodified_executable(evict->supplementary_page)); 
		{
			evict->supplementary_page->evicted = true;
		}

		struct frame* f = frame_table_remove(evict->paddr);
		free(f);
	}

	struct hash* spt = &thread_current()->supplementary_page_table;
	struct page* supp_page = supplementary_page_table_put(spt, uaddr);
	
	struct frame* frame = frame_table_put(page, uaddr,supp_page);

	return frame;
}

void*
frame_get_page(enum palloc_flags flags, void *uaddr) 
{
	lock_acquire(&frame_lock);

	struct frame* frame = frame_get_page_core(flags,uaddr);

	lock_release(&frame_lock);
	return frame->paddr;
}

struct frame*
frame_get_evict()
{
  while (true) 
  {
	  struct hash_iterator i;
	  hash_first(&i, &frame_table);
	  while (hash_next(&i))
	  {
	    struct frame* f = hash_entry(hash_cur(&i), 
	      struct frame, helem);

	   
    	if (pagedir_is_accessed(f->supplementary_page->pd, f->uaddr))
    	{
    		pagedir_set_accessed(f->supplementary_page->pd, f->uaddr, false);
    	} 
    	else 
    	{
    		if(!f->locked) 
    		{
    			f->locked = true;
    			return f;
    		}
    	}
	  }
  }

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
		printf("free:%p\n", p->vaddr);
		if (p != NULL) free(p);	
	}
	
	lock_release(&frame_lock);
	return;
}

static struct process*
frame_get_process(struct hash_elem* e)
{
	struct frame* f = hash_entry(e, struct frame, helem);
	struct page* page = f->supplementary_page;
	struct process* p = page->process;

	return p;
}

void
frame_cleanup()
{
	lock_acquire(&frame_lock);

	struct process* proc = process_current();
	struct hash_elem* removeElems[hash_size(&frame_table)]; //list of frames to remove

	int count = 0;
	struct hash_iterator i;
	hash_first(&i, &frame_table);
	while (hash_next(&i))
	{
		struct hash_elem* e = hash_cur(&i);

		if (frame_get_process(e) == proc)
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

void 
frame_set_page_lock(void* base, int length, bool locked)
{
	lock_acquire(&frame_lock);

	void* ueaddr = (void*)((char*)base + length - 1);

	struct hash* spt = &thread_current()->supplementary_page_table;

	const void* cur;
	for(cur=base; cur < ueaddr; cur+=4096)
	{
		void* kaddr = pagedir_get_page(thread_current()->pagedir, cur);
		struct frame* f = frame_table_lookup_core(kaddr);
		if(f == NULL)
		{
			lock_release(&frame_lock);
			struct page* supp_page = supplementary_page_table_lookup(spt,cur);
			f = supplementary_page_load(supp_page,true);
			lock_acquire(&frame_lock);
		}
		f->locked = locked;
	}

	void *kaddr = pagedir_get_page(thread_current()->pagedir, ueaddr);
	struct frame* f = frame_table_lookup_core(kaddr);
	if(f == NULL) 
	{
		lock_release(&frame_lock);
		struct page* supp_page = supplementary_page_table_lookup(spt,ueaddr);
		f = supplementary_page_load(supp_page,true);
		lock_acquire(&frame_lock);
	}
	f->locked = locked;

	lock_release(&frame_lock);
}
