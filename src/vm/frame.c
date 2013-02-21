#include <debug.h>
#include "frame.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "vm/page.h"

#define PAGE_SIZE 4096

unsigned frame_hash (const struct hash_elem *f_, void *aux UNUSED);
bool frame_less(const struct hash_elem *a, const struct hash_elem *b, 
	void *aux);

unsigned
frame_hash (const struct hash_elem *f_, void *aux UNUSED)
{
	const struct frame *f = hash_entry(f_, struct frame, helem);
	return hash_bytes (&f->uaddr, sizeof(f->uaddr));
}

bool 
frame_less(const struct hash_elem *a, const struct hash_elem *b, 
	void *aux)
{
	struct frame *fa = hash_entry(a, struct frame, helem);
	struct frame *fb = hash_entry(b, struct frame, helem);

	return fa->uaddr < fb->uaddr;
}

bool 
frame_table_init(void) 
{
	return hash_init(&frame_table, frame_hash, frame_less, NULL);
}

/*
 * Assumes that the user addresses are page alligned
*/
struct hash_elem*
frame_table_put(void *uaddr)
{
	ASSERT ((int)uaddr % PAGE_SIZE == 0);
	struct frame* f = malloc(sizeof(struct frame));
	f->uaddr = uaddr;

	return hash_insert(&frame_table, &f->helem);
}

struct frame*
frame_table_lookup(void* uaddr)
{
	//allign user address to page boundaries
	void* page = (void*)(((int)uaddr/PAGE_SIZE) * PAGE_SIZE);
	struct frame f;
	struct hash_elem *e;

	f.uaddr = page;
	e = hash_find(&frame_table, &f.helem);
	return e != NULL ? hash_entry (e, struct frame, helem) : NULL;
}

struct frame*
frame_table_remove(void *uaddr)
{
	struct frame f;
	struct hash_elem *e;

	f.uaddr = uaddr;
	e = hash_delete(&frame_table, &f.helem);
	return e != NULL ? hash_entry (e, struct frame, helem) : NULL;
}

void*
frame_get_page(enum palloc_flags flags) 
{
	void* page = palloc_get_page(flags);
	if (page == NULL)
	{
		//TODO ERROR HANDLING
	}

	if (flags == PAL_USER)
	{
		struct hash* spt = &thread_current()->supplementary_page_table;
		supplementary_page_table_put(spt, page);	
	}
	
	frame_table_put(page);
	return page;
}

void
frame_free_page(void *page)
{
	ASSERT ((int)page % PAGE_SIZE == 0);
	palloc_free_page(page);
	
	struct hash* spt = &thread_current()->supplementary_page_table;
	struct page* p = supplementary_page_table_remove(spt, page);
	if (p != NULL) free(p);
	
	struct frame* f = frame_table_remove(page);
	if (f != NULL) free(f); //free if not null
	return;
}
