#include "frame.h"
#include "threads/palloc.h"

#define PAGE_SIZE 4096

unsigned
frame_hash (const struct hash_elem *f_, void *aux UNUSED)
{
	const struct frame *f = hash_entry(f_, struct frame, hash_elem);
	return hash_bytes (&f->uaddr, sizeof(p->uaddr));
}

bool 
frame_less(const struct hash_elem *a, const struct hash_elem *b, 
	void *aux)
{
	struct frame *fa = hash_entry(a, struct frame, helem);
	struct frame *fb = hash_entry(b, struct frame, helem);

	return fa->uaddr < fa->uaddr;
}

void 
frame_table_init() 
{
	hash_init(&frame_table, frame_hash, frame_less, NULL);
}

/*
 * Assumes that the user addresses are page alligned
*/
hash_elem*
frame_table_put(void *uaddr)
{
	ASSERT ((int)uaddr % PAGE_SIZE == 0);
	struct frame* f = malloc(sizeof(struct frame));
	f->uaddr = uaddr;

	return hash_insert(&frame_table, f->helem);
}

struct frame*
frame_table_lookup(void* uaddr)
{
	//allign user address to page boundaries
	void* page = (void*)((int)uaddr/PAGE_SIZE) * PAGE_SIZE;
	struct frame f;
	struct hash_elem *e;

	f.uaddr = page;
	e = hash_find(&frame_table, &f.helem);
	return e != NULL ? hash_entry (e, struct frame, hash_elem) : NULL;
}

struct frame*
frame_table_remove(void *uaddr)
{
	struct frame f;
	struct hash_elem *e;

	f.uaddr = uaddr;
	e = hash_delete(&frame_table, &f.helem);
	return e != NULL ? hash_entry (e, struct frame, hash_elem) : NULL;
}

void*
frame_get_page(struct hash* spt, enum palloc_flags) 
{
	void* page = palloc_get_page(flags);
	if (page == NULL)
	{
		//TODO ERROR HANDLING
	}

	supplementary_page_table_put(spt, page);
	frame_table_put(page);
	return page;
}

void
frame_free_page(struct hash* spt, void *page)
{
	ASSERT ((int)page % PAGE_SIZE == 0);
	palloc_free_page(page);
	struct page* p = supplementary_page_table_remove(spt, page);
	if (p != NULL) fre(p);
	struct frame* f = frame_table_remove(page);
	if (f != NULL) free(f); //free if not null
	return;
}