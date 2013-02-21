#include "page.h"
#include "threads/malloc.h"
#include "threads/palloc.h"

#define PAGE_SIZE 4096

unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED)
{
	const struct page *p = hash_entry(p_, struct page, helem);
	return hash_bytes (&p->vaddr, sizeof(p->vaddr));
}

bool 
page_less(const struct hash_elem *a, const struct hash_elem *b, 
	void *aux UNUSED)
{
	struct page *pa = hash_entry(a, struct page, helem);
	struct page *pb = hash_entry(b, struct page, helem);

	return pa->vaddr < pb->vaddr;
}

/*
 * Takes in an spt (supplemental page table)
 */
bool 
supplementary_page_table_init(struct hash* spt) 
{
	
	return hash_init(spt, page_hash, page_less, NULL);
}

/*
 * Assumes that the user addresses are page alligned
*/
struct hash_elem*
supplementary_page_table_put(struct hash* spt, void *vaddr)
{
	ASSERT ((int)vaddr % PAGE_SIZE == 0);
	struct page* p = malloc(sizeof(struct page));	
	p->vaddr = vaddr;

	return hash_insert(spt, &(p->helem));
}

struct page*
supplementary_page_table_lookup(struct hash* spt, void* vaddr)
{
	//allign user address to page boundaries
	void* page = (void*)(((int)vaddr/PAGE_SIZE) * PAGE_SIZE);
	struct page p;
	struct hash_elem *e;

	p.vaddr = page;
	e = hash_find(spt, &p.helem);
	return e != NULL ? hash_entry (e, struct page, helem) : NULL;
}

struct page*
supplementary_page_table_remove(struct hash* spt, void *vaddr)
{
	struct page p;
	struct hash_elem *e;

	p.vaddr = vaddr;
	e = hash_delete(spt, &p.helem);
	return e != NULL ? hash_entry (e, struct page, helem) : NULL;
}
