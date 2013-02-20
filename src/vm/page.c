#include "page.h"
#include "threads/palloc.h"

unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED)
{
	const struct page *p = hash_entry(p_, struct page, hash_elem);
	return hash_bytes (&p->vaddr, sizeof(p->vaddr));
}

bool 
page_less(const struct hash_elem *a, const struct hash_elem *b, 
	void *aux)
{
	struct page *pa = hash_entry(a, struct page, helem);
	struct page *pb = hash_entry(b, struct page, helem);

	return pa->vaddr < pa->vaddr;
}

/*
 * Takes in an spt (supplemental page table)
 */
void 
supplementary_page_table_init(struct hash* spt) 
{
	hash_init(&spt, page_hash, page_less, NULL);
}

/*
 * Assumes that the user addresses are page alligned
*/
hash_elem*
supplementary_page_table_put(struct hash* spt, void *vaddr)
{
	ASSERT ((int)vaddr % PAGE_SIZE == 0);
	struct page* = malloc(sizeof(struct page));
	page->vaddr = vaddr;

	return hash_insert(&spt, page->helem);
}

struct page*
supplementary_page_table_lookup(struct hash* spt, void* vaddr)
{
	//allign user address to page boundaries
	void* page = (void*)((int)vaddr/PAGE_SIZE) * PAGE_SIZE;
	struct page p;
	struct hash_elem *e;

	p.vaddr = page;
	e = hash_find(&spt, &f.helem);
	return e != NULL ? hash_entry (e, struct page, hash_elem) : NULL;
}

struct page*
supplementary_page_table_remove(struct hash* spt, void *vaddr)
{
	struct page p;
	struct hash_elem *e;

	p.vaddr = vaddr;
	e = hash_delete(, &p.helem);
	return e != NULL ? hash_entry (e, struct page, hash_elem) : NULL;
}
