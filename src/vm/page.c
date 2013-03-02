#include "lib/round.h"
#include "page.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/process.h"

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
	lock_init(&thread_current()->spt_lock);
	return hash_init(spt, page_hash, page_less, NULL);
}

/*
 * Assumes that the user addresses are page alligned
*/
struct page*
supplementary_page_table_put(struct hash* spt, void *vaddr)
{
	ASSERT ((int)vaddr % PAGE_SIZE == 0);

	lock_acquire(&thread_current()->spt_lock);
	struct page* p = malloc(sizeof(struct page));	

	if (p == NULL) return NULL;

	p->pd = thread_current()->pagedir;
	p->process = process_current();

	p->vaddr = vaddr;
	p->mmentry = NULL;
	p->executable = false;
	p->executable_modified = false;
	p->evicted = false;
	p->writable = true;

	struct hash_elem* helem = hash_insert(spt, &(p->helem));

	lock_release(&thread_current()->spt_lock);

	if(helem == NULL) return p;
	else return hash_entry(helem, struct page, helem);
}

struct page*
supplementary_page_table_lookup(struct hash* spt, void* vaddr)
{
	lock_acquire(&thread_current()->spt_lock);
	void* page = (void*)ROUND_DOWN((uint64_t)vaddr, (uint64_t)PAGE_SIZE);
	struct page p;
	struct hash_elem *e;

	p.vaddr = page;
	e = hash_find(spt, &p.helem);

	struct page* lookup_page = e != NULL ? hash_entry (e, struct page, helem) : NULL;

	lock_release(&thread_current()->spt_lock);

	return lookup_page;
}

struct page*
supplementary_page_table_remove(struct hash* spt, void *vaddr)
{
	lock_acquire(&thread_current()->spt_lock);
	struct page p;
	struct hash_elem *e;

	p.vaddr = vaddr;
	e = hash_delete(spt, &p.helem);

	struct page* removed = e != NULL ? hash_entry (e, struct page, helem) : NULL;

	lock_release(&thread_current()->spt_lock);
	return removed;
}
