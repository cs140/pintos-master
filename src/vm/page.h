#ifndef PAGE_H
#define FRAME_H
#include <debug.h>
#include "lib/kernel/hash.h"


struct page
{
	uint32_t *pd; //page directory
	void *vaddr; //virtual address
	struct mmap_entry* mmentry; //null if not mmapped
	struct swap_slot* sslot; //null if not in swap table 
	bool zeroed; //zero page	
	struct hash_elem helem;
};

unsigned page_hash (const struct hash_elem *p_, void *aux UNUSED);
bool page_less(const struct hash_elem *a, 
	const struct hash_elem *b, void *aux);
bool supplementary_page_table_init(struct hash* spt);
struct hash_elem* supplementary_page_table_put(struct hash* spt, void *vaddr);
struct page* supplementary_page_table_lookup(struct hash* spt, void* vaddr);
struct page* supplementary_page_table_remove(struct hash* spt, void *vaddr);

#endif /* vm.page.h */
