#ifndef PAGE_H
#define FRAME_H

struct page
{
	uint32_t *pd; //page directory
	void *vaddr; //virtual address
	struct mmap_entry* mmentry; //null if not mmapped
	struct swap_slot* sslot; //null if not in swap table 
	bool zeroed; //zero page	
	struct hash_elem hash_elem;
}