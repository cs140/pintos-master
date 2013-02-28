#ifndef PAGE_H
#define PAGE_H
#include <debug.h>
#include "lib/kernel/hash.h"
#include "lib/user/syscall.h"
#include "filesys/filesys.h"
// #include "filesys/file.c"

struct page
{
	uint32_t *pd; //page directory
	struct process* process;
	void *vaddr; //virtual address
	mapid_t mapid; //map id
	struct mmap_entry* mmentry; //null if not mmapped
	struct swap_slot* sslot; //null if not in swap table 
	bool executable; 
	bool evicted;
	size_t swap_slot;
	int page_read_bytes; //zero page if read_bytes==0
	uint8_t* kpage;	
	off_t ofs;
	bool writable;
	struct hash_elem helem;
};

unsigned page_hash (const struct hash_elem *p_, void *aux UNUSED);
bool page_less(const struct hash_elem *a, 
	const struct hash_elem *b, void *aux);
bool supplementary_page_table_init(struct hash* spt);
struct page* supplementary_page_table_put(struct hash* spt, void *vaddr);
struct page* supplementary_page_table_lookup(struct hash* spt, void* vaddr);
struct page* supplementary_page_table_remove(struct hash* spt, void *vaddr);



#endif /* vm.page.h */
