#ifndef FRAME_H
#define FRAME_H
#include "lib/kernel/hash.h"
#include "threads/palloc.h"
#include "threads/synch.h"

/* This struct contains meta data surrounding a physical page */
struct frame
{
	//needs to store reverse to a virtual page
	int locked; //field that says whether or not page can be evicted
	void *paddr; //physical page address
	void *uaddr; //user address in page directory
	struct page* supplementary_page;
	struct hash_elem helem;
};

struct lock frame_lock;
struct hash frame_table;

bool frame_table_init(void);
struct frame* frame_table_put(void *paddr, void *uaddr);
struct frame* frame_table_lookup(void* uaddr);
struct frame* frame_table_remove(void *uaddr);
void* frame_get_page(enum palloc_flags, void *uaddr);
void frame_free_page(void *page);
struct frame* frame_get_evict(void);
void frame_cleanup(void);


#endif /* vm.frame.h */
