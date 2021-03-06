#ifndef SWAP_H
#define SWAP_H

#include "threads/synch.h"
#include "vm/frame.h"

struct swap_pool
{
	struct lock lock;
	size_t swap_num_slots;
	struct bitmap *swap_map; /* Bitmap of free swap slots */
};

void swap_init (void);
void* swap_get_frame(struct frame* evict);
bool swap_out(struct frame* frame,bool dirty);
struct frame* read_from_swap(struct page* fault_page);

#endif
