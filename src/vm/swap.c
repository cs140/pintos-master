#include <bitmap.h>
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "devices/block.h"
#include "threads/malloc.h"
#include "userprog/exception.h"
#include "userprog/pagedir.h"	
#include "userprog/process.h"
#include "vm/swap.h"
#include "vm/page.h"
#include "vm/mmap.h"

#define BITS_PER_BYTE 8
#define PGSIZE 4096

struct swap_pool swap_table;

void init_swap_pool(void);
static bool write_to_swap(struct frame* frame);

void
swap_init (void)
{
	init_swap_pool();	
}

void
init_swap_pool(void)
{
	lock_init(&swap_table.lock);	
	struct block* swap_block = block_get_role(BLOCK_SWAP);
	swap_table.swap_num_slots = block_size(swap_block) / (PGSIZE/BLOCK_SECTOR_SIZE);
	swap_table.swap_map = bitmap_create(20000);
}

void*
swap_get_frame(struct frame* evict)
{
	void* page;
	lock_acquire(&swap_table.lock);
	
	if(evict == NULL) 
		PANIC("swap_get_frame: no evictable frame");

	page = evict->paddr;

	bool dirty = pagedir_is_dirty(evict->supplementary_page->pd,evict->uaddr);
	pagedir_clear_page(evict->supplementary_page->pd,evict->uaddr);

	if(!swap_out(evict,dirty)) 
		PANIC("swap_get_frame: failed to swap out");

	lock_release(&swap_table.lock);
	return page;
}

bool 
swap_out(struct frame* frame, bool dirty)
{
	if (frame->supplementary_page->mmentry != NULL) 
	{
		return mmap_unmap_page(frame,dirty);
	} 
	else 
	{
		return write_to_swap(frame);
	}
}

bool
write_to_swap(struct frame* frame)
{
	size_t swap_slot = bitmap_scan_and_flip(swap_table.swap_map,0,1,false);
	if(swap_slot == BITMAP_ERROR)
	{	
		return false;
	}
	
	frame->supplementary_page->swap_slot = swap_slot;
	struct block* swap_block = block_get_role(BLOCK_SWAP);
	void* base = frame->paddr;

	int i;
	for(i = 0; i < PGSIZE/BLOCK_SECTOR_SIZE; i++)
	{
		void* data = (char*)base + BLOCK_SECTOR_SIZE*i;
		uint32_t sector = (swap_slot*PGSIZE/BLOCK_SECTOR_SIZE) + i;
		
		block_write(swap_block,sector,data);
	}

	return true;
}

struct frame*
read_from_swap(struct page* fault_page)
{
	struct frame* f;

	void* new_page = frame_get_locked_page(PAL_USER, fault_page->vaddr);
	lock_acquire(&swap_table.lock);

	size_t swap_slot = fault_page->swap_slot;
	bitmap_flip(swap_table.swap_map, swap_slot);

	install_page(fault_page->vaddr, new_page, fault_page->writable);
	fault_page->kpage = new_page;
	f = frame_table_lookup(new_page);

	struct block* swap_block = block_get_role(BLOCK_SWAP);
	void* base = fault_page->kpage;

	int i;
	for(i = 0; i < PGSIZE/BLOCK_SECTOR_SIZE; i++)
	{
		void* data = (char*)base + BLOCK_SECTOR_SIZE*i;
		uint32_t sector = (swap_slot*PGSIZE/BLOCK_SECTOR_SIZE) + i;
		
		block_read(swap_block,sector,data);
	}

	fault_page->evicted = false;
	lock_release(&swap_table.lock);

	return f;
}
