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
	// swap_table.base = malloc(bufSize);
	// PANIC("swap_slots:%d\n", swap_table.swap_num_slots);
	// PANIC("block_size:%u\n", (uint32_t)block_size(swap_block));
	swap_table.swap_map = bitmap_create(20000);
	// while (swap_table.swap_map == NULL)
	// {

	// }
	// bitmap_create_in_buf (swap_table.swap_num_slots, 
	// 	bitmap_needed_bytes(swap_table.swap_num_slots), bufSize);
}

void*
swap_get_frame(struct frame* evict)
{
	// printf("swap get frame\n");
	void* page;

	lock_acquire(&swap_table.lock);

	if(evict == NULL) 
		PANIC("swap_get_frame: no evictable frame");

	if(evict->supplementary_page->evicted) PANIC("DAFUQ\n");

	// evict->locked = true;
	// lock_release(&swap_table.lock);
	// printf("frame_get_evict\n");

	page = evict->paddr;

	if(!swap_out(evict)) 
		PANIC("swap_get_frame: failed to swap out");

	// lock_acquire(&swap_table.lock);
	evict->supplementary_page->evicted = true;
	// lock_release(&swap_table.lock);

	pagedir_clear_page(evict->supplementary_page->pd,evict->uaddr);
	struct frame* f = frame_table_remove(evict->paddr);
	if (f == NULL)
		{
			PANIC("DID NOT EXIST\n");
		}
	free(f);
	// printf("frame_table_remove\n");
	lock_release(&swap_table.lock);
	return page;
}

bool 
swap_out(struct frame* frame)
{
	//TODO: Handle other cases
	// printf("swap out:%p\n", frame->uaddr);
	return write_to_swap(frame);
}

bool
install_other_page (void *upage, void *kpage, bool writable, uint32_t *pd)
{
  return (pagedir_get_page (pd, upage) == NULL
          && pagedir_set_page (pd, upage, kpage, writable));
}

bool
write_to_swap(struct frame* frame)
{
	// lock_acquire(&swap_table.lock);
	// while (swap_table.swap_map == NULL) {}
	size_t swap_slot = bitmap_scan_and_flip(swap_table.swap_map,0,1,false);

	// printf("write swap:%d\n",swap_slot);
	// if(swap_slot == 133) printf("LOOK HERE:%p : %s\n",frame->uaddr,frame->uaddr);

	if(swap_slot == BITMAP_ERROR)
	{	
		// lock_release(&swap_table.lock);
		return false;
	}
	
	frame->supplementary_page->swap_slot = swap_slot;
	struct block* swap_block = block_get_role(BLOCK_SWAP);
	// if(swap_block != NULL) PANIC("FUCK\n");

	void* base = frame->uaddr;

	if(pagedir_get_page(frame->supplementary_page->pd,frame->uaddr) == NULL)
		{
			supplementary_page_load(frame->supplementary_page);
						printf("ABOUT TO WRITE\n");
		}
		
		printf("writing %p %d %d\n",frame->uaddr,frame->supplementary_page->pd,thread_current()->pagedir);
	int i;
	for(i = 0; i < PGSIZE/BLOCK_SECTOR_SIZE; i++)
	{
		void* data = (char*)base + BLOCK_SECTOR_SIZE*i;
		uint32_t sector = (swap_slot*PGSIZE/BLOCK_SECTOR_SIZE) + i;
		
		block_write(swap_block,sector,data);
	}

	printf("HERE\n");

	// lock_release(&swap_table.lock);

	return true;
}

void
read_from_swap(struct page* fault_page)
{
	get_lock();
	void* new_page = uframe_get_page(PAL_USER, fault_page->vaddr);
	// printf("new_page:%p %p\n", new_page,fault_page->vaddr);
	// PANIC("kpage:%p\n", fault_page->kpage);
	lock_acquire(&swap_table.lock);

    size_t swap_slot = fault_page->swap_slot;
    // printf("swap_read: %d\n",swap_slot);
    bitmap_flip(swap_table.swap_map, swap_slot);
    // lock_release(&swap_table.lock);

    // fault_page->evicted = true;

    install_page(fault_page->vaddr, new_page, fault_page->writable);
    struct frame* f = frame_table_lookup(fault_page->kpage);

    struct block* swap_block = block_get_role(BLOCK_SWAP);
    void* base = fault_page->vaddr;

    int i;
    for(i = 0; i < PGSIZE/BLOCK_SECTOR_SIZE; i++)
	{
		void* data = (char*)base + BLOCK_SECTOR_SIZE*i;
		uint32_t sector = (swap_slot*PGSIZE/BLOCK_SECTOR_SIZE) + i;
		
		block_read(swap_block,sector,data);
	}

	// printf("LOOK HERE 2: %p : %s\n",base,base);

    // lock_acquire(&swap_table.lock);
    fault_page->evicted = false;
    // f->locked = false;
    // if(swap_slot != 133)PANIC("kpage:%p %d\n", fault_page->kpage,printf("done\n"));
    lock_release(&swap_table.lock);
    release_lock();
}
