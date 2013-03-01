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
	// evict->locked = true;
	
	if(evict == NULL) 
		PANIC("swap_get_frame: no evictable frame");

	if(evict->supplementary_page->evicted) PANIC("DAFUQ %p %p\n",evict->supplementary_page->vaddr, evict->supplementary_page->mmentry);

	// evict->locked = true;
	// lock_release(&swap_table.lock);
	// printf("frame_get_evict\n");

	page = evict->paddr;

	if(!swap_out(evict)) 
		PANIC("swap_get_frame: failed to swap out");

	// lock_acquire(&swap_table.lock);
	// printf("set true %p\n",evict->supplementary_page);
	if(evict->supplementary_page->mmentry == NULL) 
		evict->supplementary_page->evicted = true;
	// lock_release(&swap_table.lock);

	pagedir_clear_page(evict->supplementary_page->pd,evict->uaddr);
	struct frame* f = frame_table_remove(evict->paddr);
	if (f == NULL) PANIC("DID NOT EXIST\n");
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
	if (frame->supplementary_page->mmentry != NULL) 
	{
		//PANIC("haha");
		return mmap_unmap_page(frame);
	} else 
	{
		return write_to_swap(frame);
	}
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

	void* base = frame->paddr;

		// printf("writing %p %d %d\n",frame->uaddr,frame->supplementary_page->pd,thread_current()->pagedir);
	int i;
	for(i = 0; i < PGSIZE/BLOCK_SECTOR_SIZE; i++)
	{
		void* data = (char*)base + BLOCK_SECTOR_SIZE*i;
		uint32_t sector = (swap_slot*PGSIZE/BLOCK_SECTOR_SIZE) + i;
		
		block_write(swap_block,sector,data);
	}

	// printf("HERE\n");

	// lock_release(&swap_table.lock);

	return true;
}

struct frame*
read_from_swap(struct page* fault_page)
{
	// get_lock();
	//void* new_page = frame_get_locked_page(PAL_USER, fault_page->vaddr);
	// printf("new_page:%p %p\n", new_page,fault_page->vaddr);
	// PANIC("kpage:%p\n", fault_page->kpage);
	// install_page(fault_page->vaddr, new_page, fault_page->writable);
	// fault_page->kpage = new_page;

	struct frame* f;
	// if (fault_page->mmentry != NULL) 
	// {
	// 	// fault_page->kpage = frame_get_locked_page(PAL_USER, fault_page->vaddr);
	// 	void* new_page = frame_get_locked_page(PAL_USER, fault_page->vaddr);
	// 	if (new_page != NULL) printf("GET FUKCING NEW FRAME\n");
	// 	lock_acquire(&swap_table.lock);

	// 	struct mmap_entry* mpt_entry = fault_page->mmentry;
	// 	struct file* file = mpt_entry->backup_file;
 //  		struct file* fi = mpt_entry->backup_file;
 //  		int index = ((uint64_t)fault_page->vaddr - (uint64_t)mpt_entry->pages[0]->vaddr) / 4096;


	// 	printf ("read map file size = %d index =%d\n", file_length(file)/4096,index);
	// 	install_page(fault_page->vaddr,new_page,true);
 //  		// struct process* process = get_process(thread_current()->tid);
 //  		fault_page->kpage = new_page;
	// 	f = frame_table_lookup(new_page);

	// 	file_seek (file, fault_page->ofs);
	// 	int page_read_bytes = fault_page->page_read_bytes;

	// 	if(page_read_bytes > 0)
	// 	{
 //    		// printf("LAZY: %p %d\n",fault_page->kpage,file_tell(process->execFile));
 //    		// printf("S: %s\n",fault_page->kpage);
	// 		file_read_at(file,fault_page->kpage,page_read_bytes,index*4096);
	// 		printf ("ACTUALLY read map file size = %d index = %d\n", file_length(file)/4096, index);
	// 	}

	// 	memset(fault_page->kpage + page_read_bytes,0,PGSIZE - page_read_bytes);

	// 	f =  frame_table_lookup(fault_page->kpage);
	//  	// f = lazy_load_segment(fault_page, fault_page->mmentry->backup_file);
	// 	fault_page->evicted = false;
	// 	printf ("done read map size = %d index = %d\n", file_length(file)/4096, index);
	// 	lock_release(&swap_table.lock);
	// } else 
	// {
		void* new_page = frame_get_locked_page(PAL_USER, fault_page->vaddr);
		lock_acquire(&swap_table.lock);
		// 
		// fault_page->kpage = new_page;

		size_t swap_slot = fault_page->swap_slot;
	    // printf("swap_read: %d\n",swap_slot);
		bitmap_flip(swap_table.swap_map, swap_slot);
	    // lock_release(&swap_table.lock);

		install_page(fault_page->vaddr, new_page, fault_page->writable);
	    // fault_page->evicted = true;
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
	// }
		// printf("LOOK HERE 2: %p : %s\n",base,base);

	    // lock_acquire(&swap_table.lock);
	    // printf("set false %p\n",fault_page);
	    // f->locked = false;
	    // if(swap_slot != 133)PANIC("kpage:%p %d\n", fault_page->kpage,printf("done\n"));

	return f;
}
