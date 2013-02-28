#ifndef MMAP_H
#define MMAP_H
#include <debug.h>
#include "lib/kernel/hash.h"
#include "threads/synch.h"
#include "threads/interrupt.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "vm/page.h"


struct mmap_entry {
	mapid_t mapid;
	struct page** pages;
	int size;	
	//struct file* file;
	struct file* backup_file;
	struct hash_elem helem;
};

unsigned mmap_page_hash (const struct hash_elem *p_, void *aux UNUSED);
bool mmap_page_less(const struct hash_elem *a, 
	const struct hash_elem *b, void *aux);
bool mmap_table_init(struct hash* mpt);
struct hash_elem* mmap_table_put(struct hash* mpt, mapid_t mapid, 
	int array_size);
struct mmap_entry* mmap_table_lookup(struct hash* mpt, mapid_t mapid);
struct mmap_entry* mmap_table_remove(struct hash* mpt, mapid_t mapid);

void mmap_cleanup(struct intr_frame* f);
void mmap_unmap(mapid_t mapid, struct intr_frame* f);

#endif 
