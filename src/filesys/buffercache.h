#ifndef BUFFERCACHE_H
#define BUFFERCACHE_H
#include "lib/kernel/hash.h"
#include "threads/synch.h"
#include "devices/block.h"
#include "filesys/filesys.h"

struct bcache_entry
{
	block_sector_t sector_num;
	void* data;
	bool dirty;
	bool locked;

	struct hash_elem helem;
};

struct bcache
{
	struct hash hash;

	struct lock lock;
	struct condition cond;
	int num_entries;
	int max_size;
};

struct bcache filesys_cache;

bool bcache_init(void);
struct bcache_entry* bcache_add(struct bcache* cache,
	block_sector_t sector_num);
struct bcache_entry* bcache_lookup(struct bcache* cache, 
	block_sector_t sector_num);
void bcache_write_entries(struct bcache* cache);
void bcache_read_ahead(struct block* block,block_sector_t sector);
void bcache_write(struct bcache_entry* entry, void* data);
void bcache_set_dirty(struct bcache_entry* entry, bool dirty);

#endif
