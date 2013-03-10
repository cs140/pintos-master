#include <debug.h>
#include "devices/timer.h"
#include "filesys/buffercache.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "lib/string.h"

#define BUFFERCACHE_MAX_SIZE 64

static unsigned bcache_hash (const struct hash_elem *b, void *aux UNUSED);
static bool bcache_less(const struct hash_elem *a, const struct hash_elem *b, 
    void *aux);
static struct bcache_entry* bcache_evict_entry(struct bcache* cache, 
    block_sector_t sector_num);
static struct bcache_entry* bcache_get_evict(struct bcache* cache);
static void bcache_write_behind(void* aux UNUSED);
static void bcache_read_sector(block_sector_t* sector);

static unsigned 
bcache_hash (const struct hash_elem *b, void *aux UNUSED)
{
    const struct bcache_entry *bc = hash_entry(b, struct bcache_entry, helem);
    return hash_bytes(&bc->sector_num, sizeof(block_sector_t));
}

static bool 
bcache_less(const struct hash_elem *a, const struct hash_elem *b, 
    void *aux UNUSED)
{
    struct bcache_entry *ba = hash_entry(a, struct bcache_entry, helem);
    struct bcache_entry *bb = hash_entry(b, struct bcache_entry, helem);
    return ba->sector_num < bb->sector_num;    
}

bool
bcache_init(void)
{
    //PANIC("INIT");
    filesys_cache.max_size = BUFFERCACHE_MAX_SIZE;
    filesys_cache.num_entries = 0;
    lock_init(&filesys_cache.lock);
    cond_init(&filesys_cache.cond);
    thread_create("write-behind", PRI_DEFAULT, bcache_write_behind, NULL);
    return hash_init(&filesys_cache.hash, bcache_hash, bcache_less, NULL);
}

static struct bcache_entry*
bcache_get_evict(struct bcache* cache)
{
    struct hash_iterator i;
    hash_first(&i, &cache->hash);
    while (hash_next(&i))
    {
        struct bcache_entry* entry = (struct bcache_entry*) hash_entry(
            hash_cur(&i), struct bcache_entry, helem);
        if(!entry->locked) return entry;
    }

    return NULL;
}

static struct bcache_entry*
bcache_evict_entry(struct bcache* cache, block_sector_t sector_num)
{
    struct bcache_entry* entry;
    if(cache->num_entries < cache->max_size)
    {
        entry = malloc(sizeof(struct bcache_entry));
        entry->data = malloc(BLOCK_SECTOR_SIZE);
        cache->num_entries++;
        if(entry == NULL) PANIC("NOT MY FAULT\n");
    }
    else
    {   
        struct bcache_entry* removeEntry = bcache_get_evict(cache);
        if(removeEntry->dirty) 
        { 
            lock_release(&filesys_cache.lock);
            block_filesys_write(removeEntry->sector_num, removeEntry->data);
            lock_acquire(&filesys_cache.lock);
        }    
        struct hash_elem* deleted_elem = hash_delete(&cache->hash, 
            &removeEntry->helem);
        entry = hash_entry(deleted_elem, struct bcache_entry, helem);
    }

    if(entry == NULL) 
    {
        PANIC("HERE\n");
        return NULL;
    }

    entry->sector_num = sector_num;
    entry->locked = true;
    entry->dirty = false;
    struct hash_elem* helem = hash_insert(&cache->hash, &entry->helem);

    if (helem != NULL)
    {
        // free(entry->data);
        // free(entry);
        // struct bcache_entry* entry = hash_entry (helem, struct bcache_entry, 
        //     helem);
        // while (entry->locked)
        //     cond_wait(&filesys_cache.cond, &filesys_cache.lock);
        PANIC("THIS\n");
        return NULL;
    }

    return entry;
}

struct bcache_entry*
bcache_add(struct bcache* cache, block_sector_t sector_num)
{
    // printf("adding:%d\n", sector_num);
    struct bcache_entry* entry = bcache_evict_entry(cache, 
        sector_num);

    if (entry == NULL)
    {
        return NULL;
    }

    //entry->data = malloc(BLOCK_SECTOR_SIZE);
    // memcpy(entry->data, data, BLOCK_SECTOR_SIZE);
    //if (sector_num == 3)
    //PANIC("Save in cache 2 %d %s",sector_num,data);
    return entry;
}

void
bcache_write(struct bcache_entry* entry, void* data)
{
    lock_acquire(&filesys_cache.lock);
    memcpy(entry->data,data,BLOCK_SECTOR_SIZE);
    entry->locked = false;
    cond_broadcast(&filesys_cache.cond, &filesys_cache.lock);
    lock_release(&filesys_cache.lock);
}

void
bcache_set_dirty(struct bcache_entry* entry, bool dirty)
{
    lock_acquire(&filesys_cache.lock);

    entry->dirty = dirty;

    lock_release(&filesys_cache.lock);
}

struct bcache_entry*
bcache_lookup(struct bcache* cache, block_sector_t sector_num)
{
    // lock_acquire(&cache->lock);
    struct bcache_entry be;
    struct hash_elem* e;

    be.sector_num = sector_num;
    e = hash_find(&cache->hash, &be.helem);

    struct bcache_entry* lookup_entry = 
        e != NULL ? hash_entry (e, struct bcache_entry, helem) : NULL;

    while (lookup_entry != NULL && lookup_entry->locked) 
        cond_wait(&filesys_cache.cond, &filesys_cache.lock);

    return lookup_entry;
    // lock_release(&cache->lock);
}

/*TODO CLEANUP*/
void 
bcache_write_entries(struct bcache* cache)
{
    lock_acquire(&filesys_cache.lock); //lock
    struct hash_iterator i;
    struct bcache_entry* entry;
    hash_first(&i, &cache->hash);
    while (hash_next(&i))
    {
        entry = (struct bcache_entry*) hash_entry(hash_cur(&i), 
            struct bcache_entry, helem);
        if (entry->dirty)
        {
            entry->locked = true; //set locked flag = true
            lock_release(&filesys_cache.lock); //unlock
            block_filesys_write(entry->sector_num, entry->data);
            lock_acquire(&filesys_cache.lock); //lock
            entry->locked = false; //set locked flag = false
            cond_broadcast(&filesys_cache.cond, &filesys_cache.lock); //signal
            entry->dirty = false;
        }
    }

    lock_release(&filesys_cache.lock); //unlock
}

void 
bcache_read_ahead(struct block* block,block_sector_t sector)
{
    lock_acquire(&filesys_cache.lock);
    struct bcache_entry* entry = bcache_lookup(&filesys_cache,sector);
    lock_release(&filesys_cache.lock);
    if(entry == NULL && sector < block_size(block))
    {
        block_sector_t* aux = malloc(sizeof(block_sector_t));
        *aux = sector;
        // PANIC("SecorR: %d",sector);
        thread_create("read-ahead", PRI_DEFAULT, 
            (thread_func*)bcache_read_sector, aux);
    }
}

static void
bcache_read_sector(block_sector_t* sector)
{
    lock_acquire(&filesys_cache.lock);
    struct bcache_entry* entry = bcache_lookup(&filesys_cache,*sector);
    if(entry != NULL) 
    {
        lock_release(&filesys_cache.lock);
        return;
    }

    entry = bcache_add(&filesys_cache, *sector);
    lock_release(&filesys_cache.lock);
    if(entry == NULL) PANIC("COULD NOT ADD TO BCACHE\n");

    // PANIC("Sector: %d",*sector);
    char buf[BLOCK_SECTOR_SIZE];
    block_filesys_read(*sector,buf);

    bcache_write(entry,buf);

    free(sector);
}

static void
bcache_write_behind(void* aux UNUSED)
{
    bcache_write_entries(&filesys_cache);
    timer_msleep(1000);
}
