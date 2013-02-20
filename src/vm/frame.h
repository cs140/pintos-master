#ifndef FRAME_H
#define FRAME_H


#include "lib/kernel/hash.h"

/* This struct contains meta data surrounding a physical page */
struct frame
{
	//needs to store reverse to a virtual page
	int locked; //field that says whether or not page can be evicted
	void *uaddr; //user address in page directory
	struct hash_elem hash_elem;
};

struct hash frame_table;