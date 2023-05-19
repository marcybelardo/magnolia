#ifndef LINKEDLIST_h
#define LINKEDLIST_h

#include "node.h"

struct LinkedList {
	struct Node *head;
	int length;
	void (*insert)(struct LinkedList *ll, int idx, void *data, int size);
	void (*remove)(struct LinkedList *ll, int idx);
	void *(*get_data)(struct LinkedList *ll, int idx);
};

void insert_ll(struct LinkedList *ll, int idx, void *data, int size);
void remove_ll(struct LinkedList *ll, int idx);
void *get_data_ll(struct LinkedList *ll, int idx);

struct LinkedList ll_construct();
void ll_destruct(struct LinkedList *ll);

#endif
