#ifndef QUEUE_h
#define QUEUE_h

#include "linkedlist.h"

struct Queue {
	struct LinkedList list;

	void (*push)(struct Queue *queue, void *data, int size);
	void *(*peek)(struct Queue *queue);
	void (*pop)(struct Queue *queue);
};

struct Queue queue_construct();
void queue_destruct(struct Queue *queue);

#endif
