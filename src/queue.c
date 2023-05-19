#include "queue.h"
#include "linkedlist.h"

void push(struct Queue *queue, void *data, int size);
void *peek(struct Queue *queue);
void pop(struct Queue *queue);

struct Queue queue_construct()
{
	struct Queue queue;
	queue.list = ll_construct();

	queue.push = push;
	queue.peek = peek;
	queue.pop = pop;

	return queue;
}

void queue_destruct(struct Queue *queue) { ll_destruct(&queue->list); }

void push(struct Queue *queue, void *data, int size)
{
	queue->list.insert(&queue->list, queue->list.length, data, size);
}

void *peek(struct Queue *queue)
{
	return queue->list.get_data(&queue->list, 0);
}

void pop(struct Queue *queue) { queue->list.remove(&queue->list, 0); }
