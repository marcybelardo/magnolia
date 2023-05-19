#include <stdlib.h>

#include "linkedlist.h"

struct Node *create_node_ll(void *data, int size);
void destroy_node_ll(struct Node *destroy);

struct Node *iterate_ll(struct LinkedList *ll, int index);
void insert_ll(struct LinkedList *ll, int idx, void *data, int size);
void remove_ll(struct LinkedList *ll, int idx);
void *get_data_ll(struct LinkedList *ll, int idx);

struct LinkedList ll_construct()
{
	struct LinkedList list;
	list.head = NULL;
	list.length = 0;

	list.insert = insert_ll;
	list.remove = remove_ll;
	list.get_data = get_data_ll;

	return list;
}

void ll_destruct(struct LinkedList *ll)
{
	for (size_t i = 0; i < ll->length; i++) {
		ll->remove(ll, 0);
	}
}

struct Node *create_node_ll(void *data, int size)
{
	struct Node *node = (struct Node *)malloc(sizeof(struct Node));
	*node = node_construct(data, size);
	return node;
}

void destroy_node_ll(struct Node *destroy) { node_destruct(destroy); }

struct Node *iterate_ll(struct LinkedList *ll, int idx)
{
	if (idx < 0 || idx >= ll->length) {
		return NULL;
	}

	struct Node *cursor = ll->head;

	for (size_t i = 0; i < idx; i++) {
		cursor = cursor->next;
	}

	return cursor;
}

void insert_ll(struct LinkedList *ll, int idx, void *data, int size)
{
	struct Node *insert = create_node_ll(data, size);

	if (idx == 0) {
		insert->next = ll->head;
		ll->head = insert;
	} else {
		struct Node *cursor = iterate_ll(ll, idx - 1);
		insert->next = cursor->next;
		cursor->next = insert;
	}

	ll->length++;
}

void remove_ll(struct LinkedList *ll, int idx)
{
	if (idx == 0) {
		struct Node *remove = ll->head;

		if (remove) {
			ll->head = remove->next;
			destroy_node_ll(remove);
		}
	} else {
		struct Node *cursor = iterate_ll(ll, idx - 1);
		struct Node *remove = cursor->next;
		cursor->next = remove->next;
		destroy_node_ll(remove);
	}

	ll->length--;
}

void *get_data_ll(struct LinkedList *ll, int idx)
{
	struct Node *cursor = iterate_ll(ll, idx);
	if (cursor) {
		return cursor->data;
	} else {
		return NULL;
	}
}
