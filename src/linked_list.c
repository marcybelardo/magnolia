#include <stdlib.h>

#include "linked_list.h"
#include "node.h"

struct LinkedList *new_linked_list()
{
	struct LinkedList *new = malloc(sizeof(struct LinkedList));
	struct Node *head = NULL;
	new->head = head;

	return new;
}

void add_node(struct LinkedList *list, struct Node *node)
{
	if (list->head->next == NULL) {
		list->head->next = node;
		return;
	}

	list->head = list->head->next;
	add_node(list, node);
}

void free_linked_list(struct LinkedList *list)
{
	if (list->head->next == NULL) {
		free_node(list->head);
		free(list);
		return;
	}

	list->head = list->head->next;
	free_linked_list(list);
}

