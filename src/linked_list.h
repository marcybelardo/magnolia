#ifndef LINKED_LIST_H
#define LINKED_LIST_H

struct LinkedList {
	struct Node *head;
};

struct LinkedList *new_linked_list();
void add_node(struct LinkedList *list, struct Node *node);
void free_linked_list(struct LinkedList *list);

#endif
