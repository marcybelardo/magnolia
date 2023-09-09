#ifndef NODE_H
#define NODE_H

struct Node {
	void *data;
	struct Node *next;
};

struct Node *new_node(void *data);
void free_node(struct Node *node);

#endif
