#include <stdlib.h>

#include "node.h"

struct Node *new_node(void *data)
{
	struct Node *new = malloc(sizeof(struct Node));
	new->data = data;
	new->next = NULL;

	return new;
}

void free_node(struct Node *node)
{
	free(node->data);
	free(node->next);
	free(node);
}

