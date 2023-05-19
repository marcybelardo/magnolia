#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "node.h"

struct Node node_construct(void *data, int size)
{
    if (size < 1) {
		printf("Invalid data size for node\n");
		exit(1);
	}

	struct Node node;

	node.data = malloc(size);
	memcpy(node.data, data, size);
	node.next = NULL;
	node.prev = NULL;

	return node;
}

void node_destruct(struct Node *node)
{
	free(node->data);
	free(node);
}
