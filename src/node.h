#ifndef NODE
#define NODE

struct Node {
	void *data;
	struct Node *next;
	struct Node *prev;
};

struct Node node_construct(void *data, int size);
void node_destruct(struct Node *node);

#endif
