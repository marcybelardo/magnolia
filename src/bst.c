/*
 *	Implementation for binary search tree
 */

#include <stdlib.h>

#include "bst.h"
#include "node.h"

struct Node *create_node_bst(void *data, int size);
void destroy_node_bst(struct Node *node);

void *search_bst(struct BinarySearchTree *tree, void *data);
void insert_bst(struct BinarySearchTree *tree, void *data, int size);

struct BinarySearchTree bst_construct(int (*compare)(void *data1, void *data2))
{
	struct BinarySearchTree tree;
	tree.compare = compare;
	tree.search = search_bst;
	tree.insert = insert_bst;
	return tree;
}

struct Node *create_node_bst(void *data, int size)
{
	struct Node *new = (struct Node *)malloc(sizeof(struct Node));
	*new = node_construct(data, size);
	return new;
}

void destroy_node_bst(struct Node *destroy) { node_destruct(destroy); }

struct Node *iterate_bst(struct BinarySearchTree *tree, struct Node *cursor,
			 void *data, int *direction)
{
	if (tree->compare(cursor->data, data) == 1) {
		if (cursor->next) {
			return iterate_bst(tree, cursor->next, data, direction);
		} else {
			*direction = 1;
			return cursor;
		}
	} else if (tree->compare(cursor->data, data) == -1) {
		if (cursor->prev) {
			return iterate_bst(tree, cursor->prev, data, direction);
		} else {
			*direction = -1;
			return cursor;
		}
	} else {
		*direction = 0;
		return cursor;
	}
}

void *search_bst(struct BinarySearchTree *tree, void *data)
{
	int *direction = NULL;
	struct Node *cursor = iterate_bst(tree, tree->head, data, direction);

	if (*direction == 0) {
		return cursor->data;
	} else {
		return NULL;
	}
}

void insert_bst(struct BinarySearchTree *tree, void *data, int size)
{
	if (!tree->head) {
		tree->head = create_node_bst(data, size);
	}

	int *direction = NULL;
	struct Node *cursor = iterate_bst(tree, tree->head, data, direction);

	if (*direction == 1) {
		cursor->next = create_node_bst(data, size);
	} else if (*direction == -1) {
		cursor->prev = create_node_bst(data, size);
	}
}
