#ifndef BST_h
#define BST_h

#include "node.h"

struct BinarySearchTree {
	struct Node *head;
	int (*compare)(void *data1, void *data2);
	void *(*search)(struct BinarySearchTree *tree, void *data);
	void (*insert)(struct BinarySearchTree *tree, void *data, int size);
};

struct BinarySearchTree bst_construct(int (*compare)(void *data1, void *data2));

#endif
