#ifndef DICT_h
#define DICT_h

#include "bst.h"
#include "dict_entry.h"

struct Dictionary {
	struct BinarySearchTree tree;
	void (*insert)(struct Dictionary *dict, void *key, int sizekey,
		       void *value, int sizeval);
	void *(*search)(struct Dictionary *dict, void *key);
};

struct Dictionary dict_construct(int (*compare)(void *key1, void *key2));
void dict_destruct(struct Dictionary *dict);

int compare_string_keys(void *entry1, void *entry2);

#endif
