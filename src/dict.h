#ifndef DICT_H
#define DICT_H

#include "linked_list.h"
#include "dict_entry.h"

struct Dictionary {
	struct LinkedList *ll;
};

struct Dictionary *new_dictionary();
void free_dictionary(struct Dictionary *dict);

#endif
