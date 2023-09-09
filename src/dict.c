#include <stdlib.h>

#include "node.h"
#include "linked_list.h"
#include "dict_entry.h"
#include "dict.h"

struct Dictionary *new_dictionary()
{
	struct Dictionary *new = malloc(sizeof(struct Dictionary));

	new->ll = new_linked_list();

	return new;
}

void new_element(struct Dictionary *dict, void *key, void *val)
{
	struct DictionaryEntry *new_elem = new_dictionary_entry(key, val);
	struct Node *new = new_node(new_elem);
	add_node(dict->ll, new);
}

void free_dictionary(struct Dictionary *dict)
{
	free_linked_list(dict->ll);
	free(dict);
}

