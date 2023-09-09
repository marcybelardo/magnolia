#include <stdlib.h>

#include "dict_entry.h"
#include "linked_list.h"

struct DictionaryEntry *new_dictionary_entry(void *key, void *val)
{
	struct DictionaryEntry *new = malloc(sizeof(struct DictionaryEntry));
	new->key = key;
	new->val = val;

	return new;
}

void free_dictionary_entry(struct DictionaryEntry *entry)
{
	free(entry->key);
	free(entry->val);
	free(entry);
}

