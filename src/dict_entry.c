#include <stdlib.h>

#include "dict_entry.h"

struct DictionaryEntry *new_dictionary_entry(char *key, char *val)
{
	struct DictionaryEntry *new = malloc(sizeof(struct DictionaryEntry));

	new->key = key;
	new->val = val;
	new->next = NULL;

	return new;
}

void free_dictionary_entry(struct DictionaryEntry *entry_to_free)
{
	free(entry_to_free->key);
	free(entry_to_free->val);
	free(entry_to_free);
}

