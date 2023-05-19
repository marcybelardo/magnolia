#include <stdlib.h>
#include <string.h>

#include "dict_entry.h"

struct Entry entry_construct(void *key, int sizekey, void *value, int sizeval)
{
	struct Entry entry;
	entry.key = malloc(sizekey);
	entry.value = malloc(sizeval);
	memcpy(entry.key, key, sizekey);
	memcpy(entry.value, value, sizeval);

	return entry;
}

void entry_destruct(struct Entry *entry)
{
	free(entry->key);
	free(entry->value);
	free(entry);
}
