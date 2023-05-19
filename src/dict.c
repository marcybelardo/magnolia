#include <stdlib.h>
#include <string.h>

#include "bst.h"
#include "dict.h"
#include "dict_entry.h"

void insert_dict(struct Dictionary *dict, void *key, int sizekey, void *value,
		 int sizeval);
void *search_dict(struct Dictionary *dict, void *key);

struct Dictionary dict_construct(int (*compare)(void *key1, void *key2))
{
	struct Dictionary dict;
	dict.tree = bst_construct(compare);
	dict.insert = insert_dict;
	dict.search = search_dict;

	return dict;
}

void *search_dict(struct Dictionary *dict, void *key)
{
	void *res = dict->tree.search(&dict->tree, key);

	if (res) {
		return ((struct Entry *)res)->value;
	} else {
		return NULL;
	}
}

void insert_dict(struct Dictionary *dict, void *key, int sizekey, void *value,
		 int sizeval)
{
	struct Entry entry = entry_construct(key, sizekey, value, sizeval);
	dict->tree.insert(&dict->tree, &entry, sizeof(entry));
}

int compare_string_keys(void *entry1, void *entry2)
{
	if (strcmp((char *)(((struct Entry *)entry1)->key),
		   (char *)(((struct Entry *)entry2)->key)) > 0) {
		return 1;
	} else if (strcmp((char *)(((struct Entry *)entry1)->key),
			  (char *)(((struct Entry *)entry2)->key)) < 0) {
		return -1;
	} else {
		return 0;
	}
}
