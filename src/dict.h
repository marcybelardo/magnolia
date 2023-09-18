#ifndef DICT_H
#define DICT_H

#include "dict_entry.h"

struct Dictionary {
	struct DictionaryEntry *head;
};

struct Dictionary *new_dictionary();
void add_entry_to_dict(struct Dictionary *dict, char *key, char *val);
char *search_dict(struct Dictionary *dict, char *key);
void free_dictionary(struct Dictionary *dict_to_free);

#endif
