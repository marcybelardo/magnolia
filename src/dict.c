#include <stdlib.h>
#include <string.h>

#include "dict_entry.h"
#include "dict.h"

struct Dictionary *new_dictionary()
{
	struct Dictionary *new = malloc(sizeof(struct Dictionary));
	new->head = NULL;

	return new;
}

void add_entry_to_dict(struct Dictionary *dict, char *key, char *val)
{
	struct DictionaryEntry *new = new_dictionary_entry(key, val);
	struct DictionaryEntry *ptr;

	if (key == NULL || val == NULL) {
		return;
	}

	if (!dict->head) {
		dict->head = new;
	} else {
		ptr = dict->head;

		while (ptr->next) {
			ptr = ptr->next;
		}

		ptr->next = new;
	}

	return;
}

char *search_dict(struct Dictionary *dict, char *key)
{
	struct DictionaryEntry *ptr;

	if (dict->head) {
		ptr = dict->head;

		while (ptr->next) {
			if (strcmp(ptr->key, key) == 0) {
				return ptr->val;
			}

			ptr = ptr->next;
		}
	}

	return NULL;
}

void free_dictionary(struct Dictionary *dict_to_free)
{
	if (dict_to_free->head->next == NULL) {
		free_dictionary_entry(dict_to_free->head);
		return;
	}

	dict_to_free->head = dict_to_free->head->next;

	return free_dictionary(dict_to_free);
}

