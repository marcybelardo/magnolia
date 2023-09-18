#ifndef DICT_ENTRY_H
#define DICT_ENTRY_H

struct DictionaryEntry {
	char *key;
	char *val;
	struct DictionaryEntry *next;
};

struct DictionaryEntry *new_dictionary_entry(char *key, char *val);
void free_dictionary_entry(struct DictionaryEntry *entry);

#endif
