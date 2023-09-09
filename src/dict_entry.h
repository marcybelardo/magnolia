#ifndef DICT_ENTRY_H
#define DICT_ENTRY_H

struct DictionaryEntry {
	void *key;
	void *val;
};

struct DictionaryEntry *new_dictionary_entry(void *key, void *val);
void free_dictionary_entry(struct DictionaryEntry *entry);

#endif
