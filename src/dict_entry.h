#ifndef DICT_ENTRY_h
#define DICT_ENTRY_h

struct Entry {
	void *key;
	void *value;
};

struct Entry entry_construct(void *key, int sizekey, void *value, int sizeval);
void entry_destruct(struct Entry *entry);

#endif
