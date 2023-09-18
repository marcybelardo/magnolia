#include <stdio.h>
#include <stdlib.h>

#include "../dict_entry.h"
#include "../dict.h"

struct TestData {
	char *key;
	char *val;
};

int main()
{
	struct TestData test_arr[100];
	struct Dictionary *test = new_dictionary();

	for (size_t i = 0; i < 100; i++) {
		test_arr[i].key = malloc(sizeof(char) * 8);
		test_arr[i].val = malloc(sizeof(char) * 8);

		snprintf(test_arr[i].key, sizeof(char) * 8, "KEY %zu", i);
		snprintf(test_arr[i].val, sizeof(char) * 8, "VAL %zu", i);
	}
	for (size_t i = 0; i < 100; i++) {
		add_entry_to_dict(test, test_arr[i].key, test_arr[i].val);
	}

	struct DictionaryEntry *current = test->head;
	size_t i = 0;

	while (current) {
		printf("Entry %zu\n", i);
		printf("%s\n", current->key);
		printf("%s\n\n", current->val);

		current = current->next;
		i++;
	}

	char *val = search_dict(test, "KEY 71");

	printf("KEY : KEY 71, VAL : %s\n", val);
	
	return 0;
}
