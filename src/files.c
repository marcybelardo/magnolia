#include <stdio.h>
#include <string.h>

#include "magnolia.h"

int read_html(char *filename, char *str)
{
	if (strcmp(filename, "../public/") == 0) {
		strcat(filename, "index.html");
	}

	FILE *fp = fopen(filename, "r");

	if (fp != NULL) {
		size_t new_len = fread(str, sizeof(char), BUFFER_SIZE, fp);
		if (ferror(fp) != 0) {
			fprintf(stderr, "Error reading file.\n");
		} else {
			str[new_len++] = '\0';
			fclose(fp);
		}
	} else {
		fclose(fp);
		return -1;
	}

	return 0;
}
