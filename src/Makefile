tests:
	gcc -Wall -Werror -o request_line_test -fsanitize=address test/request_line_test.c dict.c dict_entry.c requests.c
	gcc -Wall -Werror -o dict_test -fsanitize=address test/dict_test.c dict.c dict_entry.c

clean:
	rm magnolia request_line_test dict_test
