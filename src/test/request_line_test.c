#include <stdio.h>

#include "../requests.h"
#include "../dict_entry.h"

int main()
{
	char line[BUF_SIZE] = "GET /index.html HTTP/1.1\r\n"
				"Content-Type: text/html\r\n"
				"Connection: keep-alive\r\n\r\n";

	struct Request *req = new_request(line);

	struct DictionaryEntry *req_ptr = req->request_line->head;
	struct DictionaryEntry *hdr_ptr = req->headers->head;

	while (req_ptr) {
		printf("%s\t %s\n", req_ptr->key, req_ptr->val);
		if (req_ptr->next) {
			req_ptr = req_ptr->next;
		} else {
			break;
		}
	}
	while (hdr_ptr) {
		printf("%s\t %s\n", hdr_ptr->key, hdr_ptr->val);
		if (hdr_ptr->next) {
			hdr_ptr = hdr_ptr->next;
		} else {
			break;
		}
	}

	return 0;
}

