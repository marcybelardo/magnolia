#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "magnolia.h"
#include "files.h"

int main(void)
{	
	char buffer[BUFFER_SIZE];

	// Create socket
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		perror("webserver (socket)");
		return 1;
	}
	printf("Socket created successfully!\n");

	// Create address to bind the socket to
	struct sockaddr_in host_addr;
	int host_addrlen = sizeof(host_addr);

	host_addr.sin_family = AF_INET;
	host_addr.sin_port = htons(PORT);
	host_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	// Create client address
	struct sockaddr_in client_addr;
	int client_addrlen = sizeof(client_addr);

	// Bind socket to address
	if (bind(sockfd, (struct sockaddr *)&host_addr, host_addrlen) != 0) {
		perror("webserver (bind)");
		return 1;
	}
	printf("Socket successfully bound to address!\n");

	// Listen for incoming connections
	if (listen(sockfd, SOMAXCONN) != 0) {
		perror("webserver (listen)");
		return 1;
	}
	printf("Server listening for connections...\n");

	for (;;) {
		// Accept incoming connections
		int newsockfd = accept(sockfd, (struct sockaddr *)&host_addr, 
					(socklen_t *)&host_addrlen);

		if (newsockfd < 0) {
			perror("webserver (accept)");
			continue; 
		}
		printf("Connection accepted!\n");

		// Get client address
		int sockn = getsockname(newsockfd, (struct sockaddr *)&client_addr, 
				(socklen_t *)&client_addrlen);
		if (sockn < 0) {
			perror("webserver (getsockname)");
			continue;
		}

		// Read from the socket
		int valread = read(newsockfd, buffer, BUFFER_SIZE);
		if (valread < 0) {
			perror("webserver (read)");
			continue;
		}

		char method[BUFFER_SIZE], uri[BUFFER_SIZE], version[BUFFER_SIZE];
		sscanf(buffer, "%s %s %s", method, uri, version);
		printf("[%s:%u] %s %s %s\n", inet_ntoa(client_addr.sin_addr), 
			ntohs(client_addr.sin_port), method, uri, version);

		char *fname = "index.html";
		char *out = malloc(sizeof(char) * BUFFER_SIZE);

		read_html(fname, out);
		printf("OUT: %s\n", out);

		char full_resp[BUFFER_SIZE] = "HTTP/1.1 200 OK\r\nServer: magnolia\r\nContent-Type: text/html\r\n\r\n";
		strcat(full_resp, out);
		printf("resp: %s\n", full_resp);

		int valwrite = write(newsockfd, full_resp, BUFFER_SIZE);
		if (valwrite < 0) {
			perror("webserver (write)");
			continue;
		}

		free(out);
		close(newsockfd);
	}

	return 0;
}
