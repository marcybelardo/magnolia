#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "magnolia.h"
#include "network.h"

int open_connection(struct connection *conn)
{
	// Create a socket
	conn->sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (conn->sockfd == -1) {
		perror("magnolia (socket)");
		return -1;
	}
	printf("Socket created successfully!\n");

	// Create client address
	conn->host_addr->sin_family = AF_INET;
	conn->host_addr->sin_port = htons(PORT);
	conn->host_addr->sin_addr.s_addr = htonl(INADDR_ANY);

	// Bind socket to address
	if (bind(conn->sockfd, (struct sockaddr *)conn->host_addr,
		 conn->host_addrlen) != 0) {
		perror("magnolia (bind)");
		return -1;
	}
	printf("Socket successfully bound to address!\n");

	// Listen for oncoming connections
	if (listen(conn->sockfd, SOMAXCONN) != 0) {
		perror("magnolia (listen)");
		return -1;
	}
	printf("Server listening for connections...\n");

	return 0;
}
