/*
 *
 *  magnolia
 *  a little http server
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/epoll.h>

#define MAX_EVENTS 16

void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == af_inet) {
		return &(((struct sockaddr_in *)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

int open_conn(char *port)
{
	int sockfd;
	struct addrinfo hints, *servinfo, *p;
	int yes = 1;
	int rv;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = af_unspec;
	hints.ai_socktype = sock_stream;
	hints.ai_flags = ai_passive;

	if ((rv = getaddrinfo(null, port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	for (p = servinfo; p != null; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			perror("[MAGNOLIA] socket");
			continue;
		}

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
			perror("[MAGNOLIA] setsockopt");
			exit(1);
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("[MAGNOLIA] bind");
			continue;
		}

		break;
	}

	freeaddrinfo(servinfo);

	if (p == NULL) {
		fprintf(stderr, "[MAGNOLIA] failed to bind\n");
		exit(1);
	}

	if (listen(sockfd, MAX_EVENTS) == -1) {
		perror("[MAGNOLIA] listen");
		exit(1);
	}

	return sockfd;
}

void setnonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	flags = flags | O_NONBLOCK;

	fcntl(fd, F_SETFL, flags);
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "USAGE: magnolia [PORT]\n");
		return 1;
	}

	char *PORT = argv[1];

	int listenfd, connfd, nfds, epollfd;
	struct epoll_event ev, events[MAX_EVENTS];
	struct sockaddr_storage conn_addr;
	socklen_t sin_size;
	char s[INET6_ADDRSTRLEN];

	listenfd = open_conn(PORT);
	setnonblocking(listenfd);
	printf("[MAGNOLIA] waiting for connections on port %s...\n", PORT);

	epollfd = epoll_create1(0);
	if (epollfd == -1) {
		perror("[MAGNOLIA] epoll_create1");
		exit(1);
	}

	ev.events = EPOLLIN | EPOLLET;
	ev.data.fd = listenfd;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, listenfd, &ev) == -1) {
		perror("[MAGNOLIA] epoll_ctl: listenfd");
		exit(1);
	}

	for (;;) {
		nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
		if (nfds == -1) {
			perror("[MAGNOLIA] epoll_wait");
			exit(1);
		}

		for (int n = 0; n < nfds; ++n) {
			if (events[n].data.fd == listenfd) {
				// accepting a new connection
				while (1) {
					sin_size = sizeof conn_addr;
					connfd = accept(listenfd, (struct sockaddr *)&conn_addr, &sin_size);
					if (connfd == -1) {
						perror("[MAGNOLIA] accept");
						continue;
					}
					setnonblocking(connfd);
					ev.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
					ev.data.fd = connfd;

					if (epoll_ctl(epollfd, EPOLL_CTL_ADD, connfd, &ev) == -1) {
						perror("[MAGNOLIA] epoll_ctl: connfd");
						continue;
					}
				}
			} else {
				// regular client processing
				char buf[1024];
			}
		}
	}

	return 0;
}
