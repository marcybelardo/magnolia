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

typedef struct {
    const char *ext;
    const char *type;
} mime_map;

mime_map MIME_TYPES [] = {
    {".css", "text/css"},
    {".gif", "image/gif"},
    {".htm", "text/html"},
    {".html", "text/html"},
    {".jpeg", "image/jpeg"},
    {".jpg", "image/jpeg"},
    {".ico", "image/x-icon"},
    {".js", "application/javascript"},
    {".pdf", "application/pdf"},
    {".mp4", "video/mp4"},
    {".png", "image/png"},
    {".svg", "image/svg+xml"},
    {".xml", "text/xml"},
    {NULL, NULL},
};

char *DEFAULT_MIME_TYPE = "text/plain";

struct m_http_req {
    char *method;
    char *uri;
};

struct m_http_resp {
    int code;
    char *msg;
    char *headers;
    char *body;
};

void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
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
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if ((rv = getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	for (p = servinfo; p != NULL; p = p->ai_next) {
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

void m_resp_to_buf(char *buf, struct m_http_resp *resp)
{
    sprintf(
            buf,
            "HTTP/1.1 %d %s\r\n"
            "%s\r\n"
            "%s", 
            resp->code, 
            resp->msg,
            resp->headers,
            resp->body
    );

    return; 
}

void send_resp(int connfd, struct m_http_resp *resp)
{
    char resp_buf[262144]; // max response size

    m_resp_to_buf(resp_buf, resp);

    if (send(connfd, resp_buf, strlen(resp_buf), 0) < 0) {
        perror("[MAGNOLIA] send");
    }

    return;
}

struct m_http_req *new_req()
{
    struct m_http_req *req = malloc(sizeof(struct m_http_req));
    req->method = malloc(sizeof(char) * 8);
    req->uri = malloc(sizeof(char) * 512);

    return req;
}

void m_req_parse(struct m_http_req *req, char* buf)
{
    char *p = buf;
    
    for (p = buf; *p != ' '; p++);
    *p = '\0';
    p++;
    req->method = buf; 
    buf = p;

    printf("%s\n", req->method);

    for (; *p != ' '; p++);
    *p = '\0';
    p++;
    req->uri = buf;
    buf = p;

    printf("%s\n", req->uri);

    return;
}

struct m_http_resp *new_resp(int code, char *msg)
{
    struct m_http_resp *resp = malloc(sizeof(struct m_http_resp));
    resp->msg = malloc(sizeof(char) * 64);
    resp->headers = malloc(sizeof(char) * 512);
    resp->body = malloc(sizeof(char) * 2048);

    resp->code = code;
    resp->msg = msg;

    return resp;
}

void m_resp_set_header(struct m_http_resp *resp, char *header)
{
    char *p1 = resp->headers;
    char *p2 = header;

    for (; *p1 != '\0'; p1++);
    for (; *p2 != '\0'; p1++, p2++) {
        *p1 = *p2;    
    }

    *p1 = '\r'; 
    *(p1 + 1) = '\n';
}

static const char *get_mime_type(char *filename)
{
    char *p = filename;
    for (; *p != '.'; p++);

    p++;
    mime_map *map = MIME_TYPES;
    while (map->ext) {
        if (strcmp(map->ext, p) == 0) {
            return map->type;
        }
        map++;
    }

    return DEFAULT_MIME_TYPE;
}

void handle_http_req(int connfd)
{
    char req_buf[65536]; // 64K
    
    if (recv(connfd, req_buf, 65536 - 1, 0) < 0) {
        perror("[MAGNOLIA] recv");
        return;
    }

    struct m_http_req *req = new_req();

    m_req_parse(req, req_buf);

    if (strcmp(req->method, "GET") != 0) {
        return; 
    }

    struct m_http_resp *resp = new_resp(200, "OK");
    m_resp_set_header(resp, "Content-Type: text/plain");
    m_resp_set_header(resp, "Content-Length: 13"); 
    resp->body = "Hello, world!";

    send_resp(connfd, resp);

    return;
}

void m_setnonblocking(int fd)
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
	m_setnonblocking(listenfd);
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
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            break;
                        } else {
                            perror("[MAGNOLIA] accept");
                            continue;
                        }
					}

                    inet_ntop(conn_addr.ss_family,
                            get_in_addr((struct sockaddr *)&conn_addr),
                            s, sizeof s);
                    printf("[MAGNOLIA] got connection from %s\n", s);

					m_setnonblocking(connfd);
					ev.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
					ev.data.fd = connfd;

					if (epoll_ctl(epollfd, EPOLL_CTL_ADD, connfd, &ev) == -1) {
						perror("[MAGNOLIA] epoll_ctl: connfd");
						continue;
					}
				}
			} else {
                handle_http_req(events[n].data.fd);
			}
		}
	}

	return 0;
}
