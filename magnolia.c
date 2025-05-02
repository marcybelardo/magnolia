/*
 *
 *  magnolia
 *  a little http server
 *
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/stat.h>

static const char PKG_NAME[] = "magnolia v 0.0.1";

#define MAX_EVENTS 16

static int SOCKFD = -1;
static char *PORT = "8888";
static char *ROOT_DIR = NULL;
static const char *INDEX_NAME = "index.html";

struct m_conn {
    int socket;
    enum {
        RECV_REQ,
        SEND_HEAD,
        SEND_RESP,
        DONE
    } state;
    char *req;
    size_t req_len;
    char *method, *uri;
    char *header;
    size_t header_len;
    char *resp;
    size_t resp_len;
};

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

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

void m_init_socket()
{
    struct addrinfo hints, *servinfo, *p;
    int yes = 1;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        exit(EXIT_FAILURE);
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((SOCKFD = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("[MAGNOLIA] socket");
            continue;
        }

        if (setsockopt(SOCKFD, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            perror("[MAGNOLIA] setsockopt");
            exit(EXIT_FAILURE);
        }

        if (bind(SOCKFD, p->ai_addr, p->ai_addrlen) == -1) {
            close(SOCKFD);
            perror("[MAGNOLIA] bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo);

    if (p == NULL) {
        fprintf(stderr, "[MAGNOLIA] failed to bind\n");
        exit(EXIT_FAILURE);
    }

    if (listen(SOCKFD, MAX_EVENTS) == -1) {
        perror("[MAGNOLIA] listen");
        exit(EXIT_FAILURE);
    }

    return;
}

static const char *get_mime_type(char *filename)
{
    char *p = strrchr(filename, '.');

    if (p) {
        mime_map *map = MIME_TYPES;
        while (map->ext) {
            if (strcmp(map->ext, p) == 0) {
                return map->type;
            }
            map++;
        }
    }

    return DEFAULT_MIME_TYPE;
}

void m_setnonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    flags = flags | O_NONBLOCK;

    fcntl(fd, F_SETFL, flags);
}

void m_add_pfd(struct pollfd *pfds[], int newfd, int *fd_count, int *fd_size)
{
    if (*fd_count == *fd_size) {
        *fd_size *= 2;
        *pfds = realloc(*pfds, sizeof(**pfds) * (*fd_size));
    }

    (*pfds)[*fd_count].fd = newfd;
    (*pfds)[*fd_count].events = POLLIN;
    (*pfds)[*fd_count].revents = 0;
    (*fd_count)++;
}

void m_del_pfd(struct pollfd pfds[], int i, int *fd_count)
{
    pfds[i] = pfds[*fd_count - 1];
    (*fd_count)--;
}

void m_add_conn(struct m_conn *conns[], int newfd, int i)
{
    (*conns)[i].socket = newfd;
    (*conns)[i].req = NULL;
    (*conns)[i].req_len = 0;
    (*conns)[i].method = NULL;
    (*conns)[i].uri = NULL;
    (*conns)[i].header = NULL;
    (*conns)[i].header_len = 0;
    (*conns)[i].resp = NULL;
    (*conns)[i].resp_len = 0;
    (*conns)[i].state = RECV_REQ;
}

void m_free_conn(struct m_conn *conn)
{
    free(conn->req);
    free(conn->method);
    free(conn->uri);
    free(conn->header);
    free(conn->resp);
}

void m_del_conn(struct m_conn conns[], int i, int *fd_count)
{
    conns[i] = conns[*fd_count - 1];
}

void m_reply(struct m_conn *conn, int code, const char *msg)
{
    conn->resp_len = snprintf(conn->resp, 256,
            "<!DOCTYPE html><head><title>%d %s</title></head><body>\n"
            "<h1>%d %s</h1>\n"
            "<hr>\n"
            "</body></html>\n",
            code, msg, code, msg); 

    conn->header_len = snprintf(conn->header, 256,
            "HTTP/1.1 %d %s\r\n"
            "Server: magnolia\r\n"
            "Content-Length: %d\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            "\r\n",
            code, msg, conn->resp_len);
}

void m_get(struct m_conn *conn) {}

void m_parse_req(struct m_conn *conn)
{
    char *p;

    assert(conn->req_len == strlen(conn->req));

    // method
    for (p = conn->req; *p != ' '; p++);
    *p++ = '\0';
    conn->method = conn->req;
    conn->req = p;

    // uri
    for (; *p != ' '; p++);
    *p++ = '\0';
    conn->uri = conn->req;
    conn->req = p;

    // get pointer to headers
    for (; (*p != ' ') &&
            (*(p + 1) != '\r') &&
            (*(p + 2) != '\n');
            p++);
    p += 3;
    conn->req = p;

    return;
}

void m_process_req(struct m_conn *conn)
{
    m_parse_req(conn);

    if (strcmp(conn->method, "GET") == 0) {
        m_get(conn);
    } else {
        m_reply(conn, 501, "Not Implemented");
    }

    conn->state = SEND_HEAD;
    free(conn->req);
    conn->req = NULL;
}

void m_recv_req(struct m_conn *conn)
{
    char buf[1024];
    size_t recvd;

    assert(conn->state == RECV_REQ);
    recvd = recv(conn->socket, buf, sizeof buf, 0);
    if (recvd < 1) {
        if (recvd == -1) {
            if (errno == EAGAIN) {
                printf("[INFO] m_recv_req would have blocked\n");
                return;
            }
            fprintf(stderr, "[ERROR] revc %d: %s\n",
                    conn->socket, strerror(errno));
        }
        conn->state = DONE;
        return;
    }

    assert(recvd > 0);
    conn->req = realloc(conn->req, conn->req_len + recvd + 1);
    memcpy(conn->req + conn->req_len, buf, recvd);
    conn->req_len += recvd;
    conn->req[conn->req_len] = '\0';

    process_req(conn);
}

void m_send_head(struct m_conn *conn)
{

}

void m_send_resp(struct m_conn *conn)
{}

void m_http_process()
{
    int newfd;
    struct sockaddr_storage client_addr;
    socklen_t addrlen;
    char clientIP[INET6_ADDRSTRLEN];

    int fd_count = 0;
    int fd_size = 5;
    struct pollfd *pfds = malloc(sizeof *pfds * fd_size);

    pfds[0].fd = SOCKFD;
    pfds[0].revents = POLLIN;
    fd_count = 1;
    
    struct m_conn *conns = malloc(sizeof *conns * fd_size);

    for (;;) {
        int poll_count = poll(pfds, fd_count, -1);
        if (poll_count == -1) {
            perror("[MAGNOLIA] poll");
            exit(EXIT_FAILURE);
        }

        for (int i = 0; i < fd_count; i++) {
            if (pfds[i].revents & (POLLIN | POLLHUP)) {
                if (pfds[i].fd == SOCKFD) {
                    // handle new conn
                    addrlen = sizeof client_addr;
                    newfd = accept(SOCKFD, (struct sockaddr *)&client_addr, &addrlen);
                    if (newfd == -1) {
                        perror("[MAGNOLIA] accept");
                    } else {
                        m_add_pfd(&pfds, newfd, &fd_count, &fd_size);
                        m_add_conn(&conns, newfd, i);
                        printf("[MAGNOLIA] new connection from %s on "
                                "socket %d\n",
                                inet_ntop(client_addr.ss_family,
                                    get_in_addr((struct sockaddr *)&client_addr),
                                    clientIP, INET6_ADDRSTRLEN),
                                newfd);
                    }
                } else {
                    switch (conns[i].state) {
                    case RECV_REQ:
                        m_recv_req(&conns[i]);
                        break;
                    case SEND_HEAD:
                        m_send_head(&conns[i]);
                        break;
                    case SEND_RESP:
                        m_send_resp(&conns[i]);
                        break;
                    case DONE:
                        break;
                    }

                    if (conns[i].state == DONE) {
                        m_del_pfd(pfds, i, &fd_count);
                        m_del_conn(conns, i, &fd_count);
                        m_free_conn(&conns[i]);
                    }
                }
            }
        }
    }
}

void parse_commands(const int argc, char *argv[])
{
    int i;
    size_t len;

    if ((argc < 2) || (argc == 2 && strcmp(argv[1], "--help") == 0)) {
        printf("USAGE:\t%s /path/to/root [flags]\n\n", argv[0]);
        exit(EXIT_SUCCESS);
    }

    ROOT_DIR = strdup(argv[1]);
    len = strlen(ROOT_DIR);
    if (len == 0) {
        fprintf(stderr, "Root directory cannot be empty\n");
        exit(EXIT_FAILURE);
    }
    if (len > 1) {
        if (ROOT_DIR[len - 1] == '/')
            ROOT_DIR[len - 1] = '\0';
    }

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "Please supply a port number\n");
                exit(EXIT_FAILURE);
            }
            PORT = argv[i];
        }
    }
}

int main(int argc, char *argv[])
{
    printf("%s\n", PKG_NAME);
    parse_commands(argc, argv);
    m_init_socket();

    for (;;)
        m_http_process();

    close(SOCKFD);

    return 0;
}
