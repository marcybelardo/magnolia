/*
 *
 *  magnolia
 *  a little http server
 *
 */

#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
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

struct m_conn_map {
    int fd;
    struct m_conn *conn;
};

struct m_poll {
    struct pollfd **pfds;
    int fd_count;
    int fd_size;
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

static char *m_strdup(const char *s)
{
    size_t len = strlen(s) + 1;
    char *dest = malloc(len);
    memcpy(dest, s, len);
    return dest;
}

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

static struct m_conn *new_conn()
{
    struct m_conn *conn = malloc(sizeof(struct m_conn));

    conn->socket = -1;
    conn->req = NULL;
    conn->req_len = 0;
    conn->method = NULL;
    conn->uri = NULL;
    conn->header = NULL;
    conn->header_len = 0;
    conn->resp = NULL;
    conn->resp_len = 0;

    conn->state = DONE;

    return conn;
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

struct m_poll *m_poll_create(int fd_size)
{
    int fd_count = 0;
    struct pollfd *pfds = malloc(sizeof *pfds * fd_size);
    struct m_poll *mp = malloc(sizeof(struct m_poll));

    pfds[0].fd = SOCKFD;
    pfds[0].events = POLLIN;
    fd_count++;

    mp->pfds = &pfds;
    mp->fd_count = fd_count;
    mp->fd_size = fd_size;

    return mp;
}

void m_add_pfd(struct m_poll *mp, int newfd)
{
    if (mp->fd_count == mp->fd_size) {
        mp->fd_size *= 2;
        mp->pfds = realloc(mp->pfds, sizeof(*(mp->pfds)) * (mp->fd_size));
    }

    mp->pfds[mp->fd_count]->fd = newfd;
    mp->pfds[mp->fd_count]->events = POLLIN;
    mp->pfds[mp->fd_count]->revents = 0;
    mp->fd_count++;
}

void m_http_process()
{
    int newfd;
    int fd_size = 5;
    struct sockaddr_storage client_addr;
    socklen_t addrlen;
    char clientIP[INET6_ADDRSTRLEN];
    struct m_conn_map *conns = malloc(sizeof *conns * fd_size);
    struct m_poll *mp = m_poll_create(fd_size);

    for (;;) {
        int poll_count = poll(*(mp->pfds), mp->fd_count, -1);
        if (poll_count == -1) {
            perror("[MAGNOLIA] poll");
            exit(EXIT_FAILURE);
        }

        for (int i = 0; i < mp->fd_count; i++) {
            if (mp->pfds[i]->revents & (POLLIN | POLLHUP)) {
                if (mp->pfds[i]->fd == SOCKFD) {
                    // handle new conn
                    addrlen = sizeof client_addr;
                    newfd = accept(SOCKFD, (struct sockaddr *)&client_addr, &addrlen);
                    if (newfd == -1) {
                        perror("[MAGNOLIA] accept");
                    } else {
                        m_add_pfd(mp, newfd);
                        printf("[MAGNOLIA] new connection from %s on "
                                "socket %d\n",
                                inet_ntop(client_addr.ss_family,
                                    get_in_addr((struct sockaddr *)&client_addr),
                                    clientIP, INET6_ADDRSTRLEN),
                                newfd);
                    }
                } else {
                    // client
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

    ROOT_DIR = m_strdup(argv[1]);
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
