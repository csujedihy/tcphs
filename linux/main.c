#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <sys/epoll.h>
#include <pthread.h>
#include <sys/eventfd.h>
#include <stdatomic.h>

#define USAGE "Usage: tcphs -s|-c <ip> [-p <port>] [-o <num conns>] [-t <duration in sec>] [-r <num procs>]\n"
#define DEFAULT_NUM_CONNS 16
#define DEFAULT_DURATION_IN_SEC 5
#define HISTO_SIZE 512
#define HISTO_GRANULARITY_US 100
#define MAX_EVENTS 64

typedef enum {
    test_start = 1,
    test_end,
} test_signal;

typedef enum {
    role_server = 's',
    role_client = 'c',
} app_role;

struct worker {
    int ep_fd;
    int event_fd;
    int listen_fd;
    volatile int running;
    volatile long long accepted_count;
    volatile long long failed_accept_count;
    volatile long long connected_count;
    volatile long long failed_connect_count;
    volatile long long failed_bind_count;;
    pthread_t thread;
    void* io_contexts;
    unsigned long histo[HISTO_SIZE];
};

struct global_config {
    app_role role;
    volatile int terminate;
    struct sockaddr_storage remote_addr;
    struct sockaddr_storage local_addr;
    int num_procs;
    int num_conns;
    int duration_in_sec;
    pthread_t* threads;
    struct worker workers[0];
};

struct global_config* g_config;

// no linger to avoid TCP timewait
int
set_socket_nolinger(
    int sockfd
    )
{
    struct linger linger_opt;
    linger_opt.l_onoff = 1;   // Enable linger
    linger_opt.l_linger = 0;  // Linger time of 0 seconds (immediate reset)
    if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &linger_opt, sizeof(linger_opt))) {
        return -1;
    }

    return 0;
}

void
print_ip_port(
    struct sockaddr_storage* sa
    )
{
    char ip_str[INET6_ADDRSTRLEN];  // INET6_ADDRSTRLEN is 46, enough for IPv6

    if (sa->ss_family == AF_INET) {
        struct sockaddr_in* addr4 = (struct sockaddr_in*)sa;
        if (inet_ntop(AF_INET, &addr4->sin_addr, ip_str, INET_ADDRSTRLEN) == NULL) {
            perror("Failed to convert IPv4 address to string\n");
            return;
        }
    } else {
        struct sockaddr_in6* addr6 = (struct sockaddr_in6*)sa;
        if (inet_ntop(AF_INET6, &addr6->sin6_addr, ip_str, INET6_ADDRSTRLEN) == NULL) {
            perror("Failed to convert IPv6 address to string\n");
            return;
        }
    }

    printf("%s:%d\n", ip_str, ntohs(((struct sockaddr_in6*)sa)->sin6_port));
}

void
notify_workers(
    test_signal sig
    )
{
    for (int i = 0; i < g_config->num_procs; ++i) {
        int event_fd = g_config->workers[i].event_fd;
        if (event_fd == -1) {
            continue;
        }

        // FIXME: this is a wrong usage of eventfd.
        if (eventfd_write(event_fd, sig)) {
            perror("Failed to notify worker");
        }
    }
}

void
new_connect_io(
    struct worker* worker
    )
{
    int sock = -1;
    int err = -1;
    int opt = 0;

    if ((sock = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0)) < 0) {
        goto done;
    }

    err = set_socket_nolinger(sock);
    if (err) {
        goto done;
    }

    if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt))) {
        goto done;
    }

    err =
        epoll_ctl(
            worker->ep_fd,
            EPOLL_CTL_ADD,
            sock,
            &(struct epoll_event){.events = EPOLLOUT | EPOLLONESHOT, .data.fd = sock});
    if (err == -1) {
        goto done;
    }

    err = bind(sock, (struct sockaddr*)&g_config->local_addr, sizeof(g_config->local_addr));
    if (err == -1) {
        worker->failed_bind_count++;
        goto done;
    }

    // Note: if connect succeeds inline, we will still get a EPOLLOUT event.
    err = connect(sock, (struct sockaddr*)&g_config->remote_addr, sizeof(g_config->remote_addr));
    if (err != 0 && errno != EINPROGRESS) {
        goto done;
    }

    err = 0;

done:
    if (err != 0) {
        worker->failed_connect_count++;
        close(sock);
    }
}

void*
io_loop(
    void* arg
    )
{
    struct worker* worker = (struct worker*)arg;
    struct epoll_event events[MAX_EVENTS];

    atomic_thread_fence(memory_order_acquire);

    while (worker->running) {
        int nfds = epoll_wait(worker->ep_fd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            if (errno == EINTR) {
                continue;  // Interrupted by a signal, retry
            }
            perror("epoll wait failed");
            goto error;
        }

        for (int eid = 0; eid < nfds; eid++) {
            struct epoll_event* event = &events[eid];
            if (event->data.fd == worker->event_fd) {
                uint64_t val = 0;
                if (eventfd_read(worker->event_fd, &val)) {
                    perror("Failed to read eventfd");
                    goto error;
                }

                if (val == test_start) {
                    for (int i = 0; i < g_config->num_conns; ++i) {
                        new_connect_io(worker);
                    }
                } else if (val == test_end) {
                    worker->running = 0;
                }
            } else if (event->data.fd == worker->listen_fd) {
                // Drain the listen socket until the accept queue is empty
                while (1) {
                    int new_socket = accept(worker->listen_fd, NULL, NULL);
                    if (new_socket == -1) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            break;  // No more connections to accept
                        }
                        perror("Accept failed");
                        continue;
                    }

                    if (set_socket_nolinger(new_socket)) {
                        perror("Failed to set socket to non-linger");
                        close(new_socket);
                        continue;
                    }

                    close(new_socket);
                }
            } else {
                // It's possible that we get a EPOLLERR event because
                // the peer also closes forcibly right after the conn
                // is established. The ERR and OUT events are not mutually
                // exclusive and could be bundled up. So, we need to
                // first check EPOLLOUT to count the successful connects 
                // and treat EPOLLERR as a failure only when EPOLLOUT is
                // not set.
                if (event->events & EPOLLOUT) {
                    int error = 0;
                    socklen_t len = sizeof(error);
                    int ret = getsockopt(event->data.fd, SOL_SOCKET, SO_ERROR, &error, &len);
                    if (ret != 0 || error != 0) {
                        worker->failed_connect_count++;
                    } else {
                        worker->connected_count++;
                    }
                } else if (event->events & EPOLLERR) {
                    worker->failed_connect_count++;
                } else {
                    printf("Unexpected event: %d\n", event->events);
                }
                close(event->data.fd);
                new_connect_io(worker);
            }
        }
    }

error:
    return NULL;
}

int
run_server() {
    int t_idx = 0;

    for (; t_idx < g_config->num_procs; ++t_idx) {
        struct worker* worker = &g_config->workers[t_idx];
        int opt;

        if ((worker->listen_fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0)) == 0) {
            break;
        }
    
        opt = 0;
        if (setsockopt(worker->listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt))) {
            perror("setsockopt (IPV6_V6ONLY) failed");
            break;
        }

        opt = 1;
        if (setsockopt(worker->listen_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt))) {
            perror("setsockopt (SO_REUSEPORT) failed");
            break;
        }
    
        if (bind(
                worker->listen_fd,
                (struct sockaddr*)&g_config->local_addr,
                sizeof(g_config->local_addr))) {
            perror("bind failed");
            break;
        }
    
        worker->ep_fd = epoll_create1(EPOLL_CLOEXEC);
        if (worker->ep_fd == -1) {
            perror("Epoll create failed");
            break;
        }

        if (epoll_ctl(
                worker->ep_fd, 
                EPOLL_CTL_ADD,
                worker->listen_fd,
                &(struct epoll_event){
                    .events = EPOLLIN | EPOLLET,
                    .data.fd = worker->listen_fd}) == -1) {
            perror("Epoll ctl failed");
            break;
        }

        if (listen(worker->listen_fd, 4096) < 0) {
            perror("Listen failed");
            break;
        }

        worker->running =  1;
        atomic_thread_fence(memory_order_release);

        if (pthread_create(&worker->thread, NULL, io_loop, worker)) {
            perror("Failed to create thread");
            break;
        }
    }

    if (t_idx != g_config->num_procs) {
        notify_workers(test_end);
    } else {
        printf("%d workers listening on ", g_config->num_procs);
        print_ip_port(&g_config->local_addr);
    }

    // Wait for all threads to join
    for (int i = 0; i < t_idx; ++i) {
        struct worker* worker = &g_config->workers[i];

        if (worker->thread) {
            pthread_join(worker->thread, NULL);
        }
    }

    for (int i = 0; i < t_idx; ++i) {
        if (g_config->workers[i].ep_fd != -1) {
            close(g_config->workers[i].ep_fd);
        }

        if (g_config->workers[i].event_fd != -1) {
            close(g_config->workers[i].event_fd);
        }

        if (g_config->workers[i].listen_fd != -1) {
            close(g_config->workers[i].listen_fd);
        }
    }

    return 0;
}

int
run_client() {
    int ret = -1;
    int t_idx = 0;

    for (; t_idx < g_config->num_procs; ++t_idx) {
        struct worker* worker = &g_config->workers[t_idx];
    
        worker->ep_fd = epoll_create1(EPOLL_CLOEXEC);
        if (worker->ep_fd == -1) {
            perror("Epoll create failed");
            break;
        }

        worker->event_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if (worker->event_fd == -1) {
            perror("eventfd failed");
            break;
        }

        // Add eventfd to epoll with level trigger
        if (epoll_ctl(
                worker->ep_fd,
                EPOLL_CTL_ADD,
                worker->event_fd,
                &(struct epoll_event){.events = EPOLLIN, .data.fd = worker->event_fd}) == -1) {
            perror("epoll_ctl for event_fd failed");
            break;
        }

        worker->running = 1;
        atomic_thread_fence(memory_order_release);

        if (pthread_create(&worker->thread, NULL, io_loop, worker)) {
            perror("Failed to create thread");
            break;
        }
    }

    if (t_idx == g_config->num_procs) {
        printf("connecting to ");
        print_ip_port(&g_config->remote_addr);
        notify_workers(test_start);
    }
    sleep(g_config->duration_in_sec);
    notify_workers(test_end);

    // Wait for all threads to join
    for (int i = 0; i < t_idx; ++i) {
        struct worker* worker = &g_config->workers[i];

        if (worker->thread) {
            pthread_join(worker->thread, NULL);
        }
    }

    // Sum up all results into the first worker
    for (int i = 1; i < g_config->num_procs; ++i) {
        g_config->workers[0].connected_count += g_config->workers[i].connected_count;
        g_config->workers[0].failed_connect_count += g_config->workers[i].failed_connect_count;
        g_config->workers[0].failed_bind_count += g_config->workers[i].failed_bind_count;
    }

    printf("HPS: %lld\n", g_config->workers[0].connected_count / g_config->duration_in_sec);
    printf("Connected: %lld\n", g_config->workers[0].connected_count);
    printf("Failed connects: %lld\n", g_config->workers[0].failed_connect_count);
    printf("Failed binds: %lld\n", g_config->workers[0].failed_bind_count);

    for (int i = 0; i < t_idx; ++i) {
        if (g_config->workers[i].ep_fd != -1) {
            close(g_config->workers[i].ep_fd);
        }

        if (g_config->workers[i].event_fd != -1) {
            close(g_config->workers[i].event_fd);
        }
    }
    return ret;
}

void
in6addr_set_v4mapped(
    struct in6_addr *in6, const struct in_addr *in4
    )
{
    memset(in6, 0, sizeof(struct in6_addr));
    in6->s6_addr[10] = 0xff;
    in6->s6_addr[11] = 0xff;
    memcpy(&in6->s6_addr[12], &in4->s_addr, sizeof(in4->s_addr));
}

int
parse_ip_address(
    char* ip,
    struct sockaddr_storage* sa
    )
{
    struct in_addr addr4;
    struct in6_addr addr6;

    sa->ss_family = 0;
    if (inet_pton(AF_INET6, ip, &addr6)) {
        sa->ss_family = AF_INET6;
        (((struct sockaddr_in6*)sa)->sin6_addr) = addr6;
    } else if (inet_pton(AF_INET, ip, &addr4)) {
        sa->ss_family = AF_INET;
        (((struct sockaddr_in*)sa)->sin_addr) = addr4;
    } else {
        return -1;
    }

    return sa->ss_family;
}

int
parse_cmd(
    int argc,
    char* argv[],
    struct global_config* config
    )
{
    int i = 1;

    if (argc < 2) {
        printf(USAGE);
        return -1;
    }
    
    config->num_procs = sysconf(_SC_NPROCESSORS_ONLN);
    config->num_conns = DEFAULT_NUM_CONNS;
    config->duration_in_sec = DEFAULT_DURATION_IN_SEC;
    config->local_addr.ss_family = AF_INET6;
    ((struct sockaddr_in6*)&config->local_addr)->sin6_addr = in6addr_any;
    ((struct sockaddr_in6*)&config->local_addr)->sin6_port = htons(0);

    while (i < argc) {
        if (strcmp(argv[i], "-s") == 0) {
            config->role = role_server;
        } else if (strcmp(argv[i], "-c") == 0) {
            config->role = role_client;
            ++i;
            if (i < argc) {
                struct sockaddr_storage temp_sa;
                if (parse_ip_address(argv[i], &temp_sa) == -1) {
                    printf("Invalid IP address: %s\n", argv[i]);
                    return -1;
                }

                if (temp_sa.ss_family == AF_INET) {
                    config->remote_addr.ss_family = AF_INET6;
                    in6addr_set_v4mapped(
                        &((struct sockaddr_in6*)&config->remote_addr)->sin6_addr,
                        &((struct sockaddr_in*)&temp_sa)->sin_addr);
                } else {
                    config->remote_addr = temp_sa;
                }
            } else {
                printf(USAGE);
                return -1;
            }
        } else if (strcmp(argv[i], "-p") == 0) {
            ++i;
            if (i < argc) {
                int port = atoi(argv[i]);
                if (port < 0 || port > 65535) {
                    printf("Invalid port: %s\n", argv[i]);
                    goto error;
                }

                if (config->role == role_server) {
                    ((struct sockaddr_in6*)&config->local_addr)->sin6_port = htons(port);
                } else {
                    ((struct sockaddr_in6*)&config->remote_addr)->sin6_port = htons(port);
                }
            } else {
                goto error;
            }
        } else if (strcmp(argv[i], "-o") == 0) {
            ++i;
            if (i < argc) {
                config->num_conns = atoi(argv[i]);
                if (config->num_conns <= 0) {
                    printf("Invalid number of connections: %s\n", argv[i]);
                    goto error;
                }
            } else {
                goto error;
            }
        } else if (strcmp(argv[i], "-t") == 0) {
            ++i;
            if (i < argc) {
                config->duration_in_sec = atoi(argv[i]);
                if (config->duration_in_sec <= 0) {
                    printf("Invalid duration: %s\n", argv[i]);
                    goto error;
                }
            } else {
                goto error;
            }
        } else if (strcmp(argv[i], "-r") == 0) {
            ++i;
            if (i < argc) {
                config->num_procs = atoi(argv[i]);
                if (config->num_procs <= 0) {
                    printf("Invalid number of threads: %s\n", argv[i]);
                    goto error;
                }
            } else {
                goto error;
            }
        } else {
            goto error;
        }
        ++i;
    }

    return 0;

error:
    return -1;
}

int
main(
    int argc,
    char* argv[]
    )
{
    struct global_config temp_config = {0};
    size_t config_size = 0;
    if (parse_cmd(argc, argv, &temp_config)) {
        printf(USAGE);
        return -1;
    }

    config_size = sizeof(struct global_config) + (temp_config.num_procs) * sizeof(struct worker);
    g_config = calloc(1, config_size);
    if (!g_config) {
        printf("Failed to allocate memory\n");
        return -1;
    }

    *g_config = temp_config;

    // Proper initialization of the workers
    for (int i = 0; i < g_config->num_procs; ++i) {
        g_config->workers[i].ep_fd = -1;
        g_config->workers[i].event_fd = -1;
        g_config->workers[i].listen_fd = -1;
    }

    if (g_config->role == role_server) {
        if (run_server()) {
            return -1;
        }
    } else {
        if (run_client()) {
            return -1;
        }
    }

    return 0;
}