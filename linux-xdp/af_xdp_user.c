#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <assert.h>
#include <unistd.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>

#include <sys/resource.h>

#include <linux/bpf.h>
#include <xdp/xsk.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>


#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define WRITE_ONCE(var, val) (*(volatile typeof(var) *)&(var) = (val))

struct global_config {
    int ifindex;
    int attach_mode;
    char ifname[IF_NAMESIZE];

    uint16_t remote_port;
    atomic_bool running;
    _Atomic(uint32_t) completed_conns; // the # of completed connections
    struct timeval start_time;
};

struct umem_info {
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem* umem;
    void* buffer;
};

#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE;
#define NUM_FRAMES 4096

struct socket_info {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct umem_info *umem;
    struct xsk_socket *xsk;

    uint64_t umem_frame_addr[NUM_FRAMES];
    uint32_t umem_frame_free;

    uint32_t conn_credit; // the # of outbound connections we are allowed to have
    uint32_t outstanding_tx;
    atomic_ushort ip_id;
    uint32_t tx_completed;
};

int xsk_map_fd;
struct global_config config;
atomic_ushort src_port = 1025;

static
uint16_t
interlocked_inc16(
    atomic_ushort* value
    )
{
    return 1 + atomic_fetch_add_explicit(value, 1, memory_order_release);
}

static
uint32_t
interlocked_inc32(
    _Atomic(uint32_t)* value
    )
{
    return 1 + atomic_fetch_add_explicit(value, 1, memory_order_release);
}

inline
static
uint16_t
port_acquire_n(
    void
    )
{
    return htons(interlocked_inc16(&src_port));
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
        fprintf(stderr, "Usage: %s -d <ifname>\n", argv[0]);
        return -1;
    }

    while (i < argc) {
        if (strcmp(argv[i], "-d") == 0) {
            ++i;
            if (i < argc) {
                strncpy(config->ifname, argv[i], IF_NAMESIZE - 1);
                config->ifindex = if_nametoindex(config->ifname);
                if (config->ifindex == 0) {
                    fprintf(stderr, "Invalid interface name: %s\n", argv[i]);
                    return -1;
                }
            } else {
                fprintf(stderr, "Missing interface name after -d\n");
                return -1;
            }
        }  else if (strcmp(argv[i], "-p") == 0) {
            ++i;
            if (i < argc) {
                config->remote_port = atoi(argv[i]);
            } else {
                fprintf(stderr, "Missing remote port number after -p\n");
                return -1;
            }
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return -1;
        }
        ++i;
    }

    return 0;
}

static
uint16_t
xsum16(
    uint8_t* data,
    uint32_t len,
    uint64_t init
    )
{
    //
    // Add up all bytes in 3 steps:
    // 1. Add the odd byte to the checksum if the length is odd.
    // 2. If the length is divisible by 2 but not 4, add the last 2 bytes.
    // 3. Sum up the rest as 32-bit words.
    //
    if ((len & 1) != 0) {
        --len;
        init += data[len];
    }

    if ((len & 2) != 0) {
        len -= 2;
        init += *((uint16_t*)(&data[len]));
    }

    for (uint32_t i = 0; i < len; i += 4) {
        init += *((uint32_t*)(&data[i]));
    }

    // Fold all carries into the final checksum.
    while (init >> 16) {
        init = (init & 0xffff) + (init >> 16);
    }

    return (uint16_t)init;
}

static
uint16_t
l4_xsum16(
    uint8_t* saddr,
    uint8_t* daddr,
    uint32_t addrlen,
    uint8_t proto,
    uint16_t ip_payload_len,
    uint8_t* data
    )
{
    uint64_t xsum = htons(proto) + htons((uint16_t)ip_payload_len);
    xsum = xsum16(saddr, addrlen, xsum);
    xsum = xsum16(daddr, addrlen, xsum);
    return ~xsum16(data, ip_payload_len, xsum);
}

static
struct umem_info*
umem_info_init()
{
    struct umem_info* info = NULL;
    int err;

    info = calloc(1, (sizeof(*info)));
    if (!info) {
        fprintf(stderr, "Failed to allocate memory for umem_info\n");
        goto Failed;
    }

    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n", strerror(errno));
        goto Failed;
    }

    uint64_t packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
    void *packet_buffer = NULL;
    if (posix_memalign(&packet_buffer, getpagesize(), packet_buffer_size)) {
        fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n", strerror(errno));
        goto Failed;
    }

    err = xsk_umem__create(&info->umem, packet_buffer, packet_buffer_size, &info->fq, &info->cq, NULL);
    if (err) {
        fprintf(stderr, "xsk_umem__create failed %s\n", strerror(err));
        goto Failed;
    }

    info->buffer = packet_buffer;
    return info;

Failed:

    if (info) {
        free(info);
    }
    return NULL;
}

static
uint64_t
alloc_umem_frame(
    struct socket_info *xsk_info
    )
{
    uint64_t frame;
    if (xsk_info->umem_frame_free == 0)
        return UINT64_MAX;

    frame = xsk_info->umem_frame_addr[--xsk_info->umem_frame_free];
    xsk_info->umem_frame_addr[xsk_info->umem_frame_free] = UINT64_MAX;
    return frame;
}

static
void
free_umem_frame(
    struct socket_info* xsk_info,
    uint64_t frame
    )
{
    assert(xsk_info->umem_frame_free < NUM_FRAMES);

    xsk_info->umem_frame_addr[xsk_info->umem_frame_free++] = frame;
}

static
uint64_t
umem_avail_frames(
    struct socket_info *xsk_info
    )
{
    return xsk_info->umem_frame_free;
}

static
struct socket_info*
socket_info_init(
    struct umem_info *umem
    )
{
    struct socket_info *info = NULL;
    struct xsk_socket_config xsk_cfg = {0};
    uint32_t idx;
    int i;
    int ret;

    info = calloc(1, sizeof(*info));
    if (!info) {
        fprintf(stderr, "Failed to allocate memory for socket_info\n");
        goto Failed;
    }

    info->umem = umem;
    xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    xsk_cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
    xsk_cfg.xdp_flags = XDP_FLAGS_SKB_MODE;
    // bind to queue 0 for now
    ret = xsk_socket__create(&info->xsk, config.ifname, 0, umem->umem, &info->rx, &info->tx, &xsk_cfg);
    if (ret) {
        fprintf(stderr, "xsk_socket__create failed %s\n", strerror(ret));
        goto Failed;
    }

    ret = xsk_socket__update_xskmap(info->xsk, xsk_map_fd);
    if (ret) {
        fprintf(stderr, "xsk_socket__update_xskmap failed %s\n", strerror(ret));
        goto Failed;
    }

    for (i = 0; i < NUM_FRAMES; ++i) {
        info->umem_frame_addr[i] = i * FRAME_SIZE;
    }
    info->umem_frame_free = NUM_FRAMES;

    ret = xsk_ring_prod__reserve(&info->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
    if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS) {
        fprintf(stderr, "xsk_ring_prod__reserve failed %s\n", strerror(ret));
        goto Failed;
    }

    for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; ++i) {
        *xsk_ring_prod__fill_addr(&info->umem->fq, idx++) = alloc_umem_frame(info);
    }

    xsk_ring_prod__submit(&info->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);

    return info;

Failed:
    if (info) {
        if (info->xsk >= 0) {
            xsk_socket__delete(info->xsk);
        }
        free(info);
    }
    return NULL;
}

const int IO_BATCH_SIZE = 32;

bool
do_rx(
    struct socket_info* xsk_info,
    uint64_t addr,
    uint32_t len
    )
{
    uint8_t* pkt = xsk_umem__get_data(xsk_info->umem->buffer, addr);
	struct ethhdr *eth = (struct ethhdr*) pkt;
	struct iphdr *ip = (struct iphdr*) (eth + 1);
    struct tcphdr *tcp = (struct tcphdr*) (ip + 1);
    uint8_t tmp_mac[ETH_ALEN];
    int ret;
    uint32_t tx_idx = 0;

    // Swap source and destination MAC addresses
    memcpy(tmp_mac, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

    // Swap source and destination IP addresses
    ip->daddr ^= ip->saddr;
    ip->saddr ^= ip->daddr;
    ip->daddr ^= ip->saddr;

    // Swap source and destination ports
    tcp->dest ^= tcp->source;
    tcp->source ^= tcp->dest;
    tcp->dest ^= tcp->source;

    uint32_t seq = ntohl(tcp->seq);
    tcp->seq = tcp->ack_seq;
    tcp->ack_seq = htonl(seq + 1);
    tcp->th_flags = TH_ACK;
    tcp->th_sum = 0; // Reset checksum
    tcp->th_sum =
        l4_xsum16(
            (uint8_t*)&ip->saddr, (uint8_t*)&ip->daddr,
            sizeof(ip->saddr), ip->protocol,
            ntohs(ip->tot_len) - sizeof(*ip),
            (uint8_t*)tcp);
    
    ret = xsk_ring_prod__reserve(&xsk_info->tx, 1, &tx_idx);
    if (ret != 1)
        return false;
    struct xdp_desc* desc = xsk_ring_prod__tx_desc(&xsk_info->tx, tx_idx);
    desc->addr = addr;
    desc->len = len;
    xsk_ring_prod__submit(&xsk_info->tx, 1);
    ++xsk_info->conn_credit;
    interlocked_inc32(&config.completed_conns);
    ++xsk_info->outstanding_tx;
    return true;
}

static
void
rx_io(
    struct socket_info* xsk_info
    )
{
    unsigned int rcvd;
    uint32_t idx_rx = 0;
    uint32_t idx_fq = 0;

    rcvd = xsk_ring_cons__peek(&xsk_info->rx, IO_BATCH_SIZE, &idx_rx);
    if (rcvd == 0) {
        return;
    }

    for (int i = 0; i < rcvd; ++i) {
        const struct xdp_desc* desc = xsk_ring_cons__rx_desc(&xsk_info->rx, idx_rx++);
        if (!do_rx(xsk_info, desc->addr, desc->len)) {
            free_umem_frame(xsk_info, desc->addr);
        }
    }

    xsk_ring_cons__release(&xsk_info->rx, rcvd);

    unsigned int free_fill_frames =
        xsk_prod_nb_free(
            &xsk_info->umem->fq,
            umem_avail_frames(xsk_info));

    if (free_fill_frames > 0) {
        unsigned int fill_rsvd =
            xsk_ring_prod__reserve(&xsk_info->umem->fq, rcvd, &idx_fq);
        for (int i = 0; i < fill_rsvd; ++i) {
            uint64_t frame = alloc_umem_frame(xsk_info);
            *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx_fq++) = frame;
        }

        xsk_ring_prod__submit(&xsk_info->umem->fq, free_fill_frames);
    }
}

const uint8_t dest_mac[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static const unsigned char src_mac[6] = { 0x9e, 0xfe, 0x00, 0x24, 0x45, 0x5e };
static const unsigned char dst_mac[6] = { 0x02, 0xac, 0x5d, 0xb6, 0xd8, 0x22 };
static struct in_addr src_addr;
static struct in_addr dst_addr;

static
void
frame_syn(
    struct socket_info* xsk_info,
    uint8_t* pkt,
    uint32_t* len
    )
{
    struct ethhdr* eth = (struct ethhdr*)pkt;
    struct iphdr* ip = (struct iphdr*)(pkt + sizeof(struct ethhdr));
    struct tcphdr* tcp = (struct tcphdr*)(pkt + sizeof(struct ethhdr) + sizeof(struct iphdr));
    *len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);

    // eth header
    memcpy(eth->h_dest, dst_mac, ETH_ALEN);
    memcpy(eth->h_source, src_mac, ETH_ALEN);
    eth->h_proto = htons(ETH_P_IP);

    // ip header
    ip->version = 4;
    ip->id = htons(atomic_fetch_add(&xsk_info->ip_id, 1));
    ip->ihl = 5;
    ip->ttl = 64;
    ip->frag_off = 0;    
    ip->tos = 0;
    ip->tot_len = htons(*len - sizeof(struct ethhdr));
    ip->saddr = src_addr.s_addr;
    ip->daddr = dst_addr.s_addr;
    ip->protocol = IPPROTO_TCP;
    WRITE_ONCE(ip->check, 0); // Reset checksum
    ip->check = ~xsum16((uint8_t*)ip, sizeof(*ip), 0);

    // tcp header
    tcp->th_sport = port_acquire_n();
    tcp->th_dport = htons(config.remote_port);
    tcp->th_win = 0xffff;
    tcp->th_x2 = 0;
    tcp->th_off = 5;
    tcp->th_flags = TH_SYN;
    tcp->th_seq = htonl(rand());
    tcp->th_ack = 0;
    tcp->th_urp = 0;
    tcp->th_sum = 0;
    tcp->th_sum =
        l4_xsum16(
            (uint8_t*)&ip->saddr, (uint8_t*)&ip->daddr,
            sizeof(ip->saddr), ip->protocol,
            ntohs(ip->tot_len) - sizeof(*ip),
            (uint8_t*)tcp);
}

static
void
conn_out(
    struct socket_info* xsk_info
    )
{
    if (xsk_info->conn_credit > 0) {
        unsigned int tx_rsvd;
        uint32_t idx_tx;

        tx_rsvd = xsk_ring_prod__reserve(&xsk_info->tx, xsk_info->conn_credit, &idx_tx);
        if (tx_rsvd > 0) {
            for (int i = 0; i < tx_rsvd; ++i) {
                struct xdp_desc* desc = xsk_ring_prod__tx_desc(&xsk_info->tx, idx_tx++);
                desc->addr = alloc_umem_frame(xsk_info);
                frame_syn(xsk_info, xsk_umem__get_data(xsk_info->umem->buffer, desc->addr), &desc->len);
            }
            xsk_ring_prod__submit(&xsk_info->tx, tx_rsvd);
            xsk_info->conn_credit -= tx_rsvd;
            xsk_info->outstanding_tx += tx_rsvd;
        }
    }
}

static
void
complete_tx(
    struct socket_info* xsk_info
    )
{
    unsigned int completed;
    uint32_t idx_cq;

    if (!xsk_info->outstanding_tx) {
        return;
    }

    sendto(xsk_socket__fd(xsk_info->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

    completed =
        xsk_ring_cons__peek(
            &xsk_info->umem->cq,
            XSK_RING_CONS__DEFAULT_NUM_DESCS, &idx_cq);
    if (completed > 0) {
        for (int i = 0; i < completed; ++i) {
            uint64_t addr = *xsk_ring_cons__comp_addr(&xsk_info->umem->cq, idx_cq++);
            free_umem_frame(xsk_info, addr);
        }
        xsk_ring_cons__release(&xsk_info->umem->cq, completed);
        xsk_info->outstanding_tx -=
            completed < xsk_info->outstanding_tx ?
                completed : xsk_info->outstanding_tx;
        xsk_info->tx_completed += completed;
    }
}

static
void
io_loop(
    struct socket_info* xsk_info
    )
{
    while (atomic_load(&config.running)) {
        conn_out(xsk_info);
        rx_io(xsk_info);
        complete_tx(xsk_info);
    }
}

static
void
exit_application(
    int signum
    )
{
    atomic_store(&config.running, 0);
    struct timeval end_time;
    gettimeofday(&end_time, NULL);
    uint64_t elapsed_time = (end_time.tv_sec - config.start_time.tv_sec) * 1000000 +
                        (end_time.tv_usec - config.start_time.tv_usec);
    // caculate the conns completed per second
    uint64_t conns_per_sec = ((uint64_t)config.completed_conns * 1000000) / elapsed_time;
    printf("Connections per second: %lu\n", conns_per_sec);
    printf("Total connections completed: %d\n", config.completed_conns);
    printf("Total time elapsed: %ld microseconds\n", elapsed_time);
}

int
main(
    int argc,
    char **argv
    )
{
    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);
    char filename[] = "af_xdp_kern.o";
    char progname[] = "xdp_prog_simple";
    struct xdp_program *prog;
    char errmsg[1024];
    int prog_fd, err; // = EXIT_SUCCESS;

    gettimeofday(&config.start_time, NULL);
	signal(SIGINT, exit_application);

    srand(time(NULL));

    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, bpf_opts);
    DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts,
                        .open_filename = filename,
                        .prog_name = progname,
                        .opts = &bpf_opts);

    if (parse_cmd(argc, argv, &config)) {
        return -1;
    }

    inet_pton(AF_INET, "1.1.1.1", &src_addr);
    inet_pton(AF_INET, "1.1.1.2", &dst_addr);

    /* Create an xdp_program froma a BPF ELF object file */
    prog = xdp_program__create(&xdp_opts);
    err = libxdp_get_error(prog);
    if (err) {
        libxdp_strerror(err, errmsg, sizeof(errmsg));
        fprintf(stderr, "Couldn't get XDP program %s: %s\n",
            progname, errmsg);
        return err;
    }

    err = xdp_program__attach(prog, config.ifindex, config.attach_mode, 0);
    if (err) {
        libxdp_strerror(err, errmsg, sizeof(errmsg));
        fprintf(
            stderr, "Couldn't attach XDP program on iface '%s' : %s (%d)\n",
            config.ifname, errmsg, err);
        return err;
    }

    printf("Success: Loading "
           "XDP prog name:%s(id:%d) on device:%s(ifindex:%d)\n",
           info.name, info.id, config.ifname, config.ifindex);

    /* This step is not really needed , BPF-info via bpf-syscall */
    prog_fd = xdp_program__fd(prog);
    err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
    if (err) {
        fprintf(stderr, "ERR: can't get prog info - %s\n",
            strerror(errno));
        return err;
    }

    struct bpf_map *map;
    map = bpf_object__find_map_by_name(xdp_program__bpf_obj(prog), "xsks_map");
    if (!map) {
        fprintf(stderr, "ERR: can't find map xsks_map\n");
        return -1;
    }

    xsk_map_fd = bpf_map__fd(map);
    if (xsk_map_fd < 0) {
        fprintf(stderr, "ERR: can't get map fd - %s\n", strerror(xsk_map_fd));
        return -1;
    }

    struct umem_info* umem_info = umem_info_init();
    if (!umem_info) {
        fprintf(stderr, "ERR: can't create umem_info\n");
        return -1;
    }

    struct socket_info* xsk_info = socket_info_init(umem_info);
    if (!xsk_info) {
        fprintf(stderr, "ERR: can't create socket_info\n");
        return -1;
    }

    config.running = true;
    xsk_info->conn_credit = 32;
    io_loop(xsk_info);

    if (xsk_info) {
        if (xsk_info->xsk) {
            xsk_socket__delete(xsk_info->xsk);
        }
        free(xsk_info);
    }
    if (umem_info) {
        if (umem_info->umem) {
            xsk_umem__delete(umem_info->umem);
        }
        free(umem_info);
    }

    return 0;
}
