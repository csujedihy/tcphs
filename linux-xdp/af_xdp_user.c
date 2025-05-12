#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

struct global_config {
    int ifindex;
    int attach_mode;
    char ifname[IF_NAMESIZE];
};

struct global_config config;

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
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return -1;
        }
        ++i;
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);
    char filename[] = "af_xdp_kern.o";
    char progname[] = "xdp_prog_simple";
    struct xdp_program *prog;
    char errmsg[1024];
    int prog_fd, err; // = EXIT_SUCCESS;

    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, bpf_opts);
    DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts,
                        .open_filename = filename,
                        .prog_name = progname,
                        .opts = &bpf_opts);

    if (parse_cmd(argc, argv, &config)) {
        return -1;
    }

    /* Create an xdp_program froma a BPF ELF object file */
    prog = xdp_program__create(&xdp_opts);
    err = libxdp_get_error(prog);
    if (err) {
        libxdp_strerror(err, errmsg, sizeof(errmsg));
        fprintf(stderr, "Couldn't get XDP program %s: %s\n",
            progname, errmsg);
        return err;
    }

    /* Attach the xdp_program to the net device XDP hook */
    err = xdp_program__attach(prog, config.ifindex, config.attach_mode, 0);
    if (err) {
        libxdp_strerror(err, errmsg, sizeof(errmsg));
        fprintf(
            stderr, "Couldn't attach XDP program on iface '%s' : %s (%d)\n",
            config.ifname, errmsg, err);
        return err;
    }

    /* This step is not really needed , BPF-info via bpf-syscall */
    prog_fd = xdp_program__fd(prog);
    err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
    if (err) {
        fprintf(stderr, "ERR: can't get prog info - %s\n",
            strerror(errno));
        return err;
    }

    printf("Success: Loading "
           "XDP prog name:%s(id:%d) on device:%s(ifindex:%d)\n",
           info.name, info.id, config.ifname, config.ifindex);
    return 0;
}
