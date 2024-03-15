#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/perf_event.h>
#include <linux/bpf.h>

#include <net/if.h>
#include <errno.h>
#include <assert.h>
#include <sys/sysinfo.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <libgen.h>
#include <linux/if_link.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_CPUS 128
#define PERF_MAP "/sys/fs/bpf/tc/globals/adjust_cpu"
static struct perf_buffer *pb = NULL;
FILE *fd_output;

static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size)
{
        struct connection_info
        {
                __be32 daddr;
                __be32 saddr;
                __be16 sport;
                __be16 dport;
        } __attribute__((packed)) *e = data;
        struct in_addr src;
        struct in_addr dst;
        src.s_addr = e->saddr;
        dst.s_addr = e->daddr;
        fprintf(fd_output, "%s:%u\t", inet_ntoa(src), ntohs(e->sport));
        fprintf(fd_output, "%s:%u\n", inet_ntoa(dst), ntohs(e->dport));
        fflush(fd_output);
}

int main(int argc, char **argv)
{
        struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
        int map_fd;
        int ret, err;

        map_fd = bpf_obj_get(PERF_MAP);
        if (map_fd < 0)
        {
                perror("couldnt get pinned timeseries map\n");
                return 1;
        }

        if (setrlimit(RLIMIT_MEMLOCK, &r))
        {
                perror("setrlimit(RLIMIT_MEMLOCK)");
                return 1;
        }
        if ((fd_output = fopen("/root/testFile", "w")) == NULL)
                return 1;

        pb = perf_buffer__new(map_fd, 8, print_bpf_output, NULL, NULL, NULL);
        err = libbpf_get_error(pb);
        if (!pb || err)
        {
                perror("perf_buffer setup failed");
                return 1;
        }
        while ((ret = perf_buffer__poll(pb, 1000)) >= 0)
        {
                printf("polling all the way!");
        }
        fclose(fd_output);
        kill(0, SIGINT);
        return ret;
}
