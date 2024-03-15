// SPDX-License-Identifier: GPL-2.0
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
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <libgen.h>
#include <linux/if_link.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
// #include <linux/tools/perf-sys.h>

struct rtt_keys
{
	char key_name[32];
} __packed;

#define MAX_CPUS 128
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
		__be32 seq_no;
		__u64 pktcnt;
		__u64 cur_ktime;
	} __attribute__((packed)) *e = data;
	struct in_addr src;
	struct in_addr dst;
	src.s_addr = e->saddr;
	dst.s_addr = e->daddr;
	fprintf(fd_output, "%s:%u\t", inet_ntoa(src), ntohs(e->sport));
	fprintf(fd_output, "%s:%u\t%llu\t%u\t%llu\n", inet_ntoa(dst), ntohs(e->dport),
			e->pktcnt, ntohl(e->seq_no), e->cur_ktime);
}

#define CONFIG_MAP "/sys/fs/bpf/tc/globals/rtt_config"
#define LB_MAP "/sys/fs/bpf/tc/globals/lb_map_ack"

/*static void sig_handler(int signo)
{
	perf_buffer__free(pb);
	exit(0);
}*/

static void usage(const char *prog)
{
	fprintf(stderr,
			"%s: %s [OPTS] <ifname|ifindex>\n\n"
			"OPTS:\n"
			"    -F    force loading prog\n",
			__func__, prog);
}

int main(int argc, char **argv)
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	// struct perf_buffer_opts pb_opts = {};
	// pb = perf_buffer__new(map_fd, 8, print_bpf_output, NULL, NULL, NULL);
	const char *optstr = "N:P:";
	int map_fd, opt, config_fd;
	char outputname[256];
	unsigned int portnum = 0;
	int ret, err;
	struct rtt_keys rtt;
	while ((opt = getopt(argc, argv, optstr)) != -1)
	{
		switch (opt)
		{
		case 'N':
			strncpy(outputname, opt, sizeof(outputname) - 1); // optarg -- opt
			break;
		case 'P':
			memset(&(rtt.key_name), 0, sizeof(rtt.key_name));
			strncpy(rtt.key_name, "port", strlen("port") + 1);
			rtt.key_name[strlen("port")] = 0;
			portnum = atoi(opt); // optarg -- opt
			break;
		default:
			usage(basename(argv[0]));
			return 1;
		}
	}
	fprintf(stderr, "\n%s %d\n", outputname, portnum);

	if (setrlimit(RLIMIT_MEMLOCK, &r))
	{
		perror("setrlimit(RLIMIT_MEMLOCK)");
		return 1;
	}

	config_fd = bpf_obj_get(CONFIG_MAP);
	if (config_fd < 0)
	{
		printf("couldnt get pinned config map\n");
		return 1;
	}

	map_fd = bpf_obj_get(LB_MAP);
	if (map_fd < 0)
	{
		printf("couldnt get pinned timeseries map\n");
		return 1;
	}
	if ((fd_output = fopen(outputname, "w")) == NULL)
		return 1;
	// pb_opts.sample_cb = print_bpf_output;
	// pb = perf_buffer__new(map_fd, 8, &pb_opts);
	pb = perf_buffer__new(map_fd, 8, print_bpf_output); // NULL, NULL, NULL
	err = libbpf_get_error(pb);
	if (!pb || err)
	{
		perror("perf_buffer setup failed");
		return 1;
	}
	while ((ret = perf_buffer__poll(pb, 1000)) >= 0)
	{
	}
	fclose(fd_output);
	kill(0, SIGINT);
	return ret;
}
