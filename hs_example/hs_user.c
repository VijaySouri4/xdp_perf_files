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

#include <hs/hs.h>
#include <stdio.h>
#include <stdlib.h>

// Define a pattern to search for - in this case, "1.1"
#define PATTERN "44"                //"1\\.1"             // 44794
#define PATTERN_FLAG HS_FLAG_DOTALL // Modify as needed for your pattern's requirements
#define PATTERN_ID 0                // An arbitrary identifier for your pattern

#define MAX_CPUS 128
#define PERF_MAP "/sys/fs/bpf/tc/globals/adjust_cpu"
static struct perf_buffer *pb = NULL;
FILE *fd_output;

hs_database_t *database = NULL;
hs_scratch_t *scratch = NULL;

int count = 0;

static int eventHandler(unsigned int id, unsigned long long from,
                        unsigned long long to, unsigned int flags, void *ctx) // callback for hs
{
    printf("Match for pattern ID %u at offset %llu\n", id, to);

    return 0; // Continue matching
}

int initialize_hyperscan() // Still needs to allocate scratchspace
{
    hs_compile_error_t *compile_err;
    if (hs_compile(PATTERN, PATTERN_FLAG, HS_MODE_BLOCK, NULL, &database, &compile_err) != HS_SUCCESS)
    {
        fprintf(stderr, "ERROR: Unable to compile pattern \"%s\": %s\n",
                PATTERN, compile_err->message);
        hs_free_compile_error(compile_err);
        return -1;
    }

    if (hs_alloc_scratch(database, &scratch) != HS_SUCCESS)
    {
        fprintf(stderr, "ERROR: Unable to allocate scratch space.\n");
        hs_free_database(database);
        return -1;
    }

    return 0; // Initialization successful
}

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

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", ntohs(e->dport)); // checking with dport instead

    // if(hs_scan(database))
    printf("destination port number: %s \n", port_str);
    if (hs_scan(database, port_str, strlen(port_str), 0, scratch, eventHandler,
                PATTERN) != HS_SUCCESS) // Change the lenght which is strlen(e->sport) right now to a fixed size for port number
    {
        // fprintf(stderr, "ERROR: Unable to scan input buffer. Exiting.\n");
        printf("ERROR: Unable to scan input buffer. Exiting");
        hs_free_scratch(scratch);
        // free(inputData);
        hs_free_database(database);
        // return -1;
    }
}

int main(int argc, char **argv)
{

    if (initialize_hyperscan() != 0)
    {
        fprintf(stderr, "Failed to initialize Hyperscan.\n");
        return -1;
    }

    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    int map_fd;
    int ret, err;

    map_fd = bpf_obj_get(PERF_MAP);
    if (map_fd < 0)
    {
        perror("couldnt get pinned perf map\n");
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
        printf("1111");
    }
    fclose(fd_output);
    kill(0, SIGINT);
    return ret;
}
