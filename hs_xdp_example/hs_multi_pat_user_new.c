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
#include <ctype.h>
#include <time.h>

#define MAX_PAYLOAD_SIZE 20
#define MAX_CPUS 128
#define MAX_PATTERNS 10000          // Adjust based on the expected number of patterns
#define PATTERN_FLAG HS_FLAG_DOTALL // Modify as needed
#define PERF_MAP "/sys/fs/bpf/tc/globals/hs_xdp_payload_map"

static struct perf_buffer *pb = NULL;
FILE *fd_output;
FILE *hs_output;

hs_database_t *database = NULL;
hs_scratch_t *scratch = NULL;
int count = 0;

clock_t start, end;
double elapsed_times[1000];
double total_elapsed = 0.0;
double max_elapsed = 0.0;
double average;

static int
eventHandler(unsigned int id, unsigned long long from,
             unsigned long long to, unsigned int flags, void *ctx)
{
    fprintf(hs_output, "Match for pattern ID %u at offset %llu\n", id, to);
    return 0; // Continue matching
}

int initialize_hyperscan()
{
    hs_compile_error_t *compile_err;
    char **patterns = malloc(MAX_PATTERNS * sizeof(char *));
    unsigned int *flags = malloc(MAX_PATTERNS * sizeof(unsigned int));
    unsigned int *ids = malloc(MAX_PATTERNS * sizeof(unsigned int));
    FILE *file = fopen("cleaned_snort_patterns.txt", "r");
    char line[1024];
    unsigned int pattern_count = 0;

    if (!patterns || !flags || !ids)
    {
        fprintf(stderr, "ERROR: Memory allocation failed\n");
        return -1;
    }

    while (fgets(line, sizeof(line), file) && pattern_count < MAX_PATTERNS)
    {
        line[strcspn(line, "\n")] = 0; // Remove newline character

        // Skip patterns that could potentially match an empty buffer
        if (strlen(line) == 0 || isspace(line[0]) || strchr(line, '*') || strchr(line, '?') || strcmp(line, "||") == 0)
        {
            continue;
        }

        patterns[pattern_count] = strdup(line);
        flags[pattern_count] = PATTERN_FLAG | HS_FLAG_ALLOWEMPTY; // You might want to use HS_FLAG_ALLOWEMPTY for specific cases
        ids[pattern_count] = pattern_count + 1;
        pattern_count++;
    }
    fclose(file);

    if (hs_compile_multi((const char **)patterns, flags, ids, pattern_count, HS_MODE_BLOCK, NULL, &database, &compile_err) != HS_SUCCESS)
    {
        fprintf(stderr, "ERROR: Unable to compile patterns: %s\n", compile_err->message);
        hs_free_compile_error(compile_err);
        for (unsigned int i = 0; i < pattern_count; i++)
        {
            free(patterns[i]);
        }
        free(patterns);
        free(flags);
        free(ids);
        return -1;
    }

    if (hs_alloc_scratch(database, &scratch) != HS_SUCCESS)
    {
        fprintf(stderr, "ERROR: Unable to allocate scratch space.\n");
        hs_free_database(database);
        for (unsigned int i = 0; i < pattern_count; i++)
        {
            free(patterns[i]);
        }
        free(patterns);
        free(flags);
        free(ids);
        return -1;
    }

    for (unsigned int i = 0; i < pattern_count; i++)
    {
        free(patterns[i]);
    }
    free(patterns);
    free(flags);
    free(ids);
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
        __u8 payload[MAX_PAYLOAD_SIZE];
    } __attribute__((packed)) *e = data;
    struct in_addr src;
    struct in_addr dst;
    src.s_addr = e->saddr;
    dst.s_addr = e->daddr;
    fprintf(fd_output, "%s:%u\t", inet_ntoa(src), ntohs(e->sport));
    fprintf(fd_output, "%s:%u\n", inet_ntoa(dst), ntohs(e->dport));
    fprintf(fd_output, "Payload: ");
    for (int i = 0; i < MAX_PAYLOAD_SIZE; i++)
    {
        // printf("before break \n");
        //  Check for the end of the payload
        if (e->payload[i] == '\0')
            break;
        // printf("after break \n");
        //  Print payload characters if printable, otherwise print a dot
        if (isprint(e->payload[i]))
            fprintf(fd_output, "%c", e->payload[i]);
        else
            fprintf(fd_output, ".");
    }
    fprintf(fd_output, "\n");
    fflush(fd_output);

    // char port_str[11];
    // snprintf(port_str, sizeof(port_str), "%u", ntohs(src.s_addr)); // checking with dport instead

    // printf("Connection Info:\n");
    // printf("  Source Address: %s\n", inet_ntoa(src));
    // printf("  Source Port: %u\n", ntohs(e->sport));
    // printf("  Destination Address: %s\n", inet_ntoa(dst));
    // printf("  Destination Port: %u\n", ntohs(e->dport));
    // printf("Checking against: %s\n", port_str);

    // char payload[MAX_PAYLOAD_SIZE + 1];
    // memcpy(payload, e->payload, MAX_PAYLOAD_SIZE);
    // payload[MAX_PAYLOAD_SIZE] = '\0';
    // printf("  Payload: %s\n", payload);

    // if (hs_scan(database, port_str, strlen(port_str), 0, scratch, eventHandler, NULL) != HS_SUCCESS)
    // {
    //     printf("ERROR: Unable to scan input buffer. Exiting.\n");
    //     hs_free_scratch(scratch);
    //     hs_free_database(database);
    // }

    start = clock();
    if (isprint(e->payload[0]))
    {
        if (hs_scan(database, (const char *)e->payload, MAX_PAYLOAD_SIZE, 0, scratch, eventHandler, NULL) != HS_SUCCESS)
        {
            printf("ERROR: Unable to scan input buffer. Exiting.\n");
            hs_free_scratch(scratch);
            hs_free_database(database);
        }
    }

    end = clock();
    double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
    elapsed_times[count] = elapsed;
    total_elapsed += elapsed;

    if (elapsed > max_elapsed)
    {
        max_elapsed = elapsed;
    }

    count++;

    // printf("received %d packets", count);

    if (count % 900 == 0)
    {
        printf("received %d packets", count);
        // average = total_elapsed / count;
        // printf("Average time per loop: %.6f seconds\n", average);
        // printf("Maximum time taken in a single loop: %.6f seconds\n", max_elapsed);
        double average = total_elapsed / 1000;
        printf("Checked against payload: %s", (const char *)e->payload);
        printf("Average time per loop: %.6f seconds\n", average);
        printf("Maximum time taken in a single loop: %.6f seconds\n", max_elapsed);
        printf("Total time taken in hyperscan: %.6f seconds\n", total_elapsed);
        // printf("working \n");
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

    if ((hs_output = fopen("/root/hsoutFILE", "w")) == NULL)
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
        // printf("1111");
    }
    fclose(fd_output);
    kill(0, SIGINT);

    // double average = total_elapsed / 1000;
    // printf("Average time per loop: %.6f seconds\n", average);
    // printf("Maximum time taken in a single loop: %.6f seconds\n", max_elapsed);
    // printf("Total time taken in hyperscan: %.6f seconds\n", total_elapsed);

    return ret;
}
