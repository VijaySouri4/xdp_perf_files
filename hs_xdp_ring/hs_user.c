// #include <bpf/libbpf.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <linux/perf_event.h>
// #include <linux/bpf.h>

// #include <net/if.h>
// #include <errno.h>
// #include <assert.h>
// #include <sys/sysinfo.h>
// #include <sys/ioctl.h>
// #include <signal.h>
// #include <bpf/bpf.h>
// #include <sys/resource.h>
// #include <libgen.h>
// #include <linux/if_link.h>
// #include <sys/socket.h>
// #include <netinet/in.h>
// #include <arpa/inet.h>

// #include <hs/hs.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <ctype.h>

// // Define a pattern to search for - in this case, "1.1"
// #define PATTERN_1 "44"
// #define PATTERN_2 "43"
// #define PATTERN_3 "4+"              // to understand use 44 since desination port is 443             //"1\\.1"             // 44794
// #define PATTERN_FLAG HS_FLAG_DOTALL // Modify as needed for your pattern's requirements
// #define PATTERN_ID 0                // An arbitrary identifier for your pattern
// #define MAX_PAYLOAD_SIZE 50

// #define MAX_CPUS 128
// // #define PERF_MAP "/sys/fs/bpf/tc/globals/hs_xdp_map"
// #define RING_MAP "/sys/fs/bpf/tc/globals/hs_xdp_payload_map_ring" // adjust_cpu used before
// // static struct perf_buffer *pb = NULL;
// FILE *fd_output;

// hs_database_t *database = NULL;
// hs_scratch_t *scratch = NULL;

// int count = 0;

// static int eventHandler(unsigned int id, unsigned long long from,
//                         unsigned long long to, unsigned int flags, void *ctx) // callback for hs
// {
//     printf("Match for pattern ID %u at offset %llu\n", id, to);

//     return 0; // Continue matching
// }

// int initialize_hyperscan() // Still needs to allocate scratchspace
// {
//     // hs_compile_error_t *compile_err;
//     hs_compile_error_t *compile_err;
//     const char *patterns[] = {PATTERN_1, PATTERN_2, PATTERN_3};
//     unsigned int flags[] = {PATTERN_FLAG, PATTERN_FLAG, PATTERN_FLAG};
//     unsigned int ids[] = {1, 2, 3};

//     if (hs_compile_multi(patterns, flags, ids, 3, HS_MODE_BLOCK, NULL, &database, &compile_err) != HS_SUCCESS)
//     {
//         fprintf(stderr, "ERROR: Unable to compile patterns: %s\n", compile_err->message);
//         hs_free_compile_error(compile_err);
//         return -1;
//     }

//     if (hs_alloc_scratch(database, &scratch) != HS_SUCCESS)
//     {
//         fprintf(stderr, "ERROR: Unable to allocate scratch space.\n");
//         hs_free_database(database);
//         return -1;
//     }

//     return 0; // Initialization successful
// }

// static int print_bpf_output(void *ctx, void *data, size_t size) // removed int cpu
// {
//     struct connection_info
//     {
//         __be32 daddr;
//         __be32 saddr;
//         __be16 sport;
//         __be16 dport;
//         __u8 payload[MAX_PAYLOAD_SIZE];
//     } __attribute__((packed)) *e = data;
//     struct in_addr src;
//     struct in_addr dst;
//     src.s_addr = e->saddr;
//     dst.s_addr = e->daddr;
//     fprintf(fd_output, "%s:%u\t", inet_ntoa(src), ntohs(e->sport));
//     fprintf(fd_output, "%s:%u\n", inet_ntoa(dst), ntohs(e->dport));
//     fflush(fd_output);

//     char port_str[11];
//     snprintf(port_str, sizeof(port_str), "%u", ntohs(src.s_addr)); // checking with dport instead

//     printf("Connection Info:\n");
//     printf("  Source Address: %s\n", inet_ntoa(src));
//     printf("  Source Port: %u\n", ntohs(e->sport));
//     printf("  Destination Address: %s\n", inet_ntoa(dst));
//     printf("  Destination Port: %u\n", ntohs(e->dport));
//     printf("Checking against: %s\n", port_str);

//     // char payload[MAX_PAYLOAD_SIZE + 1];
//     // memcpy(payload, e->payload, MAX_PAYLOAD_SIZE);
//     // payload[MAX_PAYLOAD_SIZE] = '\0';
//     // printf("  Payload: %s\n", payload);
//     for (int i = 0; i < MAX_PAYLOAD_SIZE; i++)
//     {
//         // printf("before break \n");
//         //  Check for the end of the payload
//         if (e->payload[i] == '\0')
//             break;
//         // printf("after break \n");
//         //  Print payload characters if printable, otherwise print a dot
//         if (isprint(e->payload[i]))
//             fprintf(fd_output, "%c", e->payload[i]);
//         else
//             fprintf(fd_output, ".");
//     }
//     fprintf(fd_output, "\n");

//     if (hs_scan(database, port_str, strlen(port_str), 0, scratch, eventHandler, NULL) != HS_SUCCESS)
//     {
//         printf("ERROR: Unable to scan input buffer. Exiting.\n");
//         hs_free_scratch(scratch);
//         hs_free_database(database);
//     }

//     return 0;
// }

// int main(int argc, char **argv)
// {

//     if (initialize_hyperscan() != 0)
//     {
//         fprintf(stderr, "Failed to initialize Hyperscan.\n");
//         return -1;
//     }

//     struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
//     int map_fd;
//     int ret, err;

//     map_fd = bpf_obj_get(RING_MAP);
//     if (map_fd < 0)
//     {
//         perror("couldnt get pinned perf map\n");
//         return 1;
//     }

//     if (setrlimit(RLIMIT_MEMLOCK, &r))
//     {
//         perror("setrlimit(RLIMIT_MEMLOCK)");
//         return 1;
//     }
//     if ((fd_output = fopen("/root/testFile", "w")) == NULL)
//         return 1;

//     // pb = perf_buffer__new(map_fd, 8, print_bpf_output, NULL, NULL, NULL);
//     static struct ring_buffer *pb = NULL;

//     pb = ring_buffer__new(map_fd, print_bpf_output, NULL, NULL);
//     err = libbpf_get_error(pb);
//     if (!pb || err)
//     {
//         perror("perf_buffer setup failed");
//         return 1;
//     }
//     while ((ret = ring_buffer__poll(pb, 1000)) >= 0)
//     {
//         // printf("1111");
//     }
//     fclose(fd_output);
//     kill(0, SIGINT);
//     return ret;
// }

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
#define RING_MAP "/sys/fs/bpf/tc/globals/hs_xdp_payload_map_ring"

static struct perf_buffer *pb = NULL;
FILE *fd_output;
FILE *hs_output;

hs_database_t *database = NULL;
hs_scratch_t *scratch = NULL;
int count = 0;

clock_t start, end;
double elapsed_times[50000];
double total_elapsed = 0.0;
double max_elapsed = 0.0;
double average;

clock_t callback_start, callback_end;
double callback_elapsed_times[50000];
double callback_start_times[50000];
double total_callback_elapsed = 0.0;
double max_callback_elapsed = 0.0;
double callback_elapsed;

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

static int print_bpf_output(void *ctx, void *data, size_t size)
{
    callback_start = clock();
    callback_start_times[count] = callback_start;

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

    const char *payload = (const char *)e->payload;

    start = clock();
    if (hs_scan(database, (const char *)e->payload, MAX_PAYLOAD_SIZE, 0, scratch, eventHandler, NULL) != HS_SUCCESS)
    {
        printf("HSERROR: Unable to scan input buffer. Exiting.\n");
        hs_free_scratch(scratch);
        hs_free_database(database);
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

    callback_end = clock();
    callback_elapsed = (double)(callback_end - callback_start) / CLOCKS_PER_SEC;
    callback_elapsed_times[count] = callback_elapsed;
    total_callback_elapsed += callback_elapsed;

    if (callback_elapsed > max_callback_elapsed)
    {
        max_callback_elapsed = callback_elapsed;
    }

    if (count % 500 == 0)
    {
        printf("Packet: %d\t", count);
        fflush(stdout);
    }

    // if (count % 900 == 0)
    // {
    //     printf("received %d packets", count);
    //     double average = total_elapsed / 1000;
    //     printf("Checked against payload: %s", (const char *)e->payload);
    //     printf("Average time per loop: %.6f seconds\n", average);
    //     printf("Maximum time taken in a single loop: %.6f seconds\n", max_elapsed);
    //     printf("Total time taken in hyperscan: %.6f seconds\n", total_elapsed);
    //     // printf("working \n");
    // }
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

    map_fd = bpf_obj_get(RING_MAP);
    if (map_fd < 0)
    {
        perror("couldnt get pinned ring map\n");
        return 1;
    }

    if (setrlimit(RLIMIT_MEMLOCK, &r))
    {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return 1;
    }
    if ((fd_output = fopen("/root/testringFile", "w")) == NULL)
        return 1;

    if ((hs_output = fopen("/root/hsringoutFILE", "w")) == NULL)
        return 1;

    static struct ring_buffer *pb = NULL;

    pb = ring_buffer__new(map_fd, print_bpf_output, NULL, NULL);
    err = libbpf_get_error(pb);
    if (!pb || err)
    {
        perror("ring_buffer setup failed");
        return 1;
    }

    time_t last_packet_time = time(NULL);

    while (1) // ring_buffer__poll(pb, 1000)
    {
        ring_buffer__poll(pb, 1000);

        if (count % 2000 == 0 && count != 0)
        {
            printf("Processed %d packets\n", count);
            printf("Hyperscan Stats:\n");
            printf("Total Packets received: %d \n", count);
            double average = total_elapsed / count;
            printf("Average time per hyperscan loop: %.6f seconds\n", average);
            printf("Maximum time taken in a single hyperscan loop: %.6f seconds\n", max_elapsed);
            printf("Total time taken in hyperscan: %.6f seconds\n", total_elapsed);
            break;
        }
    }
    fclose(fd_output);
    // kill(0, SIGINT);
    printf("Outside");

    printf("Hyperscan Stats:\n");
    printf("Total Packets received: %d \n", count);
    double average = total_elapsed / count;
    printf("Average time per hyperscan loop: %.6f seconds\n", average);
    printf("Maximum time taken in a single hyperscan loop: %.6f seconds\n", max_elapsed);
    printf("Total time taken in hyperscan: %.6f seconds\n", total_elapsed);

    printf("Callback function Stats:\n");
    double callback_average = total_callback_elapsed / count;
    printf("Average time per callback function: %.6f seconds\n", callback_average);
    printf("Maximum time taken in a single callback function: %.6f seconds\n", max_callback_elapsed);
    printf("Total time taken in callback function: %.6f seconds\n", total_callback_elapsed);

    // Calculate and display the time difference between subsequent packets
    if (count > 1)
    {
        double callback_start_diff = (double)(callback_start_times[count - 1] - callback_start_times[count - 2]) / CLOCKS_PER_SEC;
        printf("Time difference between the last two packets: %.6f seconds\n", callback_start_diff);
    }
    return ret;
}
