/* Compile program with:
gcc -I/usr/local/include/hs hs_test_1000.c /usr/local/lib/libhs.a -lstdc++
 -lm*/

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>

#include <hs/hs.h>

#define NUM_BUFFERS 1000
#define BUFFER_SIZE 7

#define MAX_PAYLOAD_SIZE 20
#define MAX_CPUS 128
#define MAX_PATTERNS 10000          // Adjust based on the expected number of patterns
#define PATTERN_FLAG HS_FLAG_DOTALL // Modify as needed

hs_database_t *database = NULL;
hs_scratch_t *scratch = NULL;
int count = 0;

FILE *hs_output;

char buffers[NUM_BUFFERS][BUFFER_SIZE];

void initializeBuffers()
{
    const char *str = "hello!";
    for (int i = 0; i < NUM_BUFFERS; i++)
    {
        strncpy(buffers[i], str, BUFFER_SIZE);
    }
}

static int eventHandler(unsigned int id, unsigned long long from,
                        unsigned long long to, unsigned int flags, void *ctx)
{
    // fprintf(hs_output, "Match for pattern ID %u at offset %llu\n", id, to);
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

int main(int argc, char *argv[])
{
    if (initialize_hyperscan() != 0)
        printf("Failed to init hyperscan");

    if ((hs_output = fopen("/users/vijay4/perf/xdp_perf_files/hs_test_1000_outFile", "w")) == NULL)
        return 1;

    initializeBuffers();

    printf("Starting scan for buffers containing 'hello!':\n");

    clock_t start, end;
    double elapsed_times[NUM_BUFFERS];
    double total_elapsed = 0.0;
    double max_elapsed = 0.0;

    for (int i = 0; i < NUM_BUFFERS; i++)
    {
        start = clock();

        if (hs_scan(database, buffers[i], BUFFER_SIZE, 0, scratch, eventHandler, NULL) != HS_SUCCESS)
        {
            fprintf(stderr, "ERROR: Unable to scan input buffer. Exiting.\n");
            hs_free_scratch(scratch);
            hs_free_database(database);
            return -1;
        }

        end = clock();
        double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
        elapsed_times[i] = elapsed;
        total_elapsed += elapsed;

        if (elapsed > max_elapsed)
        {
            max_elapsed = elapsed;
        }
    }

    double average = total_elapsed / NUM_BUFFERS;
    printf("Average time per buffer scan: %.6f seconds\n", average);
    printf("Maximum time taken in a single buffer scan: %.6f seconds\n", max_elapsed);
    printf("Total time taken to scan all buffers: %.6f seconds\n", total_elapsed);

    hs_free_scratch(scratch);
    hs_free_database(database);
    return 0;
}