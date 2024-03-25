#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>

#include <hs/hs.h>

#define MAX_PAYLOAD_SIZE 20
#define MAX_CPUS 128
#define MAX_PATTERNS 10000          // Adjust based on the expected number of patterns
#define PATTERN_FLAG HS_FLAG_DOTALL // Modify as needed

hs_database_t *database = NULL;
hs_scratch_t *scratch = NULL;
int count = 0;

FILE *hs_output;

static int eventHandler(unsigned int id, unsigned long long from,
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

int main(int argc, char *argv[])
{
    if (initialize_hyperscan() != 0)
        printf("Faileed to init hyperscan");

    // if (argc != 2)
    // {
    //     fprintf(stderr, "Usage: %s <input file>\n", argv[0]);
    //     return -1;
    // }

    // char *inputFN = argv[1];

    // if (access(inputFN, F_OK) != 0)
    // {
    //     fprintf(stderr, "ERROR: file doesn't exist.\n");
    //     return -1;
    // }
    // if (access(inputFN, R_OK) != 0)
    // {
    //     fprintf(stderr, "ERROR: can't be read.\n");
    //     return -1;
    // }

    // unsigned int length;
    // char *inputData = readInputData(inputFN, &length);
    // if (!inputData)
    // {
    //     hs_free_database(database);
    //     return -1;
    // }

    if ((hs_output = fopen("/users/vijay4/perf/xdp_perf_files/hs_test_1000_outFile", "w")) == NULL)
        return 1;

    // printf("Scanning %u bytes with Hyperscan\n", length);

    int counter = 0;
    char str[] = "hello!";

    printf("Starting scan for %s:", str);

    clock_t start, end;
    double elapsed_times[1000];
    double total_elapsed = 0.0;
    double max_elapsed = 0.0;

    while (counter < 1000)
    {
        start = clock();

        if (hs_scan(database, str, 7, 0, scratch, eventHandler,
                    NULL) != HS_SUCCESS)
        {
            fprintf(stderr, "ERROR: Unable to scan input buffer. Exiting.\n");
            hs_free_scratch(scratch);
            // free(inputData);
            hs_free_database(database);
            return -1;
        }

        end = clock();
        double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
        elapsed_times[counter] = elapsed;
        total_elapsed += elapsed;

        if (elapsed > max_elapsed)
        {
            max_elapsed = elapsed;
        }

        counter++;
    }

    double average = total_elapsed / 1000;
    printf("Average time per loop: %.6f seconds\n", average);
    printf("Maximum time taken in a single loop: %.6f seconds\n", max_elapsed);
    printf("Total time taken in the loop: %.6f seconds\n", total_elapsed);

    hs_free_scratch(scratch);
    // free(inputData);
    hs_free_database(database);
    return 0;
}