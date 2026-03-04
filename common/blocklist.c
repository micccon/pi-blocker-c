#define _POSIX_C_SOURCE 200809L

#include "blocklist.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BLOCKLIST_LINE_BUFFER 256

static char **g_blocklist = NULL;
static size_t g_blocklist_size = 0;

// Comparison function for bsearch/qsort. Expects pointers to string pointers.
static int compare_strings(const void *a, const void *b)
{
    const char *sa = *(const char **)a;
    const char *sb = *(const char **)b;
    return strcmp(sa, sb);
}

// Binary-search helper for one domain string.
static bool check_domain(const char *domain)
{
    if (!domain || !g_blocklist || g_blocklist_size == 0)
        return false;

    void *found = bsearch(&domain, g_blocklist, g_blocklist_size,
                          sizeof(char *), compare_strings);
    return (found != NULL);
}

void free_blocklist(void)
{
    if (g_blocklist)
    {
        for (size_t i = 0; i < g_blocklist_size; i++)
            free(g_blocklist[i]);
        free(g_blocklist);
    }

    g_blocklist = NULL;
    g_blocklist_size = 0;
}

int load_blocklist(const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (!file)
    {
        perror("Could not open blocklist file");
        return -1;
    }

    free_blocklist();

    size_t lines = 0;
    char buffer[BLOCKLIST_LINE_BUFFER];
    while (fgets(buffer, sizeof(buffer), file))
        lines++;

    rewind(file);

    g_blocklist = calloc(lines, sizeof(char *));
    if (!g_blocklist)
    {
        fclose(file);
        perror("Out of memory loading blocklist");
        return -1;
    }

    size_t i = 0;
    while (fgets(buffer, sizeof(buffer), file) && i < lines)
    {
        buffer[strcspn(buffer, "\r\n")] = '\0';
        if (buffer[0] == '\0')
            continue;

        g_blocklist[i] = strdup(buffer);
        if (g_blocklist[i] == NULL)
        {
            fclose(file);
            free_blocklist();
            perror("Failure to allocate memory for blocklist entry");
            return -1;
        }
        i++;
    }

    fclose(file);
    g_blocklist_size = i;

    qsort(g_blocklist, g_blocklist_size, sizeof(char *), compare_strings);
    printf("Blocklist loaded: %zu domains active.\n", g_blocklist_size);
    return 0;
}

bool is_blocked(const char *host)
{
    if (!host)
        return false;

    if (check_domain(host))
        return true;

    const char *dot = strchr(host, '.');
    while (dot != NULL)
    {
        const char *parent_domain = dot + 1;
        dot = strchr(parent_domain, '.');
        if (!dot)
            break;

        if (check_domain(parent_domain))
            return true;
    }

    return false;
}
