#include "dns.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// Define globals
char **g_blocklist = NULL;
size_t g_blocklist_size = 0;

// Comparison function to be used to for binary search
// Expects pointers to string pointers (char**)
int compare_strings(const void *a, const void *b)
{
	const char *sa = *(const char **)a;
	const char *sb = *(const char **)b;
	return strcmp(sa, sb);
}

// --- BLOCKLIST MANAGEMENT ---

// Frees each entry in the blocklist and the blocklist itself
void free_blocklist()
{
	if (g_blocklist)
	{
		for (size_t i = 0; i < g_blocklist_size; i++)
			free(g_blocklist[i]);
		free(g_blocklist);
	}
}

// Loads text file of domains into memory and prepares them
// Assumes file is already sorted
void load_blocklist(const char *filename)
{
	FILE *file = fopen(filename, "r");
	if (!file)
	{
		perror("Could not open blocklist.txt");
		return;
	}

	// Counts lines to allocate exact memory
	size_t lines = 0;
	char buffer[BLOCKLIST_LINE_BUFFER];
	while ( fgets(buffer, sizeof(buffer), file) )
		lines++;

	rewind(file); // Go back to beginning of file

	// Allocate the main pointer array
	g_blocklist = calloc(lines, sizeof(char*));
	if (!g_blocklist)
	{
		perror("Out of memory loading blocklist");
		exit(1);
	}

	// Read and store each domain
	size_t i = 0;
	while ( fgets(buffer, sizeof(buffer), file) && i < lines)
	{
		// Strip newline character
		buffer[strcspn(buffer, "\r\n")] = 0;

		// Skip any potential empty lines
		if (strlen(buffer) == 0) continue;

		// Allocate ram for this specific string
		if ( (g_blocklist[i] = strdup(buffer)) == NULL )
		{
			fclose(file);
			free_blocklist();
			perror("Failure to allocate memory for specific string");
			exit(1);
		}

		i++;
	}

	fclose(file);
	g_blocklist_size = i;

	// We assume the file is sorted, if you didn't sort externally uncomment this line
	// qsort(g_blocklist, g_blocklist_size, sizeof(char*), compare_strings);

	printf("Blocklist loaded: %zu domains active.\n", g_blocklist_size);
}

// Helper to perform the actual bsearch call
bool check_domain(const char *domain)
{
	if (!g_blocklist || g_blocklist_size == 0) return false;

	// Note: Use 'domain' directly if your compare_strings expects a char*
	void *found = bsearch(&domain, g_blocklist, g_blocklist_size,
		sizeof(char*), compare_strings);
	return (found != NULL);
}

// Checks if the given host is on the blocklist or not
bool is_blocked(char *host)
{
	// Check domain given first
	if ( check_domain(host) ) return true;

	// Walk up the domain tree
	char *dot = strchr(host, '.');
	while (dot != NULL)
	{
		// Move past current dot to next level
		char *parent_domain = dot + 1;

		// Get new dot, if no more dots (e.g ".com") break
		dot = strchr(parent_domain, '.');
		if (!dot) break;

		if ( check_domain(parent_domain) ) return true;
	}
	return false;
}

// --- DNS PARSER ---

// Reads the name of a domain
unsigned char* read_name(unsigned char* reader, unsigned char* buffer, int* count)
{
	// Parameter checks
	if (!reader || !buffer || !count)
	{
		perror("Null / invalid arguments to read_name");
		exit(1);
	}

	// Malloc name buffer
	char *name = (char *)calloc(DNS_NAME_SIZE, 1);
	if (name == NULL)
	{
		perror("Unable to malloc for name in read_name");
		exit(1);
	}

	*count = 0;
	int name_offset = 0;
	int jumped = 0;
	int loop_count = 0; // To prevent malicious continuous jumps

	// Main loop, checks standard end and max count
	while( *reader != 0 && *count < DNS_NAME_SIZE && loop_count < MAX_LOOP_COUNT) // 0 marks end of name
	{
		// Compression check (11xxxxxx / 0xC0)
		if ( (*reader & JUMP_HEX_VALUE) == JUMP_HEX_VALUE )
		{
			// Calculate offset
			// Combine bottom 6 bits of byte 1 with byte 2
			int jump_offset = ( (*reader & FIRST_OFFSET_HEX_VALUE) << 8)
						| *(reader + 1);

			// Count the pointer size if we haven't jumped yet
			if (jumped == 0)
				*count += 2;

			jumped = 1; // Set to "jump mode"

			reader = buffer + jump_offset;
		}
		else // Standard labeling
		{
			unsigned int segment_len = *reader;

			// Prevent buffer overflow
			if (name_offset + segment_len + 1 >= DNS_NAME_SIZE)
			{
				fprintf(stderr, "Error: DNS name too long, truncated.\n");
				free(name);
				return NULL; // Stop reading to protect memory
			}

			// Copy the segment length of letters into the url name
			memcpy(&name[name_offset], reader + 1, segment_len);

			// Update positions
			name_offset += segment_len;
			reader += segment_len + 1;

			// Add the '.'
			name[name_offset] = '.';
			name_offset++;

			// Increment count only if we haven't jumped
			if (jumped == 0)
				*count += segment_len + 1;
		}
		loop_count++;
	}
	// Remove potential trailing dot
	if (name_offset > 0)
		name[name_offset - 1] = '\0';
	else
		name[0] = '\0';

	// Account for the final null byte
	if (jumped == 0) *count += 1;

	return (unsigned char*)name;
}
