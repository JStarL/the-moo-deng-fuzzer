#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LENGTH 1024
#define MAX_FIELDS 10
#define BUFFER_SIZE 32  // Intentionally small buffer size

void process_csv(const char* filename) {
    // FILE* file = fopen(filename, "r");
    // if (file == NULL) {
    //     printf("Error opening file\n");
    //     return;
    // }

    char line[MAX_LINE_LENGTH];
    char* fields[MAX_FIELDS];
    char buffer[BUFFER_SIZE];  // Vulnerable buffer

    while (fgets(line, sizeof(line), stdin)) {
        int field_count = 0;
        char* token = strtok(line, ",");
        
        while (token != NULL && field_count < MAX_FIELDS) {
            fields[field_count++] = token;
            token = strtok(NULL, ",");
        }

        // Vulnerable: copies field data without proper bounds checking
        for (int i = 0; i < field_count; i++) {
            strcpy(buffer, fields[i]);  // Potential buffer overflow!
            printf("Field %d: %s\n", i, buffer);
        }
    }

    // fclose(file);
}

int main(int argc, char* argv[]) {
    // if (argc != 2) {
    //     printf("Usage: %s <csv_file>\n", argv[0]);
    //     return 1;
    // }

    process_csv(argv[1]);

    return 0;
}
