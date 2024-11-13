#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 256  // 更小的缓冲区大小

void process_pdf_chunk(const char *chunk, size_t size) {
    char buffer[BUFFER_SIZE];
    static int page_count = 0;  // 静态变量用于记录页面计数

    for (size_t i = 0; i < size; i++) {
        // Check for a page start pattern (e.g., "/Page")
        if (strncmp(&chunk[i], "/Page", 5) == 0) {
            page_count++;
            printf("Found page %d\n", page_count);

            // Copy a portion of page content to a buffer
            if (i + BUFFER_SIZE < size) {
                strncpy(buffer, &chunk[i], BUFFER_SIZE - 1);
                buffer[BUFFER_SIZE - 1] = '\0';  // Ensure null-termination
                printf("Page content: %.100s\n", buffer);  // Print first 100 chars
            }
        }

        // Detect "/HugeText" pattern and process safely
        if (strncmp(&chunk[i], "/HugeText", 9) == 0) {
            printf("Processing large text block...\n");

            // Safely copy a portion to avoid overflow
            strncpy(buffer, &chunk[i], BUFFER_SIZE - 1);
            buffer[BUFFER_SIZE - 1] = '\0';
            printf("Large text processed: %.100s\n", buffer);
        }
    }
}

int main() {
    char buffer[BUFFER_SIZE];
    size_t bytesRead;

    // Read and process PDF data chunk by chunk from standard input
    while ((bytesRead = fread(buffer, 1, BUFFER_SIZE, stdin)) > 0) {
        process_pdf_chunk(buffer, bytesRead);
    }

    return 0;  // 确保 main 函数以 return 语句结束
}
