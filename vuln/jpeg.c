#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUFFER 1024
#define SMALL_BUFFER 32  // Intentionally small buffer

// Vulnerable function to process JPEG markers
void process_jpeg_markers(const unsigned char* data, size_t size) {
    size_t i = 0;
    char small_buffer[SMALL_BUFFER];  // Vulnerable small buffer
    while (i < size - 1) {
        if (data[i] == 0xFF) {
            switch (data[i + 1]) {
                case 0xD8: // SOI
                    printf("Start of Image\n");
                    break;
                case 0xE0: // APP0
                    printf("Application Segment 0\n");
                    // Vulnerable: doesn't check for repeated APP0 markers
                    i += 2; // Skip marker
                    i += (data[i] << 8) | data[i + 1]; // Skip segment
                    continue;
                case 0xE1: // APP1 (EXIF)
                    printf("Application Segment 1 (EXIF)\n");
                    i += 2; // Skip marker
                    size_t segment_size = (data[i] << 8) | data[i + 1];
                    i += 2; // Skip size bytes
                    
                    // Vulnerable: Copy segment data without proper bounds checking
                    memcpy(small_buffer, &data[i], segment_size - 2);  // Buffer overflow!
                    small_buffer[SMALL_BUFFER - 1] = '\0';  // Attempt to null-terminate
                    
                    printf("EXIF data: %s\n", small_buffer);
                    i += segment_size - 2;
                    continue;
                case 0xDB: // DQT
                    printf("Define Quantization Table\n");
                    break;
                case 0xC0: // SOF0
                    printf("Start of Frame\n");
                    break;
                case 0xDA: // SOS
                    printf("Start of Scan\n");
                    return; // Vulnerable: stops processing after SOS
                case 0xD9: // EOI
                    printf("End of Image\n");
                    return;
                default:
                    printf("Unknown marker: 0x%02X\n", data[i + 1]);
                    break;
            }
        }
        i++;
    }
}

int main(int argc, char* argv[]) {
    // if (argc != 2) {
    //     printf("Usage: %s <jpeg_file>\n", argv[0]);
    //     return 1;
    // }

    // FILE* file = fopen(argv[1], "rb");
    // if (file == NULL) {
    //     printf("Error opening file\n");
    //     return 1;
    // }

    unsigned char buffer[MAX_BUFFER];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer), stdin);

    // fclose(file);

    process_jpeg_markers(buffer, bytes_read);

    return 0;
}
