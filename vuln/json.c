#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>

#define MAX_BUFFER 1024

void process_json(const char* json_string) {
    cJSON* json = cJSON_Parse(json_string);
    if (json == NULL) {
        const char* error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            // Vulnerable format string
            printf(error_ptr);
        }
        return;
    }

    cJSON* name = cJSON_GetObjectItemCaseSensitive(json, "name");
    if (cJSON_IsString(name) && (name->valuestring != NULL)) {
        // Vulnerable format string
        printf(name->valuestring);
    }

    cJSON_Delete(json);
}

int main(int argc, char* argv[]) {

    char buffer[MAX_BUFFER];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, stdin);
    buffer[bytes_read] = '\0';

    process_json(buffer);

    return 0;
}
