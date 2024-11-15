#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#define MAX_DEPTH 100
#define MAX_NODE_NAME_LENGTH 50

void traverse_node(xmlNode *node, int depth) {
    if (depth > MAX_DEPTH) {
        int *crash = NULL;
        *crash = 1;
    }

    for (xmlNode *current = node; current; current = current->next) {
        if (current->type == XML_ELEMENT_NODE) {
            char buffer[MAX_NODE_NAME_LENGTH];
            strcpy(buffer, (const char *)current->name);
            printf("Node: %s, Depth: %d\n", buffer, depth);
        }
        traverse_node(current->children, depth + 1);
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <xml_file>\n", argv[0]);
        return 1;
    }

    xmlDoc *document = xmlReadFile(argv[1], NULL, 0);
    if (document == NULL) {
        fprintf(stderr, "Error: Unable to parse XML file %s\n", argv[1]);
        return 1;
    }

    xmlNode *root = xmlDocGetRootElement(document);
    if (root == NULL) {
        fprintf(stderr, "Error: XML file %s is empty\n", argv[1]);
        xmlFreeDoc(document);
        return 1;
    }

    printf("Starting XML traversal:\n");
    traverse_node(root, 1);

    xmlFreeDoc(document);
    xmlCleanupParser();
    return 0;
}
