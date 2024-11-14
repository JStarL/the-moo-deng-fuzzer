#include <stdio.h>
#include <stdlib.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#define MAX_DEPTH 100

// Recursive function to traverse XML nodes and check depth
void traverse_node(xmlNode *node, int depth) {
    if (depth > MAX_DEPTH) {
        // Simulate a crash if depth exceeds the maximum allowed depth
        fprintf(stderr, "Error: XML depth exceeded maximum allowed depth of %d\n", MAX_DEPTH);
        int *crash = NULL;  // Trigger segmentation fault
        *crash = 1;
    }

    for (xmlNode *current = node; current; current = current->next) {
        if (current->type == XML_ELEMENT_NODE) {
            printf("Node: %s, Depth: %d\n", current->name, depth);
        }

        // Recursively traverse child nodes, increasing depth
        traverse_node(current->children, depth + 1);
    }
}

// Main function to parse XML file and start traversal
int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <xml_file>\n", argv[0]);
        return 1;
    }

    // Initialize libxml2 library and parse the XML file
    xmlDoc *document = xmlReadFile(argv[1], NULL, 0);
    if (document == NULL) {
        fprintf(stderr, "Error: Unable to parse XML file %s\n", argv[1]);
        return 1;
    }

    // Get the root element node
    xmlNode *root = xmlDocGetRootElement(document);
    if (root == NULL) {
        fprintf(stderr, "Error: XML file %s is empty\n", argv[1]);
        xmlFreeDoc(document);
        return 1;
    }

    // Start traversing the XML nodes from the root
    printf("Starting XML traversal:\n");
    traverse_node(root, 1);

    // Cleanup libxml2 parser and free resources
    xmlFreeDoc(document);
    xmlCleanupParser();
    return 0;
}
