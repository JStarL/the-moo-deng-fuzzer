#include <stdio.h>
#include <libxml/parser.h>

void parseXML(const char *filename) {
    xmlParserCtxtPtr ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
        fprintf(stderr, "Failed to create parser context\n");
        return;
    }

    // 设置解析标志，禁用一切保护措施
    xmlDocPtr doc = xmlCtxtReadFile(ctxt, filename, NULL, XML_PARSE_HUGE | XML_PARSE_NOENT);
    if (doc == NULL) {
        fprintf(stderr, "Failed to parse %s\n", filename);
        xmlFreeParserCtxt(ctxt);
        return;
    }

    xmlFreeDoc(doc);
    xmlFreeParserCtxt(ctxt);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <xmlfile>\n", argv[0]);
        return 1;
    }
    parseXML(argv[1]);
    return 0;
}
