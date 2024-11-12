import io
import xml
import xml.etree.ElementTree as xmlTree

MAX_DEPTH_NEST = 150
'''  example xml file

<html>
    <head>
        <link href="http://somewebsite.com" />
    </head>
    <body>
        <h1>I'm not a web developer.</h1>
    </body>

    <div id="#lol">
        <a href="http://google.com">Here is some link...</a>
    </div>


    <tail>
        <a href="http://bing.com">Footer link</a>
    </tail>
</html>
EOF '''

def xml_bof(filePath):
    tree = xmlTree.parse(filePath)
    root_node = tree.getroot()
    child_node = xmlTree.SubElement(root, 'div')

    def tag_deep_nest:
    # tag is deep nesting

    def content_overflow:
    # "http://{"A" * 0x10000}.com"

    # not sure with these
    def tag_int_overflow:
    def tag_int_underflow:

    def long_tag:
    # child_node name overflow

def xml_fstring(filePath):
    def content_fstring:
    # "http://{%s *0x10}.com"
    def tag_fstring:
    # child_node name %s


