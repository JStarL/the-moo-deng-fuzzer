import io
import xml
import xml.etree.ElementTree as xmlTree
# import xml.etree.ElementTree import parse
# tree = parse("blah.xml")
# note = tree.getroot()

from mutations.buffer_overlow import buffer_overflow_mutation, bigger_buffer_overflow_mutation
from mutations.format_str import random_combined_injection
from mutations.bit_flip import bit_flip, byte_flip

MAX_DEPTH_NEST = 150
'''
def read_xml_input():
    filename = 'testxml.txt'
    with open(filename, 'r') as file:
        xml_string = file.read()

    # print("xml contents\n", xml_string) # testing

'''
def read_xml_input(filename: str) -> None:
    with open(filename, 'r') as file:
        xml_string = file.read()

def xml_bof(filePath):
    tree = xmlTree.parse(filePath) # given xml file as a tree structure
    root_node = tree.getroot() # root node of the tree
    # child_node = xmlTree.SubElement(root, 'div')
    try:
        root_node = xml.fromstring()
    except xmlTree.ParseError:
        return


    def tag_deep_nest:
    # tag is deep nesting
    # idk what to do yet


    def content_overflow:
        

    # not sure with these
    def tag_int_overflow:
    def tag_int_underflow:

    def long_tag:
    # child_node name overflow

def xml_fstring(filePath):
    def content_fstring:
    # "http://{%s *0x10}.com"
    # how to use random_combined_injection in format_str.py???
    def tag_fstring:
    # child_node name %s
