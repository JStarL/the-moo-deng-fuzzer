from typing import Dict
from graph_tool.all import Graph
from graph_tool.libgraph_tool_core import Vertex
from binary import Binary

class ControlFlowGraph:
    def __init__(self, main_addr: int, binary: Binary) -> None:
        """Initialise a new instance of the `Graph` class

        Args:
            main_addr: The address to the main function
            binary: The instance of `Binary` containing the target binary
        """
        self.graph              = Graph(directed = True)

        # Vertex properties
        self.offset_map         = self.graph.new_vertex_property("int")
        self.size_map           = self.graph.new_vertex_property("int")

        # Dictionary to store the graph nodes by offset for easy lookup
        self.offset_to_vertex   = {}
        self.pending_edges      = []

        self.add_function(
                binary  = binary, 
                addr    = main_addr,
        )

    # TODO: Come up with a better name for this
    def add_edge_if_exists(self, vertex: Vertex, block: Dict, key: str) -> None:
        if key in block and block[key] is not None:
            if block[key] in self.offset_to_vertex:
                self.graph.add_edge(vertex, self.offset_to_vertex[block[key]])
            else:
                self.pending_edges.append((vertex, block[key]))

    def add_function(self, addr: int, binary: Binary) -> None:
        graph = binary.get_graph(addr)
        blocks = map(lambda x: x.get('blocks', []), graph)
        blocks = list(blocks)

        # This just flattens the 2d list into a 1d list
        blocks = [item for sublist in blocks for item in sublist]

        # Bit wacky but this should be faster than doing
        #
        # - one loop for the vertices,
        # - and one for the edges.
        #
        # This will be O(n) instead of O(n^2)
        for block in blocks:
            offset                          = block['offset']
            vertex                          = self.graph.add_vertex()
            self.offset_map[vertex]         = offset
            self.size_map[vertex]           = block['size']
            self.offset_to_vertex[offset]   = vertex

            self.add_edge_if_exists(
                    vertex  = vertex,
                    block   = block,
                    key     = 'fail',
            )

            self.add_edge_if_exists(
                    vertex  = vertex,
                    block   = block,
                    key     = 'jump',
            )

        for source, target in self.pending_edges:
            if target in self.offset_to_vertex:
                self.graph.add_edge(
                        source  = source,
                        target  = self.offset_to_vertex[target]
                )
        # TODO: Find function calls made by the function at `addr` and link it to the graph
        # TODO: Recursively dissassemble each function that the current function calls to
