from typing import Dict, List
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
        self.addr_map         = self.graph.new_vertex_property("int")
        self.size_map           = self.graph.new_vertex_property("int")

        # Dictionary to store the graph nodes by address for easy lookup
        self.addr_to_vertex     = {}
        self.pending_edges      = []

        self.add_function(
                binary  = binary, 
                addr    = main_addr,
        )

    # TODO: Come up with a better name for this
    def add_edge_if_exists(self, vertex: Vertex, block: Dict, key: str) -> None:
        """Given a basic block, 

        - add an edge to the specified key (jump/fail) if the vertex exist, or
        - add it to `self.pending_edges()` otherwise.

        Args:
            vertex: The vertex representing the block.
            block: The dictionary containing the attributes of the block.
            key: The key of the dictionary containing the target block.
        """
        if key in block and block[key] is not None:
            if block[key] in self.addr_to_vertex:
                self.graph.add_edge(vertex, self.addr_to_vertex[block[key]])
            else:
                self.pending_edges.append((vertex, block[key]))

    def add_function(self, addr: int, binary: Binary) -> None:
        """Add the basic blocks of a function to the graph.
        This will recursively call itself on any function called by the current one.

        Args:
            addr: The address of the target function
            binary: The binary which the function belongs to.
        """
        blocks = binary.get_blocks(addr)
        
        # Bit wacky but this should be faster than doing
        #
        # - one loop for the vertices,
        # - and one for the edges.
        #
        # This will be O(n) instead of O(n^2)
        for block in blocks:
            offset                          = block['addr']
            vertex                          = self.graph.add_vertex()
            self.addr_map[vertex]           = offset
            self.size_map[vertex]           = block['size']
            self.addr_to_vertex[offset]     = vertex

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
            if target in self.addr_to_vertex:
                self.graph.add_edge(
                        source  = source,
                        target  = self.addr_to_vertex[target]
                )
        # TODO: Find function calls made by the function at `addr` and link it to the graph
        # TODO: Recursively dissassemble each function that the current function calls to

    def find_dead_ends(self) ->  List[Vertex]:
        """Find vetices with no outgoing edges

        Returns:
            A list of vertices with no outgoing edges
        """
        return [v for v in self.graph.vertices() if v.out_degree == 0]
