from graph_tool.all import Graph
from binary import Binary

class ControlFlowGraph:
    def __init__(self, main_addr: int, binary: Binary) -> None:
        """Initialise a new instance of the `Graph` class

        Args:
            main_addr: The address to the main function
            binary: The instance of `Binary` containing the target binary
        """
        self.g = Graph(directed = True)
        self.add_function(
                binary  = binary, 
                addr    = main_addr,
        )

    def add_function(self, addr: int, binary: Binary) -> None:
        graph = binary.get_graph(addr)
        blocks = map(lambda x: x.get('blocks', []), graph)
        blocks = list(blocks)
        
        # TODO: Flatten `blocks` as it is a 2D list
        # TODO: Find function calls made by the function at `addr` and link it to the graph
        # TODO: Recursively dissassemble each function that the current function calls to
