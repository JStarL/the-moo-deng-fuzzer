from typing import Dict, List
import r2pipe
import json
import logging

logger = logging.getLogger("coverage")
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


class Binary:
    def __init__(self, binary: str, base_addr: int = 0) -> None:
        """Initialise an instance of the binary class

        Args:
            base_addr: The base address 
            binary: Path to the target binary
        """
        logger.info(f"Initialising an instance of `binary` with the base address {base_addr} and ELF file {binary}")
        self.binary = binary
        self.base_addr = base_addr
        self.__init_radare2__()

    def __init_radare2__(self) -> None:
        """Open the target binary and analyse it"""
        self.r2 = r2pipe.open(self.binary)
        self.analyse_all()

    def analyse_all(self):
        """Performs a full analysis of the binary."""
        logger.info(f"Analysing the binary {self.binary}")
        self.r2.cmd('aaa')

    def get_blocks(self, addr: int) -> List[Dict[int, int]]:
        """Find the basic blocks in a function

        Args:
            addr: The address to the function

        Returns:
            A list of dictionaries containing

            - the starting address (`addr`),
            - the size (`size`),
            - the operation address (`opaddr`)
            - the number of instructions (`ninstr`),
            - the address of ecah instruction (`instrs`), and
            - whether or not it has been analysed by radare2 (`traced`)

            for each basic block.

        """
        result = self.r2.cmd(f"afbj @ {addr}")
        blocks = json.loads(result)
        return blocks
