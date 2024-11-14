from typing import Dict, List
import r2pipe
import logging
import time

logger = logging.getLogger("coverage")
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


class Binary:
    """The binary to be analysed

    Attributes: 
        binary: Path to the binary file
        base_addr: Starting address of the program's memory region
        r2: The instance of r2pipe that is opened for the target binary
    """
    def __init__(self, binary: str, base_addr: int = 0) -> None:
        """Initialise an instance of the binary class

        Args:
            base_addr: The base address
            binary: Path of the target binary
        """
        logger.info(
            f"Initialising an instance of `binary` with the base address {base_addr} and ELF file {binary}"
        )
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
        self.r2.cmd("aaa")

    def get_blocks(self, addr: int) -> List[Dict]:
        """Get the control flow graph of a function

        Args:
            addr: The address of the function

        Returns:
            A list of dictionaries representing the basic blocks.
        """
        return self.r2.cmdj(f"afbj @ {addr}")

    def run_with_log(self, breakpoints: [int]) -> [int]:
        self.r2.cmd("ood")

        for addr in breakpoints:
            addr = self.base_addr + addr
            logger.info(f"Adding breakpoint at {hex( addr )}")
            self.r2.cmd(f"db {addr} if 0")  # Breakpoint with a false condition
            self.r2.cmd(f"dbc {addr} '!echo \"Passed through address {addr}\"'")  # Log message on hit

        # Start running
        self.r2.cmd("dc")

        # Periodically check if the process is still running
        while True:
            status = self.r2.cmd("dcs").strip()
            if status == "finished":
                break
            time.sleep(0.5)

