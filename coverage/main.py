import r2pipe
import logging

logger = logging.getLogger("coverage")
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


class Binary:
    def __init__(self, elf: str, base_addr: int = 0) -> None:
        """Initialise an instance of the binary class

        Args:
            base_addr: The base address 
            elf: [TODO:description]
        """
        logger.info("Initialising an instance of `binary` with the base address ")
        self.elf = elf
        self.base_addr = base_addr

    def __init_radare2__(self) -> None:
        """Initialise """
        self.r2 = r2pipe.open(self.elf)

        # Analyse the binary
        logger.info(f"Analysing the binary {self.elf}")
        self.r2.cmd("aaa")
