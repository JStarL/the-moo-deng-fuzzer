import logging
import sys

def logger_setup(log_type = None): 
    level = logging.DEBUG


    if log_type == 'DEBUG':
        logging.basicConfig(format='(%(asctime)s) %(levelname)s:%(pathname)s-%(lineno)d:%(message)s ',
                            datefmt='%d-%m-%y %I:%M:%S %p',
                            level=level)
    else:
        logging.basicConfig(format='(%(asctime)s) %(levelname)s:%(message)s ',
                        datefmt='%d-%m-%y %I:%M:%S %p',
                        level=level)

    logger = logging.getLogger()
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter('(%(asctime)s) %(levelname)s: %(message)s'))
    logger.addHandler(console_handler)

    return logger

if "-d" in sys.argv or "--debug" in sys.argv or 'DEBUG' in sys.argv:
    log_type = 'DEBUG'
else:
    log_type = None

fuzzer_logger = logger_setup(log_type)
# use : call "from logger import fuzzer_logger"
