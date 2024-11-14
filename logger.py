import logging
import sys

def logger_setup(log_type = None):
    if log_type == "DEBUG":
        level = logging.DEBUG
    else:
        level = logging.INFO

    logging.basicConfig(format='(%(asctime)s) %(levelname)s:%(pathname)s-%(lineno)d:%(message)s ',
                        datefmt='%d-%m-%y %I:%M:%S %p',
                        level=level)
    
    logger = logging.getLogger()
    log_file = logging.FileHandler('fuzzer.log')
    logger.addHandler(log_file)
    
    # logger.setLevel(logging.INFO)
    
    if level == logging.DEBUG:
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
