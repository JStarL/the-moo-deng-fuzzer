import logging

def logger_setup(log_type):
    logger = logging.getLogger()
    log_file = logging.FileHandler('fuzzer.log')
    # logger.setLevel(logging.INFO)
    
    if log_type == "-d":
        logging.basicConfig(format='(%(asctime)s) %(levelname)s:%(pathname)s-%(lineno)d:%(message)s ',
                            datefmt = '%d-%m-%y %I:%M:%S $p',
                            level=logging.DEBUG)
                            # have to add more formats thread/process things 
    else:
        logging.basicConfig(format='(%(asctime)s) %(levelname)s:%(pathname)s-%(lineno)d:%(message)s ',
                            datefmt = '%d-%m-%y %I:%M:%S $p',
                            level=logging.INFO)

    # format of the log - timestamp, vulns type + file extension type, file path, error line
    '''
    log_format = logging.Formatter(
        %(%d %m, %Y %H:%M:%S)s - %(vultype)s %(\n)s %(fileextension)s %(filepath)s
    )
    log_file.setFormatter(log_format)
    '''
    return logger

def 

fuzzer_logger = logger_setup()
# use : call "from logger import fuzzer_logger"
