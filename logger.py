import logging

def logger_setup():
    # create logger
    logger = logging.getLogger()
    # log_file = logging.FileHandler('fuzzer.log')
    logger.setLevel(logging.DEBUG)
    # format of the log - timestamp, vulns type + file extension type, file path, error line
    log_format = logging.Formatter(
        %(%d %m, %Y %H:%M:%S)s - %(vultype)s %(\n)s %(fileextension)s %(filepath)s
    )
    # log_file.setFormatter(log_format)

    return logger

fuzzer_logger = logger_setup()
# use : call "from logger import fuzzer_logger"
