import os
import logging

def mkDir(path):
    logger = logging.getLogger(__name__)
    if os.path.exists(path) == False:
        try:
            os.mkdir(path)
            logger.info('Created [%s]', path)
        except:
            if logger != None:
                logger.error('Could not create a temp folder')
            exit()
    else:
        if logger != None:
            logger.info('[%s] Already Exists', path)

def mvDir(path):
    logger = logging.getLogger(__name__)
    if os.path.exists(path) == False:
        logger.error("[%s] Not Found", path)
        exit()
    else:
        try:
            os.chdir(path)
            logger.info('Moved to [%s]', path)
        except:
            logger.error("Could not move into [%s]", path)
            exit()
