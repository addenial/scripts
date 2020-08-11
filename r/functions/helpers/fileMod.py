import os
import logging

def formatFile(inputFilePath):
    logger = logging.getLogger(__name__)
    try:
        os.system('dos2unix -q ' + inputFilePath)
        os.system("sed -i '/^$/d' " + inputFilePath)
    except:
        logger.error("Could not format [%s]", inputFilePath)
