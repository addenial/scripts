import os
import logging

def executeCommand(command):
    logger = logging.getLogger(__name__)

    print "\tCommand: ", command
    logger.info("Command: [%s]", command)

    try:
        os.system(command)
        logger.info('Executed [%s] Successfully', command)
        return True
    except:
        logger.error('Could not execute command')
        return False
