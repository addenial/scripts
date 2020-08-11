import logging
import os
import glob
import re

from abc import ABCMeta, abstractmethod
from helpers.executeCommand import executeCommand
from helpers.writeFile import writeFile

class redReconAbstractBaseClass(object):
    __metaclass__ = ABCMeta

    dependencies = None
    checkNull = None

    title = None
    header = None
    data = None

    def checkDependencies(self, checkPaths, checkNull):
        logger = logging.getLogger(__name__)
        flag = True
        if checkPaths is not None:
            for path in checkPaths:
                try:
                    if os.path.exists(path) is False:
                        logger.debug("Dependency %s not found for %s", path, __name__)
                        flag = False
                except Exception as e: logger.debug(e)
        if checkNull is not None:
            for variable in checkNull:
                if variable is None:
                    logger.debug("Dependency not set for %s", __name__)
                    flag = False

        return flag

    @abstractmethod
    def craftCommand(self, preface=None):
        pass

    def execute(self, preface=None):
        state = self.checkDependencies(self.dependencies, self.checkNull)
        if state is True:
            return executeCommand(self.craftCommand(preface))

    @abstractmethod
    def parse(self, inputDirectory):
        pass

    def searchFiles(self, inputDirectory, suffix):
        logger = logging.getLogger(__name__)
        files = []
        logger.debug("Searching File Path: [%s]", (inputDirectory + os.path.sep + suffix))
        for file_path in glob.glob(inputDirectory + os.path.sep + suffix):
            logger.debug("Opening: [%s]", file_path)
            with open(file_path, 'r') as f:
                host = re.findall( r'[0-9]+(?:\.[0-9]+){3}', f.name )[0]
                extension = f.name.split('.')[-1]
                logger.debug('Procesing for host [%s]', host)

                file_data = f.readlines()
                files.append([host, extension, file_data])

        return files

    def writeCSV(self, outputFile):
        logger = logging.getLogger(__name__)
        for cnt in range(len(self.data)):
            if len(self.data[cnt]) > 0:
                title = outputFile + '_' + self.title[cnt] + '.csv'
                logger.info("Writing: [%s]", title)
                writeFile(title, self.header[cnt], self.data[cnt])

    def run(self, prefix, outputFilename, dir, parse_only_mode):
        if parse_only_mode is not True:
            self.execute(prefix)
        self.parse(dir)
        self.writeCSV(outputFilename)

