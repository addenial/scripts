import logging

from abc import ABCMeta, abstractmethod
from redReconAbstractBaseClass import redReconAbstractBaseClass
from helpers.executeCommand import executeCommand

class redReconAbstractBaseClassCredentialsRequired(redReconAbstractBaseClass):
    __metaclass__ = ABCMeta

    @abstractmethod
    def craftCommand(self, preface=None, creds=None):
        pass

    def execute(self, preface=None, creds=None):
        if creds is not None:
            self.creds = creds
        state = self.checkDependencies(self.dependencies, [self.creds.domain, self.creds.username, self.creds.hashed_password])
        if state is True:
            return executeCommand(self.craftCommand(preface, creds))

    @property
    def creds(self):
        return self._creds

    @creds.setter
    def creds(self, value):
        self._creds = value

    def run(self, prefix, creds, outputFilename, dir, parse_only_mode):
        if parse_only_mode is not True:
            self.execute(prefix, creds)
        self.parse(dir)
        self.writeCSV(outputFilename)