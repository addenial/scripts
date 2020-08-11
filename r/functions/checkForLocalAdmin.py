import logging

from functions.helpers import settings
from redReconAbstractBaseClassCredentialsRequired import redReconAbstractBaseClassCredentialsRequired

class checkForLocalAdmin(redReconAbstractBaseClassCredentialsRequired):
    dependencies = [settings.PYWERVIEW]

    def craftCommand(self, preface=None, creds=None):
        if preface is not None:
            command = preface + " "
        else:
            command = ""
        command += 'python '
        command += settings.PYWERVIEW
        command += ' invoke-checklocaladminaccess '
        command += '-w ' + self.creds.domain + ' '
        command += '-u ' + self.creds.username + ' '
        command += '--hashes ' + self.creds.hashed_password + ' '
        command += "--computername {} '>' {}_local_admin"

        self.command = command
        return self.command

    def parse(self, inputDirectory):
        self.title = ['Has_Local_Admin']
        self.header = ['IP Address,Domain,Username,Password,Has Local Admin']
        self.data = [[]]

        files = self.searchFiles(inputDirectory, "*_local_admin")
        for file in files:
            host = file[0]
            for line in file[2]:
                self.data[0].append('{0},{1},{2},{3},{4}'.format(host, self.creds.domain, self.creds.username, self.creds.hashed_password, line.rstrip('\n')))

        return self.title, self.header, self.data
