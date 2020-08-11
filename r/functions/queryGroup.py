import logging

from functions.helpers import settings
from functions.redReconAbstractBaseClassCredentialsRequired import redReconAbstractBaseClassCredentialsRequired

class queryGroup(redReconAbstractBaseClassCredentialsRequired):
    groupName = None

    checkNull = [groupName]

    def craftCommand(self, preface=None, creds=None):
        logger = logging.getLogger(__name__)
        if preface is not None:
            command = preface + " "
        else:
            command = ""

        if creds is not None:
            self.creds = creds;

        command += 'pth-net rpc group members '
        command += "'"
        command += self.groupName.replace(' ', '\ ')
        command += "' "
        command += "-U '"
        command += self.creds.domain
        command += '\\\\'
        command += self.creds.username
        command += '%'
        command += self.creds.hashed_password
        command += "' --request-timeout 3 -S {} '>' {}_"
        command += self.groupName.replace(' ', '')
        command += '.group'

        self.command = command
        return self.command

    def parse(self, inputDirectory):
        logger = logging.getLogger(__name__)

        self.title = [self.groupName]
        self.header = ['IP Address,Local Domain,Account Group']
        self.data = [[]]

        files = self.searchFiles(inputDirectory, "*.group")
        for file in files:
            host = file[0]
            extension = file[1]
            lines = file[2]

            for line in lines:
                split_string = line.rstrip('\n').split('\\')

                if len(split_string) < 2:
                    logger.error('The input line [%s] in [%s] was too short', line, host)
                else:
                    self.data[0].append('{0},{1},{2}'.format(host, split_string[0], split_string[1]))

        return self.title, self.header, self.data