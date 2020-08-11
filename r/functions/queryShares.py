import logging

from functions.helpers import settings
from functions.redReconAbstractBaseClassCredentialsRequired import redReconAbstractBaseClassCredentialsRequired

class queryShares(redReconAbstractBaseClassCredentialsRequired):
    dependencies = [settings.PYWERVIEW]

    def craftCommand(self, preface=None, creds=None):
        logger = logging.getLogger(__name__)
        if preface is not None:
            command = preface + " "
        else:
            command = ""

        if creds is not None:
            self.creds = creds;

        command += 'python '
        command += settings.PYWERVIEW
        command += ' get-netshare '
        command += '-w ' + self.creds.domain + ' '
        command += '-u ' + self.creds.username + ' '
        command += '--hashes ' + self.creds.hashed_password + ' '
        command += "--computername {} '>' {}_shares"

        self.command = command
        return self.command

    def parse(self, inputDirectory):
        logger = logging.getLogger(__name__)

        self.title = ['Shares']
        self.header = ['IP Address,NetName,Remark,Type']
        self.data = [[]]

        files = self.searchFiles(inputDirectory, "*_shares")
        for file in files:
            host = file[0]
            extension = file[1]
            lines = file[2]

            for line in lines:
                if line == '\n':
                    self.data[0].append('{0},{1},{2},{3}'.format(host, NetName, Remark, Type))
                elif line.startswith('shi1_netname'):
                    NetName = line.rstrip('\n').split(':')[1].lstrip()
                elif line.startswith('shi1_remark'):
                    Remark = line.rstrip('\n').split(':')[1].lstrip()
                elif line.startswith('shi1_type'):
                    Type = line.rstrip('\n').split(':')[1].lstrip()

        return self.title, self.header, self.data