import logging

from functions.helpers import settings
from functions.redReconAbstractBaseClassCredentialsRequired import redReconAbstractBaseClassCredentialsRequired

class netSessions(redReconAbstractBaseClassCredentialsRequired):
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
        command += ' get-netsession '
        command += '-w ' + self.creds.domain + ' '
        command += '-u ' + self.creds.username + ' '
        command += '--hashes ' + self.creds.hashed_password + ' '
        command += "--computername {} '>' {}_net_sessions"

        self.command = command
        return self.command

    def parse(self, inputDirectory):
        logger = logging.getLogger(__name__)

        self.title = ['Net_Sessions']
        self.header = ['Host,Client,Idle Time,Session Time,Username']
        self.data = [[]]

        files = self.searchFiles(inputDirectory, "*_net_sessions")
        for file in files:
            host = file[0]
            extension = file[1]
            lines = file[2]

            ipaddress = None
            idle_time = None
            time = None
            username = None

            for line in lines:
                if line == '\n' and ipaddress != None:
                    self.data[0].append('{0},{1},{2},{3},{4}'.format(host, ipaddress, idle_time, time, username))
                    ipaddress = None
                    idle_time = None
                    time = None
                    username = None
                elif line.startswith("sesi10_cname"):
                    ipaddress = line.rstrip('\n').split(':')[1].lstrip().lstrip('\\')
                elif line.startswith("sesi10_idle_time"):
                    idle_time = line.rstrip('\n').split(':')[1].lstrip()
                elif line.startswith("sesi10_time"):
                    time = line.rstrip('\n').split(':')[1].lstrip()
                elif line.startswith("sesi10_username"):
                    username = line.rstrip('\n').split(':')[1].lstrip()

        return self.title, self.header, self.data