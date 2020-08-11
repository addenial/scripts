import logging

from functions.helpers import settings
from functions.redReconAbstractBaseClassCredentialsRequired import redReconAbstractBaseClassCredentialsRequired

class wmic(redReconAbstractBaseClassCredentialsRequired):
    dependencies = [settings.WMIC]

    target = None

    checkNull = [target]

    def craftCommand(self, preface=None, creds=None):
        logger = logging.getLogger(__name__)
        if preface is not None:
            command = preface + " "
        else:
            command = ""

        if creds is not None:
            self.creds = creds;

        command += settings.WMIC
        command += ' -U ' + self.creds.domain + '/'
        command += self.creds.username + '%'
        command += self.creds.hashed_password + ' '
        command += "//{} " + "'" + '"Select * from '
        if self.target == 'process':
            command += ' Win32_Process"' + "'"
            command += " '>' {}_process"
        elif self.target == 'service':
            command += ' Win32_Service"' + "'"
            command += " '>' {}_service"

        self.command = command
        return self.command

    def parse(self, inputDirectory):
        logger = logging.getLogger(__name__)

        self.title = [self.target]
        self.header = ['AcceptPause,AcceptStop,Caption,CheckPoint,CreationClassName,DelayedAutoStart,Description,DesktopInteract,' \
             'DisplayName,ErrorControl,ExitCode,InstallDate,Name,PathName,ProcessId,ServiceSpecificExitCode,ServiceType,' \
             'Started,StartMode,StartName,State,Status,SystemCreationClassName,SystemName,TagId,WaitHint']
        self.data = [[]]

        files = self.searchFiles(inputDirectory, ("*_" + self.target))
        for file in files:
            host = file[0]
            extension = file[1]
            lines = file[2]

            for line in lines:
                try:
                    values = line.split('|')
                    item = host + ","
                    for value in values:
                        item = item + value.replace(',', '') + ",";

                    self.data[0].append(item[:-2])#Clean up trailing comma and a newline left by wmic
                except Exception as e: logger.debug(e)

        return self.title, self.header, self.data