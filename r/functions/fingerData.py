import logging

from redReconAbstractBaseClass import redReconAbstractBaseClass
from functions.helpers import settings


class fingerData(redReconAbstractBaseClass):
    dependencies = [settings.FINGERDATA]

    def craftCommand(self, preface=None):
        logger = logging.getLogger(__name__)
        if preface is not None:
            command = preface + " "
        else:
            command = ""
        command += 'python '
        command += settings.FINGERDATA
        command += ' -i {} '
        command += "'>' {}_smb_info.finger"

        self.command = command
        return self.command

    def parse(self, inputDirectory):
        logger = logging.getLogger(__name__)
        self.title = ['finger_data']
        self.header = ['IP Address,Domain,Hostname,SMB Signing,OS Version,LANMAN Client']
        self.data = [[]]

        files = self.searchFiles(inputDirectory, '*_smb_info.finger')
        for file in files:
            host = file[0]
            extension = file[1]

            signing_enabled = ''
            os_version_one = ''
            os_version_two = ''
            netbios_hostname = ''
            machine_domain = ''

            for line in file[2]:
                line = line.rstrip('\n')

                if 'SMB signing' in line:
                    signing_enabled = line.split(':')[1][1:]
                elif 'Os version' in line:
                    os_version_one = line.split(':')[1].replace('\'', '').strip()
                elif 'Lanman Client' in line:
                    os_version_two = line.split(':')[1].replace('\'', '').strip()
                elif 'Machine Hostname' in line:
                    netbios_hostname = line.split(':')[1].replace('\'', '').strip()
                elif 'This machine is part of the' in line:
                    machine_domain = line.split('\'')[1].strip()

            self.data[0].append('{0},{1},{2},{3},{4},{5}'.format(host, machine_domain, netbios_hostname, signing_enabled, os_version_one,
                                             os_version_two))

        return self.title, self.header, self.data