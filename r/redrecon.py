import binascii
import hashlib
import logging
import os
import shutil

from functions.helpers.arguments import getArguments, validateArgumentParameters
from functions.helpers.directoryMod import mkDir, mvDir
from functions.helpers.fileMod import formatFile
from functions.helpers.log import configureLogger

from functions.checkForLocalAdmin import checkForLocalAdmin
from functions.credentials import credentials
from functions.fingerData import fingerData
from functions.netSessions import netSessions
from functions.queryGroup import queryGroup
from functions.queryShares import queryShares
from functions.secretsDump import secretsDump
from functions.wmic import wmic

CURRENT_DIRECTORY = "." + os.path.sep

def createCommandPrefix(args):
    command = 'cat '
    if args.input_file[0] == os.path.sep:
        command += args.input_file + ' | '
    else:
        command += '../' + args.input_file + ' | '
    command += 'parallel --no-notice -j ' + str(args.thread_count) + ' '

    return command

def initialPasswordHandle(args):
    logger = logging.getLogger(__name__)

    if args.hashed_password == None and args.password != None:
        nthash = binascii.hexlify(hashlib.new('md4', args.password.encode('utf-16le')).digest())
        ntlmhash = 'aad3b435b51404eeaad3b435b51404ee' + ':' + nthash
    elif args.hashed_password != None:
        nthash = args.hashed_password
        ntlmhash = 'aad3b435b51404eeaad3b435b51404ee' + ':' + nthash
    else:
        nthash = ' None'
        ntlmhash = ' None'

    if args.silent is False:
        print 'Credentials Selected:'
        print '\tDomain: ', args.domain
        print '\tUsername: ', args.username
        print '\tPassword: ', args.password
        print '\tNTLM Hash: ', nthash

    logger.info("Domain: [%s]", args.domain)
    logger.info("Username: [%s]", args.username)
    logger.info("Password: [%s]", args.password)
    logger.info("NTLM Hash: [%s]", ntlmhash)

    return nthash, ntlmhash

if __name__ == '__main__':
    #Command Line Arguments
    args = getArguments()
    validateArgumentParameters(args)

    #Logging
    configureLogger(args)
    logger = logging.getLogger(__name__)

    present_working_directory = os.path.dirname(os.path.realpath(__file__))
    logger.info("Working from [%s]", present_working_directory)

    #Create Hashed Password
    nthash, ntlmhash = initialPasswordHandle(args)
    creds = credentials(args.domain, args.username, args.password, ntlmhash)

    #Ensure Proper Format for Input File
    if args.parse_only is not True:
        formatFile(args.input_file)

    #Make a Directory for Raw and Parsed File Output
    if args.parse_only is True:
        raw_output_directory = args.input_file
        if os.path.exists(raw_output_directory) is not True:
            print("Unable to find raw files to parse...Exiting")
            exit(-1)
    else:
        if args.output_directory == None:
            parsed_output_directory = present_working_directory + os.path.sep + 'Parsed'
            raw_output_directory = present_working_directory + os.path.sep + 'Raw'
        else:
            parsed_output_directory = args.output_directory.rstrip(os.path.sep) + os.path.sep + 'Parsed'
            raw_output_directory = args.output_directory.rstrip(os.path.sep) + os.path.sep + 'Raw'
        mkDir(raw_output_directory)
    mkDir(parsed_output_directory)

    #Generate Parallels Friendly Command Preface
    command = createCommandPrefix(args)

    #Generate Output Filename Prefix & Path
    outputFileName = parsed_output_directory + os.path.sep + args.output_file

    # Move into Raw Directory
    mvDir(raw_output_directory)

    if args.secrets_dump == True:
        secretsDump().run(command, creds, outputFileName, raw_output_directory, args.parse_only)
    if args.local_groups == True:
        query_group = queryGroup()
        query_group.groupName = 'Administrators'
        query_group.run(command, creds, outputFileName, raw_output_directory, args.parse_only)
    if args.rdp_members == True:
        query_group = queryGroup()
        query_group.groupName = 'Remote Desktop Users'
        query_group.run(command, creds, outputFileName, raw_output_directory, args.parse_only)
    if args.finger_data == True:
        fingerData().run(command, outputFileName, raw_output_directory, args.parse_only)
    if args.net_sessions == True:
        netSessions().run(command, creds, outputFileName, raw_output_directory, args.parse_only)
    if args.local_admin == True:
        if args.parse_only is True:
            print "Checking for Local Admin does not currently work in parse only mode"#Still deciding what the best way of handling this is
        else:
            checkForLocalAdmin().run(command, creds, outputFileName, raw_output_directory, args.parse_only)
    if args.net_share == True:
        queryShares().run(command, creds, outputFileName, raw_output_directory, args.parse_only)
    if args.process == True:
        process = wmic()
        process.target = 'process'
        process.run(command, creds, outputFileName, raw_output_directory, args.parse_only)
    if args.service == True:
        service = wmic()
        service.target = 'service'
        service.run(command, creds, outputFileName, raw_output_directory, args.parse_only)

    #Clean Up
    mvDir(present_working_directory)