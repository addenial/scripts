import argparse

def getArguments():
    parser = argparse.ArgumentParser(description='redrecon')
    parser.add_argument('--output_file', dest='output_file', default='RedRecon', help='Prefix Output File Names')
    parser.add_argument('--output_directory', dest='output_directory', help='Output Directory')
    parser.add_argument('-t', '--thread_count', dest='thread_count', default=1, type=int, help='Number of Threads, Default: 1')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Additional Debugging Information')
    parser.add_argument('-s', '--silent', dest='silent', action='store_true', help='Suppress Info in Log File')
    parser.add_argument('--parse_only', dest='parse_only', action='store_true', help="Parse existing raw files, treat input as directory with raw files")

    required_arguments = parser.add_argument_group('Required')
    required_arguments.add_argument('-i', '--input_file', dest='input_file', required=True, help='Input File of Newline Seperated IP Addresses or Host Names')

    authentication_group = parser.add_argument_group('Authentication Parameters')
    authentication_group.add_argument('-d', '--domain', dest='domain', help='Domain Name')
    authentication_group.add_argument('-u', '--username', dest='username', help='Username')
    authentication_group_password = authentication_group.add_mutually_exclusive_group()
    authentication_group_password.add_argument('-p', '--plaintext_password', dest='password', help='Password')
    authentication_group_password.add_argument('-P', '--hashed_password', dest='hashed_password', help='NTLM Hashed Password')

    parse_group = parser.add_argument_group('Parse Choices')
    parse_group.add_argument('--secrets_dump', dest='secrets_dump', action='store_true', help='Execute and Parse secretsdump.py')
    parse_group.add_argument('--local_groups', dest='local_groups', action='store_true', help='Query Local Admin Group Members')
    parse_group.add_argument('--rdp_members', dest='rdp_members', action='store_true', help='Query Remote Desktop Group Members')
    parse_group.add_argument('--finger_data', dest='finger_data', action='store_true', help='Responder Finger')
    parse_group.add_argument('--net_sessions', dest='net_sessions', action='store_true', help='Query All Sessions')
    parse_group.add_argument('--local_admin', dest='local_admin', action='store_true', help='Check to see if you have Local Admin')
    parse_group.add_argument('--net_share', dest='net_share', action='store_true', help='Query for Connected Shares')
    parse_group.add_argument('--process', dest='process', action='store_true', help='Get Processes [BETA]')
    parse_group.add_argument('--services', dest='service', action='store_true', help='Get Services [BETA]')
    parse_group.add_argument('--the_works', dest='everything', action='store_true', help='Parse All The Things!')

    args = parser.parse_args()
    return args

def validateArgumentParameters(args):
    if args.everything == True:
        args.secrets_dump = True
        args.local_groups = True
        args.rdp_members = True
        args.finger_data = True
        args.net_sessions = True
        args.local_admin = True
        args.net_share = True
        args.process = True
        args.service = True

        if args.parse_only == False:
            # Validate Parameters
            if args.secrets_dump == False and args.local_groups == False and args.rdp_members == False and args.finger_data == False \
                    and args.net_sessions == False and args.local_admin == False and args.net_share == False and args.process == False\
                    and args.service == False:
                print 'No Parse Choice was selected'
                exit()

            if args.secrets_dump == True or args.local_groups == True or args.rdp_members == True or args.net_sessions == True \
                    or args.local_admin == True or args.net_share == True or args.process == True or args.service == True:
                if args.domain == None or args.username == None or (args.password == None and args.hashed_password == None):
                    print 'No credentials were provided despite Parse Choice(s) requiring credentials'
                    exit()