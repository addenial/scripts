#!/usr/bin/env python
# Parses masscan xml file into either a list of service visioning nmap commands or an MTL style CSV.
# By: Michael Contino
# Version: 0.1.0
# Last Updated: 12/4/16
# import of the things (all python default)
import argparse
import csv
import xml.etree.ElementTree

#thx contino %) 

# parse all of the required arguments
parser = argparse.ArgumentParser(description='Parses masscan xml file into either a list of service visioning nmap commands or an MTL style CSV.')
parser.add_argument('-f', '--file', required=True, help='The XML file outputted by masscan (-oX option)')
parser.add_argument('-p', '--parameters', required=False, help='A list of nmap parameters to use when generating command list (testing)')
parser.add_argument('-n', '--nmaps', action="store_true", required=False, help='Generate nmap service visioning commands instead of a csv')
parser.add_argument('-b', '--banners', action="store_true", required=False, help='Weather or not banners should be parsed into the csv (beta)')
parser.add_argument('-o', '--output', required=False, help='The output file in csv format or nmap commands if -n supplied.')
args = vars(parser.parse_args())

# Remove all those Dupes
def noHash(seq):
    seen = set()
    return [ x for x in seq if str( x ) not in seen and not seen.add( str( x ) )]


# Try to open the specified xml file and find the root
xml_root = xml.etree.ElementTree.parse(open(args['file'], 'r')).getroot()

all_open_ports = []

for host in xml_root.findall('host'):
    host_open_ports = []
    ip_address = host[0].get('addr')
    for port in host[1]:
        open_port = port.get('portid')
        port_type = port.get('protocol')

        if args['banners']:
            for banner in port:
                port_banner = banner.get('banner')
                port_service = banner.get('name')
                if port_service == None:
                    port_service = "Unknown"
    if args['banners']:
        host_open_ports.append([ip_address, port_type , open_port, port_service, port_banner])
    else:
        host_open_ports.append([ip_address, port_type, open_port])
    all_open_ports.append(host_open_ports)

# switch to writing nmap commands if specified
if args['nmaps']:
    list_nmap_commands = []
    for port in noHash(all_open_ports):
        # if open port is tcp ensure its reflected in the nmap command
        if port[0][1] == 'tcp':
            # if the user is providing their own parameters use them instead
            if args['parameters']:
                list_nmap_commands.append(("nmap -sS " + str(args['parameters']) + "  -p " + port[0][2] + "-oX " + port[0][0] + "#" + port[0][2] + ".xml " + port[0][0]))
            # else use the default group wide service visioning settings
            else:
                list_nmap_commands.append(("nmap -vv -sV --version-all -sS -PN --max-scan-delay 100ms --max-retries 3 --min-rtt-timeout 1500ms --max-rtt-timeout 1500ms -p " + port[0][2] + " -oX " + port[0][0] + "#" + port[0][2] + ".xml " + port[0][0]))
        # if open port is udp (beta) ensure its reflected in the nmap command
        if port[0][1] == 'udp':
            # if the user is providing their own parameters use them instead
            if args['parameters']:
                list_nmap_commands.append(("nmap -sU " + str(args['parameters']) + "  -p " + port[0][2] + "-oX " + port[0][0] + "#" + port[0][2] + ".xml " + port[0][0]))
            # else use the default group wide service visioning settings
            else:
                list_nmap_commands.append(("nmap -vv -sV --version-all -sU -PN --max-scan-delay 100ms --max-retries 3 --min-rtt-timeout 1500ms --max-rtt-timeout 1500ms -p " + port[0][2] + " -oX " + port[0][0] + "#" + port[0][2] + ".xml " + port[0][0]))

    # if the output file is specified write commands to that file
    if args['output']:
        out_file = open(args['output'], 'w')
        for command in sorted(set(list_nmap_commands)):
            out_file.write(command + "\n")

    # if output is not specified, print commands to the screen
    else:
        print "Listing Nmap Commands"
        for command in sorted(set(list_nmap_commands)):
            print command

# Else just write all open ports to ouput
else:
    # if output is specified write out the csv file
    if args['output']:
        # however if banners is also specified, write those to the CSV as well
        if args['banners']:
            out_file = csv.writer(open(args['output'], 'w'), delimiter=',', lineterminator='\n')
            out_file.writerow(('IP Address', 'Protocol', 'Port', 'Service', 'Banner'))
            for port in noHash(all_open_ports):
                out_file.writerow(port[0])
        else:
            out_file = csv.writer(open(args['output'], 'w'), delimiter=',', lineterminator='\n')
            out_file.writerow(('IP Address', 'Protocol', 'Port'))
            for port in noHash(all_open_ports):
                out_file.writerow(port[0])

    # if output is not specified, print to the screen
    else:
        # however if banners is also specified, write those to console as well
        if args['banners']:
            print "IP Address\tProtocol\tPort\tService\tBanner"
            for port in noHash(all_open_ports):
                print port[0][0], "\t", port[0][1], "\t", port[0][2], "\t", port[0][3], "\t", port[0][4]
        # else just write the normal format to the screen
        else:
            print "IP Address\tProtocol\tPort"
            for port in noHash(all_open_ports):
                print port[0][0], "\t", port[0][1], "\t", port[0][2]

