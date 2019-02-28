#!/bin/python
import xml.etree.ElementTree as ET
import sys

if len(sys.argv) == 1:
     print "Usage: " + sys.argv[0] + " result.xml"
     sys.exit()

masscan_file = sys.argv[1]
tree = ET.parse(masscan_file)
root = tree.getroot()

for data in root.iter('address'):
    ip = data.get('addr')
    for data in root.iter('port'):
        port = data.get('portid')
    print(ip + ':' + port)
