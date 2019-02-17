#!/usr/bin/python
# encoding=utf8
import sys
reload(sys)
sys.setdefaultencoding('utf8')

import json

if len(sys.argv) == 1:
    print "Usage: " + sys.argv[0] + " bloodhound_users.json"
    sys.exit()

bhuserfile = sys.argv[1]
with open(bhuserfile) as data_file:
    data = json.load(data_file)


#print data['users'][0]['Name']
print "name,enabled,displayname,email,title,description"
for i in data['users']:
    oname = i['Name'] 
    oemail = i['Properties']['email']
    oenabled = i['Properties']['enabled']
    otitle = i['Properties']['title']
    odisplay = i['Properties']['displayname']
    odescription = i['Properties']['description']
    print "%s,%s,%s,%s,%s,%s" %(oname,oenabled,odisplay,oemail,otitle,odescription) 

