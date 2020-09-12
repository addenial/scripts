#!/usr/bin/ruby


#preptargets.rb

#show only ip:port from mtl csv
#replace , with :
system(' cat mtl.csv | cut -d "," -f 1,2 | sed -e "s/,/:/g"  ')




#to grep for multiple values - for example web instaces
#ruby preptargets.rb  | grep -E '80|443|8080|8443'


#to prepend with http or https
#cat 80.open | sed -e 's/^/http:\/\//'
#cat 443.open | sed -e 's/^/https:\/\//'


#append "/index.html" to end of each line 
#cat 80.open | sed -e 's/$/\/index.html/'


#to remove all instances of character "$" from a file
#cat domain_computers.txt |  sed -e "s/\\$//g"
#sed -e "s/\\$//g" domain_computers.txt


#display to screen without word wrap (useful for screenshots)
#cat results_TCP_full.xml  | cut -c1-80





