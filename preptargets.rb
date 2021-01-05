#!/usr/bin/ruby


#prep to show first uniq 3 octect only:
#cat out_servers.csv | cut -d "," -f 3 | sort | uniq | cut -d "." -f 1,2,3 | uniq > subnet

#append .0/24 to the end
#cat subnet | sed -e 's/$/.0\/24/'

#append in place
#sed -i -e 's/$/.0\/24/' subnet

#append /32 to the end
#cat subnet | sed -e 's/$/\/32/'

#COMBO - all above, take in ips, show class-c subnets
#cat out_servers.csv | cut -d "," -f 3 | sort | uniq | cut -d "." -f 1,2,3 | uniq | sed -e 's/$/.0\/24/'





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


#sort all targets for 2nd column 
#cat mtl.csv | sort -t, -k2
##web
#cat mtl.csv | sort -t, -k2 | grep http
##ssl
#cat mtl.csv | sort -t, -k2 | grep ssl
##sslscan prep
#cat mtl.csv | sort -t, -k2 | grep ssl | cut -d "," -f 1,2 | sed -e "s/,/:/g"






