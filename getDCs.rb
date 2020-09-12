#!/usr/bin/ruby   





#Check to make sure that we have a file argument and it exists. 
if(ARGV.count != 1) 
	puts "Usage: getDCs.rb <domain name>\n  domain.local"
	exit(1)
end

puts "\nSearching DCs for -----> #{ARGV.first} \n\n"

$targetD = ARGV.first

#temp file
system("nslookup #{$targetD}  > _temp_DCs.txt ")
#grepping for IPv4 addresses
system('cat _temp_DCs.txt | cat _temp_DCs.txt | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | sort | uniq > DCs.txt    ') 

#common windows ports only
system("nmap -Pn -sS -p 53,88,445,3389 --open -iL DCs.txt -n -oA getDCs")

#check if DCs respond to ping only
system('nmap -sn -iL DCs.txt -n -oA getDCs-ping ')


#show if hosts responded to ICMP ping 
puts "\n ICMP responses from:"
system('cat getDCs-ping.gnmap |  grep "Up" | cut -d " " -f 2  ')


#show open 88 Kerberos for reference
puts "\n TCP 88 Open:"
system(' awk "/88\/open/ {print $2}" getDCs.gnmap  | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | sort | uniq ' )

#show open 445 SMB
puts "\n TCP 445 Open:"
system(' awk "/445\/open/ {print $2}" getDCs.gnmap  | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | sort | uniq ' )

#show open 389 LDAP
puts "\n TCP 389 Open:"
system(' awk "/389\/open/ {print $2}" getDCs.gnmap  | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | sort | uniq ' )

#show only open 53 DNS ports
puts "\n TCP 53 Open:"
system(' awk "/53\/open/ {print $2}" getDCs.gnmap | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | sort | uniq ' )






