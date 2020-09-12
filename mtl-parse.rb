#!/usr/bin/ruby


#`ruby nmap_parse.rb -i results_TCP_Top200Ports_sS_sV.xml > mtl.csv`
`ruby nmap_parse.rb -i results_UDP_Top1024Ports_sU_sV.xml > mtl.csv`
`ruby nmap_parse.rb -i results_TCP_full.xml >> mtl.csv`


#unique open ports across all, pulled from mtl
`cat mtl.csv | grep -vF tcpwrapped | cut -d, -f2 | sort | uniq > ports.txt`


#show all discovered ports, comma seperated for nessus,etc.
system("cat ports.txt | sed -e ':a' -e 'N' -e '$!ba' -e 's/\\n/,/g'   ")


ports='ports.txt'
File.readlines(ports).each do |line|
  puts line.chomp
  `awk '/#{line.chomp}\\/open/ {print $2}' *.gnmap | sort | uniq > #{line.chomp}.open`
end
