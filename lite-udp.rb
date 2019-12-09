#!/usr/bin/ruby
`nmap -iL ips.txt -Pn -sU -sV --top-ports 1024 -T3 --defeat-icmp-ratelimit --script=reverse-index --script-timeout 500m -oA results_UDP_Top1024Ports_sU_sV --stats-every 240s --host-timeout 1080m`
