#!/usr/bin/ruby
#`nmap -iL ips.txt -Pn -O --osscan-limit -sS -sV --top-ports 200 --defeat-rst-ratelimit -open -T3 --script=resolveall,reverse-index --script-args http.useragent="Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko" --script-timeout 500m -oA results_TCP_Top200Ports_sS_sV --stats-every 240s --host-timeout 1080m --randomize-hosts`

system('nmap -iL ips.txt -Pn -O --osscan-limit -sS -sV --top-ports 200 --defeat-rst-ratelimit -open -T3 --script=resolveall,reverse-index --script-args http.useragent="Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko" --script-timeout 500m -oA results_TCP_Top200Ports_sS_sV --stats-every 240s --host-timeout 1080m --randomize-hosts')

