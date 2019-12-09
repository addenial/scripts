sudo nmap -iL ips.txt -Pn -n -sS -p- -T4 --script=reverse-index --script-timeout 500m -oA results_TCP_full --stats-every 240s --host-timeout 1080m
