iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT #allow loopback access
iptables -A OUTPUT -d 255.255.255.255 -j ACCEPT #make sure you can communicate with any DHCP server
iptables -A INPUT -s 255.255.255.255 -j ACCEPT #make sure you can communicate with any DHCP server
iptables -A INPUT -s 172.16.177.0/24 -d 172.16.177.0/24 -j ACCEPT #make sure that you can communicate within your own network
iptables -A OUTPUT -s 172.16.177.0/24 -d 172.16.177.0/24 -j ACCEPT
iptables -A FORWARD -i eth0 -o tun0 -j ACCEPT
iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT # make sure that eth+ and tun+ can communicate
iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE # in the POSTROUTING chain of the NAT table, map the tun+ interface outgoing packet IP address, cease examining rules and let the header be modified, so that we don't have to worry about ports or any other issue - please check this rule with care if you have already a NAT table in your chain
iptables -A OUTPUT -o eth0 ! -d X.X.X.X -j DROP # VPN IP or pivot box -if destination for outgoing packet on eth+ is NOT a.b.c.d, drop the packet, so that nothing leaks if VPN disconnects
ip6tables -A OUTPUT -j REJECT #block all egress ipv6, not using it
