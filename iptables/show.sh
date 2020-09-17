#!/bin/bash
iptables -L -v
echo "-----------"
iptables -L -v -t nat
echo "-----------"
ip6tables -L -v
