#!/usr/bin/ruby

#prep ip:port for all ssl/tls services found in mtl
#`sed 's/$/:443/' 443.open > ssltargets.txt`
#anyway to autodetect if its tlsssl?
#`sed 's/$/:4055/' 4055.open >> ssltargets.txt`


#sslscan --targets=ssltargets.txt --xml=results_sslscan.xml
#python3 sslscan_parse.py -i results_sslscan.xml -o results_sslscan.csv


#grep for sslv3
puts "\nSSLv3 Protocol Support-"
puts `cat results_sslscan.csv  | grep SSLv3 | cut -d, -f1,2 | sort | uniq | sed -e 's/,/:/g'`
#grep for tlsv1
puts "\nTLSv1.0 Protocol Support-"
puts `cat results_sslscan.csv  | grep TLSv1.0 | cut -d, -f1,2 | sort | uniq | sed -e 's/,/:/g'`
#weak ciphers
puts "\nRC4 Weak Cipher Support-"
puts `cat results_sslscan.csv  | grep RC4 | cut -d, -f1,2 | sort | uniq | sed -e 's/,/:/g'`

puts "\nTriple DES Weak Cipher Support-"
puts `cat results_sslscan.csv  | grep DES-CBC3 | cut -d, -f1,2 | sort | uniq | sed -e 's/,/:/g'`

puts "\nDHE 1024 bits Weak Cipher Support-"
puts `cat results_sslscan.csv  | grep 'DHE 1024' | cut -d, -f1,2 | sort | uniq | sed -e 's/,/:/g'`
