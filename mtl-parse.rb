#!/usr/bin/ruby

#unique open ports across all, pulled from mtl
`cat mtl.csv | grep -vF tcpwrapped | cut -d, -f2 | sort | uniq > ports.txt`



ports='ports.txt'
File.readlines(ports).each do |line|
  puts line.chomp
  `awk '/#{line.chomp}\\/open/ {print $2}' *.gnmap | sort | uniq > #{line.chomp}.open`
end

