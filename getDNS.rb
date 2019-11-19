#!/usr/bin/ruby

#thx lm %)

require 'optparse'
require 'resolv'
require 'thread'

#Options Stuff, is this isn't obvious too bad!
options = {}
optparse = OptionParser.new do |opts|
	opts.banner = "Usage: getDNS.rb [options]"
	opts.on("-r", "--resolvers FILE", "Optional: File of DNS servers, one per line") { |file|
		options[:resolvers] = file
	}
	opts.on("-d", "--domain TEXT", "DNS Domain to lookup hosts from") { |domain|
		options[:domain] = domain
	}
	opts.on("-i", "--ips FILE", "Input list of IPs to resolve") { |file|
		options[:ips] = file
	}
	opts.on("-o", "--output FILE", "Where to output our CSV file") { |file|
		options[:out] = file
	}
end
optparse.parse!

#Output file and input host file are mandatory.
if(options[:out].nil? or options[:ips].nil? or options[:domain].nil?)
	puts optparse
	exit
end

#Open our files, read the ips and chomp those.
outfile = File.new(options[:out], "w")
ips = IO.readlines(options[:ips]).map(&:chomp)

# If we don't have a list of resolvers, then don't worry about doing threads.
if(options[:resolvers].nil?)
	#Header output in our output file
	outfile.printf("IP,Hostname\n")

	#Loop through each ip
	ips.each { |ip|
		begin
			# Resolve the hostname
			hostname = Resolv.getname(ip)

			# Output the results if we got them
			outfile.printf("%s,%s\n", ip, hostname)
			printf("[*] %s\n", ip)
		rescue
			#Otherwise just put out an error.
			printf("[!] %s\n", ip)
		end
		#Wait a random amount of time to not overload the server.
		sleep(rand(0.1...0.4))
	}
else 
	# Put out the header in the output file.
	outfile.printf("DNS Server,IP,Hostname\n")

	#Take each input ip and add it to a thread safe queue. 
	queue = Queue.new
	ips.each { |ip|
		queue << ip
	}

	#Array to hold all of our threads.
	threads = []

	#Create mutexes for our output so we don't overwrite each other.
	mutex_stdout = Mutex.new
	mutex_outfile = Mutex.new

	#Get our file and chomp each line.
	resolvers = IO.readlines(options[:resolvers]).map(&:chomp)

	# Loop through the resolver file and create a thread for each server.
	resolvers.each { |dnsserver|
		threads << Thread.new(dnsserver) {
			# Setup our own DNS resolver. 
			resolver = Resolv::DNS.new(:nameserver => [dnsserver], :search =>[options[:domain]], :ndots => 1)

			#Loop until there's nothing left in the queue. 
			until queue.empty? 
				#Pop a new ip off the queue, if its not there just set it to 
				#Nil meaning we're done.
				ip = queue.pop(true) rescue nil 
				#If the ip was nil (meaning we're done), 
				#skip actually trying so the thread can end.
				if(!ip.nil?) 
					begin 
						#Get the hostname from our current DNS server
						host = resolver.getname(ip) 

						#Wait until we can take control of our file before we print
						mutex_outfile.synchronize { 
							outfile.printf("%s,%s,%s\n", dnsserver, ip, host)
						}
						#Wait until we can take control of stdout before we print
						mutex_stdout.synchronize { 
							printf("[*] %s -> %s -> %s\n", dnsserver, ip, host)
						}
					rescue Exception => e
						#Wait until we can take control of stdout before we print
						mutex_stdout.synchronize { 
							printf("[!] %s -> %s\n", dnsserver, ip)
						}
					end
				end
				#Sleep some set of time so we don't overload our server
				sleep(rand(0.1...0.5))
			end
		}
	}
end

#Wait for our threads to end.
threads.each { |t|
	t.join
}
