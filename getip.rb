#!/usr/bin/ruby

#thx lm, mw %)

require 'optparse'
require 'resolv'
require 'thread'
require 'net/ping'

#checks if the host is up!
def up?(host,flag)
	if flag == true
    		check = Net::Ping::External.new(host)
    		check.ping?
	end
end

#Options Stuff, is this isn't obvious too bad!
options = {}
optparse = OptionParser.new do |opts|
	opts.banner = "Usage: getip.rb [options]"
	opts.on("-r", "--resolvers FILE", "Optional: File of DNS servers, one per line") { |file|
		options[:resolvers] = file
	}
	opts.on("-d", "--domain TEXT", "DNS Domain to lookup hosts from") { |domain|
		options[:domain] = domain
	}
	opts.on("-i", "--hosts FILE", "Input list of hosts to resolve") { |file|
		options[:hosts] = file
	}
	opts.on("-o", "--output FILE", "Where to output our CSV file") { |file|
		options[:out] = file
	}
	opts.on("-x","--ping","Optional: Ping hosts to confirm it is up"){ |flag| options[:ping] = true }

end
optparse.parse!

#Output file and input host file are mandatory.
if(options[:out].nil? or options[:hosts].nil? or options[:domain].nil?)
	puts optparse
	exit
end

#Open our files, read the hosts and chomp those.
outfile = File.new(options[:out], "w")
hosts = IO.readlines(options[:hosts]).map(&:chomp)

# If we don't have a list of resolvers, then don't worry about doing threads.
if(options[:resolvers].nil?)
	#Header output in our output file
	outfile.printf("Hostname,IP,Online\n")

	#Loop through each host
	hosts.each { |hostname|
		begin
			# Resolve the IP address
			ip = Resolv.getaddress(hostname)
			strIP = String(ip)
			status = up?(strIP,options[:ping])
			# Output the results if we got them
			outfile.printf("%s,%s,%s,\n", hostname, ip, status)
			printf("[*] %s\n", hostname)
		rescue
			#Otherwise just put out an error.
			printf("[!] %s\n", hostname)
		end
		#Wait a random amount of time to not overload the server.
		#sleep(rand(0.1...0.4))
	}
else 
	# Put out the header in the output file.
	outfile.printf("DNS Server,Hostname,IP,Online\n")

	#Take each input host and add it to a thread safe queue. 
	queue = Queue.new
	hosts.each { |host|
		queue << host
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
				#Pop a new host off the queue, if its not there just set it to 
				#Nil meaning we're done.
				host = queue.pop(true) rescue nil 
				#If the host was nil (meaning we're done), 
				#skip actually trying so the thread can end.
				if(!host.nil?) 
					begin 
						#Get the IP from our current DNS server
						ip = resolver.getaddress(host)
						strIP = String(ip)
						status = up?(strIP,options[:ping])

						#Wait until we can take control of our file before we print
						mutex_outfile.synchronize { 
							outfile.printf("%s,%s,%s,%s\n", dnsserver, host, ip,status)
						}
						#Wait until we can take control of stdout before we print
						mutex_stdout.synchronize { 
							printf("[*] %s -> %s -> %s -> %s\n", dnsserver, host, ip,status)
						}
					rescue Exception => e
						#Wait until we can take control of stdout before we print
						mutex_stdout.synchronize { 
							printf("[!] %s -> %s\n", dnsserver, host)
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

