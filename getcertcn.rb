#!/usr/bin/ruby

require 'socket'
require 'openssl'

#Check to make sure that we have a file argument and it exists. 
if(ARGV.count != 1) 
	puts "Usage: getcertcn.rb <file>\n   file can include a port (host:port), 443 used by default."
	exit(1)
end
if(!File.exists?(ARGV.first)) 
	puts "ERROR: Unable to open #{ARGV.first}."
	exit(1)
end

#Open the file and loop through it in a block
o_File = File.new(ARGV.first)
o_File.each { |line|
	line.chomp!   #clean it up
	if(line.empty?)  #skip empty lines
		next
	end

	host = ""    #blank vars to hold temp data
	port = 443   #default to port 443 if none specified

	target = line.split(':') #Split the current line to see if we have a port.  Should be in format host:port
	if(target.count == 2)
		port = target[1]
	end

	begin
		socket = TCPSocket.new(line, port) #Make a TCP socket connection
		ssl = OpenSSL::SSL::SSLSocket.new(socket) #Append a buffer from the SSL library onto the socket
		ssl.sync_close = true #sync the closing so that the SSL object will close the TCP socket if it dies
		ssl.connect #Connect.  woohoo its happening!

		#check to see if the distinguished name has a real hostname in it.  If so match out the hostname and set the variable outside the begin block
		host = /CN=((?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\.?)/.match(ssl.peer_cert.subject.to_s)[1]

		#Close the SSL buffer and TCP socket (see sync_close above)
		ssl.sysclose
	rescue Exception => e #Real error handling is for suckers, Exception is way better
			#host = "ERROR: #{e.message}"
                        host = " "
	end

	printf("%s,%s\n", line, host) #Print output to our user. 
}

o_File.close #Close our input file
