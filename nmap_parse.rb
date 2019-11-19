require 'nmap/parser'
require 'optparse'
parser = Nmap::Parser.new
file=0

#thx rr %)

options = {}
optparse = OptionParser.new do|opts|
	#Help Option Contents
	opts.banner = "	
Usage:
			
nmap_parse.rb -i results_TCP_full.xml > results_TCP_full.csv - Parse output to CSV file\n\n"
	
	#Define input 
	options[:inputfile] = nil
	opts.on( '-i', '--inputfile FILE', 'Parse the nmap scan file' ) do|file1|
		options[:inputfile] = file1
	end
 
	#Defines the help option
	opts.on( '-h', '--help', 'Display this screen' ) do
		puts opts
		exit
	end
end

#Help Menu
def help() 
	puts "\nnmap_parse.rb -i results_TCP_full.xml > results_TCP_full.csv - Parse output to CSV file\n\n -i, --inputfile FILE             Parse the nmap scan file\n -h, --help                       Display this screen"
end
 
#If an invalid option is passed, then display help and exit, otherwise parse the options
begin
	optparse.parse!
	if options[:inputfile]==nil #If no argument is passed, then display help and exit
		help()
		exit
	end
rescue OptionParser::ParseError
	help() #iIf a bad argument was passed
	exit
end


file=options[:inputfile] #Set the passed argument
last = File.open(file) { |f| f.extend(Enumerable).inject { |_,ln| ln } } #read the last line of the file
if last.include? '</nmaprun>'  #See if the last line contains </nmaprun> which indicates the scan has completed successfully, otherwise quit
	parser = Nmap::Parser.parsefile(file)  
		
	#Figure out what type of scan we are doing - ICMP or TCP/UDP
	if ((parser.session.scan_args.include? '-sP') || (parser.session.scan_args.include? '-PE') || (parser.session.scan_args.include? ' -sn'))
		parser.hosts("up") do |host|
		#It counts as a result for ICMP if one of the below responses are received
			if ((host.reason == "echo-reply") || (host.reason == "arp-response") || (host.reason == "localhost-response"))
				puts "#{host.ip4_addr},icmp,icmp,#{host.hostname()}".encode("us-ascii")
			end
		end
	else 
	#If we are here then we must be parsing TCP,UDP or SCTP
	parser.hosts("up") do |host|
		host.getports(:any) do |port|		
			if port.state == "open"	#only look at actual open ports, skip open|filtered
				#IP,port/protocol,basic port version,dns,service version info						
				#if port.service.tunnel==nil
				#	puts "#{host.ip4_addr},#{port.num},#{port.proto},#{port.service.name},#{host.hostname()},#{port.service.product} #{port.service.version} #{port.service.extra}".encode("us-ascii")
			
				#end
				puts "#{host.ip4_addr},#{port.num},#{port.proto},#{port.service.name}#{port.service.tunnel},#{host.hostname()},#{port.service.product}#{port.service.version}#{port.service.extra}".encode("us-ascii")
			end
		end		
	end
end
else
	puts "\nThe input file #{file} does not appear to be a valid, complete Nmap XML output file.\nThe last line does not contain the </nmaprun> closing tag.
		
	1) Was Nmap run with XML output (-oX)?
	2) Are you sure the scan finished?\n
	To parse what is available, try adding </nmaprun> as the last line."
	Process.exit
end
	
	







	
	
	
	
	

