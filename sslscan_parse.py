# thx Jesse N %) 

from xml.etree import ElementTree
import csv
import argparse
import sys
import os


class CSVCreate:
    def __init__(self, root, outputfile):
        self.f = open(outputfile, 'w', newline='')
        self.csvwriter = csv.writer(self.f)
        self.root = root

    def write(self):
        head = ['IP', 'Port', 'Vulnerable to Heartbleed', 'TLS Compression', 'TLS Session Renegotiation', 'Certificate Subject Domain', "Certificate Alt Domain Names", "Certificate Expiration","Signature Algorithm","PK Error" , "PK Type","PK Bits","Certificate Issuer" ,"Self-Signed" ,"Valid Start" ,"Valid End" , "Supported SSL Version", "SSL Version Status", "SSL Cipher Bits", "SSL Cipher","cipher detail"]

        self.csvwriter.writerow(head)

        for ssltest in self.root.findall('ssltest'):
            ip = ssltest.attrib['host']

            port = ssltest.attrib['port']

            heartbleedvulnerability = []
            for hvuln in ssltest.iter('heartbleed'):
                if int(hvuln.attrib['vulnerable']) is 1:
                    heartbleedvulnerability.append(hvuln.attrib['sslversion'])
            if heartbleedvulnerability:
                if len(heartbleedvulnerability) > 1:
                    heartbleed = "[!] " + "; ".join(heartbleedvulnerability) + " are vulnerable to heartbleed"
                else:
                    heartbleed = "[!] " + str(heartbleedvulnerability) + " is vulnerable to heartbleed"
            else:
                heartbleed = "No"
            
            if int(ssltest.find('compression').attrib['supported']) is 0:
                compression = "Compression disabled"
            else:
                compression = "[!] Compression enabled"

            if int(ssltest.find('renegotiation').attrib['supported']) is 1:
                if int(ssltest.find('renegotiation').attrib['secure']) is 1:
                    renogotation = "Secure session renegotiation supported"
                else:
                    renogotation = "[!] Insecure session renegotiation supported"
            else:
                renogotation = "Server does not support session renegotiation"

            try:

                if ',' in ssltest.find('certificate').find('subject').text:
                    certificate = ";".join(ssltest.find('certificate').find('subject').text.split(','))

                else:
                    certificate = ssltest.find('certificate').find('subject').text
            
                if isinstance(ssltest.find('certificate').find('altnames'), ElementTree.Element):
                    if ',' in ssltest.find('certificate').find('altnames').text:
                        altnames = ";".join(ssltest.find('certificate').find('altnames').text.split(','))
                    else:
                        altnames = ssltest.find('certificate').find('altnames').text
                else:
                    altnames = "No Alternative Domain Names"

                if ssltest.find('certificate').find('expired').text is 'true':
                    expired = "Certificate is expired"
                else:
                    expired = "Certificate is live"
                
                pk_bits = ''
                issuer = ''
                certselfsigned = ''
                validstart = ''
                validend = ''
                signaturealgorithm = ssltest.find('certificate').find('signature-algorithm').text
                pk_error = ssltest.find('certificate').find('pk').attrib['error']
                pk_type = ssltest.find('certificate').find('pk').attrib['type']
                pk_bits = ssltest.find('certificate').find('pk').attrib['bits']
                issuer = ssltest.find('certificate').find('issuer').text
                certselfsigned = ssltest.find('certificate').find('self-signed').text
                validstart = ssltest.find('certificate').find('not-valid-before').text
                validend = ssltest.find('certificate').find('not-valid-after').text
            
            except KeyError:
                pass 
            except AttributeError:
                pass


            for cipherinfo in ssltest.iter('cipher'):
                row = []

                sslversion = cipherinfo.attrib['sslversion']
                status = cipherinfo.attrib['status']
                bits = cipherinfo.attrib['bits']
                cipher = cipherinfo.attrib['cipher']
                
                cipherdetail = ""

                try:
                    curve = cipherinfo.attrib['curve']
                    ecdhebits = cipherinfo.attrib['ecdhebits']
                    cipherdetail = "Curve " + curve + " ECDHE " + ecdhebits
                except KeyError:
                    pass
                try: 
                    dhebits = cipherinfo.attrib['dhebits']
                    cipherdetail = "DHE " + dhebits + " bits"
                except KeyError:
                    pass

                row.append(ip)
                row.append(port)
                row.append(heartbleed)
                row.append(compression)
                row.append(renogotation)
                row.append(certificate)
                row.append(altnames)
                row.append(expired)
                row.append(signaturealgorithm)
                row.append(pk_error)
                row.append(pk_type)
                row.append(pk_bits)
                row.append(issuer)
                row.append(certselfsigned)
                row.append(validstart)
                row.append(validend)
                row.append(sslversion)
                row.append(status)
                row.append(bits)
                row.append(cipher)
                row.append(cipherdetail)

                self.csvwriter.writerow(row)
        self.f.close()


class Main:
    def __init__(self):
        parser = argparse.ArgumentParser(description='Convert SSLScan XML files to CSVs')
        parser.add_argument('-i', '--filename', default=False, help='Input file name (i.e. sslscan.xml)')
        parser.add_argument('-o', '--output', default=False, help='Output file name (i.e. sslscan.csv)')
        args = parser.parse_args()

        self.filename = args.filename
        if args.output:
            self.outputfile = args.output
        else:
            self.outputfile = self.filename.split('.')[0] + ".csv"

        self.go()

    def go(self):
        if os.path.isfile(self.filename):
            if os.stat(self.filename).st_size != 0:
                tree = ElementTree.parse(self.filename)
                csvcreate = CSVCreate(tree.getroot(), self.outputfile)
                csvcreate.write()
            else:
                print("[!] %s is empty!" % self.filename)
        else:
            print("[!] %s does not exist!" % self.filename)


if __name__ == "__main__":
    try:
        Main()
    except KeyboardInterrupt:
        print("You killed it.")
        sys.exit()

