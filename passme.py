#!/usr/bin/python

import hashlib,binascii, getpass; print('Enter the password:'); password = getpass.getpass(); nthash = hashlib.new('md4', password.encode('utf-16le')).digest() ; lmnthash = "aad3b435b51404eeaad3b435b51404ee" + ":" + binascii.hexlify(nthash) ; print("The LM/NTLM hash is:") ; print(lmnthash)
