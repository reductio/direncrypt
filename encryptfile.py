#!/usr/bin/python3

from cryptfuncs import derive_new_key, encrypt_name, encrypt_file
import sys
import os

notfile = lambda x: not os.path.isfile( x )
basename = os.path.basename
dirname = os.path.dirname
exists = os.path.exists

def read_arguments():
	file = sys.argv[1]
	keyfile = sys.argv[2]

	if notfile( file ) or notfile( keyfile ):
		return None, None
	else:
		return file, keyfile

def main():
	file, keyfile = read_arguments()
	if file == None:
		print( "Invalid arguments!\nUsage: encryptfile.py FILE KEYFILE" )
		return
	key = derive_new_key( keyfile )
	enc_filename = encrypt_name( basename( file ), key )	
	dest_dir = dirname( file )
	out = dest_dir + enc_filename
	if exists( out ):
		print( "%s already exists. Stopping." % out )
		return
	encrypt_file( file, out, keyfile )
	print( "File encrypted: %s" % out ) 	

if __name__ == "__main__":
	main()
