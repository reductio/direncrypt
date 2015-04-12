#!/usr/bin/python3

import os
import sys
from cryptfuncs import derive_new_key, convert_directory

def read_check_dirs():
	try:
		orgdir = sys.argv[1]
		newdir = sys.argv[2]
		keyfile = sys.argv[3]
		if not os.path.isdir( orgdir ) or not os.path.isdir( newdir ) or not os.path.isfile( keyfile ):
			return None, None, None
		#TODO check
		if orgdir[-1] == "/":
			orgdir = orgdir[:-1]
		return orgdir, newdir, keyfile
	except IndexError:
		return None, None, None


def main():
	source, dest, keyfile = read_check_dirs()
	if source == None or dest == None or keyfile == None:
		print( "Invalid parameters!\nUsage: encryptdir.py SOURCE DEST KEYFILE" )
		return
	key = derive_new_key( keyfile )
	convert_directory( source, dest, key, keyfile )
		

if __name__ == "__main__":
	main()
