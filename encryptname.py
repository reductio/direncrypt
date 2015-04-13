#!/usr/bin/python3

from cryptfuncs import derive_new_key, encrypt_name 
import sys
import os

def main():
	keyfile = sys.argv[1]
	name = sys.argv[2]
	
	if not os.path.isfile( keyfile ):
		print( "Invalid Keyfile" )
		return

	key = derive_new_key( keyfile )
	print( encrypt_name( name, key ) )	

if __name__ == "__main__":
	main() 
