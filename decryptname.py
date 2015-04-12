#!/usr/bin/python3

from encryptdir import derive_new_key, decrypt_name
import sys
import os

def main():
	keyfile = sys.argv[1]
	name = sys.argv[2]
	
	if not os.path.isfile( keyfile ):
		print( "Invalid Keyfile" )
		return

	key = derive_new_key( keyfile )
	print( decrypt_name( name, key ) )	

if __name__ == "__main__":
	main() 
