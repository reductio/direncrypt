#!/usr/bin/python3

import os
import sys
from subprocess import Popen, PIPE
from base64 import b64encode, b64decode

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

def hash_name( name ):
	proc = Popen( ["openssl", "dgst", "-sha256", "-r"], stdin = PIPE, stdout = PIPE )
	stdout, stderr = proc.communicate( name.encode( "utf-8" ) )
	sha = stdout.decode( "utf-8" )
	sha = sha.split( ' ' )[0]
	return sha

def encrypt_name( name, key ):
	namehash = hash_name( name )
	salt = namehash[:16]
	iv = namehash[-32:]
	saltiv = salt + iv
	saltivb64 = b64encode( saltiv.encode( "utf-8" ), b"-_" ).decode( "utf-8" )
	proc = Popen( ["openssl", "aes-256-cbc", "-a", "-salt", "-S", salt, "-iv", iv, "-k", key], stdin = PIPE, stdout = PIPE )
	stdout, stderr = proc.communicate( input = name.encode( "utf-8" ) )
	stdout = stdout.decode( "utf-8" ).replace( "+", "-" ).replace( "/", "_" )
	nname = stdout[:-1] + "." + saltivb64
	return nname

def decrypt_name( name, key ):
	name, saltivb64 = name.split( '.' )
	name = name.replace( "-", "+" ).replace( "_", "/" ) + "\n"
	saltiv = b64decode( saltivb64.encode( "utf-8" ), b"-_" )
	salt = saltiv[:16]
	iv = saltiv[-32:]
	proc = Popen( ["openssl", "aes-256-cbc", "-a", "-d", "-k", key, "-S", salt, "-iv", iv], stdin = PIPE, stdout = PIPE )
	stdout, stderr = proc.communicate( input = name.encode( "utf-8" ) )
	dname = stdout.decode( "utf-8")
	return dname

def encrypt_file( file, out, keyfile ):
	proc = Popen( ["openssl", "aes-256-cbc", "-salt", "-kfile", keyfile, "-in", file, "-out", out] )
	proc.communicate()
	return

def convert_directory( source, dest, key, keyfile ):
	sourcename = os.path.basename( source )
	encdest = encrypt_name( sourcename, key )
	destpath = dest + "/" + encdest + "/"
	if os.path.isdir( destpath ):
		print( "Destination already exists" )
		return
	os.makedirs( destpath )
	for f in ( source + "/" + fp for fp in os.listdir( source ) ):
		fname = os.path.basename( f )
		ename = encrypt_name( fname, key )
		if os.path.isfile( f ):
			stats = os.stat( f )
			destfile = destpath + ename
			encrypt_file( f, destfile, keyfile )
			os.utime( destfile, ( stats.st_atime, stats.st_mtime ) )
		elif os.path.isdir( f ):
			stats = os.stat( f )
			destdir = destpath
			print( "calling convert directory:", f, destdir )
			convert_directory( f, destdir, key, keyfile )
			os.utime( destdir, ( stats.st_atime, stats.st_mtime ) )
		else:
			print( "Unsupported file type!" )
	print( "%s -> %s" % ( sourcename, encdest ) )

def derive_new_key( keyfile ):
	proc = Popen( ["openssl", "dgst", "-sha256", "-r", keyfile], stdout = PIPE )
	stdout, _ = proc.communicate()
	sha = stdout.decode( "utf-8" )
	sha = sha.split( ' ' )[0]
	return sha

def main():
	source, dest, keyfile = read_check_dirs()
	if source == None or dest == None or keyfile == None:
		print( "Invalid parameters!" )
		return
	key = derive_new_key( keyfile )
	convert_directory( source, dest, key, keyfile )
		

if __name__ == "__main__":
	main()
