import os
import sys
from subprocess import Popen, PIPE
from base64 import b64encode, b64decode

import Crypto
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.Cipher import AES
from Crypto.Util import Counter

e64 = lambda x: b64encode( x, b"-_" )
d64 = lambda x: b64decode( x, b"-_" )

def sha256( byte_array ):
	sha = SHA256Hash( data = byte_array )
	return sha.digest()

def hash_name( name ):
	sha = sha256( name.encode( "utf-8" ) )
	return sha

def create_counter_function( iv, init = 1 ):
	bits = 128 - ( len( iv ) << 3 )
	return Counter.new( bits, prefix = iv, initial_value = init, allow_wraparound = True )

def encrypt_name( name, key ):
	namehash = hash_name( name )
	iv = namehash[:8]
	salt = namehash[8:16]
	key = sha256( key + salt )

	aes = AES.new( key, AES.MODE_CTR, counter = create_counter_function( iv ) )
	encname = aes.encrypt( name )

	saltiv = salt + iv
	saltivb64 = e64( saltiv ).decode( "utf-8" )
	encnameb64 = e64( encname ).decode( "utf-8" )

	return encnameb64 + '.' + saltivb64

def decrypt_name( name, key ):
	encname64, saltivb64 = name.split( '.' )

	saltiv = d64( saltivb64.encode( "utf-8" ) )
	encname = d64( encname64.encode( "utf-8" ) )

	salt = saltiv[:8]
	iv = saltiv[8:16]
	key = sha256( key + salt )

	aes = AES.new( key, AES.MODE_CTR, counter = create_counter_function( iv ) )
	dname = aes.decrypt( encname ).decode( "utf-8" )

	return dname

def encrypt_file( file, out, keyfile ):
	proc = Popen( ["openssl", "aes-256-cbc", "-salt", "-kfile", keyfile, "-in", file, "-out", out] )
	proc.communicate()
	return

def decrypt_file( file, out, keyfile ):
	proc = Popen( ["openssl", "aes-256-cbc", "-d", "-salt", "-kfile", keyfile, "-in", file, "-out", out] )
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
	with open( keyfile, "rb" ) as k:
		keydata = k.read( 10240 )
	return keydata
