import os
import sys
from subprocess import Popen, PIPE
from base64 import b64encode, b64decode

import Crypto
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
from Crypto.Random import random

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

def create_random_salt_iv():
	rnd = Random.new()
	return rnd.read( 16 ), rnd.read( 8 )

def encrypt_file( file, out, keyfile ):
	if os.path.exists( out ):
		print( "file exists!" )
		return

	if not os.path.exists( file ):
		print( "input file does not exist!" )
		return

	salt, iv = create_random_salt_iv()
	key = sha256( derive_new_key( keyfile ) + salt )
	aes = AES.new( key, AES.MODE_CTR, counter = create_counter_function( iv ) )

	with open( out, "wb" ) as outfile:
		outfile.write( salt )
		outfile.write( iv )
		outfile.write( b'________' )

		with open( file, "rb" ) as infile:
			while True:
				data = infile.read( 1 * 1024 * 1024 )
				if len( data ) == 0:
					break
				data = aes.encrypt( data )
				outfile.write( data )
	return

def decrypt_file( file, out, keyfile ):
	if os.path.exists( out ):
		print( "file exists!" )
		return

	if not os.path.exists( file ):
		print( "input file does not exist!" )
		return

	with open( file, "rb" ) as infile:
		salt = infile.read( 16 )
		iv = infile.read( 8 )
		check = infile.read( 8 )
		key = sha256( derive_new_key( keyfile ) + salt )
		aes = AES.new( key, AES.MODE_CTR, counter = create_counter_function( iv ) )

		with open( out, "wb" ) as outfile:
			while True:
				data = infile.read( 1 * 1024 * 1024 )
				if len( data ) == 0:
					break
				data = aes.decrypt( data )
				outfile.write( data )
	return

def __ed_in_stream( data, data_offset, key, iv, encrypt ):
	block_offset, mod = divmod( data_offset, 16 )
	aes = AES.new( key, AES.MODE_CTR, counter = create_counter_function( iv, init = 1 + block_offset ) )
	func = aes.encrypt if encrypt else aes.decrypt
	if mod:
		func( b' ' * mod ) #skip the bytes for this block
	return func( data )

def encrypt_in_stream( data, data_offset, key, iv ):
	return __ed_in_stream( data, data_offset, key, iv, True )

def decrypt_in_stream( data, data_offset, key, iv ):
	return __ed_in_stream( data, data_offset, key, iv, False )

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


def __test_encrypt_in_stream():
	rand = Random.new()
	key = rand.read( 32 )
	iv = b'12345678'
	aes = AES.new( key, AES.MODE_CTR, counter = create_counter_function( iv ) )
	data = rand.read( 100 * 1024 * 1024 )
	encdata = aes.encrypt( data )

	for i in range( 1000 ):
		start = random.randint( 0, len( data ) - 1 )
		length = 1000
		data_block = data[start:start+length]
		comp_block = encdata[start:start+length]
		test_block = encrypt_in_stream( data_block, start, key, iv )
		if not comp_block == test_block:
			return False
	return True

def __test():
	print( "Testing encrypt_in_stream ... ", end = "" )
	print( "PASSED" if __test_encrypt_in_stream() else "FAILED" )
	pass

if __name__ == "__main__":
	__test()
