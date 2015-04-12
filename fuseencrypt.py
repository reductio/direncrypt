#!/usr/bin/env python

from __future__ import with_statement

from errno import EACCES
from os.path import realpath
from sys import argv, exit
from threading import Lock

from os.path import basename, dirname, isfile, isdir

import os

from fuse import FUSE, FuseOSError, Operations, LoggingMixIn

from cryptfuncs import encrypt_name, decrypt_name, derive_new_key, encrypt_file
import random

filehandledict = dict()
keyfile = None
key = None
tempdir = None
mountpoint = None

class Filehandle:
	def __init__( self, fh, tempfile ):
		self.fh = fh
		self.tempfile = tempfile

	def is_in_cache( self ):
		return False
	
	def read( self, offset, size ):
		os.lseek( self.fh, offset, 0 )
		return os.read( self.fh, size )

class Loopback(LoggingMixIn, Operations):
    def __init__(self, root):
        self.root = realpath(root)
        self.rwlock = Lock()

    def __call__(self, op, path, *args):
        return super(Loopback, self).__call__(op, self.root + path, *args)

    def translate_path( self, path ):
        parts = filter( lambda x: x != "", path.split( "/" ) )
        parts = map( lambda x: decrypt_name( x, key ) if x.startswith("U2FsdGVkX1") else x, parts )
        path = "/" + "/".join( parts )
        return path

    def access(self, path, mode):
        if not os.access(path, mode):
            raise FuseOSError(EACCES)

    chmod = os.chmod
    chown = os.chown

    def create(self, path, mode):
        raise FuseOSError(ENOTSUP)

    def flush(self, path, fh):
        return os.fsync(fh)

    def fsync(self, path, datasync, fh):
        return os.fsync(fh)

    def getattr(self, path, fh=None):
        translated = False
        try:
            path = self.translate_path( path )
            translated = True
        except:
            pass
        st = os.stat(path)
        stat = dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
            'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid'))
        if translated:
              stat['st_size'] = ( stat['st_size'] // 16 + 2 ) * 16
        return stat

    getxattr = None

    def link(self, target, source):
        raise FuseOSError(ENOTSUP)

    listxattr = None
    mkdir = os.mkdir
    mknod = os.mknod

    def open(self, path, flags):
        size_new = self.getattr( path )['st_size']
        translated = False
        try:
            path = self.translate_path( path )
            translated = True
        except:
            raise FuseOSError(EACCESS)
        while True:
            tempfile = tempdir + str( random.randint( 0, 1000000 ) )
            if not os.path.exists( tempfile ):
                break
        encrypt_file( path, tempfile, keyfile )
        size_real = os.path.getsize( tempfile )
        if size_new != size_real:
                raise FuseOSError(EACCESS)
        fh = os.open( tempfile, flags )
        filehandledict[fh] = Filehandle( fh, tempfile )
        return fh

    def read(self, path, size, offset, fh):
        with self.rwlock:
            if fh in filehandledict:
                fho = filehandledict[fh]
                return fho.read( offset, size )
            else:
                print( "No filehandle found" )
                raise FuseOSError(EACCES)

    def readdir(self, path, fh):
        return ['.', '..'] + [ encrypt_name( x, key ) for x in os.listdir(path) if isfile( path + "/" + x ) or isdir( path + "/" + x ) ]

    readlink = os.readlink

    def release(self, path, fh):
        handle = filehandledict[fh]
        del filehandledict[fh]
        r = os.close(fh)
        os.remove( handle.tempfile )
        return r

    def rename(self, old, new):
        raise FuseOSError(ENOTSUP)

    rmdir = os.rmdir

    def statfs(self, path):
        stv = os.statvfs(path)
        return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
            'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag',
            'f_frsize', 'f_namemax'))

    def symlink(self, target, source):
        raise FuseOSError(ENOTSUP)

    def truncate(self, path, length, fh=None):
        raise FuseOSError(ENOTSUP)

    unlink = os.unlink
    utimens = os.utime

    def write(self, path, data, offset, fh):
        raise FuseOSError(ENOTSUP)

def create_temp_dir( prefix = "/tmp/" ):
	prefix = prefix + "/fuseencrypt-"
	while True:
		prefix = prefix + str( random.randint( 0, 100000000000 ) )
		if not os.path.exists( prefix ):
			os.makedirs( prefix )
			break
	return prefix + "/"

if __name__ == '__main__':
    if len(argv) != 4:
        print('usage: %s <root> <mountpoint> <keyfile>' % argv[0])
        exit(1)
    keyfile = argv[3]
    tempdir = create_temp_dir()
    mountpoint = realpath(argv[2])
    print( "mountpoint", mountpoint )
    print( "tempdir: %s" % tempdir )
    if isfile( keyfile ):
       key = derive_new_key( keyfile )
    else:
       print('Keyfile has to be a regular file') 
       exit(1)

    fuse = FUSE(Loopback(argv[1]), argv[2], foreground=True)

    os.rmdir( tempdir )
