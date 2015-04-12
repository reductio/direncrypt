#!/usr/bin/env python

from __future__ import with_statement

from errno import EACCES
from os.path import realpath
from sys import argv, exit
from threading import Lock

from os.path import basename, dirname, isfile, isdir

import os

from fuse import FUSE, FuseOSError, Operations, LoggingMixIn

from cryptfuncs import encrypt_name, decrypt_name, derive_new_key

filehandledict = dict()
keyfile = None
key = None

class Filehandle:
	def __init__( self, fh ):
		self.fh = fh

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
        st = os.lstat(path)
        return dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
            'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid'))

    getxattr = None

    def link(self, target, source):
        return os.open(path, os.O_WRONLY | os.O_CREAT, mode)

    listxattr = None
    mkdir = os.mkdir
    mknod = os.mknod

    def open(self, path, flags):
        fh = os.open( path, flags )
        filehandledict[fh] = Filehandle( fh )
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
        return ['.', '..'] + [ encrypt_name( x, key ) for x in os.listdir(path) if isfile( x ) or isdir( x ) ]

    readlink = os.readlink

    def release(self, path, fh):
        del filehandledict[fh]
        return os.close(fh)

    def rename(self, old, new):
        return os.rename(old, self.root + new)

    rmdir = os.rmdir

    def statfs(self, path):
        stv = os.statvfs(path)
        return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
            'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag',
            'f_frsize', 'f_namemax'))

    def symlink(self, target, source):
        return os.symlink(source, target)

    def truncate(self, path, length, fh=None):
        with open(path, 'r+') as f:
            f.truncate(length)

    unlink = os.unlink
    utimens = os.utime

    def write(self, path, data, offset, fh):
        with self.rwlock:
            os.lseek(fh, offset, 0)
            return os.write(fh, data)


if __name__ == '__main__':
    if len(argv) != 4:
        print('usage: %s <root> <mountpoint> <keyfile>' % argv[0])
        exit(1)
    keyfile = argv[3]
    if isfile( keyfile ):
       key = derive_new_key( keyfile )
    else:
       print('Keyfile has to be a regular file') 
       exit(1)
    fuse = FUSE(Loopback(argv[1]), argv[2], foreground=True)
