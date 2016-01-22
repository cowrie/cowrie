# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""

import os
import time
import fnmatch
import hashlib
import re
import stat
import errno

from twisted.python import log

A_NAME, \
    A_TYPE, \
    A_UID, \
    A_GID, \
    A_SIZE, \
    A_MODE, \
    A_CTIME, \
    A_CONTENTS, \
    A_TARGET, \
    A_REALFILE = range(0, 10)
T_LINK, \
    T_DIR, \
    T_FILE, \
    T_BLK, \
    T_CHR, \
    T_SOCK, \
    T_FIFO = range(0, 7)

class TooManyLevels(Exception):
    """
    62 ELOOP Too many levels of symbolic links.  A path name lookup involved more than 8 symbolic links.
    raise OSError(errno.ELOOP, os.strerror(errno.ENOENT))
    """
    pass



class FileNotFound(Exception):
    """
    raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
    """
    pass



class HoneyPotFilesystem(object):
    """
    """

    def __init__(self, fs, cfg):
        self.fs = fs
        self.cfg = cfg

        # Keep track of open file descriptors
        self.tempfiles = {}
        self.filenames = {}

        # Keep count of new files, so we can have an artificial limit
        self.newcount = 0


    def resolve_path(self, path, cwd):
        """
        """
        pieces = path.rstrip('/').split('/')

        if path[0] == '/':
            cwd = []
        else:
            cwd = [x for x in cwd.split('/') if len(x) and x is not None]

        while 1:
            if not len(pieces):
                break
            piece = pieces.pop(0)
            if piece == '..':
                if len(cwd): cwd.pop()
                continue
            if piece in ('.', ''):
                continue
            cwd.append(piece)

        return '/%s' % ('/'.join(cwd),)


    def resolve_path_wc(self, path, cwd):
        """
        """
        pieces = path.rstrip('/').split('/')
        if len(pieces[0]):
            cwd = [x for x in cwd.split('/') if len(x) and x is not None]
            path = path[1:]
        else:
            cwd, pieces = [], pieces[1:]
        found = []
        def foo(p, cwd):
            if not len(p):
                found.append('/%s' % ('/'.join(cwd),))
            elif p[0] == '.':
                foo(p[1:], cwd)
            elif p[0] == '..':
                foo(p[1:], cwd[:-1])
            else:
                names = [x[A_NAME] for x in self.get_path('/'.join(cwd))]
                matches = [x for x in names if fnmatch.fnmatchcase(x, p[0])]
                for match in matches:
                    foo(p[1:], cwd + [match])
        foo(pieces, cwd)
        return found


    def get_path(self, path, follow_symlinks=True):
        """
        This returns the Cowrie file system objects for a directory
        """
        cwd = self.fs
        for part in path.split('/'):
            if not len(part):
                continue
            ok = False
            for c in cwd[A_CONTENTS]:
                if c[A_NAME] == part:
                    if c[A_TYPE] == T_LINK:
                        cwd = self.getfile(c[A_TARGET],
                            follow_symlinks=follow_symlinks)
                    else:
                        cwd = c
                    ok = True
                    break
            if not ok:
                raise FileNotFound
        return cwd[A_CONTENTS]


    def exists(self, path):
        """
        Return True if path refers to an existing path.
        Returns False for broken symbolic links.
        """
        f = self.getfile(path, follow_symlinks=True)
        if f is not False:
            return True


    def lexists(self, path):
        """
        Return True if path refers to an existing path.
        Returns True for broken symbolic links.
        """
        f = self.getfile(path, follow_symlinks=False)
        if f is not False:
            return True


    def update_realfile(self, f, realfile):
        """
        """
        if not f[A_REALFILE] and os.path.exists(realfile) and \
                not os.path.islink(realfile) and os.path.isfile(realfile) and \
                f[A_SIZE] < 25000000:
            f[A_REALFILE] = realfile


    def realfile(self, f, path):
        """
        """
        self.update_realfile(f, path)
        if f[A_REALFILE]:
            return f[A_REALFILE]
        return None


    def getfile(self, path, follow_symlinks=True):
        """
        This returns the Cowrie file system object for a path
        """
        if path == '/':
            return self.fs
        pieces = path.strip('/').split('/')
        cwd = ''
        p = self.fs
        for piece in pieces:
            if piece not in [x[A_NAME] for x in p[A_CONTENTS]]:
                return False
            for x in p[A_CONTENTS]:
                if x[A_NAME] == piece:
                    if piece == pieces[-1] and follow_symlinks==False:
                        p = x
                    elif x[A_TYPE] == T_LINK:
                        if x[A_TARGET][0] == '/':
                            # Absolute link
                            p = self.getfile(x[A_TARGET],
                                follow_symlinks=follow_symlinks)
                        else:
                            # Relative link
                            p = self.getfile('/'.join((cwd, x[A_TARGET])),
                                follow_symlinks=follow_symlinks)
                        if p == False:
                            # Broken link
                            return False
                    else:
                        p = x
            cwd = '/'.join((cwd, piece))
        return p


    def file_contents(self, target, count=0):
        """
        Retrieve the content of a file in the honeyfs
        It follows links.
        It tries A_REALFILE first and then tries honeyfs directory
        """
        if count > 8:
            raise TooManyLevels
        path = self.resolve_path(target, os.path.dirname(target))
        if not path or not self.exists(path):
            raise FileNotFound
        f = self.getfile(path)
        if f[A_TYPE] == T_DIR:
            raise IsADirectoryError
        elif f[A_TYPE] == T_LINK:
            return self.file_contents(f[A_TARGET], count + 1)
        elif f[A_TYPE] == T_FILE and f[A_REALFILE]:
            return file(f[A_REALFILE], 'rb').read()
        realfile = self.realfile(f, '%s/%s' % \
            (self.cfg.get('honeypot', 'contents_path'), path))
        if realfile:
            return file(realfile, 'rb').read()


    def mkfile(self, path, uid, gid, size, mode, ctime=None):
        """
        """
        if self.newcount > 10000:
            return False
        if ctime is None:
            ctime = time.time()
        dir = self.get_path(os.path.dirname(path))
        outfile = os.path.basename(path)
        if outfile in [x[A_NAME] for x in dir]:
            dir.remove([x for x in dir if x[A_NAME] == outfile][0])
        dir.append([outfile, T_FILE, uid, gid, size, mode, ctime, [],
            None, None])
        self.newcount += 1
        return True


    def mkdir(self, path, uid, gid, size, mode, ctime=None):
        """
        """
        if self.newcount > 10000:
            raise OSError(errno.EDQUOT, os.strerror(errno.EDQUOT), path)
        if ctime is None:
            ctime = time.time()
        if not len(path.strip('/')):
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT), path)
        try:
            dir = self.get_path(os.path.dirname(path.strip('/')))
        except IndexError:
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT), path)
            return False
        dir.append([os.path.basename(path), T_DIR, uid, gid, size, mode,
            ctime, [], None, None])
        self.newcount += 1


    def isfile(self, path):
        """
        Return True if path is an existing regular file. This follows symbolic
        links, so both islink() and isfile() can be true for the same path.
        """
        try:
            f = self.getfile(path)
        except:
            return False
        return f[A_TYPE] == T_FILE


    def islink(self, path):
        """
        Return True if path refers to a directory entry that is a symbolic
        link. Always False if symbolic links are not supported by the python
        runtime.
        """
        try:
            f = self.getfile(path)
        except:
            return False
        return f[A_TYPE] == T_LINK


    def isdir(self, path):
        """
        Return True if path is an existing directory.
        This follows symbolic links, so both islink() and isdir() can be true for the same path.
        """
        if path == '/':
            return True
        try:
            dir = self.getfile(path)
        except:
            dir = None
        if dir is None or dir is False:
            return False
        if dir[A_TYPE] == T_DIR:
            return True
        else:
            return False

    """
    Below additions for SFTP support, try to keep functions here similar to os.*
    """
    def open(self, filename, openFlags, mode):
        """
        #log.msg("fs.open %s" % filename)

        #if (openFlags & os.O_APPEND == os.O_APPEND):
        #    log.msg("fs.open append")

        #if (openFlags & os.O_CREAT == os.O_CREAT):
        #    log.msg("fs.open creat")

        #if (openFlags & os.O_TRUNC == os.O_TRUNC):
        #    log.msg("fs.open trunc")

        #if (openFlags & os.O_EXCL == os.O_EXCL):
        #    log.msg("fs.open excl")

        # treat O_RDWR same as O_WRONLY
        """
        if openFlags & os.O_WRONLY == os.O_WRONLY or openFlags & os.O_RDWR == os.O_RDWR:
            # strip executable bit
            hostmode = mode & ~(111)
            hostfile = '%s/sftp_%s_%s' % \
                       (self.cfg.get('honeypot', 'download_path'),
                    time.strftime('%Y%m%d%H%M%S'),
                    re.sub('[^A-Za-z0-9]', '_', filename))
            #log.msg("fs.open file for writing, saving to %s" % safeoutfile)
            self.mkfile(filename, 0, 0, 0, stat.S_IFREG | mode)
            fd = os.open(hostfile, openFlags, hostmode)
            self.update_realfile(self.getfile(filename), hostfile)
            self.tempfiles[fd] = hostfile
            self.filenames[fd] = filename
            return fd

        elif openFlags & os.O_RDONLY == os.O_RDONLY:
            return None

        return None


    def read(self, fd, size):
        """
        """
        # this should not be called, we intercept at readChunk
        raise notImplementedError


    def write(self, fd, string):
        """
        """
        return os.write(fd, string)


    def close(self, fd):
        """
        """
        if not fd:
            return True
        if self.tempfiles[fd] is not None:
            shasum = hashlib.sha256(open(self.tempfiles[fd], 'rb').read()).hexdigest()
            shasumfile = self.cfg.get('honeypot', 'download_path') + "/" + shasum
            if (os.path.exists(shasumfile)):
                os.remove(self.tempfiles[fd])
            else:
                os.rename(self.tempfiles[fd], shasumfile)
            os.symlink(shasum, self.tempfiles[fd])
            self.update_realfile(self.getfile(self.filenames[fd]), shasumfile)
            log.msg(format='SFTP Uploaded file \"%(filename)s\" to %(outfile)s',
                    eventid='cowrie.session.file_upload',
                    filename=os.path.basename(self.filenames[fd]),
                    outfile=shasumfile,
                    shasum=shasum)
            del self.tempfiles[fd]
            del self.filenames[fd]
        return os.close(fd)


    def lseek(self, fd, offset, whence):
        """
        """
        if not fd:
            return True
        return os.lseek(fd, offset, whence)


    def mkdir2(self, path):
        """
        FIXME mkdir() name conflicts with existing mkdir
        """
        dir = self.getfile(path)
        if dir != False:
            raise OSError(errno.EEXIST, os.strerror(errno.EEXIST), path)
        self.mkdir(path, 0, 0, 4096, 16877)


    def rmdir(self, path):
        """
        """
        path = path.rstrip('/')
        name = os.path.basename(path)
        parent = os.path.dirname(path)
        dir = self.getfile(path, follow_symlinks=False)
        if dir == False:
            raise OSError(errno.EEXIST, os.strerror(errno.EEXIST), path)
        if dir[A_TYPE] != T_DIR:
            raise OSError(errno.ENOTDIR, os.strerror(errno.ENOTDIR), path)
        if len(self.get_path(path))>0:
            raise OSError(errno.ENOTEMPTY, os.strerror(errno.ENOTEMPTY), path)
        pdir = self.get_path(parent,follow_symlinks=True)
        for i in pdir[:]:
            if i[A_NAME] == name:
                pdir.remove(i)
                return True
        return False


    def utime(self, path, atime, mtime):
        """
        """
        p = self.getfile(path)
        if p == False:
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
        p[A_CTIME] = mtime


    def chmod(self, path, perm):
        """
        """
        p = self.getfile(path)
        if p == False:
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
        p[A_MODE] = stat.S_IFMT(p[A_MODE]) | perm


    def chown(self, path, uid, gid):
        """
        """
        p = self.getfile(path)
        if p == False:
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
        if (uid != -1):
            p[A_UID] = uid
        if (gid != -1):
            p[A_GID] = gid


    def remove(self, path):
        """
        """
        p = self.getfile(path, follow_symlinks=False)
        if p == False:
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
        self.get_path(os.path.dirname(path)).remove(p)
        return


    def readlink(self, path):
        """
        """
        p = self.getfile(path, follow_symlinks=False)
        if p == False:
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
        if not (p[A_MODE] & stat.S_IFLNK):
            raise OSError
        return p[A_TARGET]


    def symlink(self, targetPath, linkPath):
        """
        """
        raise notImplementedError


    def rename(self, oldpath, newpath):
        """
        """
        old = self.getfile(oldpath)
        if old == False:
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))
        new = self.getfile(newpath)
        if new != False:
            raise OSError(errno.EEXIST, os.strerror(errno.EEXIST))

        self.get_path(os.path.dirname(oldpath)).remove(old)
        old[A_NAME] = os.path.basename(newpath)
        self.get_path(os.path.dirname(newpath)).append(old)
        return


    def listdir(self, path):
        """
        """
        names = [x[A_NAME] for x in self.get_path(path)]
        return names


    def lstat(self, path):
        """
        """
        return self.stat(path, follow_symlinks=False)


    def stat(self, path, follow_symlinks=True):
        """
        """
        if (path == "/"):
            p = {A_TYPE:T_DIR, A_UID:0, A_GID:0, A_SIZE:4096, A_MODE:16877,
                A_CTIME:time.time()}
        else:
            p = self.getfile(path, follow_symlinks=follow_symlinks)

        if (p == False):
            raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))

        return _statobj( p[A_MODE], 0, 0, 1, p[A_UID], p[A_GID], p[A_SIZE],
            p[A_CTIME], p[A_CTIME], p[A_CTIME])


    def realpath(self, path):
        """
        """
        return path


    def update_size(self, filename, size):
        """
        """
        f = self.getfile(filename)
        if f == False:
            return
        if f[A_TYPE] != T_FILE:
            return
        f[A_SIZE] = size



class _statobj(object):
    """
    Transform a tuple into a stat object
    """
    def __init__(self, st_mode, st_ino, st_dev, st_nlink, st_uid, st_gid, st_size, st_atime, st_mtime, st_ctime):
        self.st_mode = st_mode
        self.st_ino = st_ino
        self.st_dev = st_dev
        self.st_nlink = st_nlink
        self.st_uid = st_uid
        self.st_gid = st_gid
        self.st_size = st_size
        self.st_atime = st_atime
        self.st_mtime = st_mtime
        self.st_ctime = st_ctime

