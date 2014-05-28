#!/usr/bin/python

###############################################################
# This program creates a command line interpreter used to edit
# kippo file system pickle files.
#
# It is intended to mimic a basic bash shell and supports relative
# file references.
#
# This isn't meant to build a brand new filesystem. Instead it
# should be used to edit existing filesystems such as the default
# /opt/kippo/fs.pickle.
#
# Donovan Hubbard
# Douglas Hubbard
# March 2013
#
###############################################################

import os, pickle, sys, locale, time, cmd
from stat import *

A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, \
    A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE = range(0, 10)
T_LINK, T_DIR, T_FILE, T_BLK, T_CHR, T_SOCK, T_FIFO = range(0, 7)

def getpath(fs, path):
    cwd = fs
    for part in path.split('/'):
        if not len(part):
            continue
        ok = False
        for c in cwd[A_CONTENTS]:
            if c[A_NAME] == part:
                cwd = c
                ok = True
                break
        if not ok:
            raise Exception('File not found')
    return cwd

def exists(fs, path):
    try:
        getpath(fs, path)
        return True
    except Exception, e:
        if str(e) == 'File not found':
            return False
        else:
            raise Exception(e)

def is_directory(fs,path):
    "Returns whether or not the file at 'path' is a directory"
    file = getpath(fs,path)
    if file[A_TYPE] == T_DIR:
        return True
    else:
        return False

def resolve_reference(pwd, relativeReference):
    '''Used to resolve a current working directory and a relative
      reference into an absolute file reference.'''

    tempPath = os.path.join(pwd, relativeReference)
    absoluteReference = os.path.normpath(tempPath)

    return absoluteReference

class fseditCmd(cmd.Cmd):

    def __init__(self, pickle_file_path):
        cmd.Cmd.__init__(self)

        if not os.path.isfile(pickle_file_path):
            print "File %s does not exist." % pickle_file_path
            sys.exit(1)

        try:
            pickle_file = open(pickle_file_path, 'rb')
        except IOError as e:
            print "Unable to open file %s" % pickle_file_path
            sys.exit(1)

        try:
            self.fs = pickle.load(pickle_file)
        except:
            print ("Unable to load file '%s'. " + \
                "Are you sure it is a valid pickle file?") % \
                (pickle_file_path,)
            sys.exit(1)

        self.pickle_file_path=pickle_file_path

        #get the name of the file so we can display it as the prompt
        path_parts = pickle_file_path.split('/')
        self.fs_name = path_parts[-1]

        self.update_pwd("/")

        self.intro = "\nKippo file system interactive editor\n" + \
            "Donovan Hubbard, Douglas Hubbard, March 2013\n" + \
            "Type 'help' for help\n"

    def save_pickle(self):
        '''saves the current file system to the pickle'''
        try:
            pickle.dump(self.fs, file(self.pickle_file_path, 'wb'))
        except:
            print ("Unable to save pickle file '%s'. " + \
                "Are you sure you have write access?") % \
                (self.pickle_file_path,)
            sys.exit(1)

    def do_exit(self, args):
        '''Exits the file system editor'''
        return True

    def do_EOF(self, args):
        '''The escape character ctrl+d exits the session'''
        #exiting from the do_EOF method does not create a newline automaticaly
        #so we add it manually
        print
        return True

    def do_ls(self, args):
        '''Prints the contents of a directory.
        Prints the current directory if no arguments are specified'''

        if not len(args):
            path = self.pwd
        else:
            path = resolve_reference(self.pwd,args)

        if exists(self.fs, path) == False:
            print "ls: cannot access %s: No such file or directory" % (path,)
            return

        if is_directory(self.fs, path) == False:
            print "ls: %s is not a directory" % (path,)
            return

        cwd = getpath(self.fs, path)

        for file in cwd[A_CONTENTS]:
            if file[A_TYPE] == T_DIR:
                print file[A_NAME] + '/'
            else:
                print file[A_NAME]

    def update_pwd(self, directory):
        self.pwd = directory
        self.prompt = self.fs_name + ":" + self.pwd + "$ "

    def do_cd(self, args):
        '''Changes the current directory.\nUsage: cd <target directory>'''

        #count  the number of arguments
        # 1 or more arguments: changes the directory to the first arg
        #                      and ignores the rest
        # 0 arguments: changes to '/'
        arguments = args.split()

        if not len(arguments):
            self.update_pwd("/")
        else:
            relative_dir = arguments[0]
            target_dir = resolve_reference(self.pwd, relative_dir)

            if exists(self.fs, target_dir) == False:
                print "cd: %s: No such file or directory" %  target_dir
            elif is_directory(self.fs, target_dir):
                self.update_pwd(target_dir)
            else:
                print "cd: %s: Not a directory" % target_dir

    def do_pwd(self, args):
        '''Prints the current working directory'''
        print self.pwd

    def do_mkdir(self, args):
        """Add a new directory in the target directory.
        Handles relative or absolute file paths. \n
        Usage: mkdir <destination>"""

        arg_list=args.split()
        if len(arg_list) != 1:
            print "usage: mkdir <new directory>"
        else:
            self.mkfile(arg_list, T_DIR)

    def do_touch(self, args):
        """Add a new file in the target directory.
        Handles relative or absolute file paths. \n
        Usage: touch <destination> [<size in bytes>]"""

        arg_list=args.split()

        if len(arg_list) < 1:
            print 'Usage: touch <destination> (<size in bytes>)'
        else:
            self.mkfile(arg_list, T_FILE)

    def mkfile(self, args, file_type):
        '''args must be a list of arguments'''
        cwd = self.fs
        path = resolve_reference(self.pwd, args[0])
        pathList = path.split('/')
        parentdir = '/'.join(pathList[:-1])
        fileName = pathList[len(pathList) - 1]

        if not exists(self.fs, parentdir):
            print ('Parent directory %s doesn\'t exist! ' +
                'Please create it first.') % \
                (parentdir,)
            return

        if exists(self.fs, path):
            print 'Error: %s already exists!' % (path,)
            return

        cwd = getpath(self.fs, parentdir)

        #get uid, gid, mode from parent
        uid = cwd[A_UID]
        gid = cwd[A_GID]
        mode = cwd[A_MODE]

        #create default file/directory size if none is specified
        if len(args) == 1:
            size = 4096
        else:
            size = args[1]

        #set the last update timestamp to now
        ctime = time.time()

        cwd[A_CONTENTS].append(
            [fileName, file_type, uid, gid, size, mode, ctime, [], None, None])

        self.save_pickle()

        print "Added '%s'" % path

    def do_rm(self, arguments):
        '''Remove an object from the filesystem.
        Will not remove a directory unless the -r switch is invoked.\n
        Usage: rm [-r] <target>'''

        args = arguments.split()

        if len(args) < 1 or len(args) > 2:
            print 'Usage: rm [-r] <target>'
            return

        if len(args) == 2 and args[0] != "-r":
            print 'Usage: rm [-r] <target>'
            return

        if len(args) == 1:
            target_path = resolve_reference(self.pwd, args[0])
        else:
            target_path = resolve_reference(self.pwd, args[1])

        if exists(self.fs, target_path) == False:
            print "File \'%s\' doesn\'t exist" % (target_path,)
            return

        if target_path == "/":
            print "rm: cannot delete root directory '/'"
            return

        target_object = getpath(self.fs, target_path)

        if target_object[A_TYPE]==T_DIR and args[0] != "-r":
            print "rm: cannot remove '%s': Is a directory" % (target_path,)
            return

        parent_path = '/'.join(target_path.split('/')[:-1])
        parent_object = getpath(self.fs, parent_path)

        parent_object[A_CONTENTS].remove(target_object)

        self.save_pickle()

        print "Deleted %s" % target_path

    def do_rmdir(self, arguments):
        '''Remove a file object. Like the unix command,
        this can only delete empty directories.
        Use rm -r to recursively delete full directories.\n
        Usage: rmdir <target directory>'''
        args = arguments.split()

        if len(args) != 1:
            print 'Usage: rmdir <target>'
            return

        target_path = resolve_reference(self.pwd, args[0])

        if exists(self.fs, target_path) == False:
            print "File \'%s\' doesn\'t exist" % (target_path,)
            return

        target_object = getpath(self.fs, target_path)

        if target_object[A_TYPE] != T_DIR:
            print "rmdir: failed to remove '%s': Not a directory" % \
                (target_path,)
            return

        #The unix rmdir command does not delete directories if they are not
        #empty
        if len(target_object[A_CONTENTS]) != 0:
            print "rmdir: failed to remove '%s': Directory not empty" % \
                (target_path,)
            return

        parent_path = '/'.join(target_path.split('/')[:-1])
        parent_object = getpath(self.fs, parent_path)

        parent_object[A_CONTENTS].remove(target_object)

        self.save_pickle()

        if self.pwd == target_path:
           self.do_cd("..")

        print "Deleted %s" % target_path

    def do_mv(self, arguments):
        '''Moves a file/directory from one directory to another.\n
        Usage: mv <source file> <destination file>'''
        args = arguments.split()
        if len(args) != 2:
            print 'Usage: mv <source> <destination>'
            return
        src = resolve_reference(self.pwd, args[0])
        dst = resolve_reference(self.pwd, args[1])

        if src == "/":
           print "mv: cannot move the root directory '/'"
           return

        src = src.strip('/')
        dst = dst.strip('/')

        if not exists(self.fs, src):
           print "Source file \'%s\' does not exist!" % src
           return

        #Get the parent directory of the source file
        #srcparent = '/'.join(src.split('/')[:-1])
        srcparent = "/".join(src.split('/')[:-1])

        #Get the object for source
        srcl = getpath(self.fs, src)

        #Get the object for the source's parent
        srcparentl = getpath(self.fs, srcparent)

        #if the specified filepath is a directory, maintain the current name
        if exists(self.fs, dst) and is_directory(self.fs, dst):
            dstparent = dst
            dstname = srcl[A_NAME]
        else:
            dstparent = '/'.join(dst.split('/')[:-1])
            dstname = dst.split('/')[-1]

        if exists(self.fs, dstparent + '/' + dstname):
            print "A file already exists at "+dst+"!"
            return

        if not exists(self.fs, dstparent):
            print 'Destination directory \'%s\' doesn\'t exist!' % dst
            return

        if src == self.pwd:
            self.do_cd("..")

        dstparentl = getpath(self.fs, dstparent)
        copy = srcl[:]
        copy[A_NAME] = dstname
        dstparentl[A_CONTENTS].append(copy)
        srcparentl[A_CONTENTS].remove(srcl)

        self.save_pickle()

        print 'File moved from /%s to /%s' % (src, dst)

    def do_cp(self, arguments):
        '''Copies a file/directory from one directory to another.\n
        Usage: cp <source file> <destination file>'''
        args = arguments.split()
        if len(args) != 2:
            print 'Usage: cp <source> <destination>'
            return

        #src, dst = args[0], args[1]

        src = resolve_reference(self.pwd, args[0])
        dst = resolve_reference(self.pwd, args[1])

        src = src.strip('/')
        dst = dst.strip('/')

        if not exists(self.fs, src):
           print "Source file '%s' does not exist!" % (src,)
           return

        #Get the parent directory of the source file
        srcparent = '/'.join(src.split('/')[:-1])

        #Get the object for source
        srcl = getpath(self.fs, src)

        #Get the ojbect for the source's parent
        srcparentl = getpath(self.fs, srcparent)

        #if the specified filepath is a directory, maintain the current name
        if exists(self.fs, dst) and is_directory(self.fs, dst):
            dstparent = dst
            dstname = srcl[A_NAME]
        else:
            dstparent = '/'.join(dst.split('/')[:-1])
            dstname = dst.split('/')[-1]

        if exists(self.fs, dstparent + '/' + dstname):
            print 'A file already exists at %s/%s!' % (dstparent, dstname)
            return

        if not exists(self.fs, dstparent):
            print 'Destination directory %s doesn\'t exist!' % (dstparent,)
            return

        dstparentl = getpath(self.fs, dstparent)
        copy = srcl[:]
        copy[A_NAME] = dstname
        dstparentl[A_CONTENTS].append(copy)

        self.save_pickle()

        print 'File copied from /%s to /%s/%s' % (src, dstparent, dstname)

    def do_file(self, args):
        '''Identifies file types.\nUsage: file <file name>'''
        arg_list = args.split()

        if len(arg_list) != 1:
            print "Incorrect number of arguments.\nUsage: file <file>"
            return

        target_path = resolve_reference(self.pwd, arg_list[0])

        if not exists(self.fs, target_path):
            print "File '%s' doesn't exist." % target_path
            return

        target_object = getpath(self.fs, target_path)

        file_type = target_object[A_TYPE]

        if file_type == T_FILE:
            msg = "normal file object"
        elif file_type == T_DIR:
            msg = "directory"
        elif file_type == T_LINK:
            msg = "link"
        elif file_type == T_BLK:
            msg = "block file"
        elif file_type == T_CHR:
            msg = "character special"
        elif file_type == T_SOCK:
            msg = "socket"
        elif file_type == T_FIFO:
            msg = "named pipe"
        else:
            msg = "unrecognized file"

        print target_path+" is a "+msg

    def do_clear(self, args):
        '''Clears the screen'''
        os.system('clear')

    def emptyline(self):
        '''By default the cmd object will repeat the last command
        if a blank line is entered. Since this is different than
        bash behavior, overriding this method will stop it.'''
        pass

    def help_help(self):
        print "Type help <topic> to get more information."

    def help_about(self):
        print "Kippo stores information about its file systems in a " + \
            "series of nested lists. Once the lists are made, they are " + \
            "stored in a pickle file on the hard drive. Every time kippo " + \
            "gets a new client, it reads from the pickle file and loads " + \
            "the fake filesystem into memory. By default this file " + \
            "is /opt/kippo/fs.pickle. Originally the script " + \
            "/opt/kippo/createfs.py was used to copy the filesystem " + \
            "of the existing computer. However, it quite difficult to " + \
            "edit the pickle file by hand.\n\nThis script strives to be " + \
            "a bash-like interface that allows users to modify " + \
            "existing fs pickle files. It supports many of the " + \
            "common bash commands and even handles relative file " + \
            "paths. Keep in mind that you need to restart the " + \
            "kippo process in order for the new file system to be " + \
            "reloaded into memory.\n\nDonovan Hubbard, Douglas Hubbard, " + \
            "March 2013\nVersion 1.0"

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "Usage: %s <fs.pickle>" % os.path.basename(sys.argv[0],)
        sys.exit(1)

    pickle_file_name = sys.argv[1].strip()
    print pickle_file_name

    fseditCmd(pickle_file_name).cmdloop()

# vim: set sw=4 et:
