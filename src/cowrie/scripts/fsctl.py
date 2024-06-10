#!/usr/bin/env python

################################################################
# This is a command line interpreter used to edit
# cowrie file system pickle files.
#
# It is intended to mimic a basic bash shell and supports
# relative file references.
#
# Do not use to build a complete file system. Use:
# /opt/cowrie/bin/createfs
#
# Instead it should be used to edit existing file systems
# such as the default: /opt/cowrie/data/fs.pickle.
#
# Donovan Hubbard
# Douglas Hubbard
# March 2013
################################################################

import cmd
import copy
import os
import pickle
import sys
import time
from stat import (
    S_IRGRP,
    S_IROTH,
    S_IRUSR,
    S_IWGRP,
    S_IWOTH,
    S_IWUSR,
    S_IXGRP,
    S_IXOTH,
    S_IXUSR,
)

from cowrie.shell.fs import FileNotFound

(
    A_NAME,
    A_TYPE,
    A_UID,
    A_GID,
    A_SIZE,
    A_MODE,
    A_CTIME,
    A_CONTENTS,
    A_TARGET,
    A_REALFILE,
) = list(range(0, 10))
T_LINK, T_DIR, T_FILE, T_BLK, T_CHR, T_SOCK, T_FIFO = list(range(0, 7))


def getpath(fs, path):
    cwd = fs
    for part in path.split("/"):
        if not len(part):
            continue
        ok = False
        for c in cwd[A_CONTENTS]:
            if c[A_NAME] == part:
                cwd = c
                ok = True
                break
        if not ok:
            raise FileNotFound
    return cwd


def exists(fs, path):
    try:
        getpath(fs, path)
        return True
    except FileNotFound:
        return False


def is_directory(fs, path):
    """
    Returns whether or not the file at 'path' is a directory

    :param fs:
    :param path:
    :return:
    """
    file = getpath(fs, path)
    if file[A_TYPE] == T_DIR:
        return True
    else:
        return False


def resolve_reference(pwd, relativeReference):
    """
    Used to resolve a current working directory and a relative reference into an absolute file reference.
    """

    tempPath = os.path.join(pwd, relativeReference)
    absoluteReference = os.path.normpath(tempPath)

    return absoluteReference


class fseditCmd(cmd.Cmd):
    def __init__(self, pickle_file_path):
        cmd.Cmd.__init__(self)

        if not os.path.isfile(pickle_file_path):
            print(f"File {pickle_file_path} does not exist.")
            sys.exit(1)

        try:
            pickle_file = open(pickle_file_path, "rb")
        except OSError as e:
            print(f"Unable to open file {pickle_file_path}: {e!r}")
            sys.exit(1)

        try:
            self.fs = pickle.load(pickle_file, encoding="utf-8")
        except Exception:
            print(
                (
                    "Unable to load file '%s'. "
                    + "Are you sure it is a valid pickle file?"
                )
                % (pickle_file_path,)
            )
            sys.exit(1)

        self.pickle_file_path = pickle_file_path

        # get the name of the file so we can display it as the prompt
        path_parts = pickle_file_path.split("/")
        self.fs_name = path_parts[-1]

        self.update_pwd("/")

        self.intro = (
            "\nKippo/Cowrie file system interactive editor\n"
            + "Donovan Hubbard, Douglas Hubbard, March 2013\n"
            + "Type 'help' for help\n"
        )

    def save_pickle(self):
        """
        saves the current file system to the pickle
        :return:
        """
        try:
            pickle.dump(self.fs, open(self.pickle_file_path, "wb"))
        except Exception as e:
            print(
                (
                    "Unable to save pickle file '%s'. "
                    + "Are you sure you have write access?"
                )
                % (self.pickle_file_path,)
            )
            print(str(e))
            sys.exit(1)

    def do_exit(self, args):
        """
        Exits the file system editor
        """
        return True

    def do_EOF(self, args):
        """
        The escape character ctrl+d exits the session
        """
        # exiting from the do_EOF method does not create a newline automatically
        # so we add it manually
        print()
        return True

    def do_ls(self, args):
        """
        Prints the contents of a directory, use ls -l to list in long format
        Prints the current directory if no arguments are specified
        """

        longls = False

        if args.startswith("-l"):
            longls = True
            args = args[3:]

        if not len(args):
            path = self.pwd
        else:
            path = resolve_reference(self.pwd, args)

        if exists(self.fs, path) is False:
            print(f"ls: cannot access {path}: No such file or directory")
            return

        if is_directory(self.fs, path) is False:
            print(f"ls: {path} is not a directory")
            return

        cwd = getpath(self.fs, path)
        files = cwd[A_CONTENTS]
        files.sort()

        largest = 0
        if len(files):
            largest = max([x[A_SIZE] for x in files])

        for file in files:
            if not longls:
                if file[A_TYPE] == T_DIR:
                    print(file[A_NAME] + "/")
                else:
                    print(file[A_NAME])
                continue

            perms = ["-"] * 10

            if file[A_MODE] & S_IRUSR:
                perms[1] = "r"
            if file[A_MODE] & S_IWUSR:
                perms[2] = "w"
            if file[A_MODE] & S_IXUSR:
                perms[3] = "x"

            if file[A_MODE] & S_IRGRP:
                perms[4] = "r"
            if file[A_MODE] & S_IWGRP:
                perms[5] = "w"
            if file[A_MODE] & S_IXGRP:
                perms[6] = "x"

            if file[A_MODE] & S_IROTH:
                perms[7] = "r"
            if file[A_MODE] & S_IWOTH:
                perms[8] = "w"
            if file[A_MODE] & S_IXOTH:
                perms[9] = "x"

            linktarget = ""

            if file[A_TYPE] == T_DIR:
                perms[0] = "d"
            elif file[A_TYPE] == T_LINK:
                perms[0] = "l"
                linktarget = f" -> {file[A_TARGET]}"

            perms = "".join(perms)
            ctime = time.localtime(file[A_CTIME])
            uid = file[A_UID]
            gid = file[A_GID]

            if uid == 0:
                uid = "root"
            else:
                uid = str(uid).rjust(4)

            if gid == 0:
                gid = "root"
            else:
                gid = str(gid).rjust(4)

            print(
                "{} 1 {} {} {} {} {}{}".format(
                    perms,
                    uid,
                    gid,
                    str(file[A_SIZE]).rjust(len(str(largest))),
                    time.strftime("%Y-%m-%d %H:%M", ctime),
                    file[A_NAME],
                    linktarget,
                )
            )

    def update_pwd(self, directory):
        self.pwd = directory
        self.prompt = self.fs_name + ":" + self.pwd + "$ "

    def do_cd(self, args):
        """
        Changes the current directory.\nUsage: cd <target directory>
        """

        # count  the number of arguments
        # 1 or more arguments: changes the directory to the first arg
        #                      and ignores the rest
        # 0 arguments: changes to '/'
        arguments = args.split()

        if not len(arguments):
            self.update_pwd("/")
        else:
            relative_dir = arguments[0]
            target_dir = resolve_reference(self.pwd, relative_dir)

            if exists(self.fs, target_dir) is False:
                print(f"cd: {target_dir}: No such file or directory")
            elif is_directory(self.fs, target_dir):
                self.update_pwd(target_dir)
            else:
                print(f"cd: {target_dir}: Not a directory")

    def do_pwd(self, args):
        """
        Prints the current working directory

        :param args:
        :return:
        """
        print(self.pwd)

    def do_mkdir(self, args):
        """
        Add a new directory in the target directory.
        Handles relative or absolute file paths. \n
        Usage: mkdir <destination>...
        """

        arg_list = args.split()
        if len(arg_list) < 1:
            print("usage: mkdir <new directory> <new directory>...")
        else:
            for arg in arg_list:
                self.mkfile(arg.split(), T_DIR)

    def do_touch(self, args):
        """
        Add a new file in the target directory.
        Handles relative or absolute file paths. \n
        Usage: touch <destination> [<size in bytes>]
        """

        arg_list = args.split()

        if len(arg_list) < 1:
            print("Usage: touch <destination> (<size in bytes>)")
        else:
            self.mkfile(arg_list, T_FILE)

    def mkfile(self, args, file_type):
        """
        args must be a list of arguments
        """
        cwd = self.fs
        path = resolve_reference(self.pwd, args[0])
        pathList = path.split("/")
        parentdir = "/".join(pathList[:-1])
        fileName = pathList[len(pathList) - 1]

        if not exists(self.fs, parentdir):
            print(f"Parent directory {parentdir} doesn't exist!")
            self.mkfile(parentdir.split(), T_DIR)

        if exists(self.fs, path):
            print(f"Error: {path} already exists!")
            return

        cwd = getpath(self.fs, parentdir)

        # get uid, gid, mode from parent
        uid = cwd[A_UID]
        gid = cwd[A_GID]
        mode = cwd[A_MODE]

        # Modify file_mode when it is a file
        if file_type == T_FILE:
            file_file_mode = int("0o100000", 8)
            permits = mode & (2**9 - 1)
            mode = file_file_mode + permits

        # create default file/directory size if none is specified
        if len(args) == 1:
            size = 4096
        else:
            size = int(args[1])

        # set the last update time stamp to now
        ctime = time.time()

        cwd[A_CONTENTS].append(
            [fileName, file_type, uid, gid, size, mode, ctime, [], None, None]
        )

        self.save_pickle()

        print(f"Added '{path}'")

    def do_rm(self, arguments):
        """
        Remove an object from the file system.
        Will not remove a directory unless the -r switch is invoked.\n
        Usage: rm [-r] <target>
        """

        args = arguments.split()

        if len(args) < 1 or len(args) > 2:
            print("Usage: rm [-r] <target>")
            return

        if len(args) == 2 and args[0] != "-r":
            print("Usage: rm [-r] <target>")
            return

        if len(args) == 1:
            target_path = resolve_reference(self.pwd, args[0])
        else:
            target_path = resolve_reference(self.pwd, args[1])

        if exists(self.fs, target_path) is False:
            print(f"File '{target_path}' doesn't exist")
            return

        if target_path == "/":
            print("rm: cannot delete root directory '/'")
            return

        target_object = getpath(self.fs, target_path)

        if target_object[A_TYPE] == T_DIR and args[0] != "-r":
            print(f"rm: cannot remove '{target_path}': Is a directory")
            return

        parent_path = "/".join(target_path.split("/")[:-1])
        parent_object = getpath(self.fs, parent_path)

        parent_object[A_CONTENTS].remove(target_object)

        self.save_pickle()

        print(f"Deleted {target_path}")

    def do_rmdir(self, arguments):
        """
        Remove a file object. Like the unix command,
        this can only delete empty directories.
        Use rm -r to recursively delete full directories.\n
        Usage: rmdir <target directory>
        """
        args = arguments.split()

        if len(args) != 1:
            print("Usage: rmdir <target>")
            return

        target_path = resolve_reference(self.pwd, args[0])

        if exists(self.fs, target_path) is False:
            print(f"File '{target_path}' doesn't exist")
            return

        target_object = getpath(self.fs, target_path)

        if target_object[A_TYPE] != T_DIR:
            print(f"rmdir: failed to remove '{target_path}': Not a directory")
            return

        # The unix rmdir command does not delete directories if they are not
        # empty
        if len(target_object[A_CONTENTS]) != 0:
            print(f"rmdir: failed to remove '{target_path}': Directory not empty")
            return

        parent_path = "/".join(target_path.split("/")[:-1])
        parent_object = getpath(self.fs, parent_path)

        parent_object[A_CONTENTS].remove(target_object)

        self.save_pickle()

        if self.pwd == target_path:
            self.do_cd("..")

        print(f"Deleted {target_path}")

    def do_mv(self, arguments):
        """
        Moves a file/directory from one directory to another.\n
        Usage: mv <source file> <destination file>
        """
        args = arguments.split()
        if len(args) != 2:
            print("Usage: mv <source> <destination>")
            return
        src = resolve_reference(self.pwd, args[0])
        dst = resolve_reference(self.pwd, args[1])

        if src == "/":
            print("mv: cannot move the root directory '/'")
            return

        src = src.strip("/")
        dst = dst.strip("/")

        if not exists(self.fs, src):
            print(f"Source file '{src}' does not exist!")
            return

        # Get the parent directory of the source file
        # srcparent = '/'.join(src.split('/')[:-1])
        srcparent = "/".join(src.split("/")[:-1])

        # Get the object for source
        srcl = getpath(self.fs, src)

        # Get the object for the source's parent
        srcparentl = getpath(self.fs, srcparent)

        # if the specified filepath is a directory, maintain the current name
        if exists(self.fs, dst) and is_directory(self.fs, dst):
            dstparent = dst
            dstname = srcl[A_NAME]
        else:
            dstparent = "/".join(dst.split("/")[:-1])
            dstname = dst.split("/")[-1]

        if exists(self.fs, dstparent + "/" + dstname):
            print("A file already exists at " + dst + "!")
            return

        if not exists(self.fs, dstparent):
            print(f"Destination directory '{dst}' doesn't exist!")
            return

        if src == self.pwd:
            self.do_cd("..")

        dstparentl = getpath(self.fs, dstparent)
        copy = srcl[:]
        copy[A_NAME] = dstname
        dstparentl[A_CONTENTS].append(copy)
        srcparentl[A_CONTENTS].remove(srcl)

        self.save_pickle()

        print(f"File moved from /{src} to /{dst}")

    def do_cp(self, arguments):
        """
        Copies a file/directory from one directory to another.\n
        Usage: cp <source file> <destination file>
        """
        args = arguments.split()
        if len(args) != 2:
            print("Usage: cp <source> <destination>")
            return

        # src, dst = args[0], args[1]

        src = resolve_reference(self.pwd, args[0])
        dst = resolve_reference(self.pwd, args[1])

        src = src.strip("/")
        dst = dst.strip("/")

        if not exists(self.fs, src):
            print(f"Source file '{src}' does not exist!")
            return

        # Get the parent directory of the source file
        # srcparent = "/".join(src.split("/")[:-1])

        # Get the object for source
        srcl = getpath(self.fs, src)

        # Get the object for the source's parent
        # srcparentl = getpath(self.fs, srcparent)

        # if the specified filepath is a directory, maintain the current name
        if exists(self.fs, dst) and is_directory(self.fs, dst):
            dstparent = dst
            dstname = srcl[A_NAME]
        else:
            dstparent = "/".join(dst.split("/")[:-1])
            dstname = dst.split("/")[-1]

        if exists(self.fs, dstparent + "/" + dstname):
            print(f"A file already exists at {dstparent}/{dstname}!")
            return

        if not exists(self.fs, dstparent):
            print(f"Destination directory {dstparent} doesn't exist!")
            return

        dstparentl = getpath(self.fs, dstparent)
        coppy = copy.deepcopy(srcl)
        coppy[A_NAME] = dstname
        dstparentl[A_CONTENTS].append(coppy)

        self.save_pickle()

        print(f"File copied from /{src} to /{dstparent}/{dstname}")

    def do_chown(self, args):
        """
        Change file ownership
        """
        arg_list = args.split()

        if len(arg_list) != 2:
            print("Incorrect number of arguments.\nUsage: chown <uid> <file>")
            return

        uid = arg_list[0]
        target_path = resolve_reference(self.pwd, arg_list[1])

        if not exists(self.fs, target_path):
            print(f"File '{target_path}' doesn't exist.")
            return

        target_object = getpath(self.fs, target_path)
        olduid = target_object[A_UID]
        target_object[A_UID] = int(uid)
        print("former UID: " + str(olduid) + ". New UID: " + str(uid))
        self.save_pickle()

    def do_chgrp(self, args):
        """
        Change file ownership
        """
        arg_list = args.split()

        if len(arg_list) != 2:
            print("Incorrect number of arguments.\nUsage: chgrp <gid> <file>")
            return

        gid = arg_list[0]
        target_path = resolve_reference(self.pwd, arg_list[1])

        if not exists(self.fs, target_path):
            print(f"File '{target_path}' doesn't exist.")
            return

        target_object = getpath(self.fs, target_path)
        oldgid = target_object[A_GID]
        target_object[A_GID] = int(gid)
        print("former GID: " + str(oldgid) + ". New GID: " + str(gid))
        self.save_pickle()

    def do_chmod(self, args):
        """
        Change file permissions
        only modes between 000 and 777 are implemented
        """

        arg_list = args.split()

        if len(arg_list) != 2:
            print("Incorrect number of arguments.\nUsage: chmod <mode> <file>")
            return

        mode = arg_list[0]
        target_path = resolve_reference(self.pwd, arg_list[1])

        if not exists(self.fs, target_path):
            print(f"File '{target_path}' doesn't exist.")
            return

        target_object = getpath(self.fs, target_path)
        oldmode = target_object[A_MODE]

        if target_object[A_TYPE] == T_LINK:
            print(target_path + " is a link, nothing changed.")
            return

        try:
            num = int(mode, 8)
        except Exception:
            print("Incorrect mode: " + mode)
            return

        if num < 0 or num > 511:
            print("Incorrect mode: " + mode)
            return

        target_object[A_MODE] = (oldmode & 0o7777000) | (num & 0o777)
        self.save_pickle()

    def do_file(self, args):
        """
        Identifies file types.\nUsage: file <file name>
        """
        arg_list = args.split()

        if len(arg_list) != 1:
            print("Incorrect number of arguments.\nUsage: file <file>")
            return

        target_path = resolve_reference(self.pwd, arg_list[0])

        if not exists(self.fs, target_path):
            print(f"File '{target_path}' doesn't exist.")
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

        print(target_path + " is a " + msg)

    def do_clear(self, args):
        """
        Clears the screen
        """
        os.system("clear")

    def emptyline(self) -> bool:
        """
        By default the cmd object will repeat the last command
        if a blank line is entered. Since this is different than
        bash behavior, overriding this method will stop it.
        """
        return False

    def help_help(self):
        print("Type help <topic> to get more information.")

    def help_about(self):
        print(
            "Kippo/Cowrie stores information about its file systems in a "
            + "series of nested lists. Once the lists are made, they are "
            + "stored in a pickle file on the hard drive. Every time cowrie "
            + "gets a new client, it reads from the pickle file and loads "
            + "the fake file system into memory. By default this file "
            + "is /opt/cowrie/data/fs.pickle. Originally the script "
            + "/opt/cowrie/bin/createfs was used to copy the file system "
            + "of the existing computer. However, it quite difficult to "
            + "edit the pickle file by hand.\n\nThis script strives to be "
            + "a bash-like interface that allows users to modify "
            + "existing fs pickle files. It supports many of the "
            + "common bash commands and even handles relative file "
            + "paths. Keep in mind that you need to restart the "
            + "cowrie process in order for the new file system to be "
            + "reloaded into memory.\n\nDonovan Hubbard, Douglas Hubbard, "
            + "March 2013\nVersion 1.0"
        )


def run():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print(
            "Usage: {} <fs.pickle> [command]".format(
                os.path.basename(
                    sys.argv[0],
                )
            )
        )
        sys.exit(1)

    pickle_file_name = sys.argv[1].strip()
    print(pickle_file_name)

    if len(sys.argv) == 3:
        fseditCmd(pickle_file_name).onecmd(sys.argv[2])
    else:
        fseditCmd(pickle_file_name).cmdloop()


if __name__ == "__main__":
    run()
