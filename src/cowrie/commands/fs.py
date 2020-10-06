# Copyright (c) 2010 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information


"""
Filesystem related commands
"""

from __future__ import absolute_import, division

import copy
import getopt
import os.path
import re

from twisted.python import log

import cowrie.shell.fs as fs
from cowrie.shell.command import HoneyPotCommand

commands = {}


class command_grep(HoneyPotCommand):
    """
    grep command
    """

    def grep_get_contents(self, filename, match):
        try:
            contents = self.fs.file_contents(filename)
            self.grep_application(contents, match)
        except Exception:
            self.errorWrite("grep: {}: No such file or directory\n".format(filename))

    def grep_application(self, contents, match):
        match = os.path.basename(match).replace('\"', '').encode('utf8')
        matches = re.compile(match)
        contentsplit = contents.split(b'\n')
        for line in contentsplit:
            if matches.search(line):
                self.writeBytes(line + b'\n')

    def help(self):
        self.writeBytes(b'usage: grep [-abcDEFGHhIiJLlmnOoPqRSsUVvwxZ] [-A num] [-B num] [-C[num]]\n')
        self.writeBytes(b'\t[-e pattern] [-f file] [--binary-files=value] [--color=when]\n')
        self.writeBytes(b'\t[--context[=num]] [--directories=action] [--label] [--line-buffered]\n')
        self.writeBytes(b'\t[--null] [pattern] [file ...]\n')

    def start(self):
        if not self.args:
            self.help()
            self.exit()
            return

        self.n = 10
        if self.args[0] == '>':
            pass
        else:
            try:
                optlist, args = getopt.getopt(self.args, 'abcDEFGHhIiJLlmnOoPqRSsUVvwxZA:B:C:e:f:')
            except getopt.GetoptError as err:
                self.errorWrite("grep: invalid option -- {}\n".format(err.opt))
                self.help()
                self.exit()
                return

            for opt in optlist:
                if opt == '-h':
                    self.help()

        if not self.input_data:
            files = self.check_arguments('grep', args[1:])
            for pname in files:
                self.grep_get_contents(pname, args[0])
        else:
            self.grep_application(self.input_data, args[0])

        self.exit()

    def lineReceived(self, line):
        log.msg(eventid='cowrie.command.input',
                realm='grep',
                input=line,
                format='INPUT (%(realm)s): %(input)s')

    def handle_CTRL_D(self):
        self.exit()


commands['/bin/grep'] = command_grep
commands['grep'] = command_grep
commands['/bin/egrep'] = command_grep
commands['/bin/fgrep'] = command_grep


class command_tail(HoneyPotCommand):
    """
    tail command
    """

    def tail_get_contents(self, filename):
        try:
            contents = self.fs.file_contents(filename)
            self.tail_application(contents)
        except Exception:
            self.errorWrite("tail: cannot open `{}' for reading: No such file or directory\n".format(filename))

    def tail_application(self, contents):
        contentsplit = contents.split(b'\n')
        lines = int(len(contentsplit))
        if lines < self.n:
            self.n = lines - 1
        i = 0
        for j in range((lines - self.n - 1), lines):
            self.writeBytes(contentsplit[j])
            if i < self.n:
                self.write('\n')
            i += 1

    def start(self):
        self.n = 10
        if not self.args or self.args[0] == '>':
            return
        else:
            try:
                optlist, args = getopt.getopt(self.args, 'n:')
            except getopt.GetoptError as err:
                self.errorWrite("tail: invalid option -- '{}'\n".format(err.opt))
                self.exit()
                return

            for opt in optlist:
                if opt[0] == '-n':
                    if not opt[1].isdigit():
                        self.errorWrite("tail: illegal offset -- {}\n".format(opt[1]))
                    else:
                        self.n = int(opt[1])
        if not self.input_data:
            files = self.check_arguments("tail", args)
            for pname in files:
                self.tail_get_contents(pname)
        else:
            self.tail_application(self.input_data)

        self.exit()

    def lineReceived(self, line):
        log.msg(eventid='cowrie.command.input',
                realm='tail',
                input=line,
                format='INPUT (%(realm)s): %(input)s')

    def handle_CTRL_D(self):
        self.exit()


commands['/bin/tail'] = command_tail
commands['/usr/bin/tail'] = command_tail
commands['tail'] = command_tail


class command_head(HoneyPotCommand):
    """
    head command
    """

    def head_application(self, contents):
        i = 0
        contentsplit = contents.split(b'\n')
        for line in contentsplit:
            if i < self.n:
                self.writeBytes(line + b'\n')
            i += 1

    def head_get_file_contents(self, filename):
        try:
            contents = self.fs.file_contents(filename)
            self.head_application(contents)
        except Exception:
            self.errorWrite("head: cannot open `{}' for reading: No such file or directory\n".format(filename))

    def start(self):
        self.n = 10
        if not self.args or self.args[0] == '>':
            return
        else:
            try:
                optlist, args = getopt.getopt(self.args, 'n:')
            except getopt.GetoptError as err:
                self.errorWrite("head: invalid option -- '{}'\n".format(err.opt))
                self.exit()
                return

            for opt in optlist:
                if opt[0] == '-n':
                    if not opt[1].isdigit():
                        self.errorWrite("head: illegal offset -- {}\n".format(opt[1]))
                    else:
                        self.n = int(opt[1])

        if not self.input_data:
            files = self.check_arguments("head", args)
            for pname in files:
                self.head_get_file_contents(pname)
        else:
            self.head_application(self.input_data)
        self.exit()

    def lineReceived(self, line):
        log.msg(eventid='cowrie.command.input', realm='head', input=line,
                format='INPUT (%(realm)s): %(input)s')

    def handle_CTRL_D(self):
        self.exit()


commands['/bin/head'] = command_head
commands['/usr/bin/head'] = command_head
commands['head'] = command_head


class command_cd(HoneyPotCommand):
    """
    cd command
    """

    def call(self):
        if not self.args or self.args[0] == "~":
            pname = self.protocol.user.avatar.home
        else:
            pname = self.args[0]
        try:
            newpath = self.fs.resolve_path(pname, self.protocol.cwd)
            inode = self.fs.getfile(newpath)
        except Exception:
            pass
        if pname == "-":
            self.errorWrite('bash: cd: OLDPWD not set\n')
            return
        if inode is None or inode is False:
            self.errorWrite('bash: cd: {}: No such file or directory\n'.format(pname))
            return
        if inode[fs.A_TYPE] != fs.T_DIR:
            self.errorWrite('bash: cd: {}: Not a directory\n'.format(pname))
            return
        self.protocol.cwd = newpath


commands['cd'] = command_cd


class command_rm(HoneyPotCommand):
    """
    rm command
   """
    def help(self):
        self.write(
            """Usage: rm [OPTION]... [FILE]...
Remove (unlink) the FILE(s).

 -f, --force           ignore nonexistent files and arguments, never prompt
 -i                    prompt before every removal
 -I                    prompt once before removing more than three files, or
                         when removing recursively; less intrusive than -i,
                         while still giving protection against most mistakes
      --interactive[=WHEN]  prompt according to WHEN: never, once (-I), or
                         always (-i); without WHEN, prompt always
      --one-file-system  when removing a hierarchy recursively, skip any
                         directory that is on a file system different from
                         that of the corresponding command line argument
      --no-preserve-root  do not treat '/' specially
      --preserve-root   do not remove '/' (default)
 -r, -R, --recursive   remove directories and their contents recursively
 -d, --dir             remove empty directories
 -v, --verbose         explain what is being done
     --help     display this help and exit
     --version  output version information and exit

By default, rm does not remove directories.  Use the --recursive (-r or -R)
option to remove each listed directory, too, along with all of its contents.

To remove a file whose name starts with a '-', for example '-foo',
use one of these commands:
 rm -- -foo

 rm ./-foo

Note that if you use rm to remove a file, it might be possible to recover
some of its contents, given sufficient expertise and/or time.  For greater
assurance that the contents are truly unrecoverable, consider using shred.

GNU coreutils online help: <http://www.gnu.org/software/coreutils/>
Full documentation at: <http://www.gnu.org/software/coreutils/rm>
or available locally via: info '(coreutils) rm invocation'\n"""
        )

    def paramError(self):
        self.errorWrite("Try 'rm --help' for more information\n")

    def call(self):
        recursive = False
        force = False
        verbose = False
        if not self.args:
            self.errorWrite("rm: missing operand\n")
            self.paramError()
            return

        try:
            optlist, args = getopt.gnu_getopt(self.args, 'rTfvh', ['help', 'recursive', 'force', 'verbose'])
        except getopt.GetoptError as err:
            self.errorWrite("rm: invalid option -- '{}'\n".format(err.opt))
            self.paramError()
            self.exit()
            return

        for o, a in optlist:
            if o in ('--recursive', '-r', '-R'):
                recursive = True
            elif o in ('--force', '-f'):
                force = True
            elif o in ('--verbose', '-v'):
                verbose = True
            elif o in ('--help', '-h'):
                self.help()
                return

        for f in args:
            pname = self.fs.resolve_path(f, self.protocol.cwd)
            try:
                # verify path to file exists
                dir = self.fs.get_path('/'.join(pname.split('/')[:-1]))
                # verify that the file itself exists
                self.fs.get_path(pname)
            except (IndexError, fs.FileNotFound):
                if not force:
                    self.errorWrite(
                        'rm: cannot remove `{}\': No such file or directory\n'.format(f))
                continue
            basename = pname.split('/')[-1]
            for i in dir[:]:
                if i[fs.A_NAME] == basename:
                    if i[fs.A_TYPE] == fs.T_DIR and not recursive:
                        self.errorWrite('rm: cannot remove `{}\': Is a directory\n'.format(i[fs.A_NAME]))
                    else:
                        dir.remove(i)
                        if verbose:
                            if i[fs.A_TYPE] == fs.T_DIR:
                                self.write('removed directory \'{}\'\n'.format(i[fs.A_NAME]))
                            else:
                                self.write('removed \'{}\'\n'.format(i[fs.A_NAME]))


commands['/bin/rm'] = command_rm
commands['rm'] = command_rm


class command_cp(HoneyPotCommand):
    """
    cp command
    """

    def call(self):
        if not len(self.args):
            self.errorWrite("cp: missing file operand\n")
            self.errorWrite("Try `cp --help' for more information.\n")
            return
        try:
            optlist, args = getopt.gnu_getopt(self.args,
                                              '-abdfiHlLPpRrsStTuvx')
        except getopt.GetoptError:
            self.errorWrite('Unrecognized option\n')
            return
        recursive = False
        for opt in optlist:
            if opt[0] in ('-r', '-a', '-R'):
                recursive = True

        def resolv(pname):
            return self.fs.resolve_path(pname, self.protocol.cwd)

        if len(args) < 2:
            self.errorWrite("cp: missing destination file operand after `{}'\n".format(self.args[0]))
            self.errorWrite("Try `cp --help' for more information.\n")
            return
        sources, dest = args[:-1], args[-1]
        if len(sources) > 1 and not self.fs.isdir(resolv(dest)):
            self.errorWrite("cp: target `{}' is not a directory\n".format(dest))
            return

        if dest[-1] == '/' and not self.fs.exists(resolv(dest)) and \
                not recursive:
            self.errorWrite(
                "cp: cannot create regular file `{}': Is a directory\n".format(dest))
            return

        if self.fs.isdir(resolv(dest)):
            isdir = True
        else:
            isdir = False
            parent = os.path.dirname(resolv(dest))
            if not self.fs.exists(parent):
                self.errorWrite("cp: cannot create regular file " + "`{}': No such file or directory\n".format(dest))
                return

        for src in sources:
            if not self.fs.exists(resolv(src)):
                self.errorWrite(
                    "cp: cannot stat `{}': No such file or directory\n".format(src))
                continue
            if not recursive and self.fs.isdir(resolv(src)):
                self.errorWrite("cp: omitting directory `{}'\n".format(src))
                continue
            s = copy.deepcopy(self.fs.getfile(resolv(src)))
            if isdir:
                dir = self.fs.get_path(resolv(dest))
                outfile = os.path.basename(src)
            else:
                dir = self.fs.get_path(os.path.dirname(resolv(dest)))
                outfile = os.path.basename(dest.rstrip('/'))
            if outfile in [x[fs.A_NAME] for x in dir]:
                dir.remove([x for x in dir if x[fs.A_NAME] == outfile][0])
            s[fs.A_NAME] = outfile
            dir.append(s)


commands['/bin/cp'] = command_cp
commands['cp'] = command_cp


class command_mv(HoneyPotCommand):
    """
    mv command
    """

    def call(self):
        if not len(self.args):
            self.errorWrite("mv: missing file operand\n")
            self.errorWrite("Try `mv --help' for more information.\n")
            return

        try:
            optlist, args = getopt.gnu_getopt(self.args, '-bfiStTuv')
        except getopt.GetoptError:
            self.errorWrite('Unrecognized option\n')
            self.exit()

        def resolv(pname):
            return self.fs.resolve_path(pname, self.protocol.cwd)

        if len(args) < 2:
            self.errorWrite("mv: missing destination file operand after `{}'\n".format(self.args[0]))
            self.errorWrite("Try `mv --help' for more information.\n")
            return
        sources, dest = args[:-1], args[-1]
        if len(sources) > 1 and not self.fs.isdir(resolv(dest)):
            self.errorWrite("mv: target `{}' is not a directory\n".format(dest))
            return

        if dest[-1] == '/' and not self.fs.exists(resolv(dest)) and len(sources) != 1:
            self.errorWrite(
                "mv: cannot create regular file `{}': Is a directory\n".format(dest))
            return

        if self.fs.isdir(resolv(dest)):
            isdir = True
        else:
            isdir = False
            parent = os.path.dirname(resolv(dest))
            if not self.fs.exists(parent):
                self.errorWrite("mv: cannot create regular file " + "`{}': No such file or directory\n".format(dest))
                return

        for src in sources:
            if not self.fs.exists(resolv(src)):
                self.errorWrite(
                    "mv: cannot stat `{}': No such file or directory\n".format(src))
                continue
            s = self.fs.getfile(resolv(src))
            if isdir:
                dir = self.fs.get_path(resolv(dest))
                outfile = os.path.basename(src)
            else:
                dir = self.fs.get_path(os.path.dirname(resolv(dest)))
                outfile = os.path.basename(dest)
            if dir != os.path.dirname(resolv(src)):
                s[fs.A_NAME] = outfile
                dir.append(s)
                sdir = self.fs.get_path(os.path.dirname(resolv(src)))
                sdir.remove(s)
            else:
                s[fs.A_NAME] = outfile


commands['/bin/mv'] = command_mv
commands['mv'] = command_mv


class command_mkdir(HoneyPotCommand):
    """
    mkdir command
    """

    def call(self):
        for f in self.args:
            pname = self.fs.resolve_path(f, self.protocol.cwd)
            if self.fs.exists(pname):
                self.errorWrite(
                    'mkdir: cannot create directory `{}\': File exists\n'.format(f))
                return
            try:
                self.fs.mkdir(pname, 0, 0, 4096, 16877)
            except (fs.FileNotFound):
                self.errorWrite('mkdir: cannot create directory `{}\': No such file or directory\n'.format(f))
            return


commands['/bin/mkdir'] = command_mkdir


class command_rmdir(HoneyPotCommand):
    """
    rmdir command
    """

    def call(self):
        for f in self.args:
            pname = self.fs.resolve_path(f, self.protocol.cwd)
            try:
                if len(self.fs.get_path(pname)):
                    self.errorWrite(
                        'rmdir: failed to remove `{}\': Directory not empty\n'.format(f))
                    continue
                dir = self.fs.get_path('/'.join(pname.split('/')[:-1]))
            except (IndexError, fs.FileNotFound):
                dir = None
            fname = os.path.basename(f)
            if not dir or fname not in [x[fs.A_NAME] for x in dir]:
                self.errorWrite(
                    'rmdir: failed to remove `{}\': No such file or directory\n'.format(f))
                continue
            for i in dir[:]:
                if i[fs.A_NAME] == fname:
                    if i[fs.A_TYPE] != fs.T_DIR:
                        self.errorWrite("rmdir: failed to remove '{}': Not a directory\n".format(f))
                        return
                    dir.remove(i)
                    break


commands['/bin/rmdir'] = command_rmdir
commands['rmdir'] = command_rmdir


class command_pwd(HoneyPotCommand):
    """
    pwd command
    """

    def call(self):
        self.write(self.protocol.cwd + '\n')


commands['/bin/pwd'] = command_pwd
commands['pwd'] = command_pwd


class command_touch(HoneyPotCommand):
    """
    touch command
    """

    def call(self):
        if not len(self.args):
            self.errorWrite('touch: missing file operand\n')
            self.errorWrite('Try `touch --help\' for more information.\n')
            return
        for f in self.args:
            pname = self.fs.resolve_path(f, self.protocol.cwd)
            if not self.fs.exists(os.path.dirname(pname)):
                self.errorWrite(
                    'touch: cannot touch `{}`: No such file or directory\n'.format(pname))
                return
            if self.fs.exists(pname):
                # FIXME: modify the timestamp here
                continue
            # can't touch in special directories
            if any([pname.startswith(_p) for _p in fs.SPECIAL_PATHS]):
                self.errorWrite(
                    'touch: cannot touch `{}`: Permission denied\n'.format(pname))
                return

            self.fs.mkfile(pname, 0, 0, 0, 33188)


commands['/bin/touch'] = command_touch
commands['touch'] = command_touch
commands['>'] = command_touch
