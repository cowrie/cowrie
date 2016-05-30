# Copyright (c) 2010 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

import getopt
import copy
from os import path
from cowrie.core.honeypot import HoneyPotCommand
from cowrie.core.fs import *

commands = {}

class command_cat(HoneyPotCommand):
    """
    """
    def start(self):
        if not self.args or self.args[0] == '>':
            pass
        if self.input_data:
            self.write(self.input_data)
        else:
            for arg in self.args:
                path = self.fs.resolve_path(arg, self.protocol.cwd)
                if self.fs.isdir(path):
                    self.error('cat: %s: Is a directory\n' % (arg,))
                    continue
                try:
                    self.write(self.fs.file_contents(path))
                except:
                    self.error('cat: %s: No such file or directory\n' % (arg,))
        self.exit()

    def lineReceived(self, line):
        log.msg(eventid='cowrie.session.file_download',
                realm='cat',
                input=line,
                format='INPUT (%(realm)s): %(input)s')

    def handle_CTRL_D(self):
        self.exit()


commands['/bin/cat'] = command_cat


class command_grep(HoneyPotCommand):
    """
    """

    def grep_get_contents(self, filename, match):
        try:
            contents = self.fs.file_contents(filename)
            self.grep_application(contents, match)
        except:
            self.error("grep: %s: No such file or directory\n" % (filename,))

    def grep_application(self, contents, match):
        match = path.basename(match)
        match = match.replace("\"","")
        contentsplit = contents.split('\n')
        matches = re.compile(".*" + match + ".*")
        for line in contentsplit:
            if matches.match(line):
                self.write(line + '\n')

    def help(self):
        self.error( '\nusage: grep [-abcDEFGHhIiJLlmnOoPqRSsUVvwxZ] [-A num] [-B num] [-C[num]]\n ')
        self.error ('[-e pattern] [-f file] [--binary-files=value] [--color=when]\n ')
        self.error ('[--context[=num]] [--directories=action] [--label] [--line-buffered]\n')
        self.error ('[--null] [pattern] [file ...]\n')

    def start(self):
        self.n = 10
        if not self.args or self.args[0] == '>':
            pass
        else:
            try:
                optlist, args = getopt.getopt(self.args, 'abcDEFGHhIiJLlmnOoPqRSsUVvwxZA:B:C:e:f:')
            except getopt.GetoptError as err:
                self.error("grep: invalid option -- %s" % (err.opt))
                self.help()
                self.exit()
                return

            for opt in optlist:
                if opt == '-h':
                    self.help()

        if not self.input_data:
            files = self.check_arguments("grep", args[1:])
            for path in files:
                self.grep_get_contents(path,args[0])
        else:
            self.grep_application(self.input_data,args[0])

        self.exit()

    def lineReceived(self, line):
        log.msg(eventid='cowrie.session.file_download',
                realm='tail',
                input=line,
                format='INPUT (%(realm)s): %(input)s')

    def handle_CTRL_D(self):
        self.exit()


commands['/bin/grep'] = command_grep
commands['/usr/bin/grep'] = command_grep


class command_tail(HoneyPotCommand):
    """
    """

    def tail_get_contents(self, filename):
        try:
            contents = self.fs.file_contents(filename)
            self.tail_application(contents)
        except:
            self.error("tail: cannot open `%s' for reading: No such file or directory\n" % (filename,))

    def tail_application(self, contents):
        contentsplit = contents.split('\n')
        lines = int(len(contentsplit))
        if lines < self.n:
            self.n = lines - 1
        i = 0
        for j in range((lines - self.n - 1), lines):
            if i < self.n:
                self.write(contentsplit[j] + '\n')
            i += 1

    def start(self):
        self.n = 10
        if not self.args or self.args[0] == '>':
            pass
        else:
            try:
                optlist, args = getopt.getopt(self.args, 'n:')
            except getopt.GetoptError as err:
                self.error("tail: invalid option -- '%s'\n" % (err.opt))
                self.exit()
                return

            for opt in optlist:
                if opt[0] == '-n':
                    if not opt[1].isdigit():
                        self.error("tail: illegal offset -- %s\n" % opt[1])
                    else:
                        self.n = int(opt[1])
        if not self.input_data:
            files = self.check_arguments("tail", args)
            for path in files:
                self.tail_get_contents(path)
        else:
            self.tail_application(self.input_data)

        self.exit()

    def lineReceived(self, line):
        log.msg(eventid='cowrie.session.file_download',
                realm='tail',
                input=line,
                format='INPUT (%(realm)s): %(input)s')

    def handle_CTRL_D(self):
        self.exit()


commands['/bin/tail'] = command_tail
commands['/usr/bin/tail'] = command_tail


class command_head(HoneyPotCommand):
    """
    """

    def head_application(self, contents):
        i = 0
        contentsplit = str(contents).split("\n")
        for line in contentsplit:
            if i < self.n:
                self.write(line + '\n')
            i += 1

    def head_get_file_contents(self, filename):
        try:
            contents = self.fs.file_contents(filename)
            self.head_application(contents)
        except:
            self.write("head: cannot open `%s' for reading: No such file or directory\n" % (filename,))

    def start(self):
        self.n = 10
        if not self.args or self.args[0] == '>':
            pass
        else:
            try:
                optlist, args = getopt.getopt(self.args, 'n:')
            except getopt.GetoptError as err:
                self.error("head: invalid option -- '%s'\n" % (err.opt,))
                self.exit()
                return

            for opt in optlist:
                if opt[0] == '-n':
                    if not opt[1].isdigit():
                        self.error("head: illegal offset -- %s\n" % opt[1])
                    else:
                        self.n = int(opt[1])

        if not self.input_data:
            files = self.check_arguments("head", args)
            for path in files:
                self.head_get_file_contents(path)
        else:
            self.head_application(self.input_data)
        self.exit()

    def lineReceived(self, line):
        log.msg(eventid='cowrie.session.file_download', realm='head', input=line,
                format='INPUT (%(realm)s): %(input)s')

    def handle_CTRL_D(self):
        self.exit()


commands['/bin/head'] = command_head
commands['/usr/bin/head'] = command_head


class command_cd(HoneyPotCommand):
    """
    """

    def call(self):
        if not self.args or self.args[0] == "~":
            path = self.protocol.user.avatar.home
        else:
            path = self.args[0]
        try:
            newpath = self.fs.resolve_path(path, self.protocol.cwd)
            inode = self.fs.getfile(newpath)
        except:
            newdir = None
        if path == "-":
            self.write('bash: cd: OLDPWD not set\n')
            return
        if inode is None or inode is False:
            self.error('bash: cd: %s: No such file or directory\n' % (path,))
            return
        if inode[A_TYPE] != T_DIR:
            self.error('bash: cd: %s: Not a directory\n' % (path,))
            return
        self.protocol.cwd = newpath


commands['cd'] = command_cd


class command_rm(HoneyPotCommand):
    def call(self):
        recursive = False
        for f in self.args:
            if f.startswith('-') and 'r' in f:
                recursive = True
        for f in self.args:
            path = self.fs.resolve_path(f, self.protocol.cwd)
            try:
                dir = self.fs.get_path('/'.join(path.split('/')[:-1]))
            except (IndexError, FileNotFound):
                self.write(
                    'rm: cannot remove `%s\': No such file or directory\n' % f)
                continue
            basename = path.split('/')[-1]
            contents = [x for x in dir]
            for i in dir[:]:
                if i[A_NAME] == basename:
                    if i[A_TYPE] == T_DIR and not recursive:
                        self.write(
                            'rm: cannot remove `%s\': Is a directory\n' % \
                            i[A_NAME])
                    else:
                        dir.remove(i)


commands['/bin/rm'] = command_rm


class command_cp(HoneyPotCommand):
    """
    """

    def call(self):
        if not len(self.args):
            self.write("cp: missing file operand\n")
            self.write("Try `cp --help' for more information.\n")
            return
        try:
            optlist, args = getopt.gnu_getopt(self.args,
                                              '-abdfiHlLPpRrsStTuvx')
        except getopt.GetoptError as err:
            self.write('Unrecognized option\n')
            return
        recursive = False
        for opt in optlist:
            if opt[0] in ('-r', '-a', '-R'):
                recursive = True

        def resolv(path):
            return self.fs.resolve_path(path, self.protocol.cwd)

        if len(args) < 2:
            self.write("cp: missing destination file operand after `%s'\n" % \
                       (self.args[0],))
            self.write("Try `cp --help' for more information.\n")
            return
        sources, dest = args[:-1], args[-1]
        if len(sources) > 1 and not self.fs.isdir(resolv(dest)):
            self.write("cp: target `%s' is not a directory\n" % (dest,))
            return

        if dest[-1] == '/' and not self.fs.exists(resolv(dest)) and \
                not recursive:
            self.write(
                "cp: cannot create regular file `%s': Is a directory\n" % \
                (dest,))
            return

        if self.fs.isdir(resolv(dest)):
            isdir = True
        else:
            isdir = False
            parent = os.path.dirname(resolv(dest))
            if not self.fs.exists(parent):
                self.write("cp: cannot create regular file " + \
                           "`%s': No such file or directory\n" % (dest,))
                return

        for src in sources:
            if not self.fs.exists(resolv(src)):
                self.write(
                    "cp: cannot stat `%s': No such file or directory\n" % (src,))
                continue
            if not recursive and self.fs.isdir(resolv(src)):
                self.write("cp: omitting directory `%s'\n" % (src,))
                continue
            s = copy.deepcopy(self.fs.getfile(resolv(src)))
            if isdir:
                dir = self.fs.get_path(resolv(dest))
                outfile = os.path.basename(src)
            else:
                dir = self.fs.get_path(os.path.dirname(resolv(dest)))
                outfile = os.path.basename(dest.rstrip('/'))
            if outfile in [x[A_NAME] for x in dir]:
                dir.remove([x for x in dir if x[A_NAME] == outfile][0])
            s[A_NAME] = outfile
            dir.append(s)


commands['/bin/cp'] = command_cp


class command_mv(HoneyPotCommand):
    """
    """
    def call(self):
        if not len(self.args):
            self.write("mv: missing file operand\n")
            self.write("Try `mv --help' for more information.\n")
            return

        try:
            optlist, args = getopt.gnu_getopt(self.args, '-bfiStTuv')
        except getopt.GetoptError as err:
            self.write('Unrecognized option\n')
            self.exit()

        def resolv(path):
            return self.fs.resolve_path(path, self.protocol.cwd)

        if len(args) < 2:
            self.write("mv: missing destination file operand after `%s'\n" % \
                       (self.args[0],))
            self.write("Try `mv --help' for more information.\n")
            return
        sources, dest = args[:-1], args[-1]
        if len(sources) > 1 and not self.fs.isdir(resolv(dest)):
            self.write("mv: target `%s' is not a directory\n" % (dest,))
            return

        if dest[-1] == '/' and not self.fs.exists(resolv(dest)) and \
                        len(sources) != 1:
            self.write(
                "mv: cannot create regular file `%s': Is a directory\n" % \
                (dest,))
            return

        if self.fs.isdir(resolv(dest)):
            isdir = True
        else:
            isdir = False
            parent = os.path.dirname(resolv(dest))
            if not self.fs.exists(parent):
                self.write("mv: cannot create regular file " + \
                           "`%s': No such file or directory\n" % \
                           (dest,))
                return

        for src in sources:
            if not self.fs.exists(resolv(src)):
                self.write(
                    "mv: cannot stat `%s': No such file or directory\n" % \
                    (src,))
                continue
            s = self.fs.getfile(resolv(src))
            if isdir:
                dir = self.fs.get_path(resolv(dest))
                outfile = os.path.basename(src)
            else:
                dir = self.fs.get_path(os.path.dirname(resolv(dest)))
                outfile = os.path.basename(dest)
            if dir != os.path.dirname(resolv(src)):
                s[A_NAME] = outfile
                dir.append(s)
                sdir = self.fs.get_path(os.path.dirname(resolv(src)))
                sdir.remove(s)
            else:
                s[A_NAME] = outfile


commands['/bin/mv'] = command_mv


class command_mkdir(HoneyPotCommand):
    """
    """
    def call(self):
        for f in self.args:
            path = self.fs.resolve_path(f, self.protocol.cwd)
            if self.fs.exists(path):
                self.write(
                    'mkdir: cannot create directory `%s\': File exists\n' % f)
                return
            try:
                self.fs.mkdir(path, 0, 0, 4096, 16877)
            except (FileNotFound) as err:
                self.write(
                    'mkdir: cannot create directory `%s\': ' % f + \
                    'No such file or directory\n')
            return


commands['/bin/mkdir'] = command_mkdir


class command_rmdir(HoneyPotCommand):
    """
    """

    def call(self):
        for f in self.args:
            path = self.fs.resolve_path(f, self.protocol.cwd)
            try:
                if len(self.fs.get_path(path)):
                    self.write(
                        'rmdir: failed to remove `%s\': Directory not empty\n' % f)
                    continue
                dir = self.fs.get_path('/'.join(path.split('/')[:-1]))
            except (IndexError, FileNotFound):
                dir = None
            fname = os.path.basename(f)
            if not dir or fname not in [x[A_NAME] for x in dir]:
                self.write(
                    'rmdir: failed to remove `%s\': ' % f + \
                    'No such file or directory\n')
                continue
            for i in dir[:]:
                if i[A_NAME] == fname:
                    if i[A_TYPE] != T_DIR:
                        self.write("rmdir: failed to remove '%s': Not a directory\n" % f)
                        return
                    dir.remove(i)
                    break


commands['/bin/rmdir'] = command_rmdir


class command_pwd(HoneyPotCommand):
    """
    """

    def call(self):
        self.write(self.protocol.cwd + '\n')


commands['/bin/pwd'] = command_pwd


class command_touch(HoneyPotCommand):
    """
    """
    def call(self):
        if not len(self.args):
            self.write('touch: missing file operand\n')
            self.write('Try `touch --help\' for more information.\n')
            return
        for f in self.args:
            path = self.fs.resolve_path(f, self.protocol.cwd)
            if not self.fs.exists(os.path.dirname(path)):
                self.write(
                    'touch: cannot touch `%s`: no such file or directory\n' % \
                    (path,))
                return
            if self.fs.exists(path):
                # FIXME: modify the timestamp here
                continue
            self.fs.mkfile(path, 0, 0, 0, 33188)


commands['/usr/bin/touch'] = command_touch
commands['/bin/touch'] = command_touch

# vim: set sw=4 et:
