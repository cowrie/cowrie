from core.Kippo import HoneyPotCommand

class command_ssh(HoneyPotCommand):
    def start(self):
        if not len(self.args.strip()):
            for l in (
                    'usage: ssh [-1246AaCfgKkMNnqsTtVvXxY] [-b bind_address] [-c cipher_spec]',
                    '           [-D [bind_address:]port] [-e escape_char] [-F configfile]',
                    '           [-i identity_file] [-L [bind_address:]port:host:hostport]',
                    '           [-l login_name] [-m mac_spec] [-O ctl_cmd] [-o option] [-p port]',
                    '           [-R [bind_address:]port:host:hostport] [-S ctl_path]',
                    '           [-w local_tun[:remote_tun]] [user@]hostname [command]',
                    ):
                self.honeypot.writeln(l)
                self.exit()
                return
        self.host = self.args.strip()
        self.honeypot.writeln('The authenticity of host \'187.42.2.9 (187.42.2.9)\' can\'t be established.')
        self.honeypot.writeln('RSA key fingerprint is 9d:30:97:8a:9e:48:0d:de:04:8d:76:3a:7b:4b:30:f8.')
        self.honeypot.terminal.write('Are you sure you want to continue connecting (yes/no)? ')
        self.callbacks = [self.yesno, self.finish]

    def yesno(self, args):
        host = args.strip()
        self.honeypot.writeln(
            'Warning: Permanently added \'%s\' (RSA) to the list of known hosts.' % \
            host)
        self.honeypot.terminal.write('%s\'s password: ' % self.host)
        self.honeypot.password_input = True

    def finish(self, args):
        user, rest, host = 'root', self.host, 'localhost'
        if self.host.count('@'):
            user, rest = self.host.split('@', 1)
        rest = rest.strip().split('.')
        if len(rest) and rest[0].isalpha():
            host = rest[0]

        self.honeypot.hostname = host
        self.honeypot.password_input = False
        self.exit()

    def lineReceived(self, line):
        print 'ssh input:', line
        self.callbacks.pop(0)(line)
