from core.Kippo import HoneyPotCommand

class command_ssh(HoneyPotCommand):
    def call(self, args):
        if not len(args.strip()):
            for l in (
                    'usage: ssh [-1246AaCfgKkMNnqsTtVvXxY] [-b bind_address] [-c cipher_spec]',
                    '           [-D [bind_address:]port] [-e escape_char] [-F configfile]',
                    '           [-i identity_file] [-L [bind_address:]port:host:hostport]',
                    '           [-l login_name] [-m mac_spec] [-O ctl_cmd] [-o option] [-p port]',
                    '           [-R [bind_address:]port:host:hostport] [-S ctl_path]',
                    '           [-w local_tun[:remote_tun]] [user@]hostname [command]',
                    ):
                self.honeypot.writeln(l)
                return
        self.honeypot.writeln('The authenticity of host \'127.0.0.4 (127.0.0.4)\' can\'t be established.')
        self.honeypot.writeln('RSA key fingerprint is 9c:30:97:8e:9e:f8:0d:de:04:8d:76:3a:7b:4b:30:f8.')
        self.honeypot.terminal.write('Are you sure you want to continue connecting (yes/no)? ')
        self.callback = (callback_connect, args)

class callback_connect(HoneyPotCommand):
    def call(self, line, args):
        host = args.strip()
        self.honeypot.writeln(
            'Warning: Permanently added \'%s\' (RSA) to the list of known hosts.' % \
            host)
        self.honeypot.terminal.write('%s\'s password: ' % args)
        self.honeypot.password_input = True
        self.callback = (callback_done, args)

class callback_done(HoneyPotCommand):
    def call(self, line, args):
        user = 'root'
        if args.count('@'):
            user, rest = args.split('@', 1)
        else:
            rest = args
        host = rest.strip().split('.')
        if len(host) and host[0].isalpha():
            host = host[0]
        else:
            host = 'localhost'
        self.honeypot.password_input = False
        self.honeypot.prompt = '%s:%%(path)s# ' % host
