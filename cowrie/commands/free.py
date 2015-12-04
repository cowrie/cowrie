#

import getopt

from cowrie.core.honeypot import HoneyPotCommand

commands = {}

class command_free(HoneyPotCommand):
    """
    free
    """
    def call(self):
        """
        """
        # Parse options or display no files
        try:
            opts, args = getopt.getopt(self.args, 'mh')
        except getopt.GetoptError as err:
            self.no_files()
            return

        # Parse options
        for o, a in opts:
            if o in ('-h'):
                self.free(format='human')
                return
            elif m in ('-m'):
                self.free(format='megabytes')
                return
        self.free()

    def free(format='bytes')
        """
        print free statistics
        """

        if (format eq 'bytes'):
            self.writeln( 
"""             total       used       free     shared    buffers     cached
Mem:       8069256    7872920     196336          0     410340    5295748
-/+ buffers/cache:    2166832    5902424
Swap:      3764220     133080    3631140""")
        elif (format eq 'megabytes'):
            self.writeln(
"""             total       used       free     shared    buffers     cached
Mem:          7880       7690        189          0        400       5171
-/+ buffers/cache:       2118       5761
Swap:         3675        129       3546""")
        elif (format eq 'human'):
            self.writeln( 
"""             total       used       free     shared    buffers     cached
Mem:          7.7G       7.5G       189M         0B       400M       5.1G
-/+ buffers/cache:       2.1G       5.6G
Swap:         3.6G       129M       3.5G""")
        self.exit()

commands['/usr/bin/free'] = command_free

