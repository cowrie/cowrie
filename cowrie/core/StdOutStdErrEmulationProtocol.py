__author__ = 'davegermiquet'

class StdOutStdErrEmulationProtocol(object):

    def __init__(self,protocol,cmd,cmdargs,input_data,next_protocol):
        self.cmd=cmd
        self.cmdargs=cmdargs
        self.input_data=input_data
        self.next_protocol=next_protocol
        self.data = ""
        self.err_data = ""
        self.protocol = protocol

    def connectionMade(self):
        self.input_data = None

    def outReceived(self, data):
        self.data = self.data + data
        if not self.next_protocol:
            self.protocol.terminal.write(data)

    def errReceived(self, data):
        self.protocol.terminal.write(data   )
        self.err_data = self.err_data + data

    def inConnectionLost(self):
        pass

    def outConnectionLost(self):
        if self.next_protocol:
            self.next_protocol.input_data = self.data
            npcmd=self.next_protocol.cmd
            npcmdargs=self.next_protocol.cmdargs
            self.protocol.call_command(self.next_protocol,npcmd,*npcmdargs)

    def errConnectionLost(self):
        pass

    def processExited(self, reason):
        print "processExited for %s, status %d" % (self.cmd,reason.value.exitCode,)

    def processEnded(self, reason):
        print "processEnded for %s, status %d" % (self.cmd,reason.value.exitCode,)
