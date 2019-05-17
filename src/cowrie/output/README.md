To create additional output plugins, place Python modules in this directory.

Plugins need to subclass cowrie.core.output.Output and define at least the
methods 'start', 'stop' and 'write'

    import cowrie.core.output

    class Output(cowrie.core.output.Output):

        def start(self):

        def stop(self):

        def write( self, event ):


