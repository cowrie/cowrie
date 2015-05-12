To create additional output plugins, place Python modules in this directory.

Plugins need to subclass cowrie.core.output.Output and define at least the
methods 'start', 'stop' and 'handleLog'

    import cowrie.core.output

    class Output(cowrie.core.output.Output):

        def start(self, cfg):

        def stop(self):

        def handleLog( self, event ):



