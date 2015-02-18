To create additional output plugins, place Python modules in this directory.

Plugins need to subclass kippo.core.output.Output and define at least the
methods 'start', 'stop' and 'handleLog'

    import kippo.core.output

    class Output(kippo.core.output.Output):

        def start(self, cfg):

        def stop(self):

        def handleLog( self, event ):



