from backend_pool.ssh_exec import execute_ssh

HOST = '127.0.0.1'
PORT_BACKEND = 4444
PORT_PROXY = 5555
USERNAME_BACKEND = 'root'
PASSWORD_BACKEND = 'example'
USERNAME_PROXY = 'root'
PASSWORD_PROXY = 'example'


class ProxyCommandCompare:
    def __init__(self):
        self.backend_data = None
        self.proxy_data = None

    def execute(self, command, deferred):
        def callback_backend(data):
            # if we haven't received data from the proxy just store the output
            if not self.proxy_data:
                self.backend_data = data
            else:
                # compare data from proxy and backend
                if data == self.proxy_data:
                    deferred.callback(True)
                else:
                    deferred.errback(ValueError())

        def callback_proxy(data):
            # if we haven't received data from the backend just store the output
            if not self.backend_data:
                self.proxy_data = data
            else:
                # compare data from proxy and backend
                if data == self.backend_data:
                    deferred.callback(True)
                else:
                    deferred.errback(ValueError("Values from proxy and backend do not match!"))

        # execute SSH exec command on both backend and proxy
        execute_ssh(HOST, PORT_BACKEND, USERNAME_BACKEND, PASSWORD_BACKEND, command, callback_backend)
        execute_ssh(HOST, PORT_PROXY, USERNAME_PROXY, PASSWORD_PROXY, command, callback_proxy)
