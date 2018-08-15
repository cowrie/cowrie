import os
import time
import docker


class DockerHelper():
    @staticmethod
    def get(name):
        """
        Create a Container that can be used within the tests.
        """
        docker_client = docker.from_env()
        docker_client.images.build(
            path=os.getcwd(), tag=f"{name}-image")
        container = docker_client.containers.run(
            image=f"{name}-image", name=f"{name}-container",
            detach=True, remove=True)
        container.reload()
        time.sleep(10)
        return container
