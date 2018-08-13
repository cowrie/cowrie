import os
import time

import docker


class DockerHelper():
    @staticmethod
    def get(name):
        """
        Create a Container that can be used within the tests.
        """
        dockerClient = docker.from_env()
        dockerClient.images.build(
            path=os.getcwd(), tag=f"{name}-image")
        container = dockerClient.containers.run(
            image=f"{name}-image", name=f"{name}-container",
            detach=True, remove=True)
        container.reload()
        time.sleep(10)
        return container
