#!/usr/bin/env python

import datetime
import json
import random

import psutil


def run():
    command: dict = {}
    command["command"] = {}
    command["command"]["ps"] = []

    randomStates = ["Ss", "S<", "D<", "Ss+"]
    for proc in psutil.process_iter():
        try:
            info = proc.as_dict(
                attrs=[
                    "pid",
                    "name",
                    "cmdline",
                    "username",
                    "cpu_percent",
                    "memory_percent",
                    "memory_info",
                    "create_time",
                    "terminal",
                    "status",
                    "cpu_times",
                ]
            )
        except psutil.NoSuchProcess:
            pass
        else:
            object = {}
            object["USER"] = info["username"]
            object["PID"] = info["pid"]
            if info["cmdline"]:
                object["COMMAND"] = "/".join(info["cmdline"])
            else:
                object["COMMAND"] = "[ " + info["name"] + " ]"
            object["CPU"] = info["cpu_percent"]
            object["MEM"] = info["memory_percent"]
            object["RSS"] = info["memory_info"].rss
            object["VSZ"] = info["memory_info"].vms
            object["START"] = datetime.datetime.fromtimestamp(
                info["create_time"]
            ).strftime("%b%d")
            if info["terminal"]:
                object["TTY"] = str(info["terminal"]).replace("/dev/", "")
            else:
                object["TTY"] = "?"
            object["STAT"] = random.choice(randomStates)
            object["TIME"] = info["cpu_times"].user
            command["command"]["ps"].append(object)

    print(json.dumps(command, indent=4, sort_keys=True))


if __name__ == "__main__":
    run()
