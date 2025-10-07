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
            obj = {}
            obj["USER"] = info["username"]
            obj["PID"] = info["pid"]
            if info["cmdline"]:
                obj["COMMAND"] = "/".join(info["cmdline"])
            else:
                obj["COMMAND"] = "[ " + info["name"] + " ]"
            obj["CPU"] = info["cpu_percent"]
            obj["MEM"] = info["memory_percent"]
            obj["RSS"] = info["memory_info"].rss
            obj["VSZ"] = info["memory_info"].vms
            obj["START"] = datetime.datetime.fromtimestamp(
                info["create_time"]
            ).strftime("%b%d")
            if info["terminal"]:
                obj["TTY"] = str(info["terminal"]).replace("/dev/", "")
            else:
                obj["TTY"] = "?"
            obj["STAT"] = random.choice(randomStates)
            obj["TIME"] = info["cpu_times"].user
            command["command"]["ps"].append(obj)

    print(json.dumps(command, indent=4, sort_keys=True))


if __name__ == "__main__":
    run()
