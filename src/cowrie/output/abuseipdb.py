# MIT License
#
# Copyright (c) 2020 Benjamin Stephens <premier_contact@ben-stephens.net>
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.


"""
Cowrie plugin for reporting login attempts via the AbuseIPDB API.

"AbuseIPDB is a project dedicated to helping combat the spread of hackers,
spammers, and abusive activity on the internet." <https://www.abuseipdb.com/>
"""

from __future__ import annotations

__author__ = "Benjamin Stephens"
__version__ = "0.3b3"

import pickle
from collections import deque
from datetime import datetime
from json.decoder import JSONDecodeError
from pathlib import Path
from time import sleep, time

from treq import post

from twisted.internet import defer, threads
from twisted.internet import reactor
from twisted.python import log
from twisted.web import http

from cowrie.core import output
from cowrie.core.config import CowrieConfig

# How often we clean and dump and our lists/dict...
CLEAN_DUMP_SCHED = 600
# ...and the file we dump to.
DUMP_FILE: str = "aipdb.dump"

ABUSEIP_URL = "https://api.abuseipdb.com/api/v2/report"
# AbuseIPDB will just 429 us if we report an IP too often; currently 15 minutes
# (900 seconds); set lower limit here to protect againt bad user input.
REREPORT_MINIMUM = 900


class Output(output.Output):
    def start(self):
        self.tolerance_attempts: int = CowrieConfig.getint(
            "output_abuseipdb", "tolerance_attempts", fallback=10
        )
        self.state_path = Path(CowrieConfig.get("output_abuseipdb", "dump_path"))
        self.state_dump = self.state_path / DUMP_FILE

        self.logbook = LogBook(self.tolerance_attempts, self.state_dump)
        # Pass our instance of LogBook() to Reporter() so we don't end up
        # working with different records.
        self.reporter = Reporter(self.logbook, self.tolerance_attempts)

        # We store the LogBook state any time a shutdown occurs. The rest of
        # our start-up is just for loading and cleaning the previous state
        try:
            with open(self.state_dump, "rb") as f:
                self.logbook.update(pickle.load(f))

            # Check to see if we're still asleep after receiving a Retry-After
            # header in a previous response
            if self.logbook["sleeping"]:
                t_wake: float = self.logbook["sleep_until"]
                t_now: float = time()
                if t_wake > t_now:
                    # If we're meant to be asleep, we'll set logbook.sleep to
                    # true and logbook.sleep_until to the time we can wake-up
                    self.logbook.sleeping = True
                    self.logbook.sleep_until = t_wake
                    # and we set an alarm so the reactor knows when he can drag
                    # us back out of bed
                    reactor.callLater(t_wake - t_now, self.logbook.wakeup)

            del self.logbook["sleeping"]
            del self.logbook["sleep_until"]
            tolerated = self.logbook.pop("tolerated")

        except (pickle.UnpicklingError, FileNotFoundError, KeyError):
            if self.state_path.exists():
                pass
            else:
                # If we don't already have an abuseipdb directory, let's make
                # one with the necessary permissions now.
                Path(self.state_path).mkdir(mode=0o700, parents=False, exist_ok=False)

        # And we do a clean-up to make sure that we're not carrying any expired
        # entries. The clean-up task ends by calling itself in a callLater,
        # thus running every CLEAN_DUMP_SCHED seconds until the end of time.
        self.logbook.cleanup_and_dump_state()

        # If tolerance_attempts > the previous setting, we need to change the
        # maximum length of the deque for any previously seen IP that we're
        # loading, otherwise we'd potentially have IPs that may never trigger
        # a report
        try:
            if tolerated != self.tolerance_attempts:
                for k in self.logbook:
                    if self.logbook[k].__class__() == deque():
                        self.logbook[k] = deque(
                            [*self.logbook[k]], maxlen=self.tolerance_attempts
                        )
        except UnboundLocalError:
            pass

        log.msg(
            eventid="cowrie.abuseipdb.started",
            format=f"AbuseIPDB Plugin version {__version__} started. Currently in beta.",
        )

    def stop(self):
        self.logbook.cleanup_and_dump_state(mode=1)

    def write(self, ev):
        if self.logbook.sleeping:
            return

        if ev["eventid"].rsplit(".", 1)[0] == "cowrie.login":
            # If tolerance_attempts was set to 1 or 0, we don't need to
            # keep logs so our handling of the event is different than if > 1
            if self.tolerance_attempts <= 1:
                self.intolerant_observer(ev["src_ip"], time(), ev["username"])
            else:
                self.tolerant_observer(ev["src_ip"], time())

    def intolerant_observer(self, ip, t, uname):
        # Checks if already reported; if yes, checks if we can rereport yet.
        # The entry for a reported IP is a tuple (None, time_reported). If IP
        # is not already in logbook, reports it immediately
        if ip in self.logbook:
            if self.logbook.can_rereport(ip, t):
                self.reporter.report_ip_single(ip, t, uname)
            else:
                return
        else:
            self.reporter.report_ip_single(ip, t, uname)

    def tolerant_observer(self, ip, t):
        # Appends the time an IP was seen to it's list in logbook. Once the
        # length of the list equals tolerance_attempts, the IP is reported.
        if ip in self.logbook:
            try:
                if self.logbook[ip][0]:
                    # Evaluates true if IP not already reported. If reported,
                    # logbook entry is of the form (None, time_reported).
                    self.logbook[ip].append(t)
                    self.logbook.clean_expired_timestamps(ip, t)

                    if len(self.logbook[ip]) >= self.tolerance_attempts:
                        self.reporter.report_ip_multiple(ip)

                elif self.logbook.can_rereport(ip, t):
                    # Check if reported IP is ready for re-reporting
                    self.logbook[ip] = deque([t], maxlen=self.tolerance_attempts)

                else:
                    return

            except IndexError:
                # If IP address was in logbook but had no entries then we're
                # fine to re-report.
                self.logbook[ip].append(t)

        else:
            self.logbook[ip] = deque([t], maxlen=self.tolerance_attempts)


class LogBook(dict):
    """
    Dictionary class with methods for cleaning and dumping its state.

    This class should be treated as global state. For the moment this is
    achieved simply by passing the instance created by Output() directly to
    Reporter(). Sharing is caring.
    """

    def __init__(self, tolerance_attempts, state_dump):
        self.sleeping = False
        self.sleep_until: float = 0.0
        self.tolerance_attempts = tolerance_attempts
        self.tolerance_window: int = 60 * CowrieConfig.getint(
            "output_abuseipdb", "tolerance_window", fallback=120
        )
        self.rereport_after: float = 3600 * CowrieConfig.getfloat(
            "output_abuseipdb", "rereport_after", fallback=24
        )
        if self.rereport_after < REREPORT_MINIMUM:
            self.rereport_after = REREPORT_MINIMUM
        self.state_dump = state_dump
        # To write our dump to disk we have a method we call in a thread so we
        # don't block if we get slow io. This is a cheap hack to get a lock on
        # the file. See self.write_dump_file()
        self._writing = False
        super().__init__()

    def wakeup(self):
        # This is the method we pass in a callLater() before we go to sleep.
        self.sleeping = False
        self.sleep_until = 0
        self.recall = reactor.callLater(CLEAN_DUMP_SCHED, self.cleanup_and_dump_state)
        log.msg(
            eventid="cowrie.abuseipdb.wakeup",
            format="AbuseIPDB plugin resuming activity after receiving "
            "Retry-After header in previous response.",
        )

    def clean_expired_timestamps(self, ip_key, current_time):
        # Performs popleft() if leftmost timestamp has expired. Continues doing
        # so until either; 1) a timestamp within our reporting window is
        # reached, or; 2) the list is empty.
        while self[ip_key]:
            if not self[ip_key][0]:
                break
            elif self[ip_key][0] < current_time - self.tolerance_window:
                self[ip_key].popleft()
            else:
                break

    def find_and_delete_empty_entries(self):
        # Search and destroy method. Iterates over dict, appends k to delete_me
        # where v is an empty list.
        delete_me = []
        for k in self:
            if not self[k]:
                delete_me.append(k)
        self.delete_entries(delete_me)

    def delete_entries(self, delete_me):
        for i in delete_me:
            del self[i]

    def can_rereport(self, ip_key, current_time):
        # Checks if an IP in the logbook that has already been reported is
        # ready to be re-reported again.
        try:
            if current_time > self[ip_key][1] + self.rereport_after:
                return True

            elif self[ip_key][0] and self.tolerance_attempts <= 1:
                # If we were previously running with a tolerance_attempts > 1
                # and have been been restarted with tolerance_attempts <= 1,
                # we could still be carrying some logs which would evaluate as
                # false in our first test. Reported IPs will still evaluate
                # false here.
                return True

            else:
                return False

        except IndexError:
            return True

    def cleanup_and_dump_state(self, mode=0):
        # Runs a full clean-up of logbook. Re-calls itself in CLEAN_DUMP_SCHED
        # seconds. MODES: 0) Normal looping task, and; 1) Sleep/Stop mode;
        # cancels any scheduled callLater() and doesn't recall itself.
        if mode == 1:
            try:
                self.recall.cancel()
            except AttributeError:
                pass

        if self.sleeping:
            t = self.sleep_until
        else:
            t = time()

        delete_me = []
        for k in self:
            if self.can_rereport(k, t):
                delete_me.append(k)
            self.clean_expired_timestamps(k, t)
        self.delete_entries(delete_me)

        self.find_and_delete_empty_entries()

        self.dump_state()

        if mode == 0 and not self.sleeping:
            self.recall = reactor.callLater(
                CLEAN_DUMP_SCHED, self.cleanup_and_dump_state
            )

    def dump_state(self):
        dump = {
            "sleeping": self.sleeping,
            "sleep_until": self.sleep_until,
            # Store current self_tolerance for comparison on next start
            "tolerated": self.tolerance_attempts,
        }

        for k, v in self.items():
            dump[k] = v

        reactor.callInThread(self.write_dump_file, dump)

    def write_dump_file(self, dump):
        # Check self._writing; waits for release; timeout after 10 seconds.
        i = 0
        while self._writing:
            sleep(1)
            i += 1
            if i >= 10:
                return

        # Acquire 'lock'
        self._writing = True

        with open(self.state_dump, "wb") as f:
            pickle.dump(dump, f, protocol=pickle.HIGHEST_PROTOCOL)

        # Release 'lock'
        self._writing = False


class Reporter:
    """
    HTTP client and methods for preparing report paramaters.
    """

    def __init__(self, logbook, attempts):
        self.logbook = logbook
        self.attempts = attempts
        self.headers = {
            "User-Agent": "Cowrie Honeypot AbuseIPDB plugin",
            "Accept": "application/json",
            "Key": CowrieConfig.get("output_abuseipdb", "api_key"),
        }

    def report_ip_single(self, ip, t, uname):
        self.logbook[ip] = (None, t)

        t = self.epoch_to_string_utc(t)

        params = {
            "ip": ip,
            "categories": "18,22",
            "comment": "Cowrie Honeypot: Unauthorised SSH/Telnet login attempt "
            f'with user "{uname}" at {t}',
        }

        self.http_request(params)

    def report_ip_multiple(self, ip):
        t_last = self.logbook[ip].pop()
        t_first = self.epoch_to_string_utc(self.logbook[ip].popleft())

        self.logbook[ip] = (None, t_last)

        t_last = self.epoch_to_string_utc(t_last)

        params = {
            "ip": ip,
            "categories": "18,22",
            "comment": "Cowrie Honeypot: {} unauthorised SSH/Telnet login attempts "
            "between {} and {}".format(self.attempts, t_first, t_last),
        }

        self.http_request(params)

    @staticmethod
    def epoch_to_string_utc(t):
        t_utc = datetime.utcfromtimestamp(t)
        return t_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def log_response_failed(ip, response, reason):
        log.msg(
            eventid="cowrie.abuseipdb.reportfail",
            format="AbuseIPDB plugin failed to report IP %(IP)s. Received HTTP "
            "status code %(response)s in response. Reason: %(reason)s.",
            IP=ip,
            response=response,
            reason=reason,
        )

    @defer.inlineCallbacks
    def http_request(self, params):
        try:
            response = yield post(
                url=ABUSEIP_URL,
                headers=self.headers,
                params=params,
            )

        except Exception as e:
            log.msg(
                eventid="cowrie.abuseipdb.reportfail",
                format="AbuseIPDB plugin failed to report IP %(IP)s. "
                "Exception raised: %(exception)s.",
                IP=params["ip"],
                exception=repr(e),
            )
            return

        if response.code != http.OK:
            if response.code == 429:
                return self.rate_limit_handler(params, response)

            try:
                reason = http.RESPONSES[response.code].decode("utf-8")
            except Exception:
                reason = "Unable to determine."

            self.log_response_failed(params["ip"], response.code, reason)

            return

        j = yield response.json()

        log.msg(
            eventid="cowrie.abuseipdb.reportedip",
            format="AbuseIPDB plugin successfully reported %(IP)s. Current "
            "AbuseIPDB confidence score for this IP is %(confidence)s",
            IP=params["ip"],
            confidence=j["data"]["abuseConfidenceScore"],
        )

    @defer.inlineCallbacks
    def rate_limit_handler(self, params, response):
        try:
            j = yield response.json()
            reason = j["errors"][0]["detail"]

        except (KeyError, JSONDecodeError):
            reason = "No other information provided or unexpected response"

        self.log_response_failed(params["ip"], response.code, reason)

        # AbuseIPDB will respond with a 429 and a Retry-After in its response
        # headers if we've exceeded our limits for the day. Here we test for
        # that header and, if it exists, put ourselves to sleep.
        retry_after = yield response.headers.hasHeader("Retry-After")

        if retry_after:
            retry = yield response.headers.getRawHeaders("Retry-After")
            retry = int(retry.pop())

            if retry > 86340:
                yield threads.deferToThread(self.sleeper_thread)

                log.msg(
                    eventid="cowrie.abuseipdb.ratelimited",
                    format="AbuseIPDB plugin received Retry-After header > 86340 "
                    "seconds in previous response. Possible delayed quota "
                    "reset on AbuseIPDB servers; retrying request now.",
                )

                return self.http_request(params)

            self.logbook.sleeping = True
            self.logbook.sleep_until = time() + retry
            reactor.callLater(retry, self.logbook.wakeup)
            # It's not serious if we don't, but it's best to call the clean-up
            # after logbook.sleeping has been set to True. The clean-up method
            # checks for this flag and will use the wake-up time rather than
            # the current time when sleep is set. mode=1 ensures we'll cancel
            # any already scheduled calls to clean-up and don't schedule
            # another one until the wake-up method calls it again.
            self.logbook.cleanup_and_dump_state(mode=1)

            self.epoch_to_string_utc(self.logbook.sleep_until)
            log.msg(
                eventid="cowrie.abuseipdb.ratelimited",
                format="AbuseIPDB plugin received Retry-After header in "
                "response. Reporting activity will resume in "
                "%(retry_after)s seconds at %(wake_at)s",
                retry_after=retry,
                wake_at=self.epoch_to_string_utc(self.logbook.sleep_until),
            )

    def sleeper_thread(self):
        # Cheap retry wait hack. Call in thread so as not to block.
        sleep(10)
