"""
dig command
"""

from __future__ import annotations

import re
import secrets
from datetime import datetime

from cowrie.shell.command import HoneyPotCommand

commands = {}


class Command_dig(HoneyPotCommand):
    @staticmethod
    def _get_random_ip() -> str:
        return (
            f"{secrets.randbelow(255) + 1}."
            f"{secrets.randbelow(256)}."
            f"{secrets.randbelow(256)}."
            f"{secrets.randbelow(253) + 1}"
        )

    @staticmethod
    def _is_valid_domain(domain: str) -> bool:
        """
        Returns True if the domain looks like a real DNS name.
        """
        # Basic check for something like "domain.com" or "sub.domain.co.uk"
        domain_regex = re.compile(
            r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
            r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*"
            r"\.[A-Za-z]{2,}$"
        )
        return bool(domain_regex.match(domain))

    def start(self):
        if not self.args:
            self.write("usage: dig <hostname>\n")
            self.exit()
            return

        domain = self.args[0]

        record_type = "A"
        query_id = secrets.randbelow(9000) + 1000

        if domain == "-v":
            self.display_version()

        elif domain == "-h" or domain == "-help":
            self.display_help()

        elif domain.startswith("-"):
            self.invalid_arg(domain)

        elif not self._is_valid_domain(domain):
            answer = "help.\t\t585\tIN\tSOA\tns0.centralnic.net. hostmaster.centralnic.net. 1743974120 900 1800 6048000 3600\n\n"
            status = "NXDOMAIN"
            self.dns_text(domain, query_id, record_type, answer, status)

        else:
            # Fake lookup result map
            mock_dns = {
                "google.com": "142.250.190.14",
                "github.com": "140.82.121.4",
                "example.com": "93.184.216.34",
                "attacker.com": "185.199.108.153",
            }
            status = "NOERROR"
            # Default fake IP for unknown domains
            ip = mock_dns.get(domain, self._get_random_ip())
            answer = f"{domain}.\t\t34\tIN\t{record_type}\t{ip}\n\n"
            self.dns_text(domain, query_id, record_type, answer, status)

        self.exit()
        return

    def display_version(self):
        self.write("DiG 9.10.6\n")

    def invalid_arg(self, domain):
        self.write(f"Invalid option: {domain}\n")
        self.write(
            """Usage:  dig [@global-server] [domain] [q-type] [q-class] {q-opt}
                        {global-d-opt} host [@local-server] {local-d-opt}
                        [ host [@local-server] {local-d-opt} [...]]
            
            Use "dig -h" (or "dig -h | more") for complete list of options\n"""
        )

    def dns_text(self, domain, query_id, record_type, answer, status):
        self.write(f"; <<>> DiG 9.10.6 <<>> {domain}\n")
        self.write(";; global options: +cmd\n")
        self.write(";; Got answer:\n")
        self.write(f";; ->>HEADER<<- opcode: QUERY, status: {status}, id: {query_id}\n")
        self.write(
            ";; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n\n"
        )

        self.write(";; OPT PSEUDOSECTION:\n")
        self.write("; EDNS: version: 0, flags:; udp: 512\n")

        self.write(";; QUESTION SECTION:\n")
        self.write(f";{domain}.\t\tIN\t{record_type}\n\n")

        self.write(";; ANSWER SECTION:\n")

        self.write(answer)

        self.write(f";; Query time: {secrets.randbelow(96) + 5} msec\n")
        self.write(";; SERVER: 2001:730:3ef2::10#53(2001:730:3ef2::10)\n")
        self.write(f";; WHEN: {datetime.now().strftime('%a %b %d %H:%M:%S UTC %Y')}\n")
        self.write(f";; MSG SIZE  rcvd: {secrets.randbelow(207) + 50}\n")

    def display_help(self):
        self.write(
            """Usage:  dig [@global-server] [domain] [q-type] [q-class] {q-opt}
            {global-d-opt} host [@local-server] {local-d-opt}
            [ host [@local-server] {local-d-opt} [...]]
Where:  domain	  is in the Domain Name System
        q-class  is one of (in,hs,ch,...) [default: in]
        q-type   is one of (a,any,mx,ns,soa,hinfo,axfr,txt,...) [default:a]
                 (Use ixfr=version for type ixfr)
        q-opt    is one of:
                 -4                  (use IPv4 query transport only)
                 -6                  (use IPv6 query transport only)
                 -b address[#port]   (bind to source address/port)
                 -c class            (specify query class)
                 -f filename         (batch mode)
                 -i                  (use IP6.INT for IPv6 reverse lookups)
                 -k keyfile          (specify tsig key file)
                 -m                  (enable memory usage debugging)
                 -p port             (specify port number)
                 -q name             (specify query name)
                 -t type             (specify query type)
                 -u                  (display times in usec instead of msec)
                 -x dot-notation     (shortcut for reverse lookups)
                 -y [hmac:]name:key  (specify named base64 tsig key)
        d-opt    is of the form +keyword[=value], where keyword is:
                 +[no]aaonly         (Set AA flag in query (+[no]aaflag))
                 +[no]additional     (Control display of additional section)
                 +[no]adflag         (Set AD flag in query (default on))
                 +[no]all            (Set or clear all display flags)
                 +[no]answer         (Control display of answer section)
                 +[no]authority      (Control display of authority section)
                 +[no]besteffort     (Try to parse even illegal messages)
                 +bufsize=###        (Set EDNS0 Max UDP packet size)
                 +[no]cdflag         (Set checking disabled flag in query)
                 +[no]cl             (Control display of class in records)
                 +[no]cmd            (Control display of command line)
                 +[no]comments       (Control display of comment lines)
                 +[no]crypto         (Control display of cryptographic fields in records)
                 +[no]defname        (Use search list (+[no]search))
                 +[no]dnssec         (Request DNSSEC records)
                 +domain=###         (Set default domainname)
                 +[no]edns[=###]     (Set EDNS version) [0]
                 +ednsflags=###      (Set EDNS flag bits)
                 +[no]ednsnegotiation (Set EDNS version negotiation)
                 +ednsopt=###[:value] (Send specified EDNS option)
                 +noednsopt          (Clear list of +ednsopt options)
                 +[no]expire         (Request time to expire)
                 +[no]fail           (Don't try next server on SERVFAIL)
                 +[no]identify       (ID responders in short answers)
                 +[no]idnout         (convert IDN response)
                 +[no]ignore         (Don't revert to TCP for TC responses.)
                 +[no]keepopen       (Keep the TCP socket open between queries)
                 +[no]multiline      (Print records in an expanded format)
                 +ndots=###          (Set search NDOTS value)
                 +[no]nsid           (Request Name Server ID)
                 +[no]nssearch       (Search all authoritative nameservers)
                 +[no]onesoa         (AXFR prints only one soa record)
                 +[no]opcode=###     (Set the opcode of the request)
                 +[no]qr             (Print question before sending)
                 +[no]question       (Control display of question section)
                 +[no]recurse        (Recursive mode)
                 +retry=###          (Set number of UDP retries) [2]
                 +[no]rrcomments     (Control display of per-record comments)
                 +[no]search         (Set whether to use searchlist)
                 +[no]short          (Display nothing except short
                                      form of answer)
                 +[no]showsearch     (Search with intermediate results)
                 +[no]split=##       (Split hex/base64 fields into chunks)
                 +[no]stats          (Control display of statistics)
                 +subnet=addr        (Set edns-client-subnet option)
                 +[no]tcp            (TCP mode (+[no]vc))
                 +time=###           (Set query timeout) [5]
                 +[no]trace          (Trace delegation down from root [+dnssec])
                 +tries=###          (Set number of UDP attempts) [3]
                 +[no]ttlid          (Control display of ttls in records)
                 +[no]vc             (TCP mode (+[no]tcp))
        global d-opts and servers (before host name) affect all queries.
        local d-opts and servers (after host name) affect only that lookup.
        -h                           (print help and exit)
        -v                           (print version and exit)\n"""
        )


commands["/bin/dig"] = Command_dig
commands["dig"] = Command_dig
