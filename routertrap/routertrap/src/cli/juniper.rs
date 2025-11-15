use super::RouterCli;
use log::info;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum JunosMode {
    Operational,    // >
    Configuration,  // #
}

pub struct JuniperJunos {
    hostname: String,
    mode: JunosMode,
    config_path: Vec<String>,
    running_config: HashMap<String, String>,
    authenticated: bool,
    username: Option<String>,
}

impl JuniperJunos {
    pub fn new(hostname: String) -> Self {
        let mut running_config = HashMap::new();
        running_config.insert("version".to_string(), "20.4R3.8".to_string());

        Self {
            hostname,
            mode: JunosMode::Operational,
            config_path: Vec::new(),
            running_config,
            authenticated: false,
            username: None,
        }
    }

    pub fn authenticate(&mut self, username: &str, _password: &str) -> bool {
        info!("JunOS: Login attempt with username: {}", username);
        self.authenticated = true;
        self.username = Some(username.to_string());
        true
    }

    fn handle_show_command(&self, args: &str) -> String {
        let parts: Vec<&str> = args.split_whitespace().collect();

        match parts.get(0) {
            Some(&"version") => self.show_version(),
            Some(&"configuration") => self.show_configuration(),
            Some(&"interfaces") => self.show_interfaces(parts.get(1).map(|s| *s)),
            Some(&"route") => self.show_route(parts.get(1).map(|s| *s)),
            Some(&"bgp") => self.show_bgp(parts.get(1).map(|s| *s)),
            Some(&"chassis") => self.show_chassis(parts.get(1).map(|s| *s)),
            Some(&"system") => self.show_system(parts.get(1).map(|s| *s)),
            Some(&"arp") => self.show_arp(),
            Some(&"ethernet-switching") => self.show_ethernet_switching(),
            Some(&"log") => self.show_log(parts.get(1).map(|s| *s)),
            Some(&"security") => self.show_security(parts.get(1).map(|s| *s)),
            _ => format!("                     ^\nsyntax error.\n"),
        }
    }

    fn show_version(&self) -> String {
        format!(
            "Hostname: {}\n\
             Model: srx300\n\
             Junos: 20.4R3.8\n\
             JUNOS Software Release [20.4R3.8]\n\
             \n\
             {} re0:\n\
             --------------------------------------------------------------------------\n\
             Hostname: {}\n\
             Model: srx300\n\
             Junos: 20.4R3.8\n\
             JUNOS Base OS boot [20.4R3.8]\n\
             JUNOS Base OS Software Suite [20.4R3.8]\n\
             JUNOS Online Documentation [20.4R3.8]\n\
             JUNOS Crypto Software Suite [20.4R3.8]\n\
             JUNOS Packet Forwarding Engine Support (SRX300) [20.4R3.8]\n\
             JUNOS Services Application Level Gateways [20.4R3.8]\n\
             JUNOS Services Captive Portal and Content Delivery [20.4R3.8]\n\
             JUNOS Services ControlPlane Junos Network Application Platform Package [20.4R3.8]\n\
             JUNOS Services AACL Container package [20.4R3.8]\n\
             JUNOS Services Jflow [20.4R3.8]\n\
             JUNOS Services NAT [20.4R3.8]\n\
             JUNOS Services RPM [20.4R3.8]\n\
             JUNOS Services RTCOM [20.4R3.8]\n\
             JUNOS Routing Software Suite [20.4R3.8]\n\n",
            self.hostname,
            self.hostname,
            self.hostname
        )
    }

    fn show_configuration(&self) -> String {
        format!(
            "## Last commit: 2024-01-15 10:30:00 UTC by {}\n\
             version 20.4R3.8;\n\
             system {{\n\
                 host-name {};\n\
                 time-zone America/New_York;\n\
                 root-authentication {{\n\
                     encrypted-password \"$1$mERr$hx5rVt7rPNoS4wqbXKX7m0\";\n\
                 }}\n\
                 name-server {{\n\
                     8.8.8.8;\n\
                     8.8.4.4;\n\
                 }}\n\
                 services {{\n\
                     ssh {{\n\
                         root-login allow;\n\
                     }}\n\
                     telnet;\n\
                     netconf {{\n\
                         ssh;\n\
                     }}\n\
                     web-management {{\n\
                         http {{\n\
                             interface ge-0/0/0.0;\n\
                         }}\n\
                         https {{\n\
                             system-generated-certificate;\n\
                             interface ge-0/0/0.0;\n\
                         }}\n\
                     }}\n\
                 }}\n\
                 syslog {{\n\
                     user * {{\n\
                         any emergency;\n\
                     }}\n\
                     file messages {{\n\
                         any notice;\n\
                         authorization info;\n\
                     }}\n\
                     file interactive-commands {{\n\
                         interactive-commands any;\n\
                     }}\n\
                 }}\n\
             }}\n\
             security {{\n\
                 screen {{\n\
                     ids-option untrust-screen {{\n\
                         icmp {{\n\
                             ping-death;\n\
                         }}\n\
                         ip {{\n\
                             source-route-option;\n\
                             tear-drop;\n\
                         }}\n\
                         tcp {{\n\
                             syn-flood {{\n\
                                 alarm-threshold 1024;\n\
                                 attack-threshold 200;\n\
                                 source-threshold 1024;\n\
                                 destination-threshold 2048;\n\
                                 timeout 20;\n\
                             }}\n\
                             land;\n\
                         }}\n\
                     }}\n\
                 }}\n\
                 zones {{\n\
                     security-zone trust {{\n\
                         host-inbound-traffic {{\n\
                             system-services {{\n\
                                 all;\n\
                             }}\n\
                             protocols {{\n\
                                 all;\n\
                             }}\n\
                         }}\n\
                         interfaces {{\n\
                             ge-0/0/0.0;\n\
                         }}\n\
                     }}\n\
                     security-zone untrust {{\n\
                         screen untrust-screen;\n\
                         interfaces {{\n\
                             ge-0/0/1.0 {{\n\
                                 host-inbound-traffic {{\n\
                                     system-services {{\n\
                                         dhcp;\n\
                                         tftp;\n\
                                     }}\n\
                                 }}\n\
                             }}\n\
                         }}\n\
                     }}\n\
                 }}\n\
                 policies {{\n\
                     from-zone trust to-zone untrust {{\n\
                         policy trust-to-untrust {{\n\
                             match {{\n\
                                 source-address any;\n\
                                 destination-address any;\n\
                                 application any;\n\
                             }}\n\
                             then {{\n\
                                 permit;\n\
                             }}\n\
                         }}\n\
                     }}\n\
                 }}\n\
             }}\n\
             interfaces {{\n\
                 ge-0/0/0 {{\n\
                     unit 0 {{\n\
                         family inet {{\n\
                             address 192.168.1.1/24;\n\
                         }}\n\
                     }}\n\
                 }}\n\
                 ge-0/0/1 {{\n\
                     unit 0 {{\n\
                         family inet {{\n\
                             dhcp;\n\
                         }}\n\
                     }}\n\
                 }}\n\
             }}\n\
             routing-options {{\n\
                 static {{\n\
                     route 0.0.0.0/0 next-hop 192.168.1.254;\n\
                 }}\n\
                 autonomous-system 65001;\n\
             }}\n\
             protocols {{\n\
                 bgp {{\n\
                     group ebgp {{\n\
                         type external;\n\
                         neighbor 192.168.1.254 {{\n\
                             peer-as 65000;\n\
                         }}\n\
                     }}\n\
                 }}\n\
             }}\n\n",
            self.username.as_ref().unwrap_or(&"admin".to_string()),
            self.hostname
        )
    }

    fn show_interfaces(&self, detail: Option<&str>) -> String {
        if detail == Some("terse") {
            "Interface               Admin Link Proto    Local                 Remote\n\
             ge-0/0/0                up    up\n\
             ge-0/0/0.0              up    up   inet     192.168.1.1/24\n\
             ge-0/0/1                up    down\n\
             ge-0/0/1.0              up    down inet\n\
             lo0                     up    up\n\
             lo0.16384               up    up   inet\n".to_string()
        } else {
            "Physical interface: ge-0/0/0, Enabled, Physical link is Up\n\
               Interface index: 148, SNMP ifIndex: 520\n\
               Link-level type: Ethernet, MTU: 1514, Speed: 1000mbps, BPDU Error: None,\n\
               MAC-REWRITE Error: None, Loopback: Disabled, Source filtering: Disabled,\n\
               Flow control: Enabled\n\
               Device flags   : Present Running\n\
               Interface flags: SNMP-Traps Internal: 0x4000\n\
               Link flags     : None\n\
               CoS queues     : 8 supported, 8 maximum usable queues\n\
               Current address: 00:05:86:71:1a:c0, Hardware address: 00:05:86:71:1a:c0\n\
               Last flapped   : 2024-01-15 10:30:00 UTC (42w3d 12:34 ago)\n\
               Input rate     : 1024 bps (2 pps)\n\
               Output rate    : 2048 bps (3 pps)\n\
             \n\
             Physical interface: ge-0/0/1, Enabled, Physical link is Down\n\
               Interface index: 149, SNMP ifIndex: 521\n\
               Link-level type: Ethernet, MTU: 1514, Speed: 1000mbps, BPDU Error: None,\n\
               MAC-REWRITE Error: None, Loopback: Disabled, Source filtering: Disabled,\n\
               Flow control: Enabled\n\
               Device flags   : Present Running Down\n\
               Interface flags: Hardware-Down SNMP-Traps Internal: 0x4000\n\
               Link flags     : None\n\
               Current address: 00:05:86:71:1a:c1, Hardware address: 00:05:86:71:1a:c1\n\
               Last flapped   : Never\n".to_string()
        }
    }

    fn show_route(&self, detail: Option<&str>) -> String {
        if detail == Some("summary") {
            "Autonomous system number: 65001\n\
             Router ID: 192.168.1.1\n\
             \n\
             inet.0: 3 destinations, 3 routes (3 active, 0 holddown, 0 hidden)\n\
                       Direct:      1 routes,      1 active\n\
                        Local:      1 routes,      1 active\n\
                       Static:      1 routes,      1 active\n".to_string()
        } else {
            "inet.0: 3 destinations, 3 routes (3 active, 0 holddown, 0 hidden)\n\
             + = Active Route, - = Last Active, * = Both\n\
             \n\
             0.0.0.0/0          *[Static/5] 42w3d 12:34:56\n\
                                 >  to 192.168.1.254 via ge-0/0/0.0\n\
             192.168.1.0/24     *[Direct/0] 42w3d 12:34:56\n\
                                 >  via ge-0/0/0.0\n\
             192.168.1.1/32     *[Local/0] 42w3d 12:34:56\n\
                                     Local via ge-0/0/0.0\n".to_string()
        }
    }

    fn show_bgp(&self, subcommand: Option<&str>) -> String {
        match subcommand {
            Some("summary") => {
                "Groups: 1 Peers: 1 Down peers: 0\n\
                 Table          Tot Paths  Act Paths Suppressed    History Damp State    Pending\n\
                 inet.0\n\
                                        0          0          0          0          0          0\n\
                 Peer                     AS      InPkt     OutPkt    OutQ   Flaps Last Up/Dwn State|#Active/Received/Accepted/Damped...\n\
                 192.168.1.254         65000        123        456       0       0     42:34:56 Establ\n\
                   inet.0: 0/0/0/0\n".to_string()
            }
            Some("neighbor") => {
                "Peer: 192.168.1.254+179 AS 65000 Local: 192.168.1.1+52341 AS 65001\n\
                   Group: ebgp                  Routing-Instance: master\n\
                   Forwarding routing-instance: master\n\
                   Type: External    State: Established    Flags: <Sync>\n\
                   Last State: OpenConfirm   Last Event: RecvKeepAlive\n\
                   Last Error: None\n\
                   Options: <Preference LocalAddress HoldTime PeerAS Refresh>\n\
                   Holdtime: 90 Preference: 170 Local AS: 65001 Local System AS: 0\n\
                   Number of flaps: 0\n\
                   Peer ID: 192.168.1.254   Local ID: 192.168.1.1       Active Holdtime: 90\n\
                   Keepalive Interval: 30         Group index: 0    Peer index: 0\n\
                   BFD: disabled, down\n\
                   Local Interface: ge-0/0/0.0\n\
                   NLRI for restart configured on peer: inet-unicast\n\
                   NLRI advertised by peer: inet-unicast\n\
                   NLRI for this session: inet-unicast\n\
                   Peer supports Refresh capability (2)\n\
                   Table inet.0 Bit: 10000\n\
                     RIB State: BGP restart is complete\n\
                     Send state: in sync\n\
                     Active prefixes:              0\n\
                     Received prefixes:            0\n\
                     Accepted prefixes:            0\n\
                     Suppressed due to damping:    0\n\
                     Advertised prefixes:          1\n\
                   Last traffic (seconds): Received 15   Sent 28   Checked 42\n\
                   Input messages:  Total 123    Updates 0        Refreshes 0      Octets 2345\n\
                   Output messages: Total 456    Updates 1        Refreshes 0      Octets 8910\n".to_string()
            }
            _ => {
                "Groups: 1 Peers: 1 Down peers: 0\n\
                 Peer                     AS      InPkt     OutPkt    OutQ   Flaps Last Up/Dwn State|#Active/Received/Accepted/Damped...\n\
                 192.168.1.254         65000        123        456       0       0     42:34:56 Establ\n".to_string()
            }
        }
    }

    fn show_chassis(&self, subcommand: Option<&str>) -> String {
        match subcommand {
            Some("hardware") => {
                "Hardware inventory:\n\
                 Item             Version  Part number  Serial number     Description\n\
                 Chassis                                JN123456789ABC    SRX300\n\
                 Routing Engine 0          BUILTIN      BUILTIN           RE-SRX300\n\
                 FPC 0            REV 28   750-054321   JN123456789       FPC\n\
                   PIC 0                   BUILTIN      BUILTIN           8x GE BASE-T\n\
                     Xcvr 0       REV 01   740-011234   ABC12345          GE-T\n\
                 Power Supply 0   REV 03   740-054321   1AB123456         PS 60W AC\n".to_string()
            }
            Some("alarms") => {
                "No alarms currently active\n".to_string()
            }
            Some("environment") => {
                "Class Item                           Status     Measurement\n\
                 Temp  CPU Die Temp                    OK         40 degrees C / 104 degrees F\n\
                 Fans  Fan 1                           OK         Spinning at normal speed\n\
                 Power DC 1                            OK\n".to_string()
            }
            _ => {
                "                     ^\nsyntax error, expecting <command>.\n".to_string()
            }
        }
    }

    fn show_system(&self, subcommand: Option<&str>) -> String {
        match subcommand {
            Some("uptime") => {
                "Current time: 2024-01-15 15:30:00 UTC\n\
                 Time Source:  NTP CLOCK\n\
                 System booted: 2023-03-01 10:00:00 UTC (42w3d 05:30 ago)\n\
                 Protocols started: 2023-03-01 10:05:30 UTC (42w3d 05:24:30 ago)\n\
                 Last configured: 2024-01-15 10:30:00 UTC (05:00:00 ago) by admin\n\
                 5:30PM  up 297 days,  5:30, 1 user, load averages: 0.12, 0.15, 0.18\n".to_string()
            }
            Some("users") => {
                format!(
                    " 5:30PM  up 297 days,  5:30, 1 user, load averages: 0.12, 0.15, 0.18\n\
                     USER     TTY      FROM                              LOGIN@  IDLE WHAT\n\
                     {}      pts/0    192.168.1.100                     3:30PM     0 cli\n",
                    self.username.as_ref().unwrap_or(&"admin".to_string())
                )
            }
            Some("processes") => {
                "last pid:  9876;  load averages:  0.12,  0.15,  0.18  up 297+05:30:00    17:30:00\n\
                 128 processes: 2 running, 126 sleeping\n\
                 \n\
                 PID USERNAME     PRI NICE   SIZE    RES STATE   C   TIME    WCPU COMMAND\n\
                 1234 root         96    0  123M  45M sleep   0  12:34  0.00% mgd\n\
                 2345 root         96    0   78M  23M sleep   0   8:56  0.00% rpd\n\
                 3456 root         96    0   56M  12M sleep   0   4:23  0.00% chassisd\n\
                 4567 root         96    0   34M   8M sleep   0   2:15  0.00% eventd\n".to_string()
            }
            Some("storage") => {
                "Filesystem              Size       Used      Avail  Capacity   Mounted on\n\
                 /dev/ada0s1a            2.0G       890M       980M        48%  /\n\
                 devfs                   1.0K       1.0K         0B       100%  /dev\n\
                 /dev/md0                 40M       1.5M        35M         4%  /mfs\n\
                 /var/jail               4.0G       1.2G       2.5G        32%  /var/jail\n".to_string()
            }
            _ => {
                "                     ^\nsyntax error, expecting <command>.\n".to_string()
            }
        }
    }

    fn show_arp(&self) -> String {
        "MAC Address       Address         Name                      Interface           Flags\n\
         00:05:86:71:1a:c0 192.168.1.1     192.168.1.1               ge-0/0/0.0          none\n\
         aa:bb:11:22:cc:dd 192.168.1.254   192.168.1.254             ge-0/0/0.0          none\n\
         bb:cc:22:33:dd:ee 192.168.1.100   192.168.1.100             ge-0/0/0.0          none\n\
         Total entries: 3\n".to_string()
    }

    fn show_ethernet_switching(&self) -> String {
        "Ethernet-switching table: 3 entries\n\
         \n\
           VLAN              MAC address       Type         Age Interfaces\n\
           default           00:05:86:71:1a:c0 Learn          0 ge-0/0/0.0\n\
           default           aa:bb:11:22:cc:dd Learn         42 ge-0/0/0.0\n\
           default           bb:cc:22:33:dd:ee Learn         15 ge-0/0/0.0\n".to_string()
    }

    fn show_log(&self, _file: Option<&str>) -> String {
        "Jan 15 15:29:45 router mgd[1234]: UI_CMDLINE_READ_LINE: User 'admin', command 'show log messages '\n\
         Jan 15 15:25:12 router mgd[1234]: UI_COMMIT_COMPLETED: commit complete\n\
         Jan 15 15:25:10 router mgd[1234]: UI_COMMIT: User 'admin' requested 'commit' operation\n\
         Jan 15 15:20:00 router rpd[2345]: bgp_peer_route_refresh: KEEPALIVE message from 192.168.1.254 (External AS 65000)\n\
         Jan 15 15:15:30 router chassisd[3456]: CHASSISD_SNMP_TRAP: SNMP trap generated\n".to_string()
    }

    fn show_security(&self, subcommand: Option<&str>) -> String {
        match subcommand {
            Some("zones") => {
                "Security zone: trust\n\
                   Send reset for non-SYN session TCP packets: Off\n\
                   Policy configurable: Yes\n\
                   Interfaces bound: 1\n\
                     ge-0/0/0.0\n\
                 \n\
                 Security zone: untrust\n\
                   Send reset for non-SYN session TCP packets: Off\n\
                   Screen: untrust-screen\n\
                   Policy configurable: Yes\n\
                   Interfaces bound: 1\n\
                     ge-0/0/1.0\n".to_string()
            }
            Some("policies") => {
                "From zone: trust, To zone: untrust\n\
                   Policy: trust-to-untrust, State: enabled, Index: 4, Sequence number: 1\n\
                     Source addresses: any\n\
                     Destination addresses: any\n\
                     Applications: any\n\
                     Action: permit\n".to_string()
            }
            Some("flow") => {
                "Session ID: 12345, Policy name: trust-to-untrust/4, Timeout: 1800, Valid\n\
                   In: 192.168.1.100/52341 --> 8.8.8.8/53;tcp, Conn Tag: 0x0, If: ge-0/0/0.0, Pkts: 123, Bytes: 12345,\n\
                   Out: 8.8.8.8/53 --> 192.168.1.100/52341;tcp, Conn Tag: 0x0, If: ge-0/0/1.0, Pkts: 234, Bytes: 23456,\n\
                 Total sessions: 1\n".to_string()
            }
            _ => {
                "                     ^\nsyntax error, expecting <command>.\n".to_string()
            }
        }
    }
}

#[async_trait::async_trait]
impl RouterCli for JuniperJunos {
    async fn handle_command(&mut self, command: &str) -> String {
        let cmd = command.trim();

        if cmd.is_empty() {
            return String::new();
        }

        info!("JunOS command: {} (mode: {:?})", cmd, self.mode);

        match self.mode {
            JunosMode::Operational => {
                if cmd == "configure" || cmd == "edit" {
                    self.mode = JunosMode::Configuration;
                    "Entering configuration mode\n\n[edit]\n".to_string()
                } else if cmd.starts_with("show ") {
                    self.handle_show_command(&cmd[5..])
                } else if cmd == "exit" || cmd == "quit" {
                    "\n".to_string()
                } else if cmd.starts_with("ping ") {
                    "PING 8.8.8.8 (8.8.8.8): 56 data bytes\n\
                     64 bytes from 8.8.8.8: icmp_seq=0 ttl=57 time=10.123 ms\n\
                     64 bytes from 8.8.8.8: icmp_seq=1 ttl=57 time=10.456 ms\n\
                     \n\
                     --- 8.8.8.8 ping statistics ---\n\
                     2 packets transmitted, 2 packets received, 0% packet loss\n\
                     round-trip min/avg/max/stddev = 10.123/10.290/10.456/0.167 ms\n".to_string()
                } else if cmd.starts_with("traceroute ") {
                    "traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 40 byte packets\n\
                     1  192.168.1.254 (192.168.1.254)  1.234 ms  1.123 ms  1.056 ms\n\
                     2  10.0.0.1 (10.0.0.1)  5.678 ms  5.567 ms  5.456 ms\n\
                     3  8.8.8.8 (8.8.8.8)  10.123 ms  10.234 ms  10.345 ms\n".to_string()
                } else if cmd == "?" || cmd == "help" {
                    self.get_help()
                } else {
                    format!("                     ^\nsyntax error.\n")
                }
            }
            JunosMode::Configuration => {
                if cmd == "exit" || cmd == "quit" {
                    if self.config_path.is_empty() {
                        self.mode = JunosMode::Operational;
                        "Exiting configuration mode\n\n".to_string()
                    } else {
                        self.config_path.pop();
                        format!("\n[edit{}]\n", self.get_config_path_str())
                    }
                } else if cmd == "top" {
                    self.config_path.clear();
                    "\n[edit]\n".to_string()
                } else if cmd.starts_with("edit ") {
                    let path = cmd[5..].trim();
                    self.config_path.push(path.to_string());
                    format!("\n[edit{}]\n", self.get_config_path_str())
                } else if cmd == "show" || cmd == "show configuration" {
                    self.show_configuration()
                } else if cmd.starts_with("set ") {
                    String::new() // Accept set commands silently
                } else if cmd.starts_with("delete ") {
                    String::new() // Accept delete commands silently
                } else if cmd == "commit" {
                    "commit complete\n".to_string()
                } else if cmd == "commit check" {
                    "configuration check succeeds\n".to_string()
                } else if cmd == "rollback" {
                    "load complete\n".to_string()
                } else if cmd == "?" || cmd == "help" {
                    self.get_config_help()
                } else {
                    String::new()
                }
            }
        }
    }

    fn get_prompt(&self) -> String {
        match self.mode {
            JunosMode::Operational => {
                format!("{}@{}> ", self.username.as_ref().unwrap_or(&"admin".to_string()), self.hostname)
            }
            JunosMode::Configuration => {
                format!("{}@{}# ", self.username.as_ref().unwrap_or(&"admin".to_string()), self.hostname)
            }
        }
    }

    fn get_banner(&self) -> String {
        format!(
            "\n\
             --- JUNOS 20.4R3.8 built 2021-02-25 18:35:56 UTC\n\
             \n"
        )
    }
}

impl JuniperJunos {
    fn get_config_path_str(&self) -> String {
        if self.config_path.is_empty() {
            String::new()
        } else {
            format!(" {}", self.config_path.join(" "))
        }
    }

    fn get_help(&self) -> String {
        "Main mode commands:\n\
           clear                Clear information in the system\n\
           configure            Manipulate software configuration information\n\
           file                 Perform file operations\n\
           help                 Provide help information\n\
           monitor              Show real-time debugging information\n\
           mtrace               Trace multicast path from source to receiver\n\
           ping                 Ping remote target\n\
           quit                 Exit the management session\n\
           request              Make system-level requests\n\
           restart              Restart software process\n\
           set                  Set CLI properties\n\
           show                 Show information about the system\n\
           ssh                  Start secure shell on another host\n\
           start                Start shell\n\
           telnet               Telnet to another host\n\
           test                 Perform diagnostic debugging\n\
           traceroute           Trace route to remote host\n".to_string()
    }

    fn get_config_help(&self) -> String {
        "Configuration mode commands:\n\
           activate             Remove the inactive tag from a statement\n\
           annotate             Add a comment to a statement\n\
           commit               Commit current set of changes\n\
           copy                 Copy a statement\n\
           deactivate           Add the inactive tag to a statement\n\
           delete               Delete a data element\n\
           edit                 Edit a sub-element\n\
           exit                 Exit from this level\n\
           help                 Provide help information\n\
           insert               Insert a new ordered data element\n\
           load                 Load configuration from ASCII file\n\
           quit                 Quit from this level\n\
           rename               Rename a statement\n\
           replace              Replace a data element\n\
           rollback             Roll back database to last committed version\n\
           run                  Run an operational-mode command\n\
           save                 Save configuration to ASCII file\n\
           set                  Set a parameter\n\
           show                 Show a parameter\n\
           status               Show users currently editing configuration\n\
           top                  Exit to top level of configuration\n\
           up                   Exit one level of configuration\n\
           wildcard             Wildcard operations\n".to_string()
    }
}
