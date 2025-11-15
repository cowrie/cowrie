use super::RouterCli;
use log::{info, warn};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CiscoMode {
    UserExec,      // >
    PrivilegedExec, // #
    GlobalConfig,  // (config)#
    InterfaceConfig, // (config-if)#
    RouterConfig,  // (config-router)#
    LineConfig,    // (config-line)#
}

pub struct CiscoIos {
    hostname: String,
    mode: CiscoMode,
    running_config: HashMap<String, String>,
    interfaces: HashMap<String, InterfaceConfig>,
    authenticated: bool,
    username: Option<String>,
}

#[derive(Debug, Clone)]
struct InterfaceConfig {
    name: String,
    ip_address: Option<String>,
    subnet_mask: Option<String>,
    status: String,
    description: Option<String>,
}

impl CiscoIos {
    pub fn new(hostname: String) -> Self {
        let mut running_config = HashMap::new();
        running_config.insert("version".to_string(), "15.2".to_string());
        running_config.insert("service".to_string(), "timestamps debug datetime msec".to_string());

        let mut interfaces = HashMap::new();

        // Add some default interfaces
        interfaces.insert("GigabitEthernet0/0".to_string(), InterfaceConfig {
            name: "GigabitEthernet0/0".to_string(),
            ip_address: Some("192.168.1.1".to_string()),
            subnet_mask: Some("255.255.255.0".to_string()),
            status: "up".to_string(),
            description: None,
        });

        interfaces.insert("GigabitEthernet0/1".to_string(), InterfaceConfig {
            name: "GigabitEthernet0/1".to_string(),
            ip_address: None,
            subnet_mask: None,
            status: "administratively down".to_string(),
            description: None,
        });

        Self {
            hostname,
            mode: CiscoMode::UserExec,
            running_config,
            interfaces,
            authenticated: false,
            username: None,
        }
    }

    pub fn authenticate(&mut self, username: &str, _password: &str) -> bool {
        // Accept any credentials for honeypot purposes
        info!("Cisco IOS: Login attempt with username: {}", username);
        self.authenticated = true;
        self.username = Some(username.to_string());
        true
    }

    fn handle_show_command(&self, args: &str) -> String {
        let parts: Vec<&str> = args.split_whitespace().collect();

        match parts.get(0) {
            Some(&"version") => self.show_version(),
            Some(&"running-config") | Some(&"run") => self.show_running_config(),
            Some(&"ip") => match parts.get(1) {
                Some(&"interface") => self.show_ip_interface(parts.get(2).map(|s| *s)),
                Some(&"route") => self.show_ip_route(),
                Some(&"bgp") => self.show_ip_bgp(),
                _ => "% Incomplete command.\n".to_string(),
            },
            Some(&"interface") | Some(&"interfaces") => {
                self.show_interfaces(parts.get(1).map(|s| *s))
            },
            Some(&"users") => self.show_users(),
            Some(&"processes") => self.show_processes(),
            Some(&"memory") => self.show_memory(),
            Some(&"cdp") => match parts.get(1) {
                Some(&"neighbors") => self.show_cdp_neighbors(),
                _ => self.show_cdp(),
            },
            Some(&"arp") => self.show_arp(),
            Some(&"mac-address-table") | Some(&"mac") => self.show_mac_address_table(),
            Some(&"vlan") => self.show_vlan(),
            _ => format!("% Invalid input detected at '^' marker.\n"),
        }
    }

    fn show_version(&self) -> String {
        format!(
            "Cisco IOS Software, C3750 Software (C3750-IPSERVICESK9-M), Version 15.2(4)E8, RELEASE SOFTWARE (fc3)\n\
             Technical Support: http://www.cisco.com/techsupport\n\
             Copyright (c) 1986-2023 by Cisco Systems, Inc.\n\
             Compiled Fri 15-Sep-23 12:00 by prod_rel_team\n\
             \n\
             ROM: Bootstrap program is C3750 boot loader\n\
             BOOTLDR: C3750 Boot Loader (C3750-HBOOT-M) Version 12.2(44)SE5, RELEASE SOFTWARE (fc1)\n\
             \n\
             {} uptime is 42 weeks, 3 days, 12 hours, 34 minutes\n\
             System returned to ROM by power-on\n\
             System image file is \"flash:c3750-ipservicesk9-mz.152-4.E8.bin\"\n\
             \n\
             cisco WS-C3750G-24TS (PowerPC405) processor (revision C0) with 131072K bytes of memory.\n\
             Processor board ID FOC1234X567\n\
             Last reset from power-on\n\
             24 Gigabit Ethernet interfaces\n\
             The password-recovery mechanism is enabled.\n\
             \n\
             512K bytes of flash-simulated non-volatile configuration memory.\n\
             Base ethernet MAC Address       : 00:1A:2B:3C:4D:5E\n\
             Motherboard assembly number     : 73-10216-08\n\
             Power supply part number        : 341-0097-02\n\
             Motherboard serial number       : FOC12345678\n\
             Power supply serial number      : AZS12345678\n\
             Model revision number           : C0\n\
             Motherboard revision number     : A0\n\
             Model number                    : WS-C3750G-24TS-S\n\
             System serial number            : FOC1234X567\n\
             Top Assembly Part Number        : 800-26857-03\n\
             Top Assembly Revision Number    : A0\n\
             Version ID                      : V04\n\
             CLEI Code Number                : COM3K00BRA\n\
             \n\
             Configuration register is 0x10F\n\n",
            self.hostname
        )
    }

    fn show_running_config(&self) -> String {
        format!(
            "Building configuration...\n\
             \n\
             Current configuration : 4532 bytes\n\
             !\n\
             version 15.2\n\
             service timestamps debug datetime msec\n\
             service timestamps log datetime msec\n\
             no service password-encryption\n\
             !\n\
             hostname {}\n\
             !\n\
             boot-start-marker\n\
             boot-end-marker\n\
             !\n\
             enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0\n\
             !\n\
             no aaa new-model\n\
             switch 1 provision ws-c3750g-24ts\n\
             !\n\
             ip routing\n\
             !\n\
             ip domain-name example.com\n\
             !\n\
             crypto pki trustpoint TP-self-signed-123456789\n\
             !\n\
             spanning-tree mode pvst\n\
             spanning-tree extend system-id\n\
             !\n\
             vlan internal allocation policy ascending\n\
             !\n\
             interface GigabitEthernet0/0\n\
              description WAN Interface\n\
              ip address 192.168.1.1 255.255.255.0\n\
              duplex auto\n\
              speed auto\n\
             !\n\
             interface GigabitEthernet0/1\n\
              shutdown\n\
             !\n\
             router bgp 65001\n\
              bgp log-neighbor-changes\n\
              network 192.168.1.0 mask 255.255.255.0\n\
             !\n\
             ip classless\n\
             ip route 0.0.0.0 0.0.0.0 192.168.1.254\n\
             !\n\
             ip http server\n\
             ip http secure-server\n\
             !\n\
             snmp-server community public RO\n\
             snmp-server community private RW\n\
             !\n\
             line con 0\n\
             line vty 0 4\n\
              login\n\
              transport input ssh\n\
             line vty 5 15\n\
              login\n\
              transport input ssh\n\
             !\n\
             ntp server 216.239.35.0\n\
             ntp server 216.239.35.4\n\
             end\n\n",
            self.hostname
        )
    }

    fn show_interfaces(&self, interface: Option<&str>) -> String {
        if let Some(if_name) = interface {
            if let Some(iface) = self.interfaces.get(if_name) {
                format!(
                    "{} is {}, line protocol is up\n\
                     Hardware is Gigabit Ethernet, address is 001a.2b3c.4d5e (bia 001a.2b3c.4d5e)\n\
                     {}\
                     MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec,\n\
                        reliability 255/255, txload 1/255, rxload 1/255\n\
                     Encapsulation ARPA, loopback not set\n\
                     Keepalive set (10 sec)\n\
                     Full-duplex, 1000Mb/s, media type is 10/100/1000BaseTX\n\
                     output flow-control is unsupported, input flow-control is unsupported\n\
                     ARP type: ARPA, ARP Timeout 04:00:00\n\
                     Last input 00:00:00, output 00:00:00, output hang never\n\
                     Last clearing of \"show interface\" counters never\n\
                     Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 0\n\
                     Queueing strategy: fifo\n\
                     Output queue: 0/40 (size/max)\n\
                     5 minute input rate 1000 bits/sec, 2 packets/sec\n\
                     5 minute output rate 2000 bits/sec, 3 packets/sec\n\
                        123456 packets input, 12345678 bytes, 0 no buffer\n\
                        Received 12345 broadcasts (0 IP multicasts)\n\
                        0 runts, 0 giants, 0 throttles\n\
                        0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored\n\
                        0 watchdog, 5678 multicast, 0 pause input\n\
                        0 input packets with dribble condition detected\n\
                        234567 packets output, 23456789 bytes, 0 underruns\n\
                        0 output errors, 0 collisions, 1 interface resets\n\
                        0 unknown protocol drops\n\
                        0 babbles, 0 late collision, 0 deferred\n\
                        0 lost carrier, 0 no carrier, 0 pause output\n\
                        0 output buffer failures, 0 output buffers swapped out\n",
                    iface.name,
                    iface.status,
                    iface.description.as_ref().map(|d| format!("  Description: {}\n", d)).unwrap_or_default()
                )
            } else {
                format!("                      ^\n% Invalid input detected at '^' marker.\n")
            }
        } else {
            let mut output = String::new();
            for iface in self.interfaces.values() {
                output.push_str(&format!(
                    "{} is {}, line protocol is {}\n",
                    iface.name,
                    iface.status,
                    if iface.status == "up" { "up" } else { "down" }
                ));
            }
            output
        }
    }

    fn show_ip_interface(&self, interface: Option<&str>) -> String {
        if let Some(if_name) = interface {
            if let Some(iface) = self.interfaces.get(if_name) {
                format!(
                    "{} is {}, line protocol is up\n\
                     Internet address is {}/{}\n\
                     Broadcast address is 255.255.255.255\n\
                     Address determined by setup command\n\
                     MTU is 1500 bytes\n\
                     Helper address is not set\n\
                     Directed broadcast forwarding is disabled\n\
                     Outgoing access list is not set\n\
                     Inbound  access list is not set\n\
                     Proxy ARP is enabled\n\
                     Local Proxy ARP is disabled\n\
                     Security level is default\n\
                     Split horizon is enabled\n\
                     ICMP redirects are always sent\n\
                     ICMP unreachables are always sent\n\
                     ICMP mask replies are never sent\n\
                     IP fast switching is enabled\n\
                     IP fast switching on the same interface is disabled\n\
                     IP Flow switching is disabled\n\
                     IP CEF switching is enabled\n",
                    iface.name,
                    iface.status,
                    iface.ip_address.as_ref().unwrap_or(&"unassigned".to_string()),
                    iface.subnet_mask.as_ref().unwrap_or(&"".to_string())
                )
            } else {
                "% Invalid interface\n".to_string()
            }
        } else {
            let mut output = String::new();
            for iface in self.interfaces.values() {
                output.push_str(&format!(
                    "{} is {}, line protocol is {}\n  Internet address is {}/{}\n",
                    iface.name,
                    iface.status,
                    if iface.status == "up" { "up" } else { "down" },
                    iface.ip_address.as_ref().unwrap_or(&"unassigned".to_string()),
                    iface.subnet_mask.as_ref().unwrap_or(&"".to_string())
                ));
            }
            output
        }
    }

    fn show_ip_route(&self) -> String {
        "Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP\n\
         Gateway of last resort is 192.168.1.254 to network 0.0.0.0\n\
         \n\
         S*    0.0.0.0/0 [1/0] via 192.168.1.254\n\
         C     192.168.1.0/24 is directly connected, GigabitEthernet0/0\n\
         L     192.168.1.1/32 is directly connected, GigabitEthernet0/0\n".to_string()
    }

    fn show_ip_bgp(&self) -> String {
        "BGP table version is 1, local router ID is 192.168.1.1\n\
         Status codes: s suppressed, d damped, h history, * valid, > best, i - internal,\n\
                       r RIB-failure, S Stale, m multipath, b backup-path, f RT-Filter,\n\
                       x best-external, a additional-path, c RIB-compressed,\n\
         Origin codes: i - IGP, e - EGP, ? - incomplete\n\
         RPKI validation codes: V valid, I invalid, N Not found\n\
         \n\
            Network          Next Hop            Metric LocPrf Weight Path\n\
         *> 192.168.1.0/24   0.0.0.0                  0         32768 i\n".to_string()
    }

    fn show_users(&self) -> String {
        format!(
            "    Line       User       Host(s)              Idle       Location\n\
             *  0 con 0     {}      idle                 00:00:00\n\
             \n\
               Interface    User               Mode         Idle     Peer Address\n",
            self.username.as_ref().unwrap_or(&"admin".to_string())
        )
    }

    fn show_processes(&self) -> String {
        "CPU utilization for five seconds: 5%/2%; one minute: 4%; five minutes: 3%\n\
         PID Runtime(ms)     Invoked      uSecs   5Sec   1Min   5Min TTY Process\n\
           1          12        1234         10  0.00%  0.00%  0.00%   0 Chunk Manager\n\
           2         456       23456         20  0.01%  0.00%  0.00%   0 Load Meter\n\
           3        1234       45678         27  0.00%  0.01%  0.00%   0 Check heaps\n\
           4        2345       67890         34  0.02%  0.01%  0.01%   0 Pool Manager\n\
           5        3456       89012         38  0.00%  0.00%  0.00%   0 Timers\n".to_string()
    }

    fn show_memory(&self) -> String {
        "                Head    Total(b)     Used(b)     Free(b)   Lowest(b)  Largest(b)\n\
         Processor    6F4A5C    134217728    45678900    88538828    87654320    85432100\n\
              I/O    1200000     33554432     8765432    24788000    24500000    22000000\n".to_string()
    }

    fn show_cdp_neighbors(&self) -> String {
        "Capability Codes: R - Router, T - Trans Bridge, B - Source Route Bridge\n\
                           S - Switch, H - Host, I - IGMP, r - Repeater, P - Phone\n\
         \n\
         Device ID        Local Intrfce     Holdtme    Capability  Platform  Port ID\n\
         Switch-Core      Gig 0/1           165          S I      WS-C3750  Gig 1/0/1\n".to_string()
    }

    fn show_cdp(&self) -> String {
        "Global CDP information:\n\
             Sending CDP packets every 60 seconds\n\
             Sending a holdtime value of 180 seconds\n\
             Sending CDPv2 advertisements is enabled\n".to_string()
    }

    fn show_arp(&self) -> String {
        "Protocol  Address          Age (min)  Hardware Addr   Type   Interface\n\
         Internet  192.168.1.1             -   001a.2b3c.4d5e  ARPA   GigabitEthernet0/0\n\
         Internet  192.168.1.254          42   00aa.bb11.cc22  ARPA   GigabitEthernet0/0\n\
         Internet  192.168.1.100          15   00bb.cc22.dd33  ARPA   GigabitEthernet0/0\n".to_string()
    }

    fn show_mac_address_table(&self) -> String {
        "          Mac Address Table\n\
         -------------------------------------------\n\
         \n\
         Vlan    Mac Address       Type        Ports\n\
         ----    -----------       --------    -----\n\
            1    001a.2b3c.4d5e    DYNAMIC     Gi0/0\n\
            1    00aa.bb11.cc22    DYNAMIC     Gi0/0\n\
         Total Mac Addresses for this criterion: 2\n".to_string()
    }

    fn show_vlan(&self) -> String {
        "VLAN Name                             Status    Ports\n\
         ---- -------------------------------- --------- -------------------------------\n\
         1    default                          active    Gi0/0, Gi0/1\n\
         \n\
         VLAN Type  SAID       MTU   Parent RingNo BridgeNo Stp  BrdgMode Trans1 Trans2\n\
         ---- ----- ---------- ----- ------ ------ -------- ---- -------- ------ ------\n\
         1    enet  100001     1500  -      -      -        -    -        0      0\n".to_string()
    }
}

#[async_trait::async_trait]
impl RouterCli for CiscoIos {
    async fn handle_command(&mut self, command: &str) -> String {
        let cmd = command.trim();

        if cmd.is_empty() {
            return String::new();
        }

        info!("Cisco IOS command: {} (mode: {:?})", cmd, self.mode);

        // Handle commands based on mode
        match self.mode {
            CiscoMode::UserExec => {
                if cmd == "enable" || cmd == "en" {
                    self.mode = CiscoMode::PrivilegedExec;
                    String::new()
                } else if cmd.starts_with("show ") {
                    self.handle_show_command(&cmd[5..])
                } else if cmd == "exit" || cmd == "quit" {
                    "Logout\n".to_string()
                } else if cmd == "?" {
                    self.get_help()
                } else {
                    "% Invalid input detected at '^' marker.\n".to_string()
                }
            }
            CiscoMode::PrivilegedExec => {
                if cmd == "configure terminal" || cmd == "conf t" {
                    self.mode = CiscoMode::GlobalConfig;
                    "Enter configuration commands, one per line.  End with CNTL/Z.\n".to_string()
                } else if cmd == "disable" {
                    self.mode = CiscoMode::UserExec;
                    String::new()
                } else if cmd.starts_with("show ") {
                    self.handle_show_command(&cmd[5..])
                } else if cmd == "reload" {
                    "System configuration has been modified. Save? [yes/no]: ".to_string()
                } else if cmd == "write memory" || cmd == "wr" {
                    "Building configuration...\n[OK]\n".to_string()
                } else if cmd == "exit" || cmd == "quit" {
                    "Logout\n".to_string()
                } else if cmd == "?" {
                    self.get_help()
                } else {
                    "% Invalid input detected at '^' marker.\n".to_string()
                }
            }
            CiscoMode::GlobalConfig => {
                if cmd == "exit" || cmd == "end" {
                    self.mode = CiscoMode::PrivilegedExec;
                    String::new()
                } else if cmd.starts_with("interface ") {
                    self.mode = CiscoMode::InterfaceConfig;
                    String::new()
                } else if cmd.starts_with("router bgp") {
                    self.mode = CiscoMode::RouterConfig;
                    String::new()
                } else if cmd.starts_with("hostname ") {
                    let parts: Vec<&str> = cmd.split_whitespace().collect();
                    if parts.len() >= 2 {
                        self.hostname = parts[1].to_string();
                    }
                    String::new()
                } else if cmd == "?" {
                    self.get_config_help()
                } else {
                    String::new() // Accept most config commands silently
                }
            }
            _ => {
                if cmd == "exit" || cmd == "end" {
                    self.mode = CiscoMode::PrivilegedExec;
                    String::new()
                } else {
                    String::new()
                }
            }
        }
    }

    fn get_prompt(&self) -> String {
        match self.mode {
            CiscoMode::UserExec => format!("{}>", self.hostname),
            CiscoMode::PrivilegedExec => format!("{}#", self.hostname),
            CiscoMode::GlobalConfig => format!("{}(config)#", self.hostname),
            CiscoMode::InterfaceConfig => format!("{}(config-if)#", self.hostname),
            CiscoMode::RouterConfig => format!("{}(config-router)#", self.hostname),
            CiscoMode::LineConfig => format!("{}(config-line)#", self.hostname),
        }
    }

    fn get_banner(&self) -> String {
        format!(
            "\n\
             **************************************************************************\n\
             * IOSv is strictly limited to use for evaluation, demonstration and IOS  *\n\
             * education. IOSv is provided as-is and is not supported by Cisco's      *\n\
             * Technical Advisory Center. Any use or disclosure, in whole or in part, *\n\
             * of the IOSv Software or Documentation to any third party for any       *\n\
             * purposes is expressly prohibited except as otherwise authorized by     *\n\
             * Cisco in writing.                                                      *\n\
             **************************************************************************\n\
             \n\
             User Access Verification\n\
             \n"
        )
    }
}

impl CiscoIos {
    fn get_help(&self) -> String {
        match self.mode {
            CiscoMode::UserExec => {
                "Exec commands:\n\
                   enable      Turn on privileged commands\n\
                   exit        Exit from the EXEC\n\
                   logout      Exit from the EXEC\n\
                   ping        Send echo messages\n\
                   show        Show running system information\n\
                   traceroute  Trace route to destination\n".to_string()
            }
            CiscoMode::PrivilegedExec => {
                "Exec commands:\n\
                   configure   Enter configuration mode\n\
                   copy        Copy from one file to another\n\
                   debug       Debugging functions\n\
                   disable     Turn off privileged commands\n\
                   exit        Exit from the EXEC\n\
                   logout      Exit from the EXEC\n\
                   ping        Send echo messages\n\
                   reload      Halt and perform a cold restart\n\
                   show        Show running system information\n\
                   traceroute  Trace route to destination\n\
                   write       Write running configuration to memory or terminal\n".to_string()
            }
            _ => String::new(),
        }
    }

    fn get_config_help(&self) -> String {
        "Configure commands:\n\
           access-list    Add an access list entry\n\
           banner         Define a login banner\n\
           crypto         Encryption module\n\
           enable         Modify enable password parameters\n\
           end            Exit from configure mode\n\
           exit           Exit from configure mode\n\
           hostname       Set system's network name\n\
           interface      Select an interface to configure\n\
           ip             Global IP configuration subcommands\n\
           line           Configure a terminal line\n\
           no             Negate a command or set its defaults\n\
           router         Enable a routing process\n\
           snmp-server    Modify SNMP engine parameters\n\
           username       Establish User Name Authentication\n".to_string()
    }
}
