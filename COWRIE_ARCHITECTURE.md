# Cowrie Honeypot Architecture Overview

## Executive Summary

Cowrie is a medium-interaction SSH/Telnet honeypot built on the Twisted networking framework (Python). It emulates a Linux shell environment to capture and log attacker interactions, file transfers, and command execution attempts. The architecture emphasizes extensibility through a plugin-based system for both output logging and command emulation.

**Key Statistics:**
- 88 Python files total
- ~30 emulated shell commands
- Support for SSH, Telnet, SFTP, and SCP
- Multiple output backends (JSON, MySQL, SQLite, HPFeeds, Splunk, etc.)
- Modular plugin architecture for easy extension

---

## 1. Overall Architecture and Main Components

### 1.1 Layered Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Twisted Async Framework                   │
├─────────────────────────────────────────────────────────────┤
│  SSH Transport (SSHv2) │ Telnet Protocol │ Direct TCP Proxy  │
├─────────────────────────────────────────────────────────────┤
│  Authentication Layer (Public Key, Password, PAM, None)     │
├─────────────────────────────────────────────────────────────┤
│  Protocol Handlers (HoneyPotInteractiveProtocol)            │
├─────────────────────────────────────────────────────────────┤
│  Shell & Command Processing (HoneyPotShell + HoneyPotCmd)   │
├─────────────────────────────────────────────────────────────┤
│  Virtual Filesystem (HoneyPotFilesystem - pickled)          │
├─────────────────────────────────────────────────────────────┤
│  Plugin System: Output Backends & DBLoggers                 │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 Directory Structure

```
cowrie/
├── cowrie/
│   ├── core/              # Core functionality
│   │   ├── honeypot.py    # HoneyPotShell, HoneyPotCommand, StdOutStdErrEmulationProtocol
│   │   ├── protocol.py    # Base/Interactive/Exec Protocols
│   │   ├── fs.py          # Virtual filesystem (pickle-based)
│   │   ├── output.py      # Output base class
│   │   ├── dblog.py       # DBLogger base class
│   │   ├── server.py      # CowrieServer (shared VM)
│   │   ├── avatar.py      # User avatar
│   │   ├── realm.py       # Authentication realm
│   │   ├── checkers.py    # Credential checkers
│   │   ├── auth.py        # User/password auth
│   │   └── pwd.py         # Unix pwd/group emulation
│   ├── ssh/               # SSH protocol implementation
│   │   ├── factory.py     # CowrieSSHFactory
│   │   ├── transport.py   # HoneyPotSSHTransport
│   │   ├── connection.py  # CowrieSSHConnection
│   │   ├── session.py     # SSH session management
│   │   ├── userauth.py    # User authentication
│   │   └── filetransfer.py # SFTP/SCP support
│   ├── telnet/            # Telnet protocol implementation
│   │   ├── transport.py   # Telnet factory
│   │   └── session.py     # Telnet session
│   ├── commands/          # Emulated shell commands (~30)
│   │   ├── base.py        # Base commands (whoami, help, w, etc.)
│   │   ├── ls.py, cat.py, mkdir.py, etc.
│   │   └── __init__.py    # Command registry
│   ├── output/            # Output backend plugins
│   │   ├── jsonlog.py     # JSON logging
│   │   ├── mysql.py       # MySQL logging
│   │   ├── sqlite.py      # SQLite logging
│   │   ├── hpfeeds.py     # HPFeeds logging
│   │   ├── splunk.py      # Splunk logging
│   │   └── dshield.py     # DShield reporting
│   ├── dblog/             # DBLogger plugins
│   │   ├── mysql.py, xmpp.py, textlog.py, hpfeeds.py
│   ├── insults/           # Terminal emulation
│   └── test/              # Unit tests
├── twisted/
│   └── plugins/
│       └── cowrie_plugin.py # Twisted plugin entry point
├── bin/                   # Utility scripts
│   ├── cowrie             # Main startup script
│   ├── createfs           # Filesystem builder
│   └── playlog            # Session replay
├── data/
│   ├── fs.pickle          # Pickled virtual filesystem
│   └── userdb.txt         # User credentials
├── honeyfs/               # Real file contents
├── dl/                    # Downloaded files storage
├── txtcmds/               # Text command responses
└── cowrie.cfg.dist        # Configuration template
```

### 1.3 Core Components

| Component | Location | Purpose |
|-----------|----------|---------|
| **HoneyPotShell** | `core/honeypot.py` | Interactive shell parser, command dispatcher |
| **HoneyPotCommand** | `core/honeypot.py` | Base class for all emulated commands |
| **HoneyPotBaseProtocol** | `core/protocol.py` | Base protocol handler for both SSH/Telnet |
| **HoneyPotInteractiveProtocol** | `core/protocol.py` | Interactive shell protocol with history |
| **HoneyPotExecProtocol** | `core/protocol.py` | Non-interactive command execution |
| **HoneyPotFilesystem** | `core/fs.py` | Virtual filesystem backed by pickle |
| **CowrieSSHFactory** | `ssh/factory.py` | SSH connection factory |
| **HoneyPotSSHTransport** | `ssh/transport.py` | SSH transport layer |
| **Output** | `core/output.py` | Abstract output plugin base |
| **DBLogger** | `core/dblog.py` | Abstract DBLogger plugin base |

---

## 2. Protocol Implementation (SSH & Telnet)

### 2.1 SSH Protocol Implementation

**Flow:** TCP Connection → SSH Transport → SSH Connection → SSH Session → Interactive/Exec Protocol

**Key Files:**
- `ssh/factory.py` - CowrieSSHFactory: Creates SSH transports, manages sessions
- `ssh/transport.py` - HoneyPotSSHTransport: Handles SSH protocol negotiation
- `ssh/connection.py` - CowrieSSHConnection: Manages SSH channels
- `ssh/userauth.py` - HoneyPotSSHUserAuthServer: Authentication handling
- `ssh/session.py` - SSHSessionForCowrieUser: Shell/Exec request handling

**SSH Features:**
```python
# Factory startup (ssh/factory.py)
CowrieSSHFactory:
  - generateHostKey() generates RSA/DSA keys
  - Supports public key, password, PAM, anonymous auth
  - Serves SSH version string (customizable)
  - Ciphers: aes128/192/256-ctr/cbc, 3des, blowfish
  - MACs: hmac-md5, hmac-sha1
  - Compression: zlib, none

# Transport initialization
HoneyPotSSHTransport:
  - otherVersionString: Client SSH version
  - transportId: UUID for session tracking
  - Generates connection event log

# Session management
SSHSessionForCowrieUser:
  - openShell() → creates HoneyPotInteractiveProtocol
  - execCommand(cmd) → creates HoneyPotExecProtocol
  - getPty() → terminal size/type
```

**SSH Authentication Handlers:**
```python
# cowrie/core/checkers.py
HoneypotPublicKeyChecker:      # Logs but rejects PubKey auth
HoneypotPasswordChecker:       # Handles password/keyboard-interactive
HoneypotNoneChecker:           # Accepts no auth (optional)
```

### 2.2 Telnet Protocol Implementation

**Flow:** TCP Connection → Telnet Transport → HoneyPotTelnetSession → Interactive Protocol

**Key Files:**
- `telnet/transport.py` - HoneyPotTelnetFactory, HoneyPotTelnetProtocol
- `telnet/session.py` - HoneyPotTelnetSession, TelnetSessionProcessProtocol

**Telnet Features:**
```python
HoneyPotTelnetSession:
  - Wrapped with HoneyPotInteractiveTelnetProtocol
  - Simple password authentication
  - Terminal options negotiation (ECHO, SGA)
  - Compatible with standard Telnet clients
  
HoneyPotInteractiveTelnetProtocol (extends HoneyPotInteractiveProtocol):
  - Overrides getProtoTransport() for Telnet transport access
  - Returns 'Telnet' as client version
```

### 2.3 Command Execution Pipeline

```
User Input
    ↓
lineReceived() [HoneyPotShell]
    ↓
lexer.split() + environment variable expansion
    ↓
cmdpending queue (handles `;`, `&&`, `||`)
    ↓
runCommand()
    ↓
getCommand() - looks up in:
  1. self.commands dict (Python modules)
  2. Filesystem (txtcmds_path)
  ↓
StdOutStdErrEmulationProtocol (pipe support)
    ↓
HoneyPotCommand.start() → call() → exit()
    ↓
Output written to terminal via outReceived()
```

**Key Code:** `core/honeypot.py`
- **HoneyPotShell.lineReceived()**: Parses shell input
- **HoneyPotShell.runCommand()**: Executes commands with pipe support
- **HoneyPotCommand**: Base class requiring `call()` method
- **StdOutStdErrEmulationProtocol**: Handles piping between commands

---

## 3. Logging and Output System

### 3.1 Event-Based Logging Architecture

**Core Principle:** Event IDs with optional parameters → Twisted logging → Observers

```
Honeypot Event
    ↓
log.msg(eventid='cowrie.event.type', param1=val1, ...)
    ↓
Twisted Log Observer
    ↓
┌────────────────────┬──────────────────┬─────────────────┐
│  DBLogger Plugins  │ Output Plugins   │  stdout/stderr  │
│  (mysql, sqlite)   │ (json, splunk)   │  (debug logs)   │
└────────────────────┴──────────────────┴─────────────────┘
```

### 3.2 Output System (`core/output.py`)

**Base Class: `Output`**

Abstract methods:
- `start()` - Initialize output backend
- `stop()` - Cleanup
- `write(event)` - Write event to backend

**Event Processing:**
```python
Output.emit(event):
  1. Skip events without eventid
  2. Add timestamp, sensor name
  3. Extract session ID from Twisted system prefix
  4. Add source IP from cached sessions
  5. Special handling for connection/disconnect events
  6. Call write(event) with enriched event
```

**Output Plugins (cowrie/output/):**
| Plugin | Purpose |
|--------|---------|
| `jsonlog.py` | JSON file logging (Daily rotation) |
| `mysql.py` | MySQL database logging |
| `sqlite.py` | SQLite database logging |
| `elasticsearch.py` | Elasticsearch indexing |
| `hpfeeds.py` | HPFeeds broker reporting |
| `splunk.py` | Splunk HEC logging |
| `virustotal.py` | VirusTotal sample submission |
| `dshield.py` | DShield attack reporting |

### 3.3 DBLogger System (`core/dblog.py`)

**Base Class: `DBLogger`**

Abstract methods:
- `createSession()` - Create session record
- `handleLoginSucceeded()` - User login
- `handleLoginFailed()` - Failed auth
- `handleCommand()` - Successful command
- `handleFileDownload()` - File download
- etc.

**Event Mapping:**
```python
Events = {
    'cowrie.session.connect': N/A (creates new session),
    'cowrie.login.success': handleLoginSucceeded(),
    'cowrie.login.failed': handleLoginFailed(),
    'cowrie.command.success': handleCommand(),
    'cowrie.command.failed': handleUnknownCommand(),
    'cowrie.session.file_download': handleFileDownload(),
    'cowrie.command.input': handleInput(),
    'cowrie.client.version': handleClientVersion(),
    'cowrie.client.size': handleTerminalSize(),
    'cowrie.session.closed': cleanup(),
}
```

### 3.4 Event Types

**Session Events:**
- `cowrie.session.connect` - New connection (src_ip, src_port, dst_ip, dst_port, session)
- `cowrie.session.closed` - Connection closed

**Authentication Events:**
- `cowrie.login.success` - Successful login
- `cowrie.login.failed` - Failed login attempt
- `cowrie.client.fingerprint` - Public key attempt

**Command Events:**
- `cowrie.command.input` - Command typed
- `cowrie.command.success` - Command found and executed
- `cowrie.command.failed` - Command not found

**File Transfer Events:**
- `cowrie.session.file_download` - File downloaded (wget/curl)
- `cowrie.session.file_upload` - File uploaded (SFTP/SCP)

**Client Events:**
- `cowrie.client.version` - SSH client version string
- `cowrie.client.size` - Terminal window size
- `cowrie.client.var` - Environment variable request

**Log Management:**
- `cowrie.log.open` - TTY log file opened
- `cowrie.log.closed` - TTY log file closed

### 3.5 Loading Plugins at Startup

**File:** `twisted/plugins/cowrie_plugin.py`

```python
CowrieServiceMaker.makeService():
    # Load DBLoggers
    for x in cfg.sections():
        if x.startswith('database_'):
            engine = x.split('_')[1]
            dblogger = __import__('cowrie.dblog.{}'.format(engine))
            log.addObserver(dblogger.emit)
    
    # Load Output Plugins
    for x in cfg.sections():
        if x.startswith('output_'):
            engine = x.split('_')[1]
            output = __import__('cowrie.output.{}'.format(engine))
            log.addObserver(output.emit)
```

**Configuration:** `cowrie.cfg`
```ini
[output_jsonlog]
logfile = log/cowrie.json

[output_mysql]
host = localhost
database = cowrie

[database_textlog]
logfile = log/cowrie.log
```

---

## 4. Command Emulation Framework

### 4.1 Command System Architecture

**Registry:** `cowrie/commands/__init__.py`
```python
__all__ = [
    'adduser', 'apt', 'base', 'busybox', 'curl', 'env',
    'ethtool', 'free', 'fs', 'gcc', 'ifconfig', 'iptables',
    'last', 'ls', 'netstat', 'nohup', 'ping', 'scp',
    'service', 'sleep', 'ssh', 'sudo', 'tar', 'uname',
    'wget', 'which', 'perl', 'uptime', 'python'
]
```

### 4.2 Base Command Class

**File:** `cowrie/commands/base.py` + `cowrie/core/honeypot.py`

```python
class HoneyPotCommand(object):
    def __init__(self, protocol, *args):
        self.protocol = protocol      # Current shell protocol
        self.args = list(args)        # Command arguments
        self.environ = protocol.cmdstack[0].environ
        self.fs = protocol.fs
        self.data = None
        self.input_data = None        # From pipe
        self.write = protocol.pp.outReceived  # stdout
        self.errorWrite = protocol.pp.errReceived  # stderr
        
        # Handle output redirection (> file)
        if '>' in self.args:
            self.write = self.write_to_file
            # ... file handling ...
    
    def start(self):
        self.call()
        self.exit()
    
    def call(self):
        # Override this! Pure virtual
        self.write('Hello World! [%s]\n' % (repr(self.args),))
    
    def exit(self):
        self.protocol.cmdstack.pop()
        self.protocol.cmdstack[-1].resume()
    
    def set_input_data(self, data):
        self.input_data = data
```

### 4.3 Command Registration

Each command module defines a `commands` dict:

```python
# Example: cowrie/commands/base.py
commands = {}

class command_whoami(HoneyPotCommand):
    def call(self):
        self.write(self.protocol.user.username + '\n')

commands['/usr/bin/whoami'] = command_whoami
commands['whoami'] = command_whoami  # Also short name
```

### 4.4 Command Discovery

**File:** `core/protocol.py` - `HoneyPotBaseProtocol.getCommand()`

```python
def getCommand(self, cmd, paths):
    # 1. Check registered commands dict
    if cmd in self.commands:
        return self.commands[cmd]
    
    # 2. Check filesystem
    if cmd[0] in ('.', '/'):
        path = self.fs.resolve_path(cmd, self.cwd)
        if self.fs.exists(path):
            # Found on filesystem
            ...
    else:
        # Search PATH
        for path_dir in paths:
            full_path = path_dir + '/' + cmd
            if self.fs.exists(full_path):
                path = full_path
                break
    
    # 3. Check txtcmds (text-based command output files)
    txt = '%s/%s' % (txtcmds_path, path)
    if os.path.exists(txt):
        return self.txtcmd(txt)  # Read file and return output
    
    return None  # Command not found
```

### 4.5 Popular Emulated Commands

| Command | Type | Implementation |
|---------|------|-----------------|
| **ls** | Native | Full ls with -l, -a, -d options |
| **cat** | Native | Reads fake filesystem or file contents |
| **whoami** | Native | Returns current username |
| **wget** | Native | Downloads files, stores in dl/ |
| **curl** | Native | Downloads files (curl variant) |
| **ssh** | Native | Pretends to SSH elsewhere |
| **gcc** | Native | Pretends to compile (fake output) |
| **python** | Native | Limited Python execution |
| **mkdir/touch/chmod** | Native | Modify virtual filesystem |
| **ps/netstat/ifconfig** | Text files | Static output from txtcmds/ |

### 4.6 Pipe Support

**File:** `core/honeypot.py` - `StdOutStdErrEmulationProtocol`

Implements `|` operator between commands:

```python
# Shell input: "ls | grep test | wc -l"
# Creates chain:
#   ls → StdOutStdErrEmulationProtocol
#        (outReceived) → grep's input_data
#   grep → StdOutStdErrEmulationProtocol
#          (outReceived) → wc's input_data
#   wc → writes to terminal

class StdOutStdErrEmulationProtocol:
    def __init__(self, protocol, cmd, cmdargs, input_data, next_command):
        self.cmd = cmd
        self.input_data = input_data
        self.next_command = next_command
        self.data = ""  # stdout data
        self.err_data = ""  # stderr data
    
    def outReceived(self, data):
        self.data += data
        if not self.next_command:
            # Last command in pipe, write to terminal
            self.protocol.terminal.write(str(data))
    
    def outConnectionLost(self):
        if self.next_command:
            # Pass output to next command's input_data
            self.next_command.input_data = self.data
            # Execute next command
            self.protocol.call_command(self.next_command, ...)
```

### 4.7 Custom Command Example

```python
# cowrie/commands/custom.py
from cowrie.core.honeypot import HoneyPotCommand

commands = {}

class command_mycommand(HoneyPotCommand):
    def call(self):
        if len(self.args) == 0:
            self.errorWrite("mycommand: missing argument\n")
            return
        
        arg = self.args[0]
        
        # Access filesystem
        path = self.fs.resolve_path(arg, self.protocol.cwd)
        if self.fs.isdir(path):
            self.write("Is a directory\n")
        elif self.fs.exists(path):
            self.write("File exists\n")
        else:
            self.write("File not found\n")

commands['/usr/bin/mycommand'] = command_mycommand
commands['mycommand'] = command_mycommand
```

---

## 5. Plugin/Extension System

### 5.1 Plugin Architecture Overview

Cowrie uses Twisted's plugin system with dynamic imports:

```
┌─────────────────────────────────────────┐
│    Twisted Plugin System (twisted/plugins/cowrie_plugin.py)
├─────────────────────────────────────────┤
│  CowrieServiceMaker
│  ├─ Loads DBLogger plugins
│  ├─ Loads Output plugins
│  └─ Registers with Twisted logging
├─────────────────────────────────────────┤
│  Plugin Discovery (based on cfg sections)
│  ├─ database_* sections → DBLoggers
│  └─ output_* sections → Output plugins
└─────────────────────────────────────────┘
```

### 5.2 Output Plugin System

**Extending:** Create `cowrie/output/mybackend.py`

```python
import cowrie.core.output

class Output(cowrie.core.output.Output):
    def __init__(self, cfg):
        cowrie.core.output.Output.__init__(self, cfg)
        # Initialize backend connection
    
    def start(self):
        """Called when plugin loads"""
        pass
    
    def stop(self):
        """Called when Cowrie shuts down"""
        pass
    
    def write(self, logentry):
        """Called for each event
        
        logentry includes:
        - eventid: 'cowrie.session.connect', etc.
        - timestamp: ISO 8601
        - sensor: Honeypot name
        - session: Session ID
        - src_ip: Attacker IP
        - ... event-specific fields
        """
        # Send to external system
```

**Configuration:** `cowrie.cfg`
```ini
[output_mybackend]
enabled = true
parameter1 = value1
```

### 5.3 DBLogger Plugin System

**Extending:** Create `cowrie/dblog/mylogger.py`

```python
from cowrie.core.dblog import DBLogger

class DBLogger(DBLogger):
    def __init__(self, cfg):
        DBLogger.__init__(self, cfg)
    
    def createSession(self, peerIP, peerPort, hostIP, hostPort):
        """Create session record, return unique session ID"""
        session_id = self._create_db_session(peerIP, peerPort, hostIP, hostPort)
        return session_id
    
    def handleLoginSucceeded(self, session, args):
        """args: {username, password}"""
        pass
    
    def handleLoginFailed(self, session, args):
        """args: {username, password}"""
        pass
    
    def handleCommand(self, session, args):
        """args: {input}"""
        pass
    
    def handleFileDownload(self, session, args):
        """args: {url, outfile, duration}"""
        pass
    
    # ... more handlers ...
```

**Configuration:** `cowrie.cfg`
```ini
[database_mylogger]
engine = mylogger
```

### 5.4 Command Plugin System

**Extending:** Create `cowrie/commands/mycommand.py`

```python
from cowrie.core.honeypot import HoneyPotCommand

commands = {}

class command_example(HoneyPotCommand):
    def call(self):
        self.write("Example command output\n")

commands['/usr/bin/example'] = command_example
commands['example'] = command_example
```

**Registration:** Add to `cowrie/commands/__init__.py`
```python
__all__ = [
    # ... existing commands ...
    'mycommand'
]
```

### 5.5 Dynamic Plugin Loading

**File:** `twisted/plugins/cowrie_plugin.py`

```python
def makeService(self, options):
    cfg = readConfigFile(options["config"])
    
    # Load all database_* plugins
    for section in cfg.sections():
        if section.startswith('database_'):
            engine = section.split('_')[1]
            try:
                # Dynamic import: cowrie.dblog.{engine}
                dblogger = __import__(
                    'cowrie.dblog.{}'.format(engine),
                    globals(), locals(), ['DBLogger']
                ).DBLogger(cfg)
                log.addObserver(dblogger.emit)
                self.dbloggers.append(dblogger)
            except Exception as e:
                log.err()
    
    # Load all output_* plugins
    for section in cfg.sections():
        if section.startswith('output_'):
            engine = section.split('_')[1]
            try:
                # Dynamic import: cowrie.output.{engine}
                output = __import__(
                    'cowrie.output.{}'.format(engine),
                    globals(), locals(), ['Output']
                ).Output(cfg)
                log.addObserver(output.emit)
                self.output_plugins.append(output)
            except Exception as e:
                log.err()
```

### 5.6 Plugin Configuration

**File:** `cowrie.cfg`

```ini
# Enable/disable protocols
[ssh]
enabled = true
listen_addr = 0.0.0.0
listen_port = 2222

[telnet]
enabled = false
listen_port = 2223

# Output plugins
[output_jsonlog]
logfile = log/cowrie.json

[output_mysql]
host = localhost
database = cowrie
username = root
password = secret

[output_elasticsearch]
host = localhost:9200
index = cowrie

# Database logging plugins
[database_textlog]
logfile = log/cowrie.log

[database_mysql]
host = localhost
database = cowrie
```

---

## 6. Additional Architecture Components

### 6.1 Virtual Filesystem

**File:** `core/fs.py` - `HoneyPotFilesystem`

- **Backend:** Python pickle file (`data/fs.pickle`)
- **Content:** Symlinks, directories, files with metadata
- **Features:**
  - File attributes: name, type, uid, gid, size, mode, ctime, contents, target
  - Supports symlinks, special files (chr, blk, sock, fifo)
  - Path resolution and wildcard matching
  - Real file mappings: honeyfs/ directory contents linked to vfs

```python
class HoneyPotFilesystem:
    # Internal representation
    A_NAME = 0
    A_TYPE = 1
    A_UID = 2
    A_GID = 3
    A_SIZE = 4
    A_MODE = 5
    A_CTIME = 6
    A_CONTENTS = 7
    A_TARGET = 8  # symlink target
    A_REALFILE = 9  # path to real file on honeyfs
    
    # File types
    T_LINK = 0  # Symlink
    T_DIR = 1   # Directory
    T_FILE = 2  # Regular file
    T_BLK = 3   # Block device
    T_CHR = 4   # Character device
    T_SOCK = 5  # Socket
    T_FIFO = 6  # FIFO pipe
```

### 6.2 Authentication System

**File:** `core/checkers.py`

```
SSH Auth Request
    ↓
HoneyPotSSHUserAuthServer
    ├─ Public Key → HoneypotPublicKeyChecker (logs, rejects)
    ├─ Password → HoneypotPasswordChecker
    ├─ Keyboard-Interactive → HoneypotPasswordChecker (PAM)
    └─ None → HoneypotNoneChecker (optional)
    ↓
Twisted Cred Portal
    ↓
HoneyPotRealm.requestAvatar()
    ↓
CowrieServer (shared VM) + CowrieUser avatar
```

**File:** `data/userdb.txt` - Format: `username:password:uid:gid`

### 6.3 Session Management

**Concept:** A "server" represents a virtual machine accessible by multiple users (shares filesystem, etc.)

```python
# cowrie/core/server.py
class CowrieServer:
    def __init__(self, realm):
        self.cfg = realm.cfg
        self.hostname = self.cfg.get('honeypot', 'hostname')
        self.fs = HoneyPotFilesystem(
            copy.deepcopy(realm.pckl),  # Copy filesystem pickle
            self.cfg
        )
```

### 6.4 TTY Session Logging

**File:** `core/ttylog.py`

- Logs all terminal I/O to UML-compatible format
- Includes timestamps for replay
- Stored in `log/tty/` directory with pattern: `{date}-{time}-{transportid}.log`

**Replay:** `bin/playlog` utility

---

## 7. Configuration System

**File:** `cowrie.cfg` - INI-style configuration

```ini
[honeypot]
hostname = svr04
listen_addr = 0.0.0.0
listen_port = 2222
ssh_version_string = SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2
auth_none_enabled = false
log_path = log
download_path = dl
contents_path = honeyfs
filesystem_file = data/fs.pickle
txtcmds_path = txtcmds

[ssh]
enabled = true
listen_port = 2222

[telnet]
enabled = false
listen_port = 2223

[output_jsonlog]
logfile = log/cowrie.json

[database_textlog]
logfile = log/cowrie.log
```

**Loading:** `core/config.py` - `readConfigFile()`

---

## 8. Execution Flow Diagram

```
TCP Connection (Port 2222)
    ↓
HoneyPotSSHTransport.connectionMade()
    ├─ Generate transportId
    ├─ Log 'cowrie.session.connect' event
    └─ Send SSH version string
    ↓
SSH Protocol Negotiation (KEX, MAC, Cipher)
    ↓
SSH_USERAUTH_REQUEST
    ├─ Query auth methods
    ├─ Attempt authentication
    │   ├─ Password check
    │   ├─ Log 'cowrie.login.success' or 'cowrie.login.failed'
    │   └─ Create session/avatar on success
    ↓
SSH_CHANNEL_OPEN (shell request)
    ↓
SSHSessionForCowrieUser.openShell()
    ├─ Create HoneyPotInteractiveProtocol
    ├─ Show MOTD
    └─ Display shell prompt
    ↓
User input (interactive)
    ↓
HoneyPotShell.lineReceived()
    ├─ Parse command line
    ├─ Expand variables
    ├─ Log 'cowrie.command.input' event
    └─ Queue commands (handle pipes, &&, ||)
    ↓
HoneyPotShell.runCommand()
    ├─ getCommand() lookup
    ├─ Create StdOutStdErrEmulationProtocol chain (for pipes)
    ├─ Log 'cowrie.command.success' or 'cowrie.command.failed'
    └─ Instantiate HoneyPotCommand subclass
    ↓
HoneyPotCommand.start()
    ├─ call() - Execute logic
    └─ exit() - Pop from cmdstack, resume shell
    ↓
Output events
    ↓
Twisted log observers
    ├─ DBLoggers (handle SQL inserts, etc.)
    └─ Output plugins (send to JSON, Splunk, etc.)
```

---

## 9. Key Design Patterns

### 9.1 Inheritance Hierarchy

```
HoneyPotCommand (base)
    ├─ command_ls
    ├─ command_cat
    ├─ command_wget
    ├─ command_python
    └─ ... 30+ commands

HoneyPotBaseProtocol (Twisted TerminalProtocol)
    ├─ HoneyPotInteractiveProtocol (shell)
    │   └─ HoneyPotInteractiveTelnetProtocol
    └─ HoneyPotExecProtocol (non-interactive)

Output (ABC)
    ├─ JsonlogOutput
    ├─ MySQLOutput
    ├─ SQLiteOutput
    └─ ... 8+ outputs

DBLogger (ABC)
    ├─ TextLogDBLogger
    ├─ MySQLDBLogger
    ├─ SQLiteDBLogger
    └─ ... 4+ db loggers
```

### 9.2 Factory Pattern

```
CowrieSSHFactory
    ├─ Creates HoneyPotSSHTransport instances
    ├─ Manages RSA/DSA keys
    ├─ Holds session dict
    └─ Dispatches to Portal (Twisted auth)

HoneyPotTelnetFactory
    ├─ Creates Telnet transports
    └─ Manages portal
```

### 9.3 Observer Pattern

```
Twisted Logging
    ├─ Event: log.msg(eventid='...', ...)
    ├─ Observer 1: DBLogger.emit()
    ├─ Observer 2: Output.emit()
    ├─ Observer 3: stdout logging
    └─ ... custom observers
```

### 9.4 Template Method Pattern

```
HoneyPotCommand
    - start() [concrete]
        ├─ call() [abstract]
        └─ exit() [concrete]

Output
    - emit() [concrete]
        └─ write() [abstract]

DBLogger
    - emit() [concrete]
        └─ handleLoginSucceeded() [abstract]
           handleCommand() [abstract]
           ... etc
```

---

## 10. Design Insights for eBPF Router Honeypot

### Key Inspiration Points for Your Design:

1. **Event-Based Architecture**
   - Use events for all significant state changes
   - Allow multiple subscribers (logging, alerting, etc.)
   - Extensible without modifying core

2. **Modular Plugin System**
   - Separate transport/routing from command emulation
   - Allow custom output backends
   - Dynamic plugin loading from config

3. **State Serialization**
   - Use pickle for filesystem snapshot (or JSON, Protocol Buffers)
   - Allows shared state across multiple connections
   - Easy backup/recovery

4. **Layered Protocols**
   - Separate protocol negotiation from session management
   - Each layer has clear responsibilities
   - Easy to add new protocols (NAT, BGP, etc.)

5. **Configuration-Driven**
   - INI-style configuration file
   - Plugin selection via config
   - Per-component settings

6. **Comprehensive Logging**
   - TTY-level session logs (for replay)
   - Event-level structured logs
   - Multiple output backends

7. **Command Abstraction**
   - Base class handles common operations
   - Subclass implements protocol-specific logic
   - Registry system for discovery

---

## File Manifest Summary

```
Core Infrastructure (88 files total):
├── cowrie/core/          (18 files) - Protocol, FS, Auth, Logging
├── cowrie/ssh/           (8 files)  - SSH protocol stack
├── cowrie/telnet/        (2 files)  - Telnet protocol
├── cowrie/commands/      (31 files) - Command emulation
├── cowrie/output/        (13 files) - Output plugins
├── cowrie/dblog/         (4 files)  - DB logging plugins
├── cowrie/insults/       (1 file)   - Terminal emulation
├── cowrie/test/          (2 files)  - Unit tests
├── twisted/plugins/      (1 file)   - Entry point
├── bin/                  (4 files)  - Utilities
└── config/data/          (4 files)  - Static data
```

