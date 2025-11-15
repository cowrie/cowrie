# Cowrie Quick Reference & Design Patterns

## Quick Component Lookup Table

### By Responsibility

| Responsibility | Key File(s) | Key Class(es) |
|---|---|---|
| **Protocol Negotiation** | ssh/transport.py | HoneyPotSSHTransport |
| **Connection Management** | ssh/factory.py | CowrieSSHFactory |
| **Session Handling** | ssh/session.py | SSHSessionForCowrieUser |
| **User Authentication** | ssh/userauth.py, core/checkers.py | HoneyPotSSHUserAuthServer, HoneypotPasswordChecker |
| **Shell Interaction** | core/honeypot.py | HoneyPotShell, HoneyPotCommand |
| **Virtual Filesystem** | core/fs.py | HoneyPotFilesystem |
| **Command Lookup** | core/protocol.py | HoneyPotBaseProtocol.getCommand() |
| **Command Execution** | cowrie/commands/*.py | command_* subclasses |
| **Event Logging** | core/output.py | Output base class |
| **Database Logging** | core/dblog.py | DBLogger base class |
| **Plugin Loading** | twisted/plugins/cowrie_plugin.py | CowrieServiceMaker |
| **Configuration** | core/config.py | readConfigFile() |

---

## Protocol Stack Layers

### SSH Stack
```
┌──────────────────────────────────────┐
│  Application: HoneyPotShell          │
│  (Command line, shell features)      │
├──────────────────────────────────────┤
│  Session: SSHSessionForCowrieUser    │
│  (Shell/Exec request handling)       │
├──────────────────────────────────────┤
│  Connection: CowrieSSHConnection     │
│  (Channel management)                │
├──────────────────────────────────────┤
│  Transport: HoneyPotSSHTransport     │
│  (SSH protocol, encryption, auth)    │
├──────────────────────────────────────┤
│  Network: Twisted TCP (asyncio)      │
│  (Sockets, async I/O)                │
└──────────────────────────────────────┘
```

### Telnet Stack
```
┌──────────────────────────────────────┐
│  Application: HoneyPotShell          │
│  (Command line, shell features)      │
├──────────────────────────────────────┤
│  Session: HoneyPotTelnetSession      │
│  (Auth, option negotiation)          │
├──────────────────────────────────────┤
│  Protocol: HoneyPotTelnetProtocol    │
│  (Telnet protocol, encoding)         │
├──────────────────────────────────────┤
│  Network: Twisted TCP (asyncio)      │
│  (Sockets, async I/O)                │
└──────────────────────────────────────┘
```

---

## Event Flow Diagrams

### Authentication Flow
```
SSH Client connects
  ↓
HoneyPotSSHTransport.connectionMade()
  ├─ transportId = uuid.uuid4()
  ├─ log 'cowrie.session.connect'
  └─ send SSH version
  ↓
SSH_USERAUTH_REQUEST
  ↓
HoneyPotSSHUserAuthServer.auth_password()
  ↓
HoneypotPasswordChecker.requestAvatarId()
  ├─ checkUserPass() → check userdb.txt
  ├─ log 'cowrie.login.success' or 'cowrie.login.failed'
  ├─ Create CowrieUser avatar
  └─ Create CowrieServer (shared virtual machine)
  ↓
Twisted Cred Portal → HoneyPotRealm
  ↓
SSHSessionForCowrieUser created
  ↓
SSH_CHANNEL_OPEN (shell)
  ↓
openShell() → HoneyPotInteractiveProtocol
  ↓
Display MOTD & prompt
```

### Command Execution Flow
```
User types: "ls -l /tmp"
  ↓
Terminal.write() → SSH protocol
  ↓
HoneyPotInteractiveProtocol.characterReceived()
  ↓
lineBuffer collected
  ↓
HoneyPotInteractiveProtocol.handle_RETURN()
  ↓
HoneyPotShell.lineReceived()
  ├─ shlex.split() + env var expansion
  ├─ log 'cowrie.command.input'
  └─ append to cmdpending
  ↓
HoneyPotShell.runCommand()
  ├─ getCommand("ls", ["/usr/bin", "/bin"])
  │   ├─ Check self.commands["ls"] → found!
  │   └─ return command_ls
  ├─ Create StdOutStdErrEmulationProtocol
  ├─ log 'cowrie.command.success'
  └─ call_command() → instantiate command_ls
  ↓
command_ls.start()
  ├─ call() → actual ls logic
  │   ├─ fs.get_path("/tmp")
  │   └─ format output
  └─ exit() → pop from cmdstack
  ↓
Output via protocol.pp.outReceived()
  ↓
HoneyPotInteractiveProtocol.showPrompt()
```

### Pipe Flow
```
User types: "ls /tmp | grep test | wc -l"
  ↓
HoneyPotShell.runCommand()
  ├─ Parse: ["ls", "/tmp"], ["grep", "test"], ["wc", "-l"]
  ├─ Build chain in reverse:
  │   wc (last) → no next_command
  │   grep → next_command = wc
  │   ls (first) → next_command = grep
  ↓
Execute ls
  ├─ create StdOutStdErrEmulationProtocol for ls
  ├─ ls.call() generates output
  └─ ls output → pp.outReceived()
  ↓
StdOutStdErrEmulationProtocol.outReceived()
  ├─ Collect data in self.data
  └─ (ls is not last in pipe)
  ↓
StdOutStdErrEmulationProtocol.outConnectionLost()
  ├─ Pass self.data to grep.input_data
  ├─ Execute grep with input_data
  ↓
grep.call()
  ├─ Process input_data
  └─ Output → pp.outReceived()
  ↓
(repeat for wc)
  ↓
wc is last → write to terminal
```

### Event Distribution
```
log.msg(eventid='cowrie.command.input', input='ls')
  ↓
Twisted logging system
  ↓
┌─────────────────────┬──────────────────┬─────────────────┐
│                     │                  │                 │
↓                     ↓                  ↓                 ↓
DBLogger.emit()   Output.emit()     stdout           (other
│                 │                 logging)          observers)
├─ Filter event  ├─ Enrich with:
├─ Handle event  │  - timestamp
│  └─MySQL.      │  - sensor
│    handleXXX() │  - session ID
└─ Update DB     │  - src_ip
                 └─ call write()
                    └─JSON file
                       Splunk
                       MySQL
                       etc.
```

---

## State Diagram: HoneyPotShell

```
        ┌─────────────────────┐
        │  Shell Initialized  │
        │  showPrompt()       │
        └──────────┬──────────┘
                   │
                   ↓ (user input)
        ┌─────────────────────┐
        │  lineReceived()     │
        │  Parse command      │
        │  Enqueue command    │
        └──────────┬──────────┘
                   │
                   ↓
        ┌─────────────────────┐
        │  runCommand()       │
        │  Lookup command     │
        │  Create StdOut...   │
        │  Instantiate cmd    │
        └──────────┬──────────┘
                   │
                   ↓
        ┌─────────────────────┐
        │  Command.start()    │
        │  Command.call()     │
        │  Generate output    │
        └──────────┬──────────┘
                   │
                   ↓
        ┌─────────────────────┐
        │  Command.exit()     │
        │  Pop cmdstack       │
        │  Resume (next cmd)  │
        └──────────┬──────────┘
                   │
                   ↓
        ┌─────────────────────┐
        │  showPrompt()       │
        └─────────────────────┘
```

---

## Class Hierarchy: Commands

```
HoneyPotCommand
    │
    ├─ command_whoami      (simple: just return username)
    ├─ command_help        (static: print help text)
    ├─ command_ls          (complex: list files with options)
    ├─ command_cat         (fs access: read files)
    ├─ command_mkdir       (fs modify: create directory)
    ├─ command_chmod       (fs modify: change permissions)
    ├─ command_wget        (network: download files)
    ├─ command_curl        (network: download files)
    ├─ command_ssh         (fake: pretend to SSH)
    ├─ command_gcc         (fake: pretend to compile)
    ├─ command_python      (interpreter: limited Python)
    ├─ command_perl        (interpreter: limited Perl)
    ├─ command_iptables    (fake: firewall rules)
    ├─ command_netstat     (fs-based: read txtcmds/)
    ├─ command_ps          (fs-based: read txtcmds/)
    └─ ... ~15 more
```

---

## Configuration Structure

### [honeypot] Section
```ini
[honeypot]
hostname = svr04                    # Displayed in prompt
listen_addr = 0.0.0.0             # Bind address
listen_port = 2222                # Default SSH port
ssh_version_string = ...          # Custom SSH version string
auth_none_enabled = false         # Allow anonymous auth
log_path = log                    # Event logs directory
download_path = dl                # Downloaded files storage
data_path = data                  # User database location
contents_path = honeyfs           # File contents directory
filesystem_file = data/fs.pickle  # Pickled filesystem
txtcmds_path = txtcmds            # Text command outputs
fake_addr = 1.2.3.4              # Client IP override (optional)
```

### [ssh] Section
```ini
[ssh]
enabled = true
listen_addr = 0.0.0.0
listen_port = 2222
```

### [telnet] Section
```ini
[telnet]
enabled = false
listen_addr = 0.0.0.0
listen_port = 2223
```

### [output_*] Section (any)
```ini
[output_jsonlog]
logfile = log/cowrie.json

[output_mysql]
host = localhost
database = cowrie
username = root
password = secret

[output_splunk]
host = localhost
port = 8088
token = HEC_token
```

### [database_*] Section (any)
```ini
[database_textlog]
logfile = log/cowrie.log

[database_mysql]
host = localhost
database = cowrie
username = root
password = secret
```

---

## Important File Paths

| Path | Purpose | Type |
|---|---|---|
| `cowrie.cfg` | Main configuration file | Config |
| `data/fs.pickle` | Virtual filesystem snapshot | Binary |
| `data/userdb.txt` | User credentials (user:pass:uid:gid) | Text |
| `honeyfs/` | Real file contents linked to vfs | Directory |
| `log/cowrie.json` | Event logs (JSON) | Log |
| `log/cowrie.log` | System logs | Log |
| `log/tty/*.log` | Session terminal I/O | Log |
| `dl/` | Downloaded/uploaded files | Directory |
| `txtcmds/` | Static command output files | Directory |
| `bin/cowrie` | Startup script | Script |
| `bin/createfs` | Filesystem builder | Script |
| `bin/playlog` | Session replay utility | Script |

---

## How to Add a New Command

### Step 1: Create Command File
File: `cowrie/commands/mynewcmd.py`

```python
from cowrie.core.honeypot import HoneyPotCommand
from cowrie.core.fs import *

commands = {}

class command_mynewcmd(HoneyPotCommand):
    def call(self):
        if not len(self.args):
            self.errorWrite("mynewcmd: missing argument\n")
            return
        
        arg = self.args[0]
        self.write("Processing: %s\n" % arg)

commands['/usr/bin/mynewcmd'] = command_mynewcmd
commands['mynewcmd'] = command_mynewcmd
```

### Step 2: Register Command
File: `cowrie/commands/__init__.py`

```python
__all__ = [
    # ... existing ...
    'mynewcmd'
]
```

### Step 3: Add to Virtual Filesystem
File: `bin/createfs` (or manually edit data/fs.pickle)

Create file in virtual filesystem so `which mynewcmd` finds it.

### Step 4: (Optional) Add Text Output
File: `txtcmds/usr/bin/mynewcmd`

Create text file with static output if command is simple.

### Step 5: Test

```bash
ssh -p 2222 root@localhost
# Or telnet localhost 2223
mynewcmd test
```

---

## How to Add a New Output Plugin

### Step 1: Create Plugin
File: `cowrie/output/myoutput.py`

```python
import cowrie.core.output

class Output(cowrie.core.output.Output):
    def __init__(self, cfg):
        cowrie.core.output.Output.__init__(self, cfg)
        self.my_config = cfg.get('output_myoutput', 'param1')
    
    def start(self):
        print("MyOutput plugin started")
    
    def stop(self):
        print("MyOutput plugin stopped")
    
    def write(self, event):
        print("Event: %s" % event['eventid'])
        # Send event to external service
        # self.send_to_service(event)

commands = []
```

### Step 2: Configure
File: `cowrie.cfg`

```ini
[output_myoutput]
param1 = value1
param2 = value2
```

### Step 3: Test
Start cowrie and check logs for "Loaded output engine: myoutput"

---

## Important Environment Variables

Set by Cowrie in shell environment:

```
LOGNAME     # Username
USER        # Username
SHELL       # Always /bin/bash
HOME        # User's home directory
TMOUT       # 1800 (30 minutes)
PATH        # /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin (root)
TERM        # Terminal type (from client)
```

---

## Twisted Logging Event Fields

### Always Present
- `eventid` - Event type identifier
- `timestamp` - ISO 8601 UTC time
- `sensor` - Honeypot name (from config)
- `session` - Session ID
- `src_ip` - Attacker IP address

### Connection Events
- `src_port` - Attacker port
- `dst_ip` - Honeypot IP
- `dst_port` - Honeypot port

### Authentication Events
- `username` - Username attempted
- `password` - Password attempted

### Command Events
- `input` - Command line typed

### File Transfer Events
- `url` - File URL
- `outfile` - Output filename
- `size` - File size
- `duration` - Transfer duration

### Client Info Events
- `version` - SSH/Telnet client version
- `width`, `height` - Terminal size

---

## Virtual Filesystem Structure (fs.pickle)

Internal structure (Python tuple):
```
fs[path] = [
    name,           # A_NAME: filename
    type,           # A_TYPE: T_DIR, T_FILE, etc.
    uid,            # A_UID: user ID
    gid,            # A_GID: group ID
    size,           # A_SIZE: file size
    mode,           # A_MODE: permissions (octal)
    ctime,          # A_CTIME: creation time
    contents,       # A_CONTENTS: file data (or None)
    target,         # A_TARGET: symlink target (or None)
    realfile        # A_REALFILE: path to honeyfs file
]
```

### File Types
- `T_LINK` (0) - Symlink
- `T_DIR` (1) - Directory
- `T_FILE` (2) - Regular file
- `T_BLK` (3) - Block device
- `T_CHR` (4) - Character device
- `T_SOCK` (5) - Socket
- `T_FIFO` (6) - FIFO pipe

---

## Key Methods for Command Implementations

```python
# Access filesystem
self.fs.resolve_path(path, cwd)      # Convert relative to absolute
self.fs.exists(path)                 # Check if path exists
self.fs.isdir(path)                  # Check if directory
self.fs.isfile(path)                 # Check if file
self.fs.get_path(path)               # List directory contents
self.fs.file_contents(path)          # Read file contents
self.fs.mkfile(path, ...)            # Create file
self.fs.mkdir(path, ...)             # Create directory

# Write output
self.write("output\n")               # stdout
self.errorWrite("error\n")           # stderr

# Access environment
self.environ['HOME']                 # Home directory
self.environ['USER']                 # Username
self.environ['PATH']                 # PATH variable

# Access user info
self.protocol.user.username          # Current user
self.protocol.user.uid               # User ID
self.protocol.cwd                    # Current working directory
self.protocol.hostname               # Honeypot hostname

# Process input data (from pipes)
self.input_data                      # Data from previous command in pipe
```

---

## Best Practices for Design Inspiration

### 1. Event-Driven Architecture
- Log everything as events
- Multiple observers can subscribe to events
- Easy to add new logging backends without code changes

### 2. Clear Separation of Concerns
- Protocol layer: SSH/Telnet negotiation
- Session layer: Auth, channel management
- Command layer: Emulation logic
- Output layer: Event distribution

### 3. Extensibility via Configuration
- Plugins loaded from config file
- No recompilation needed for new plugins
- Per-component settings in INI format

### 4. Virtual State Management
- Serialized filesystem allows shared state
- Each connection gets a copy for isolation
- Can backup/restore entire environment

### 5. Command Pattern for Shell Commands
- Base class handles common operations
- Subclass implements specific logic
- Registry for command discovery

### 6. Graceful Degradation
- Commands can fail without crashing shell
- Unknown commands logged but don't crash
- Plugins can fail without affecting core

---

## Performance Considerations

### Design Patterns Used
1. **Lazy Initialization**: Plugins loaded on demand
2. **Caching**: Filesystem pickle cached in memory
3. **Asynchronous I/O**: Twisted handles all socket operations
4. **Connection Pooling**: Database connections reused

### Potential Bottlenecks
1. **Filesystem Pickle**: Large vfs = large memory footprint
2. **Command Parsing**: shlex for every input line
3. **Event Distribution**: Multiple output plugins = sequential processing
4. **Database Writes**: Synchronous operations can block

### Optimization Tips
1. Minimize pickled filesystem size
2. Use fast output backends (JSON over MySQL)
3. Consider async database writes for high volume
4. Profile plugin execution time

