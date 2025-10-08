# FTPGet Async Rewrite Implementation Plan

## Problem Statement
The current `ftpget` command uses Python's blocking `ftplib`, which blocks the Twisted reactor and prevents other SSH connections from being processed during FTP downloads (Issue #1674).

## Solution
Rewrite `ftpget` to use Twisted's async `FTPClient` from `twisted.protocols.ftp`.

## Current Implementation Analysis

### File: `src/cowrie/commands/ftpget.py`

**Current Flow (Blocking):**
1. Parse command line args (lines 51-92)
2. Validate filesystem paths (lines 94-101)
3. **BLOCKING**: Call `ftp_download()` synchronously (line 120)
4. Within `ftp_download()`:
   - **BLOCKING**: `ftp.connect()` (line 181)
   - **BLOCKING**: `ftp.login()` (line 202)
   - **BLOCKING**: `ftp.retrbinary()` (line 223)
5. Log results and update filesystem (lines 124-165)

**Key Components:**
- Uses `ftplib.FTP` (line 172)
- Writes to `Artifact` object during download (line 223)
- Logs to cowrie.log and protocol dispatcher (lines 126-154)
- Updates honeyfs with downloaded file (lines 157-163)

## Twisted FTPClient API

### Key Classes
- `twisted.protocols.ftp.FTPClient` - FTP client protocol
- `twisted.protocols.ftp.FTPDataPortFactory` - Factory for data connections
- `twisted.protocols.basic.FileSender` - Utility for async file writing

### API Methods (all return Deferreds)
- `queueLogin(username, password)` - Authenticate
- `cwd(path)` - Change working directory
- `retrieveFile(path, protocol)` - Download file (needs a protocol to receive data)
- `quit()` - Close connection

### Data Transfer Pattern
```python
# Need a protocol that implements IProtocol to receive data
class FileReceiver(Protocol):
    def __init__(self, artifact):
        self.artifact = artifact

    def dataReceived(self, data):
        self.artifact.write(data)

    def connectionLost(self, reason):
        # Transfer complete
        pass

# Use with FTPClient
protocol = FileReceiver(artifact)
d = client.retrieveFile('/remote/file', protocol)
```

## Implementation Plan

### Phase 1: Core Async Structure

**1. Create FTPFileReceiver Protocol**
```python
from twisted.internet.protocol import Protocol

class FTPFileReceiver(Protocol):
    """Protocol to receive FTP file data"""
    def __init__(self, artifact, verbose_callback=None):
        self.artifact = artifact
        self.verbose_callback = verbose_callback
        self.bytes_received = 0

    def dataReceived(self, data):
        self.artifact.write(data)
        self.bytes_received += len(data)
        if self.verbose_callback:
            self.verbose_callback(self.bytes_received)

    def connectionLost(self, reason):
        # Called when transfer completes
        pass
```

**2. Refactor start() method**
```python
def start(self) -> None:
    # Parse args (existing code)
    # Validate paths (existing code)

    # Create artifact
    self.artifactFile = Artifact(self.local_file)

    # Start async download - returns deferred
    deferred = self.ftp_download_async()

    if deferred:
        deferred.addCallback(self.download_success)
        deferred.addErrback(self.download_error)
    else:
        self.exit()
```

**3. Implement async download method**
```python
from twisted.internet import reactor
from twisted.internet.protocol import ClientCreator
from twisted.protocols.ftp import FTPClient

def ftp_download_async(self) -> Deferred:
    """Async FTP download using Twisted"""

    # Create FTP client
    creator = ClientCreator(reactor, FTPClient,
                           username=self.username or 'anonymous',
                           password=self.password or 'busybox@',
                           passive=True)

    # Connect
    if self.verbose:
        self.write(f"Connecting to {self.host}\n")

    d = creator.connectTCP(self.host, self.port, timeout=30)
    d.addCallback(self._ftp_connected)
    return d

def _ftp_connected(self, client):
    """Called when FTP connection established"""
    self.ftp_client = client

    if self.verbose:
        self.write(f"ftpget: cmd USER {self.username or 'anonymous'}\n")
        if self.password:
            self.write(f"ftpget: cmd PASS {self.password}\n")

    # Change to remote directory if needed
    if self.remote_dir:
        d = client.cwd(self.remote_dir)
    else:
        d = defer.succeed(None)

    d.addCallback(lambda _: self._start_retrieval())
    return d

def _start_retrieval(self):
    """Start file retrieval"""
    if self.verbose:
        self.write("ftpget: cmd TYPE I (null)\n")
        self.write("ftpget: cmd PASV (null)\n")
        self.write(f"ftpget: cmd RETR {self.remote_file}\n")

    # Create receiver protocol
    receiver = FTPFileReceiver(self.artifactFile)

    # Retrieve file
    d = self.ftp_client.retrieveFile(self.remote_file, receiver)
    d.addCallback(lambda _: self._quit_ftp())
    return d

def _quit_ftp(self):
    """Quit FTP connection"""
    if self.verbose:
        self.write("ftpget: cmd QUIT (null)\n")

    d = self.ftp_client.quit()
    return d
```

**4. Success/Error handlers**
```python
def download_success(self, result):
    """Called when download completes successfully"""
    self.artifactFile.close()

    # Log success (existing code from lines 139-154)
    log.msg(...)
    self.protocol.logDispatch(...)

    # Update honeyfs (existing code from lines 157-163)
    self.fs.mkfile(...)

    self.exit()

def download_error(self, failure):
    """Called when download fails"""
    self.artifactFile.close()

    # Log failure (existing code from lines 126-135)
    log.msg(...)
    self.protocol.logDispatch(...)

    # Write error message
    self.write(f"ftpget: {failure.getErrorMessage()}\n")

    self.exit()
```

### Phase 2: Error Handling

**Error Cases to Handle:**
1. Connection refused (network error)
2. Authentication failure
3. File not found
4. Permission denied
5. Connection timeout
6. Transfer interrupted

**Implementation:**
```python
from twisted.protocols.ftp import CommandFailed, BadResponse

def download_error(self, failure):
    error_msg = "Connection error"

    if failure.check(CommandFailed):
        # FTP command failed (auth, file not found, etc)
        error_msg = f"FTP error: {failure.value.args[0]}"
    elif failure.check(BadResponse):
        # Server returned bad response
        error_msg = f"Server error: {failure.value.args[0]}"
    else:
        # Network/connection error
        error_msg = f"Connection failed: {failure.getErrorMessage()}"

    self.write(f"ftpget: {error_msg}\n")
    # ... rest of error handling
```

### Phase 3: Testing

**Update `test_ftpget.py`:**

1. **Add mock FTP server fixture:**
```python
from twisted.protocols.ftp import FTPFactory, FTPRealm
from twisted.cred.portal import Portal
from twisted.cred.checkers import InMemoryUsernamePasswordDatabaseDontUse

class FTPTestCase(unittest.TestCase):
    def setUp(self):
        # Create mock FTP server
        portal = Portal(FTPRealm(...))
        portal.registerChecker(InMemoryUsernamePasswordDatabaseDontUse(...))
        factory = FTPFactory(portal)
        self.ftp_server = reactor.listenTCP(0, factory)
        self.ftp_port = self.ftp_server.getHost().port
```

2. **Test cases to add:**
- `test_successful_download()` - Happy path
- `test_connection_refused()` - Network error
- `test_auth_failure()` - Bad credentials
- `test_file_not_found()` - Missing remote file
- `test_verbose_output()` - Verbose flag
- `test_custom_port()` - Non-standard port
- `test_non_blocking()` - **Verify doesn't block reactor**

3. **Non-blocking verification test:**
```python
def test_non_blocking_download(self):
    """Verify FTP download doesn't block other operations"""
    # Start FTP download
    self.proto.lineReceived(b"ftpget -v server.com remote.txt\n")

    # Immediately try another command
    self.proto.lineReceived(b"echo 'test'\n")

    # Should see echo output before FTP completes
    # (proves download is non-blocking)
    output = self.tr.value()
    self.assertIn(b"test", output)
```

## Migration Steps

1. ✅ Create new branch: `ftp-async-rewrite`
2. ✅ Research Twisted FTPClient API
3. ✅ Document current implementation
4. ✅ Create implementation plan
5. ✅ Implement FTPFileReceiver protocol
6. ✅ Refactor start() to use async pattern
7. ✅ Implement connection/auth callbacks
8. ✅ Implement retrieval callback
9. ✅ Add comprehensive error handling
10. ✅ Update test suite
11. ✅ Add non-blocking verification test
12. ✅ Run all tests (9/9 passing)
13. ⏳ Test with real FTP server
14. ⏳ Update documentation
15. ⏳ Submit PR

## Key Differences from Current Implementation

| Current (Blocking) | New (Async) |
|-------------------|-------------|
| `ftplib.FTP()` | `twisted.protocols.ftp.FTPClient` |
| Synchronous calls | Deferred chains |
| Blocks reactor | Non-blocking |
| try/except for errors | addErrback handlers |
| Direct function calls | Callback-based flow |

## Compatibility Considerations

**Maintaining Compatibility:**
- Same command-line interface
- Same output format
- Same logging events
- Same filesystem updates
- Same artifact handling

**Breaking Changes:**
- None expected (purely internal refactor)

## Risk Assessment

**Low Risk:**
- Well-defined async pattern (follows wget.py)
- Twisted FTPClient is mature/stable
- Existing test suite provides baseline

**Medium Risk:**
- Error handling edge cases
- Verbose output timing (async nature)

**Mitigation:**
- Comprehensive testing
- Gradual rollout (feature flag?)
- Monitor for regressions

## Success Criteria

1. ✅ All existing tests pass (9/9 tests passing)
2. ✅ New non-blocking test passes (test_non_blocking_behavior)
3. ✅ No blocking calls to reactor (ftplib removed, using Twisted FTPClient)
4. ✅ Same user experience (output/behavior maintained)
5. ✅ Proper error handling for all cases (CommandFailed, network errors)
6. ⏳ Code review approval
7. ⏳ Successfully tested against real FTP servers

## References

- Issue: https://github.com/cowrie/cowrie/issues/1674
- Twisted FTPClient: https://docs.twistedmatrix.com/en/stable/api/twisted.protocols.ftp.FTPClient.html
- BusyBox ftpget: https://www.busybox.net/downloads/BusyBox.html
- Similar async pattern: `src/cowrie/commands/wget.py`
