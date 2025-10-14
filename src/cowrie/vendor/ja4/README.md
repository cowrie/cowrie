# JA4+ (Python Implementation) <!-- omit from toc -->

This Python tool implements JA4+, a fingerprinting methodology for network traffic analysis. It processes PCAP files and extracts JA4+ fingerprints for multiple protocols, including TLS, HTTP, SSH, TCP, and X.509 certificates. The output is structured in JSON format, providing detailed metadata such as IP addresses, ports, domains, and fingerprintable handshake characteristics. This tool is designed for security research, threat detection, and network traffic investigation.

For more details on JA4+ and its implementations in other open-source tools (Rust, Wireshark, and Zeek), see the [main JA4+ README](../README.md).

## Table of Contents <!-- omit from toc -->

- [Dependencies](#dependencies)
  - [Installing tshark](#installing-tshark)
    - [Linux](#linux)
    - [macOS](#macos)
    - [Windows](#windows)
  - [Installing Python](#installing-python)
    - [Linux](#linux-1)
    - [macOS](#macos-1)
    - [Windows](#windows-1)
- [Release Assets](#release-assets)
- [Running JA4+](#running-ja4)
  - [Usage](#usage)
    - [Command-line Arguments](#command-line-arguments)
  - [Examples](#examples)
    - [Running `ja4.py`](#running-ja4py)
    - [Example output](#example-output)
    - [JSON Output Format](#json-output-format)
  - [Using a Key File for TLS Decryption](#using-a-key-file-for-tls-decryption)
- [Testing](#testing)
- [Creating a Release](#creating-a-release)
- [License](#license)

## Dependencies

To run JA4+, `tshark` and Python 3 are required. For full functionality, `tshark` version 4.0.6 or later is recommended.

### Installing tshark

#### Linux

Install it using your package manager (the package name is either `tshark` or `wireshark-cli`, depending on the distribution). For example, on Ubuntu:

```sh
sudo apt install tshark
```

#### macOS

1. [Download](https://www.wireshark.org/download.html) and install Wireshark (includes `tshark`).
2. Add `tshark` to your `PATH`:
   ```sh
   sudo ln -s /Applications/Wireshark.app/Contents/MacOS/tshark /usr/local/bin/tshark
   ```

#### Windows

1. [Download](https://www.wireshark.org/download.html) and install Wireshark (includes `tshark.exe`).
2. Locate `tshark.exe` (usually in `C:\Program Files\Wireshark\tshark.exe`).
3. Add the folder containing `tshark.exe` to your system `PATH`:
   - Open **System Properties** > **Environment Variables** > **Edit Path**.

### Installing Python

#### Linux

Install Python 3 using your package manager. For example, on Ubuntu:

```sh
sudo apt install python3
```

#### macOS

[Download](https://www.python.org/downloads/macos/) and install Python 3 using the universal installer.

#### Windows

[Download](https://www.python.org/downloads/windows/) and install Python 3 using the Windows installer.

## Release Assets

Release assets for the Python implementation are named as follows:

- `ja4-python-vX.Y.Z.tar.gz`

This archive contains the full `python/` directory and is attached to a release named like `python-vX.Y.Z`.

## Running JA4+

Once `tshark` and Python 3 are installed, you can run `ja4.py` as follows:

- On Linux and macOS:
  ```sh
  python3 ja4.py [pcap] [options]
  ```
- On Windows, open **Command Prompt** and run:
  ```cmd
  python ja4.py [pcap] [options]
  ```

### Usage

#### Command-line Arguments

```txt
positional arguments:
  pcap                      The pcap file to process

optional arguments:
  -h, --help                Show this help message and exit
  -key KEY                  The key file to use for decryption
  -v, --verbose             Verbose mode
  -J, --json                Output in JSON format
  --ja4                     Output JA4 fingerprints only
  --ja4s                    Output JA4S fingerprints only
  --ja4l                    Output JA4L-C/S fingerprints only
  --ja4h                    Output JA4H fingerprints only
  --ja4x                    Output JA4X fingerprints only
  --ja4ssh                  Output JA4SSH fingerprints only
  -r, --raw_fingerprint     Output raw fingerprint
  -o, --original_rendering  Output original rendering
  -f, --output [FILE]       Send output to file
  -s, --stream [STREAM]     Inspect a specific stream
```

### Examples

#### Running `ja4.py`

```sh
# Default output:
python3 ja4.py capturefile.pcapng 

# JSON output:
python3 ja4.py capturefile.pcapng -J

# Verbose mode (dumping headers, cookies, ciphers, etc.):
python3 ja4.py capturefile.pcapng -Jv

# Inspect a particular stream:
python3 ja4.py capturefile.pcapng -Jv -s 17

# Filter by fingerprint type (e.g., JA4H only):
python3 ja4.py capturefile.pcapng -J --ja4h

# Use a key file for TLS decryption:
python3 ja4.py capturefile.pcapng -Jv -key sslkeylog.log
```

#### Example output

Running `python3 ja4.py capturefile.pcapng` might produce output like this:

```txt
{'stream': 0, 'src': '192.168.1.168', 'dst': '142.251.16.94', 'srcport': '50112', 'dstport': '443', 'domain': 'clientservices.googleapis.com', 'JA4.1': 't13d1516h2_8daaf6152771_e5627efa2ab1', 'JA4_r.1': 't13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601', 'JA4_o.1': 't13d1516h2_acb858a92679_8fc3c02244b2', 'JA4_ro.1': 't13d1516h2_1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035_ff01,0033,002d,0005,4469,000d,0010,0023,001b,002b,0000,0012,000a,0017,000b,0015_0403,0804,0401,0503,0805,0501,0806,0601'}
{'stream': 1, 'src': '192.168.1.168', 'dst': '142.251.163.147', 'srcport': '50113', 'dstport': '443', 'domain': 'www.google.com', 'JA4.1': 't13d1516h2_8daaf6152771_e5627efa2ab1', 'JA4_r.1': 't13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601', 'JA4_o.1': 't13d1516h2_acb858a92679_2331e95fde68', 'JA4_ro.1': 't13d1516h2_1301,1302,1303,c02b,c02f,c02c,c030,cca9,cca8,c013,c014,009c,009d,002f,0035_001b,0017,ff01,0010,000d,002b,0005,0023,0033,0000,0012,000b,000a,4469,002d,0015_0403,0804,0401,0503,0805,0501,0806,0601'}
```

#### JSON Output Format

To output results in JSON format, use `-J`:

```sh
python3 ja4.py <pcap-filename> -J
```

Example JSON output:

```json
{
    "stream": 2,
    "src": "192.168.1.168",
    "dst": "142.251.163.95",
    "srcport": "50053",
    "dstport": "443",
    "client_ttl": "128",
    "domain": "optimizationguide-pa.googleapis.com",
    "JA4": "q13d0310h3_55b375c5d22e_cd85d2d88918",
    "server_ttl": "60",
    "JA4S": "q130200_1301_234ea6891581",
    "JA4L-S": "2380_60",
    "JA4L-C": "46_128"
}
{
    "stream": 3,
    "src": "192.168.1.168",
    "dst": "20.112.52.29",
    "srcport": "50154",
    "dstport": "80",
    "JA4H": "ge11nn07enus_bc8d2ed93139_000000000000_000000000000"
}
{
    "stream": 4,
    "src": "192.168.1.169",
    "dst": "44.212.59.210",
    "srcport": "64339",
    "dstport": "22",
    "client_ttl": "128",
    "server_ttl": "115",
    "JA4L-S": "2925_115",
    "JA4L-C": "20_128",
    "ssh_extras": {
        "hassh": "ec7378c1a92f5a8dde7e8b7a1ddf33d1",
        "hassh_server": "2307c390c7c9aba5b4c9519e72347f34",
        "ssh_protocol_client": "SSH-2.0-OpenSSH_for_Windows_8.1",
        "ssh_protocol_server": "SSH-2.0-OpenSSH_8.7",
        "encryption_algorithm": "aes256-gcm@openssh.com"
    },
    "JA4SSH.1": "c36s36_c38s93_c60s8",
    "JA4SSH.2": "c36s36_c40s95_c62s3",
    "JA4SSH.3": "c36s36_c51s80_c68s1",
    "JA4SSH.4": "c36s36_c12s12_c11s1"
}
```

### Using a Key File for TLS Decryption

The `-key` option lets `ja4.py` decrypt TLS traffic using a **key log file**, which contains session keys needed for decryption.

Key log files can be generated by **browsers** (e.g., Firefox, Chrome) or **servers** running OpenSSL-based software. The file must be captured during traffic recording for decryption to work.

Run `ja4.py` with a key file:

```sh
ja4.py capturefile.pcapng -key sslkeylog.log
```

For details on generating an SSL key log file, see:  
[Wireshark Wiki: Using the (Pre)-Master-Secret Log File](https://wiki.wireshark.org/TLS#using-the-pre-master-secret)

**Note:** Works for TLS 1.3 only with session keys; PFS may prevent decryption.

## Testing

Sample PCAP files for testing `ja4.py` are available in the [`pcap`](../pcap/) directory. These files cover various network protocols and scenarios, including TLS, QUIC, HTTP, SSH, and edge cases. They can be used to verify expected output and assess fingerprinting accuracy.

## Creating a Release

To create a Python release, push a tag starting with `python-`, for example:

```sh
git tag python-v0.1.0
git push origin python-v0.1.0
```

## License

See the [Licensing](../README.md#licensing) section in the repo root. We are committed to work with vendors and open source projects to help implement JA4+ into those tools. Please contact john@foxio.io with any questions.

Copyright (c) 2024, FoxIO
