# Copyright (c) 2023, FoxIO, LLC.
# All rights reserved.
# Patent Pending
# JA4 is Open-Source, Licensed under BSD 3-Clause
# JA4+ (JA4S, JA4H, JA4L, JA4X, JA4SSH) are licenced under the FoxIO License 1.1. For full license text, see the repo root.
#
#!/usr/bin/env python3

import os, sys, json
from hashlib import sha256
import argparse
from subprocess import PIPE, Popen, call
from ja4ssh import to_ja4ssh, update_ssh_entry
from ja4x import to_ja4x
from ja4h import to_ja4h
from common import *
from datetime import datetime
import signal

def signal_handler(sig, frame):
    cache = get_cache({'hl': 'tcp'})
    print(json.dumps(cache, indent=2))

def version_check(ver):
    vers = ver.split('.')
    major = vers[0]
    minor = vers[1]
    last = vers[2] if len(vers) >= 3 else 0

    version_error = f"You are running an older version of tshark. JA4 is designed to work with tshark version 4.0.6 and above.\
    \nSome functionality may not work properly with older versions."
    if int(major) < 4: 
        print(version_error)
    else:
        if int(major) == 4 and int(minor) == 0 and int(last) < 6:
            print(version_error)


SAMPLE_COUNT = 200
raw_fingerprint = False
original_rendering = False

TCP_FLAGS = { 'SYN': 0x0002, 'ACK': 0x0010, 'FIN': 0x0001 }

keymap = {
    'frame': {
        'frno': 'number',
        'protos': 'protocols',
        'timestamp': 'time_epoch'
    },
    'ip': {
        'src': 'src',
        'dst': 'dst',
        'ttl': 'ttl'
    },
    'ipv6': {
        'src': 'src',
        'dst': 'dst',
        'ttl': 'hlim'
    },
    'tcp': {
         'flags': 'flags',
         'ack': 'ack',
         'seq': 'seq',
         'fin': 'flags_fin',
         'stream': 'stream',
         'srcport': 'srcport',
         'dstport': 'dstport',
         'len': 'len',
         'flags_ack': 'flags_ack',
    },
    'udp': {
         'stream': 'stream',
         'srcport': 'srcport',
         'dstport': 'dstport',
    },
    'quic': {
         'packet_type': 'long_packet_type',
    },
    'tls':{
        'version': 'handshake_version',
        'type': 'handshake_type',
        'extensions': 'handshake_extension_type',
        'ciphers': 'handshake_ciphersuite',
        'domain': 'handshake_extensions_server_name',
        'supported_versions': 'handshake_extensions_supported_version',
        'alpn': 'handshake_extensions_alps_alpn_str',
        'alpn_list': 'handshake_extensions_alpn_str',
        'sig_alg_lengths': 'handshake_sig_hash_alg_len',
        'signature_algorithms': 'handshake_sig_hash_alg',
    },
    'x509af': {
        'cert_extensions': 'extension_id',
        'extension_lengths': 'extensions',
        'subject_sequence': 'rdnSequence'
    },
    'http': {
        'method': 'request_method', 
        'headers': 'request_line',
        'cookies': 'cookie',
        'lang': 'accept_language',
    },
    'http2': {
        'method': 'headers_method', 
        'headers': 'header_name',
        'lang': 'headers_accept_language',
        'cookies': 'headers_set_cookie',
        'cookies': 'headers_cookie'
    },
    'ssh': {
        'ssh_protocol': 'protocol',
        'hassh': 'kex_hassh',
        'hassh_server': 'kex_hasshserver',
        'direction': 'direction',
        'algo_client': 'encryption_algorithms_client_to_server',
        'algo_server': 'encryption_algorithms_server_to_client',
    }
}

debug_fields = [ 
    'A', 
    'B', 
    'C', 
    'D', 
    'protos',
    'server_extensions', 
    'client_extensions', 
    'server_ciphers', 
    'client_ciphers',
    'printable_certs'
]
debug = False
mode = "default"
fp_out = None
jsons = []
output_types = [ 'ja4x', 'ja4h' , 'ja4', 'ja4s', 'ja4ssh', 'ja4l']

########### JA4 / JA4S FUNCTIONS #####################
def hops(x):
    x = int(x)
    initial_ttl = 54
    if x > 64 and x <= 128:
        initial_ttl = 128
    if x > 128:
        initial_ttl = 255
    return (initial_ttl - x)

def calculate_ja4_latency(x, ptype, STREAM):
    try:
        cache = get_cache(x)
        if int(x['stream']) in cache:
            conn = cache[int(x['stream'])]
            if 'B' in conn and 'A' in conn:
                diff = epoch_diff(conn['A'], conn['B'])
                ttl = conn['server_ttl']
                cache_update(x, 'JA4L-S',  f"{diff}_{ttl}", STREAM)
            if ptype == 'tcp' and 'C' in conn and 'B' in conn:
                ttl = conn['client_ttl']
                diff = epoch_diff(conn['B'], conn['C'])
                cache_update(x, 'JA4L-C',  f"{diff}_{ttl}", STREAM)
            if ptype == 'quic' and 'D' in conn and 'C' in conn:
                ttl = conn['client_ttl']
                diff = epoch_diff(conn['C'], conn['D'])
                cache_update(x, 'JA4L-C',  f"{diff}_{ttl}", STREAM)
    except Exception as e:
        #print (f'failed to calculate latency : {e}')
        pass

def to_ja4s(x, debug_stream):
    if x['stream'] == debug_stream:
        print (f"computing ja4s for stream {x['stream']}")
    ptype = 'q' if x['quic'] else 't'

    if 'extensions' not in x:
        x['extensions'] = []

    if 'ciphers' not in x:
        x['ciphers'] = []

    # get extensions in hex in the order they are present (include grease values)
    x['extensions'] = [ '{:04x}'.format(int(k)) for k in x['extensions'] ]
    ext_len = '{:02d}'.format(min(len(x['extensions']), 99))
    
    if x['extensions']:
        extensions = sha_encode(x['extensions'])
    else:
        extensions = '000000000000'

    # only one cipher for ja4s
    x['ciphers'] = x['ciphers'][2:]

    x['version'] = x['version'][0] if isinstance(x['version'], list) else x['version']
    if 'supported_versions' in x:
        x['version'] = get_supported_version(x['supported_versions'])
    version = TLS_MAPPER[x['version']] if x['version'] in TLS_MAPPER else '00'
  
    alpn = '00' 
    if 'alpn_list' in x:
        if isinstance(x['alpn_list'], list):
            alpn = x['alpn_list'][0]
        else:
            alpn = x['alpn_list']
    if len(alpn) > 2:
        alpn = f"{alpn[0]}{alpn[-1]}"
    if ord(alpn[0]) > 127:
        alpn = '99'

    x['JA4S'] = f"{ptype}{version}{ext_len}{alpn}_{x['ciphers']}_{extensions}"
    x['JA4S_r'] = f"{ptype}{version}{ext_len}{alpn}_{x['ciphers']}_{','.join(x['extensions'])}"

    cache_update(x, 'JA4S', x['JA4S'], debug_stream)
    cache_update(x, 'JA4S_r', x['JA4S_r'], debug_stream)
    cache_update(x, 'server_extensions', x['extensions'], debug_stream)
    cache_update(x, 'server_ciphers', x['ciphers'], debug_stream)

def to_ja4(x, debug_stream):
    if x['stream'] == debug_stream:
        print (f"computing ja4 for stream {x['stream']}")
    ptype = 'q' if x['quic'] else 't'

    if 'extensions' not in x:
        x['extensions'] = []

    if 'ciphers' not in x:
        x['ciphers'] = []

    x['extensions'] = [ '0x{:04x}'.format(int(k)) for k in x['extensions'] ]
    ext_len = '{:02d}'.format(min(len([ x for x in x['extensions'] if x not in GREASE_TABLE]), 99))
    cache_update(x, 'client_ciphers', x['ciphers'], debug_stream)

    if ('0x000d' in x['extensions']):
        x['signature_algorithms'] = [ y[2:] for y in get_signature_algorithms(x) ]
    else:
        x['signature_algorithms'] = ''

    cache_update(x, 'client_extensions', x['extensions'], debug_stream)

    x['sorted_extensions'], _len, _ = get_hex_sorted(x, 'extensions')
    x['original_extensions'], _len, _ = get_hex_sorted(x, 'extensions', sort=False)
    if (x['signature_algorithms'] == ''):
        x['sorted_extensions'] = x['sorted_extensions']
        x['original_extensions'] = x['original_extensions']
    else:
        x['sorted_extensions'] = x['sorted_extensions'] + '_' + ','.join(x['signature_algorithms'])
        x['original_extensions'] = x['original_extensions'] + '_' + ','.join(x['signature_algorithms'])

    if x['extensions']:
        sorted_extensions = sha_encode(x['sorted_extensions'])
        original_extensions = sha_encode(x['original_extensions'])
    else:
        sorted_extensions = '000000000000'
        original_extensions = '000000000000'
    
    x['sorted_ciphers'], cipher_len, sorted_ciphers = get_hex_sorted(x, 'ciphers')
    x['original_ciphers'], cipher_len, original_ciphers = get_hex_sorted(x, 'ciphers', sort=False)

    if not x['ciphers']:
        sorted_ciphers = '000000000000'
        original_ciphers = '000000000000'
        cipher_len = '00'

    sni = 'd' if 'domain' in x else 'i'
    x['version'] = x['version'][0] if isinstance(x['version'], list) else x['version']
    if 'supported_versions' in x:
        x['version'] = get_supported_version(x['supported_versions'])
    version = TLS_MAPPER[x['version']] if x['version'] in TLS_MAPPER else '00'

    alpn = '00' 
    if 'alpn_list' in x:
        if isinstance(x['alpn_list'], list):
            alpn = x['alpn_list'][0]
        else:
            alpn = x['alpn_list']

    if len(alpn) > 2:
        alpn = f"{alpn[0]}{alpn[-1]}"

    if ord(alpn[0]) > 127:
        alpn = '99'

    entry = get_cache(x)[x['stream']]
    if not entry.get('count'):
        idx = 0
    else:
        idx = entry['count']
    idx += 1
    cache_update(x, 'count', idx, debug_stream)

    x[f'JA4.{idx}'] = f"{ptype}{version}{sni}{cipher_len}{ext_len}{alpn}_{sorted_ciphers}_{sorted_extensions}"
    x[f'JA4_o.{idx}'] = f"{ptype}{version}{sni}{cipher_len}{ext_len}{alpn}_{original_ciphers}_{original_extensions}"
    x[f'JA4_r.{idx}'] = f"{ptype}{version}{sni}{cipher_len}{ext_len}{alpn}_{x['sorted_ciphers']}_{x['sorted_extensions']}"
    x[f'JA4_ro.{idx}'] = f"{ptype}{version}{sni}{cipher_len}{ext_len}{alpn}_{x['original_ciphers']}_{x['original_extensions']}"
    [ cache_update(x, key, x[key], debug_stream) for key in [ 'domain', f'JA4.{idx}', f'JA4_r.{idx}', f'JA4_o.{idx}', f'JA4_ro.{idx}'] if key in x ]

############ END OF JA4 and JA4S FUNCTIONS #####################


# New display function
def display(x):
    global output_types

    cache = get_cache({"hl": "tcp"})
    if x['quic']:
        cache = get_cache({"hl": "quic"})
    elif 'http' in x['protos'] and 'ocsp' not in x['protos']:
        cache = get_cache({"hl": "http"})
   
    printout (cache[int(x['stream'])], 'ALL')
    clean_cache(x)
    

# Write output to file or console based on fp_out
def printout (x, ja_type):
    global raw_fingerprint, original_rendering, output_types

    if not x:
        return

    final = dict(x)
    delete_keys(['count', 'stats'], final)

    if not raw_fingerprint:
        delete_keys(['JA4_r', 'JA4_ro', 'JA4S_r', 'JA4H_r', 'JA4H_ro'], final)

    if original_rendering:
        delete_keys(['JA4'], final)
        if raw_fingerprint:
            delete_keys(['JA4_r', 'JA4H_r'], final)
    else:
        delete_keys(['JA4_o'], final)
        if raw_fingerprint:
            delete_keys(['JA4_ro', 'JA4H_ro'], final)

    if 'ja4' not in output_types:
        delete_keys(['JA4', 'JA4_o', 'JA4_r', 'JA4_ro'], final)
    if 'ja4s' not in output_types:
        delete_keys(['JA4S', 'JA4S_r'], final)
    if 'ja4l' not in output_types:
        delete_keys(['JA4L-S', 'JA4L-C'], final)
    if 'ja4h' not in output_types:
        delete_keys(['JA4H', 'JA4H_r', 'JA4H_ro'], final)
    if 'ja4x' not in output_types:
        ja4x_keys = [ k for k in x if k.startswith('JA4X') ]
        delete_keys(ja4x_keys, final)

    if 'ja4x' in output_types: #ja_type == 'JA4X':
        # JA4X works on the packet rather than a cache entry
        unwanted = [ 'hl', 'frno', 'protos', 'ack', 'seq', 'flags', 'flags_ack', 'quic', 'len', 'timestamp', 'ttl' ]
        delete_keys(unwanted, final)
        if not debug:
            delete_keys(['cert_extensions', 'extension_lengths', 'issuers', 'subjects', 'rdn_oids', 'issuer_sequence', 'subject_sequence', 'issuer_hashes', 'subject_hashes'], final)

    if 'ja4ssh' in output_types: 
        delete_keys([ 'timestamp' ], final)

    if 'JA4' not in str(final.keys()):
        return

    if not debug:
        delete_keys(debug_fields, final)

    if fp_out:
        fp_out.write(f'{final}\n') if mode == 'default' else jsons.append(final)
    else:
        print(final) if mode == 'default' else print(json.dumps(final, indent=4))

# If the SSH connection is not terminated or the last sample is less than 200
# the finalize function just cleans up and prints the last JA4SSH hash
def finalize_ja4ssh(stream=None):
    cache = get_cache({"hl": "tcp"})
    if stream:
        entry = cache[stream]
        if entry['protos'].endswith(":ssh"):
            to_ja4ssh(entry)
            printout(entry, 'JA4SSH')
            del(cache[stream])

    if stream is None:
        for stream_id, entry in cache.items():
            if entry['protos'].endswith(":ssh"):
                to_ja4ssh(entry)
                printout(entry, 'JA4SSH')

def finalize_ja4():
    cache = get_cache({"hl": "quic"})
    for stream, entry in cache.items():
        printout(entry, 'JA4CS')

    cache = get_cache({"hl": "tcp"})
    for stream, entry in cache.items():
        printout(entry, 'JA4CS')

# Layer update is a common function to update different layer
# parameters into the packet.
def layer_update(x, pkt, layer):
    l = None
    x['hl'] = layer

    if layer == 'quic':
        quic = pkt['layers'].pop('quic', None) 
        if quic:
            if isinstance(quic, list):
                quic = quic[0]
            [ x.update({key: quic[f'{layer}_{layer}_{item}']}) for key, item in keymap[layer].items() if f'{layer}_{layer}_{item}' in quic ]
            l = quic['tls'] if 'tls' in quic.keys() else None
            layer = 'tls'
    else:
        l = pkt['layers'].pop(layer, None) if layer != 'x509af' else pkt['layers'].pop('tls', None)

    if layer == 'tls':
        l = scan_tls(l)
    else:
        l = l[0] if isinstance(l, list) else l


    if l:
        [ x.update({key: l[f'{layer}_{layer}_{item}']}) for key, item in keymap[layer].items() if f'{layer}_{layer}_{item}' in l ]

    if layer == 'x509af' and l:
        [ x.update({key: l[f'tls_tls_{item}']}) for key, item in keymap['tls'].items() if f'tls_tls_{item}' in l ]
        x.update({'issuer_sequence': l['x509if_x509if_rdnSequence']}) if 'x509if_x509if_rdnSequence' in l else None
        if 'x509if_x509if_id' in l:
            x.update({'rdn_oids':l['x509if_x509if_id']})
        if 'x509if_x509if_oid' in l:
            x.update({'rdn_oids':l['x509if_x509if_oid']})
        x.update({'printable_certs': l['x509sat_x509sat_printableString']}) if 'x509sat_x509sat_printableString' in l else None

    # Some extension types are a list bug #29
    if 'type' in x and isinstance(x['type'], list):
        x['type'] = x['type'][0]

def main():

    global STREAM
    global jsons, fp_out, debug, mode, output_types
    global raw_fingerprint, original_rendering

    ssh_sample_count = 200

    desc = "A python script for extracting JA4 fingerprints from PCAP files"
    parser = argparse.ArgumentParser(description=(desc))
    parser.add_argument("pcap", help="The pcap file to process")
    parser.add_argument("-key", required=False, help="The key file to use for decryption")

    parser.add_argument("-v", "--verbose", required=False, action="store_true", default=False, help="verbose mode")
    parser.add_argument("-J", "--json", required=False, action="store_true", default=False, help="output in JSON")
    parser.add_argument("--ja4", action="store_true", default=False, help="Output JA4 fingerprints only")
    parser.add_argument("--ja4s", action="store_true", default=False, help="Output JA4S fingerprints only")
    parser.add_argument("--ja4l", action="store_true", default=False, help="Output JA4L-C/S fingerprints only")
    parser.add_argument("--ja4h", action="store_true", default=False, help="Output JA4H fingerprints only")
    parser.add_argument("--ja4x", action="store_true", default=False, help="Output JA4X fingerprints only")
    parser.add_argument("--ja4ssh", action="store_true", default=False, help="Output JA4SSH fingerprints only")
    parser.add_argument("-r", "--raw_fingerprint", required=False, action="store_true", help="Output raw fingerprint")
    parser.add_argument("-o", "--original_rendering", required=False, action="store_true", help="Output original rendering")
    parser.add_argument("-f", "--output", nargs='?', const='ja4.output', help="Send output to file <filename>")
    parser.add_argument("-s", "--stream", nargs='?', const='0', help="Inspect a specific stream <stream>")

    try:
        args = parser.parse_args()
    except Exception as e:
        print (parser.print_help())

    if args.ja4x or args.ja4h or args.ja4 or args.ja4s or args.ja4ssh or args.ja4l:
        output_types = []
    output_types.append('ja4x') if args.ja4x else None
    output_types.append('ja4') if args.ja4 else None
    output_types.append('ja4s') if args.ja4s else None
    output_types.append('ja4h') if args.ja4h else None
    output_types.append('ja4ssh') if args.ja4ssh else None
    output_types.append('ja4l') if args.ja4l else None
    debug = True if args.verbose else False
    mode = "json" if args.json else "default"

    if args.raw_fingerprint:
        raw_fingerprint = True

    if args.original_rendering:
        original_rendering = True

    signal.signal(signal.SIGINT, signal_handler)

    # Outfile file
    outfile = f'{args.pcap}-output.json' if args.output == 'OUTFILE' else args.output
    if outfile:
        fp_out = open(outfile, 'w')

    STREAM = -1
    if args.stream:
        STREAM = int(args.stream)

    # Quick version check
    ver = Popen(["tshark", "-v"], stdout=PIPE, encoding='utf-8')
    version = ver.stdout.readline().split(' ')[2]
    version_check(version)

    if args.key:
        ps = Popen(["tshark", "-r", args.pcap, "-o",  f"tls.keylog_file:{os.path.abspath(args.key)}", "-T", "ek", "-n"], stdout=PIPE, encoding='utf-8')
    else:
        if args.pcap.endswith('.ek'):
            ps = Popen(["cat", args.pcap], stdout=PIPE, encoding='utf-8')
        else:
            ps = Popen(["tshark", "-r", args.pcap, "-T", "ek", "-n"], stdout=PIPE, encoding='utf-8')

    for idx, line in enumerate(iter(ps.stdout.readline, '')): # enumerate(sys.stdin):
        if "layers" in line:
            pkt = json.loads(line)
            layers = pkt['layers'] 

            x = {}
            layer_update(x, pkt, 'frame')
            layer_update(x, pkt, 'ip') if 'ipv6' not in x['protos'] else layer_update(x, pkt, 'ipv6')

            if 'tcp' in x['protos']:
                layer_update(x, pkt, 'tcp') 
                if 'ocsp' in x['protos'] or 'x509ce' in x['protos']:
                    layer_update(x, pkt, 'x509af') 
                elif 'http' in x['protos']:
                    if 'http2' in x['protos']:
                        layer_update(x, pkt, 'http2') 
                    else:
                        layer_update(x, pkt, 'http') 
                elif 'tls' in x['protos']:
                    layer_update(x, pkt, 'tls') 
                elif 'ssh' in x['protos']:
                    layer_update(x, pkt, 'ssh')
                x['quic'] = False


            elif 'udp' in x['protos'] and 'quic' in x['protos']: 
                layer_update(x, pkt, 'udp')
                layer_update(x, pkt, 'quic')
                x['quic'] = True

            else:
                continue

            if 'stream' not in x:
                continue

            # We update the stream value into the cache first
            # to start recording this entry and then the tuple as well
            #print (idx, x['stream'], x['protos'])
            x['stream'] = int(x['stream'])

            [ cache_update(x, key, x[key], STREAM) for key in [ 'stream', 'src', 'dst', 'srcport', 'dstport', 'protos' ] ] #if x['srcport'] != '443' else None

            # Added for SSH
            if 'tcp' in x['protos'] and 'ja4ssh' in output_types:
                if (int(x['srcport']) == 22) or (int(x['dstport']) == 22):
                    cache_update(x, 'count', 0, STREAM)
                    cache_update(x, 'stats', [], STREAM)
                    entry = get_cache(x)[x['stream']]
                    update_ssh_entry(entry, x, ssh_sample_count, STREAM)
                    if 'flags' in x and int(x['flags'], 0) & TCP_FLAGS['FIN'] and int(x['flags'], 0) & TCP_FLAGS['ACK']:
                        finalize_ja4ssh(x['stream']) 

            # Timestamp recording happens on cache here
            # This is for TCP
            if 'tcp' in x['protos']: # and 'tls' not in x['protos']:
                if 'flags' in x:
                    flags = int(x['flags'], 0)
                    if (flags & TCP_FLAGS['SYN']) and not (flags & TCP_FLAGS['ACK']):
                        cache_update(x, 'A', x['timestamp'], STREAM)
                        cache_update(x, 'timestamp', x['timestamp'], STREAM)
                        cache_update(x, 'client_ttl', x['ttl'], STREAM) if 'ttl' in x else None
                    if (flags & TCP_FLAGS['SYN']) and (flags & TCP_FLAGS['ACK']):
                        cache_update(x, 'B', x['timestamp'], STREAM)
                        cache_update(x, 'server_ttl', x['ttl'], STREAM) if 'ttl' in x else None
                    if (flags & TCP_FLAGS['ACK']) and not (flags & TCP_FLAGS['SYN']) and 'ack' in x and x['ack'] == '1' and 'seq' in x and x['seq'] == '1':
                        cache_update(x, 'C', x['timestamp'], STREAM)
                        calculate_ja4_latency(x, 'tcp', STREAM)

            # Timestamp recording for QUIC, printing of QUIC JA4 and JA4S happens
            # after we see the final D packet.
            if 'packet_type' in x:
                if x['packet_type'] == '0' and 'type' in x and x['type'] == '1':
                    cache_update(x, 'A', x['timestamp'], STREAM) 
                    cache_update(x, 'client_ttl', x['ttl'], STREAM)
                if x['packet_type'] == '0' and 'type' in x and x['type'] == '2':
                    cache_update(x, 'B', x['timestamp'], STREAM) 
                    cache_update(x, 'server_ttl', x['ttl'], STREAM)
                if x['packet_type'] == '2' and x['srcport'] == '443':
                    cache_update(x, 'C', x['timestamp'], STREAM) 
                if x['packet_type'] == '2' and x['dstport'] == '443':
                    if (cache_update(x, 'D', x['timestamp'], STREAM)):
                        calculate_ja4_latency(x, 'quic', STREAM) 
                        display(x)

            # Hash calculations. 
            if x['hl'] == 'tls' and x.get('type') == '2':
                to_ja4s(x, STREAM)

            if x['hl'] == 'x509af':
                to_ja4x(x, STREAM) 
                display(x)

            if x['hl'] in ['http', 'http2']:
                if 'headers' in x and 'method' in x:
                    to_ja4h(x, STREAM)
                    display(x)

            if x['hl'] == 'tls' and x.get('type') == '1':
                try:
                    to_ja4(x, STREAM)
                except Exception as e:
                    print (e)
                    pass

    #finalize_ja4ssh() if 'ja4ssh' in output_types else None
    finalize_ja4() if ('ja4' in output_types or 'ja4s' in output_types) else None

    if fp_out and mode == 'json':
        json.dump(jsons, fp_out, indent=4)

if __name__ == '__main__':
    main()

    
