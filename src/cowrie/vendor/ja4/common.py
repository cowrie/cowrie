# Copyright (c) 2023, FoxIO, LLC.
# All rights reserved.
# Patent Pending
# JA4 is Open-Source, Licensed under BSD 3-Clause
# JA4+ (JA4S, JA4H, JA4L, JA4X, JA4SSH) are licenced under the FoxIO License 1.1. For full license text, see the repo root.
#

from hashlib import sha256
from datetime import datetime

conn_cache = {}
quic_cache = {}
http_cache = {}
ssh_cache = {}

TLS_MAPPER = {'0x0002': "s2",
              '0x0300': "s3",
              '0x0301': "10",
              '0x0302': "11",
              '0x0303': "12",
              '0x0304': "13"}

GREASE_TABLE = {'0x0a0a': True, '0x1a1a': True, '0x2a2a': True, '0x3a3a': True,
                '0x4a4a': True, '0x5a5a': True, '0x6a6a': True, '0x7a7a': True,
                '0x8a8a': True, '0x9a9a': True, '0xaaaa': True, '0xbaba': True,
                '0xcaca': True, '0xdada': True, '0xeaea': True, '0xfafa': True}

def delete_keys(keys, x):
    for key in keys:
        if key in x:
            del(x[key])


######## SIMPLE CACHE FUNCTIONS #############################
# The idea is to record quic packets into a quic_cache
# and record tcp tls packets into a conn_cache
# The cache is indexed by the stream number and hold all the
# required data including timestamps
# we print final results from the cache

def get_cache(x):
    if x['hl'] in [ 'http', 'http2']:
        return http_cache
    elif x['hl'] == 'quic':
        return quic_cache
    else:
        return conn_cache

def clean_cache(x):
    cache = get_cache(x)
    if x['stream'] in cache:
        del(cache[x['stream']])

# Updates the cache and records timestamps
def cache_update(x, field, value, debug_stream=-1):
    cache = get_cache(x)
    stream = int(x['stream'])
    update = False

    if field == 'stream' and stream not in cache:
        cache[stream] = { 'stream': stream}
        return

    # Do not update main tuple fields if they are already in
    if field in [ 'stream', 'src', 'dst', 'srcport', 'dstport', 'A', 'B', 'JA4S', 'D', 'server_extensions', 'count', 'stats'] and field in cache[stream]:
        return

    # update protos only if we have extra information
    if field == 'protos':
        if field in cache[stream] and len(value) <= len(cache[stream][field]):
            return

    # special requirement for ja4c when the C timestamp needs to be the
    # the last before D
    if field == 'C' and 'D' in cache[stream]:
        return

    if stream in cache:
        if stream == debug_stream:
            print (f'updating ({"quic" if x["quic"] else "tcp"}) stream {stream} {field} {value}')
        cache[stream][field] = value
        update = True
    return update

###### END OF CACHE FUNCTIONS

# Joins an array by commas in the order they are presented
# and returns the first 12 chars of the sha256 hash
def sha_encode(values):
    if isinstance(values, list):
        return sha256(','.join(values).encode('utf8')).hexdigest()[:12]
    else:
        return sha256(values.encode('utf8')).hexdigest()[:12]

# processes ciphers found in a packet
# tshark keeps the ciphers either as a list or as a single value
# based on whether it is ciphersuites or ciphersuite
def get_hex_sorted(entry, field, sort=True):
    values = entry[field]
    if not isinstance(values, list):
        values = [ values ]

    # remove GREASE and calculate length
    c = [ x[2:] for x in values if x not in GREASE_TABLE ]
    actual_length = min(len(c), 99)

    # now remove SNI and ALPN values
    if field == 'extensions' and sort:
        c = [ x for x in c if x not in ['0000', '0010']]

    c.sort() if sort else None

    return ','.join(c), '{:02d}'.format(actual_length), sha_encode(c)

def get_supported_version(v):
    if not isinstance(v, list):
        v = [ v ]
    versions = [ k for k in v if k not in GREASE_TABLE ]
    versions.sort()
    return versions[-1]


## Time diff of epoch times / 2
## computes t2 - t1
## returns diff in seconds
def epoch_diff(t1, t2):
    dt1 = datetime.fromtimestamp(float(t1))
    dt2 = datetime.fromtimestamp(float(t2))
    return int((dt2-dt1).microseconds/2)
    

# Scan for tls
def scan_tls(layer):
    if not layer:
        return None

    if not isinstance(layer, list):
        if 'tls_tls_handshake_type' in layer:
            return layer
    else:
        for l in layer:
            if 'tls_tls_handshake_type' in l:
                return l

# Get the right signature algorithms
def get_signature_algorithms(packet): 
    if 'sig_alg_lengths' in packet and isinstance(packet['sig_alg_lengths'], list):
        alg_lengths = [ int(int(x)/2) for x in packet['sig_alg_lengths'] ]

        extensions = packet['extensions']
        idx = 0
        try:
            if extensions.index('13') > extensions.index('35'):
                idx = 1 
        except Exception as e:
            pass
        packet['signature_algorithms'] = packet['signature_algorithms'][alg_lengths[idx]:]
    return [ x for x in packet['signature_algorithms'] if x not in GREASE_TABLE ]
        
