# Copyright (c) 2023, FoxIO, LLC.
# All rights reserved.
# Patent Pending
# JA4SSH is licenced under the FoxIO License 1.1. For full license text, see the repo root.

ja4sh_stats = {
    'client_payloads': [],
    'server_payloads': [],
    'client_packets': 0,
    'server_packets': 0,
    'client_acks': 0,
    'server_acks': 0
}

def tuple_string (x):
    return f"{x['stream']}: [{x['src']}:{x['srcport']} - {x['dst']}:{x['dstport']}]"

## JA4SSH Processing

def process_extra_parameters(entry, x, direction):
    if 'ssh_extras' not in entry:
        entry['ssh_extras'] = {
		'hassh': '',
                'hassh_server': '',
                'ssh_protocol_client': '',
                'ssh_protocol_server': '',
                'encryption_algorithm': '',
	}
    extras = entry['ssh_extras']
    if 'ssh_protocol' in x:
        extras[f'ssh_protocol_{direction}'] = x['ssh_protocol']
    if 'hassh' in x:
        extras['hassh'] = x['hassh']
    if 'hassh_server' in x:
        extras['hassh_server'] = x['hassh_server']
    if 'algo_client' in x:
        extras['encryption_algorithm'] = x['algo_client'].split(',')[0]
    if 'algo_server' in x:
        extras['encryption_algorithm'] = x['algo_server'].split(',')[0]

## Updates a SSH cache entry
## we return 1 whenever a new stats entry is added based on the sample rate
## This way the caller can print this packet out
def update_ssh_entry(entry, x, ssh_sample_count, debug_stream=None):
    
    if entry['count'] == 0 and len(entry['stats']) == 0:
        entry['stats'].append(dict(ja4sh_stats))

    # Only count SSH PSHACK packets
    if 'ssh' in x['protos']:
        entry['count'] += 1

    e = entry['stats'][-1]
    direction = 'client' if entry['src'] == x['src'] else 'server'

    if 'ssh' in x['protos']:
        e[f'{direction}_payloads'].append(x['len'])
        e[f'{direction}_packets'] += 1

    # Update ACK count based on direction and Bare Acks
    if 'ssh' not in x['protos'] and x['flags'] == '0x0010':
        e[f'{direction}_acks'] += 1

    # Added extra output parameters
    if 'ssh' in x['protos']:
        process_extra_parameters(entry, x, direction)

    if x['stream'] == debug_stream:
        print (f"stats[{len(entry['stats'])}]:tcp flag = {x['flags']}, c{e['client_packets']}s{e['server_packets']}_c{e['client_acks']}s{e['server_acks']}")

    if (entry['count'] % ssh_sample_count) == 0:
        to_ja4ssh(entry) if entry['count'] != 0 else None
        if (entry['count'] / ssh_sample_count) == len(entry['stats']):
            entry['stats'].append(dict(ja4sh_stats))

        if debug_stream and int(x['stream']) == debug_stream:
            if entry['count'] != 0:
                idx = len(entry['stats']) - 1
                try:
                    computed = entry[f'JA4SSH.{idx}']
                    print (f'computed JA4SSH.{idx}: {computed}')
                except Exception as e:
                    pass

# computes the JA4SSH from the segment x:
# The segment has data as specified by ja4sh_stats
##
def to_ja4ssh(x):
    idx = len(x['stats'])
    e = x['stats'][idx-1]
    if e['client_payloads'] or e['server_payloads']:
        mode_client = max(e['client_payloads'], key=e['client_payloads'].count) if e['client_payloads'] else 0
        mode_server = max(e['server_payloads'], key=e['server_payloads'].count) if e['server_payloads'] else 0
        client_packets = e['client_packets']
        server_packets = e['server_packets']
        client_acks = e['client_acks']
        server_acks = e['server_acks']
        hash_value = f'c{mode_client}s{mode_server}_c{client_packets}s{server_packets}_c{client_acks}s{server_acks}'
        x[f'JA4SSH.{idx}'] = hash_value
        
