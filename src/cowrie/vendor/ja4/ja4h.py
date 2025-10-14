# Copyright (c) 2023, FoxIO, LLC.
# All rights reserved.
# Patent Pending
# JA4H is licenced under the FoxIO License 1.1. For full license text, see the repo root.

from common import sha_encode, cache_update

######### HTTP FUNCTIONS ##############################
def http_method(method):
    return method.lower()[:2]

def http_language(lang):
    lang = lang.replace('-','').replace(';',',').lower().split(',')[0]
    lang = lang[:4]
    return f"{lang}{'0'*(4-len(lang))}"

def to_ja4h(x, debug_stream=-1):
    cookie = 'c' if 'cookies' in x else 'n'
    header_fields = [y.lower().split(':')[0] for y in  x['headers'] ]
    referer = 'r' if 'referer' in str(header_fields) else 'n'

    method = http_method(x['method'])
    version = 11 if x['hl'] == 'http' else 20
    unsorted_cookie_fields = []
    unsorted_cookie_values = []

    x['headers'] = [ h.split(':')[0] for h in x['headers'] ]
    x['headers'] = [ h for h in x['headers']
            if not h.startswith(':') and not h.lower().startswith('cookie')
            and h.lower() != 'referer' and h ]

    raw_headers = x['headers'][:]

    #x['headers'] = [ '-'.join([ y.capitalize() for y in h.split('-')]) for h in x['headers'] ]
    header_len = '{:02d}'.format(min(len(x['headers']), 99))

    if 'cookies' in x:
        if isinstance(x['cookies'], list):
            x['cookie_fields'] = [ y.split('=')[0].lstrip().rstrip() for y in x['cookies'] ]
            x['cookie_values'] = [ y.lstrip().rstrip() for y in x['cookies'] ]
        else:
            x['cookie_fields'] = [ y.split('=')[0].lstrip().rstrip() for y in x['cookies'].split(';') ]
            x['cookie_values'] = [ y.lstrip().rstrip() for y in x['cookies'].split(';') ]

        unsorted_cookie_fields = x['cookie_fields'][:]
        unsorted_cookie_values = x['cookie_values'][:]

        x['cookie_fields'].sort()
        x['cookie_values'].sort()

    cookies = sha_encode(x['cookie_fields']) if 'cookies' in x else '0'*12
    cookie_values = sha_encode(x['cookie_values']) if 'cookies' in x else '0'*12

    lang = http_language(x['lang']) if 'lang' in x else '0000'
    headers = sha_encode(x['headers'])
    x['JA4H'] = f'{method}{version}{cookie}{referer}{header_len}{lang}_{headers}_{cookies if len(cookies) else ""}_{cookie_values}'
    x['JA4H_r'] = f"{method}{version}{cookie}{referer}{header_len}{lang}_{','.join(raw_headers)}_"
    x['JA4H_ro'] = f"{method}{version}{cookie}{referer}{header_len}{lang}_{','.join(raw_headers)}_"
    if 'cookie_fields' in x:
        x['JA4H_ro'] += f"{','.join(unsorted_cookie_fields)}_{','.join(unsorted_cookie_values)}"
        x['JA4H_r'] += f"{','.join(x['cookie_fields'])}_{','.join(x['cookie_values'])}"
    cache_update(x, 'JA4H', x['JA4H'], debug_stream)
    cache_update(x, 'JA4H_r', x['JA4H_r'], debug_stream)
    cache_update(x, 'JA4H_ro', x['JA4H_ro'], debug_stream)
    return x

############# END OF HTTP FUNCTIONS ##################
