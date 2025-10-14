# Copyright (c) 2023, FoxIO, LLC.
# All rights reserved.
# Patent Pending
# JA4X is licenced under the FoxIO License 1.1. For full license text, see the repo root.
# Credit: W.

from hashlib import sha256
from common import sha_encode, cache_update

############ JA4X FUNCTIONS #####################
# JA4X decoding happens here.
# JA4X packets are TCP TLS packets
# This function calculates different ja4x fingerprints for each cert in the TLS packet
# JA4X does not use any caching from common.py

def encode_variable_length_quantity(v: int) -> list:
    m = 0x00
    output = []
    while v >= 0x80:
        output.insert(0, (v & 0x7F) | m)
        v = v >> 7
        m = 0x80
    output.insert(0, v | m)
    return output

def oid_to_hex(oid: str) -> str:
    a = [int(x) for x in oid.split(".")]
    oid = [a[0] * 40 + a[1]]
    for n in a[2:]:
        oid.extend(encode_variable_length_quantity(n))
    oid.insert(0, len(oid))
    oid.insert(0, 0x06)
    return "".join("{:02x}".format(num) for num in oid)[4:]

def to_ja4x(x, debug_stream=-1):
    # The extensions were stored as arrays of [ [2.5.19.35, 1.3.6.1.1.2], [ 2.5.19.2 ] ]
    # we need to convert them into hex codes and then use sha256
    if 'extension_lengths' not in x:
        return
    
    x['issuers'] = []
    x['subjects'] = []
    x['issuer_hashes'] = []
    x['subject_hashes'] = []
    for issuers, subjects, i_hash, s_hash in issuers_subjects(x):
        x['issuers'].append(issuers)
        x['subjects'].append(subjects)
        x['issuer_hashes'].append(i_hash)
        x['subject_hashes'].append(s_hash)

    # Get issuer name from CN and ON by scanning the sequence.
    # This is very specific to the way tshark holds the sequence.
    if 'printable_certs' in x:
        certs = str(x['printable_certs'])
        issuers = str(x['issuers'])
        subjects = str(x['subjects'])
        idx = 1
        for _i, _s in zip(issuers, subjects):
            remove_oids(_i, ['550406', '55040b'])
            remove_oids(_s, ['550406', '55040b'])

            try:
                cn_on = get_CN_ON(certs, _i)
                x[f'JA4X.{idx}._Issuer'] = cn_on
                cache_update(x, f'JA4X.{idx}._Issuer', x[f'JA4X.{idx}._Issuer'], debug_stream)
            except Exception as e:
                pass

            try:
                cn_on = get_CN_ON(certs, _s)
                x[f'JA4X.{idx}._Subject'] = cn_on
                cache_update(x, f'JA4X.{idx}._Subject', x[f'JA4X.{idx}._Subject'], debug_stream)
            except Exception as e:
                pass

            idx += 1

    for idx, i in enumerate(x['extension_lengths']):
        i = int(i)
        header_len = '{:02d}'.format(i)
        exts = x['cert_extensions'][:i] if isinstance(x['cert_extensions'], list) else [ x['cert_extensions']  ]
        if isinstance(x['cert_extensions'], list):
            del x['cert_extensions'][:i]
        hex_strings = [ oid_to_hex(ext) for ext in exts ]

        # compute the ja4x hash for each cert
        x[f'JA4X.{idx+1}'] = f'{x["issuer_hashes"][idx]}_{x["subject_hashes"][idx]}_' + sha256(",".join(hex_strings).encode('utf8')).hexdigest()[:12]
        cache_update(x, f'JA4X.{idx+1}', x[f'JA4X.{idx+1}'], debug_stream)
    return x

# Process Issuers and Subjects in the order they appear
# Input is an issuer and subjects lengths array along with oids
def issuers_subjects(x):
    for issuer_len, subject_len in zip(x['issuer_sequence'], x['subject_sequence']):
        # we have one issuer and subject sequence for each certificate
        issuers = []
        subjects = []
        for i in range(0, int(issuer_len)):
            issuer = x['rdn_oids'].pop(0)
            issuers.append(oid_to_hex(issuer))
        for i in range(0, int(subject_len)):
            subject = x['rdn_oids'].pop(0)
            subjects.append(oid_to_hex(subject))

        yield issuers, subjects, sha_encode(issuers), sha_encode(subjects)


def get_CN_ON(certs, seq):
    CN = None
    ON = None
    for i in seq:
        popped = certs.pop(0)
        if i == '55040a':
            ON = popped
        if i == '550403':
            CN = popped
    if CN and ON:
        return f"CN={CN}, ON={ON}"
    else:
        raise Exception('no CN ON found')

def remove_oids(seq, oids):
    for oid in oids:
        seq.remove(oid) if oid in seq else None
    

    
############ END OF JA4X FUNCTIONS #####################
