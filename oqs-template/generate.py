#!/usr/bin/env python3

import copy
import glob
import jinja2
import jinja2.ext
import os
import re
import shutil
import subprocess
import yaml

kemoidcnt=0

# TLS SignatureScheme private use range (RFC 8446, section 4.2.3)
SIG_PRIVATE_USE_RANGE = range(0xFE00, 0x10000)

# For files generated, the copyright message can be adapted
# see https://github.com/open-quantum-safe/oqs-provider/issues/2#issuecomment-920904048
# SPDX message to be leading, OpenSSL Copyright notice to be deleted
def fixup_copyright(filename):
   with open(filename, "r") as origfile:
      with open(filename+".new", "w") as newfile:
         newfile.write("// SPDX-License-Identifier: Apache-2.0 AND MIT\n\n")
         skipline = False
         checkline = True
         for line in origfile:
             if checkline==True and " * Copyright" in line:
                skipline=True
             if "*/" in line:
                skipline=False
                checkline=False
             if not skipline:
                newfile.write(line)
   os.rename(filename+".new", filename)

def get_kem_nistlevel(alg):
    if 'LIBOQS_SRC_DIR' not in os.environ:
        print("Must include LIBOQS_SRC_DIR in environment")
        exit(1)
    # translate family names in generate.yml to directory names for liboqs algorithm datasheets
    if alg['family'] == 'CRYSTALS-Kyber': datasheetname = 'kyber'
    elif alg['family'] == 'SIDH': datasheetname = 'sike'
    elif alg['family'] == 'NTRU-Prime': datasheetname = 'ntruprime'
    else: datasheetname = alg['family'].lower().replace('-', '_')
    # load datasheet
    algymlfilename = os.path.join(os.environ['LIBOQS_SRC_DIR'], 'docs', 'algorithms', 'kem', '{:s}.yml'.format(datasheetname))
    algyml = yaml.safe_load(file_get_contents(algymlfilename, encoding='utf-8'))
    # hacks to match names
    def matches(name, alg):
        def simplify(s):
            return s.lower().replace('_', '').replace('-', '')
        if 'FrodoKEM' in name: name = name.replace('FrodoKEM', 'Frodo')
        if 'Saber-KEM' in name: name = name.replace('-KEM', '')
        if '-90s' in name: name = name.replace('-90s', '').replace('Kyber', 'Kyber90s')
        if simplify(name) == simplify(alg['name_group']): return True
        return False
    # find the variant that matches
    for variant in algyml['parameter-sets']:
        if matches(variant['name'], alg) or ('alias' in variant and matches(variant['alias'], alg)):
            return variant['claimed-nist-level']
    return None

def get_sig_nistlevel(family, alg):
    if 'LIBOQS_SRC_DIR' not in os.environ:
        print("Must include LIBOQS_SRC_DIR in environment")
        exit(1)
    # translate family names in generate.yml to directory names for liboqs algorithm datasheets
    if family['family'] == 'CRYSTALS-Dilithium': datasheetname = 'dilithium'
    else: datasheetname = family['family'].lower().replace('-', '_')
    # load datasheet
    algymlfilename = os.path.join(os.environ['LIBOQS_SRC_DIR'], 'docs', 'algorithms', 'sig', '{:s}.yml'.format(datasheetname))
    algyml = yaml.safe_load(file_get_contents(algymlfilename, encoding='utf-8'))
    # hacks to match names
    def matches(name, alg):
        def simplify(s):
            return s.lower().replace('_', '').replace('-', '').replace('+', '')
        if 'SLH_DSA_PURE' in name: name = name.replace('_PURE', '')
        if simplify(name) == simplify(alg['name']): return True
        return False
    # find the variant that matches
    for variant in algyml['parameter-sets']:
        if matches(variant['name'], alg) or ('alias' in variant and matches(variant['alias'], alg)):
            return variant['claimed-nist-level']
    return None

def nist_to_bits(nistlevel):
   if nistlevel==1 or nistlevel==2:
      return 128
   elif nistlevel==3 or nistlevel==4:
      return 192
   elif nistlevel==5:
      return 256
   else:
      return None

def get_tmp_kem_oid():
   # doesn't work for runs on different files:
   # global kemoidcnt
   # kemoidcnt = kemoidcnt+1
   # return "1.3.9999.99."+str(kemoidcnt)
   return "NULL"

def complete_config(config):
   for kem in config['kems']:
      bits_level = nist_to_bits(get_kem_nistlevel(kem))
      if bits_level == None:
          print("Cannot find security level for {:s} {:s}".format(kem['family'], kem['name_group']))
          exit(1)
      kem['bit_security'] = bits_level

      if 'nid_hybrid' in kem:
          # now add hybrid_nid to hybrid_groups
          phyb = {}
          if (bits_level == 128):
              phyb['hybrid_group']='p256'
          elif (bits_level == 192):
              phyb['hybrid_group']='p384'
          elif (bits_level == 256):
              phyb['hybrid_group']='p521'
          else:
              print("Warning: Unknown bit level for %s. Cannot assign hybrid." % (kem['group_name']))
              exit(1)
          phyb['bit_security']=bits_level
          phyb['nid']=kem['nid_hybrid']
          if 'hybrid_oid' in kem: phyb['hybrid_oid']=kem['hybrid_oid']
          else: phyb['hybrid_oid'] = get_tmp_kem_oid()
          kem['hybrids'].insert(0, phyb)
          if not 'oid' in kem:
             kem['oid'] = get_tmp_kem_oid()

   for famsig in config['sigs']:
      for sig in famsig['variants']:
         bits_level = nist_to_bits(get_sig_nistlevel(famsig, sig))
         if bits_level == None:
             print("Cannot find security level for {:s} {:s}. Setting to 0.".format(famsig['family'], sig['name']))
             bits_level = 0
         sig['security'] = bits_level
   return config

def run_subprocess(command, outfilename=None, working_dir='.', expected_returncode=0, input=None, ignore_returncode=False):
    result = subprocess.run(
            command,
            input=input,
            stdout=(open(outfilename, "w") if outfilename!=None else subprocess.PIPE),
            stderr=subprocess.PIPE,
            cwd=working_dir,
        )

    if not(ignore_returncode) and (result.returncode != expected_returncode):
        if outfilename == None:
            print(result.stdout.decode('utf-8'))
        assert False, "Got unexpected return code {}".format(result.returncode)

# For list.append in Jinja templates
Jinja2 = jinja2.Environment(loader=jinja2.FileSystemLoader(searchpath="."),extensions=['jinja2.ext.do'])

def file_get_contents(filename, encoding=None):
    with open(filename, mode='r', encoding=encoding) as fh:
        return fh.read()

def file_put_contents(filename, s, encoding=None):
    with open(filename, mode='w', encoding=encoding) as fh:
        fh.write(s)

def populate(filename, config, delimiter, overwrite=False):
    fragments = glob.glob(os.path.join('oqs-template', filename, '*.fragment'))
    if overwrite == True:
        source_file = os.path.join('oqs-template', filename, os.path.basename(filename)+ '.base')
        contents = file_get_contents(source_file)
    else:
        contents = file_get_contents(filename)
    for fragment in fragments:
        identifier = os.path.splitext(os.path.basename(fragment))[0]
        if filename.endswith('.md'):
            identifier_start = '{} OQS_TEMPLATE_FRAGMENT_{}_START -->'.format(delimiter, identifier.upper())
        else:
            identifier_start = '{} OQS_TEMPLATE_FRAGMENT_{}_START'.format(delimiter, identifier.upper())
        identifier_end = '{} OQS_TEMPLATE_FRAGMENT_{}_END'.format(delimiter, identifier.upper())
        preamble = contents[:contents.find(identifier_start)]
        postamble = contents[contents.find(identifier_end):]
        if overwrite == True:
            contents = preamble + Jinja2.get_template(fragment).render({'config': config}) + postamble.replace(identifier_end + '\n', '')
        else:
            contents = preamble + identifier_start + Jinja2.get_template(fragment).render({'config': config}) + postamble
    file_put_contents(filename, contents)

def load_config(include_disabled_sigs=False, include_disabled_kems=False):
    config = file_get_contents(os.path.join('oqs-template', 'generate.yml'), encoding='utf-8')
    config = yaml.safe_load(config)
    if not include_disabled_sigs:
        for sig in config['sigs']:
            sig['variants'] = [variant for variant in sig['variants'] if ('enable' in variant and variant['enable'])]
    if not include_disabled_kems:
        config['kems'] = [kem for kem in config['kems'] if ('enable_kem' in kem and kem['enable_kem'])]

    # remove KEMs without NID (old stuff)
    newkems = []
    for kem in config['kems']:
        if 'nid' in kem:
           newkems.append(kem)
    config['kems']=newkems

    # remove SIGs without OID (old stuff)
    for sig in config['sigs']:
        newvars = []
        for variant in sig['variants']:
            if 'oid' in variant:
                newvars.append(variant)
        sig['variants']=newvars

    for kem in config['kems']:
        kem['hybrids'] = []
        if 'extra_nids' not in kem or 'current' not in kem['extra_nids']:
            continue
        hybrid_nids = set()
        for extra_hybrid in kem['extra_nids']['current']:
            if extra_hybrid['hybrid_group'] == "x25519" or extra_hybrid['hybrid_group'] == "p256" or extra_hybrid['hybrid_group'] == "bp256" or extra_hybrid['hybrid_group'] == "secp256_r1":
               extra_hybrid['bit_security'] = 128
            if extra_hybrid['hybrid_group'] == "x448" or extra_hybrid['hybrid_group'] == "p384" or extra_hybrid['hybrid_group'] == "bp384" or extra_hybrid['hybrid_group'] == "secp384_r1":
               extra_hybrid['bit_security'] = 192
            if extra_hybrid['hybrid_group'] == "p521" or extra_hybrid['hybrid_group'] == "bp512" or extra_hybrid['hybrid_group'] == "secp521_r1":
               extra_hybrid['bit_security'] = 256
            if not 'hybrid_oid' in extra_hybrid:
                extra_hybrid['hybrid_oid'] = get_tmp_kem_oid()
            kem['hybrids'].append(extra_hybrid)
            if 'hybrid_group' in extra_hybrid:
                extra_hybrid_nid = extra_hybrid['nid']
                if extra_hybrid_nid in hybrid_nids:
                    print("ERROR: duplicate hybrid NID for", kem['name_group'],
                          ":", extra_hybrid_nid, "in generate.yml.",
                          "Curve NIDs may only be specified once per KEM.")
                    exit(1)
                hybrid_nids.add(extra_hybrid_nid)
    return config

# Validates that non-standard TLS code points are in the private use range
def validate_iana_code_points(config):
    reserved = list(range(65024, 65280))
    in_use = list(reserved)
    def validate(kem, name):
        nid = str(kem['nid'])
        nid = int(nid, 16) if nid[:2] == '0x' else int(nid, 10)
        if nid in reserved and nid in in_use:
            in_use.remove(nid)
        elif nid not in reserved:
            print(f"Non-standard TLS group {name} code point {kem['nid']} not in private use range.")
            print(f"Next free code in point in private use range: {min(in_use)}")
            exit(1)
        elif nid not in in_use:
            print(f"Non-standard TLS group {name} code point {kem['nid']} already in use in oqs-provider.")
            print(f"Next free code in point in private use range: {min(in_use)}")
            exit(1)

    for kem in config['kems']:
        if 'iana' not in kem or not kem['iana']:
            validate(kem, f"{kem['name_group']}")

            for hybrid in kem['hybrids']:
                if 'iana' not in hybrid or not hybrid['iana']:
                    validate(hybrid, f"{kem['name_group']}_{hybrid['hybrid_group']}")

def parse_code_point(code_point):
    code_point = str(code_point)
    return int(code_point, 16) if code_point[:2].lower() == '0x' else int(code_point, 10)

# Yields (entry, TLS name, family, variant) for every signature variant and its
# hybrids; with history=True also for composites and previous versions
# ('extra_nids' 'old', 'extra_oids'), which hold code points of earlier releases.
def sig_tls_entries(config, history=False):
    for famsig in config['sigs']:
        for variant in famsig['variants']:
            versions = [variant]
            if history:
                versions += (variant.get('extra_nids') or {}).get('old', [])
                if isinstance(variant.get('extra_oids'), dict):
                    versions.append(variant['extra_oids'])
            for version in versions:
                yield version, variant['name'], famsig['family'], variant
                for classical_alg in version.get('mix_with', []) or []:
                    yield classical_alg, f"{classical_alg['name']}_{variant['name']}", famsig['family'], variant
                for composite_alg in (version.get('composite', []) or []) if history else []:
                    yield composite_alg, f"{variant['name']}_{composite_alg['name']}", famsig['family'], variant

# A signature variant (and its hybrids) gets a TLS code point only if it is
# actually used in TLS: built ('enable') and TLS-capable ('enable_tls')
def sig_uses_tls(variant):
    return bool(variant.get('enable')) and bool(variant.get('enable_tls'))

def snapshot_version(filename):
    return tuple(int(n) for n in filename.rsplit('-', 1)[1].split('.'))

# Returns the signature code points used by releases (generate.yml-* snapshots):
# code point -> names it was assigned to, and name -> code point in the latest
# release having that name. Names are lowercased, as OpenSSL matches algorithm
# names case-insensitively.
def load_released_sig_code_points():
    by_code_point, by_name = {}, {}
    snapshots = sorted(glob.glob(os.path.join('oqs-template', 'generate.yml-*')), key=snapshot_version)
    for filename in snapshots:
        old_config = yaml.safe_load(file_get_contents(filename, encoding='utf-8'))
        for entry, name, _, _ in sig_tls_entries(old_config, history=True):
            if 'code_point' in entry:
                by_code_point.setdefault(parse_code_point(entry['code_point']), set()).add(name.lower())
        for entry, name, _, _ in sig_tls_entries(old_config):
            if 'code_point' in entry:
                by_name[name.lower()] = parse_code_point(entry['code_point'])
    return by_code_point, by_name

# Code points set in generate.yml (including earlier versions of algorithms)
def sig_code_points_in_use(config):
    return {parse_code_point(entry['code_point'])
            for entry, _, _, _ in sig_tls_entries(config, history=True)
            if entry.get('code_point', 'auto') != 'auto'}

# Private use code points neither in use nor used by any release
def free_sig_code_points(config, released):
    taken = set(released) | sig_code_points_in_use(config)
    return [cp for cp in SIG_PRIVATE_USE_RANGE if cp not in taken]

# Replaces each "code_point: 'auto'" in generate.yml and saves the file. An
# algorithm gets back the code point of its latest release if that is still
# free, otherwise the lowest private use code point that is neither in use nor
# used by any release.
def assign_auto_sig_code_points(filename):
    text = file_get_contents(filename, encoding='utf-8')
    pattern = re.compile(r"^(?!\s*#)(.*?'?code_point'?:\s*)'auto'", re.MULTILINE)
    matches = len(pattern.findall(text))
    if matches == 0:
        return
    config = yaml.safe_load(text)
    # entries with 'auto', in the order their code points appear in the file
    auto = []
    for famsig in config['sigs']:
        for variant in famsig['variants']:
            for key in variant:
                if key == 'code_point' and variant['code_point'] == 'auto':
                    auto.append(variant['name'])
                elif key == 'mix_with':
                    auto += [f"{c['name']}_{variant['name']}" for c in variant['mix_with'] or []
                             if c.get('code_point') == 'auto']
    if len(auto) != matches:
        print("ERROR: unexpected placement of \"code_point: 'auto'\" in generate.yml.")
        exit(1)
    by_code_point, by_name = load_released_sig_code_points()
    in_use = sig_code_points_in_use(config)
    free = iter(free_sig_code_points(config, by_code_point))
    names = iter(auto)
    def assign(match):
        name = next(names)
        code_point = by_name.get(name.lower())
        if code_point is None or code_point in in_use or by_code_point[code_point] != {name.lower()}:
            code_point = next(free, None)
            if code_point is None:
                print("ERROR: no free signature code point left in the private use range.")
                exit(1)
        in_use.add(code_point)
        print(f"Assigned signature code point {code_point:#06x} to {name}")
        return f"{match.group(1)}'{code_point:#06x}'"
    file_put_contents(filename, pattern.sub(assign, text), encoding='utf-8')

# Enforces lowercase algorithm names; standardized hybrid KEM names
# ('standard_name') are exempt
def validate_alg_names(config):
    errors = []
    for kem in config['kems']:
        if kem['name_group'] != kem['name_group'].lower():
            errors.append(kem['name_group'])
    for _, name, _, _ in sig_tls_entries(config):
        if name != name.lower():
            errors.append(name)
    if errors:
        print("ERROR: algorithm names must be lowercase:", ", ".join(errors))
        exit(1)

# Controlled allocation of TLS signature code points: only algorithms used in
# TLS get one; it must be unique, in the private use range (unless 'iana: true'),
# and must not reuse a code point of another algorithm from a previous release.
def validate_sig_code_points(config):
    by_code_point, _ = load_released_sig_code_points()
    in_use = {}
    errors = []
    for entry, name, _, variant in sig_tls_entries(config):
        if not sig_uses_tls(variant):
            if 'code_point' in entry:
                errors.append(f"{name}: not used in TLS ('enable' and 'enable_tls' not both true), "
                              "so it must not have a code point.")
            continue
        if 'code_point' not in entry:
            errors.append(f"{name}: used in TLS but no code point is set (use 'auto').")
            continue
        code_point = parse_code_point(entry['code_point'])
        if code_point in in_use:
            errors.append(f"{name}: code point {code_point:#06x} already used by {in_use[code_point]}.")
        in_use[code_point] = name
        if entry.get('iana'):
            continue
        if code_point not in SIG_PRIVATE_USE_RANGE:
            errors.append(f"{name}: code point {code_point:#06x} not in private use range 0xfe00..0xffff.")
        elif code_point in by_code_point and name.lower() not in by_code_point[code_point]:
            errors.append(f"{name}: code point {code_point:#06x} was used by "
                          f"{', '.join(sorted(by_code_point[code_point]))} in a previous release.")
    if errors:
        print("ERROR: invalid signature code points in generate.yml:")
        for error in errors:
            print("  " + error)
        exit(1)
    print(f"Free signature code points: {len(free_sig_code_points(config, by_code_point))}")

assign_auto_sig_code_points(os.path.join('oqs-template', 'generate.yml'))
full_config = load_config(include_disabled_sigs=True, include_disabled_kems=True)
validate_alg_names(full_config)
validate_sig_code_points(full_config)

# extend config with "hybrid_groups" array:
config = load_config() # extend config with "hybrid_groups" array

# complete config with "bit_security" and "hybrid_group from
# nid_hybrid information
config = complete_config(config)

validate_iana_code_points(config)

populate('oqsprov/oqsencoders.inc', config, '/////')
populate('oqsprov/oqsdecoders.inc', config, '/////')
populate('oqsprov/oqs_prov.h', config, '/////')
populate('oqsprov/oqsprov.c', config, '/////')
populate('oqsprov/oqsprov_capabilities.c', config, '/////')
populate('oqsprov/oqs_kmgmt.c', config, '/////')
populate('oqsprov/oqs_encode_key2any.c', config, '/////')
populate('oqsprov/oqs_decode_der2key.c', config, '/////')
populate('oqsprov/oqsprov_keys.c', config, '/////')
populate('scripts/common.py', config, '#####')
populate('test/test_common.c', config, '/////')

config2 = load_config(include_disabled_sigs=True)
config2 = complete_config(config2)

populate('ALGORITHMS.md', config2, '<!---')
populate('README.md', config2, '<!---')
print("All files generated")
os.environ["LIBOQS_DOCS_DIR"]=os.path.join(os.environ["LIBOQS_SRC_DIR"], "docs")
import generate_oid_nid_table
