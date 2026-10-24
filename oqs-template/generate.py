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

      if kem.get('use_hybrid'):
          # add the default (ECP) hybrid to hybrid_groups
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
          if 'nid_hybrid' in kem: phyb['nid']=kem['nid_hybrid']
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
            if 'hybrid_group' in extra_hybrid and 'nid' in extra_hybrid:
                extra_hybrid_nid = extra_hybrid['nid']
                if extra_hybrid_nid in hybrid_nids:
                    print("ERROR: duplicate hybrid NID for", kem['name_group'],
                          ":", extra_hybrid_nid, "in generate.yml.",
                          "Curve NIDs may only be specified once per KEM.")
                    exit(1)
                hybrid_nids.add(extra_hybrid_nid)
    return config

# TLS code points ('nid' and 'nid_hybrid' for KEMs, 'code_point' for
# signatures) are managed the same way for KEMs and signatures:
# - only algorithms actually used in TLS have them: KEMs with 'enable_kem' and
#   'enable_tls', signatures with 'enable' and 'enable_tls', and their hybrids;
# - unless marked 'iana: true', they are unique, lie in the RFC 8446 private
#   use range, and do not reuse a code point that a previous release
#   (generate.yml-* snapshots) gave to another algorithm;
# - 'auto' assigns the code point of the algorithm's latest release if still
#   free, otherwise the lowest free one, and writes it into generate.yml.
TLS_CODE_POINT_SPACES = {
    # RFC 8446, section 4.2.7: NamedGroup ecdhe_private_use
    'kems': {'range': range(0xFE00, 0xFF00), 'format': lambda cp: f"{cp}",
             'enable': ('enable_kem', 'enable_tls')},
    # RFC 8446, section 4.2.3: SignatureScheme private_use
    'sigs': {'range': range(0xFE00, 0x10000), 'format': lambda cp: f"{cp:#06x}",
             'enable': ('enable', 'enable_tls')},
}

# Curve of the default KEM hybrid ('use_hybrid') by bit security
DEFAULT_HYBRID_CURVES = {128: 'p256', 192: 'p384', 256: 'p521'}

# Name of the default hybrid of a KEM, e.g. p384_mlkem768, or None if the KEM's
# security level is unknown. The level comes from the liboqs datasheet or, for
# KEMs no longer in liboqs, from oqs-template/oldalgs.yml.
_default_hybrid_names = {}
def default_hybrid_name(kem):
    key = (kem['family'], kem['name_group'])
    if key not in _default_hybrid_names:
        try:
            nist_level = get_kem_nistlevel(kem)
        except FileNotFoundError:
            nist_level = None
        if nist_level is None:
            old_algs = yaml.safe_load(file_get_contents(os.path.join('oqs-template', 'oldalgs.yml'), encoding='utf-8'))
            nist_level = (old_algs.get(kem['name_group']) or {}).get('claimed-nist-level')
        curve = DEFAULT_HYBRID_CURVES.get(nist_to_bits(nist_level))
        _default_hybrid_names[key] = f"{curve}_{kem['name_group']}" if curve else None
    return _default_hybrid_names[key]

# An algorithm (and its hybrids) has TLS code points only if it is used in TLS
def uses_tls(kind, alg):
    return all(alg.get(flag) for flag in TLS_CODE_POINT_SPACES[kind]['enable'])

def parse_code_point(code_point):
    code_point = str(code_point)
    return int(code_point, 16) if code_point[:2].lower() == '0x' else int(code_point, 10)

def algorithms(config, kind):
    if kind == 'kems':
        return config.get('kems', []) or []
    return [variant for famsig in config.get('sigs', []) or [] for variant in famsig['variants']]

# Yields (container, key, name, identity, iana) for each TLS code point of a
# KEM; history=True adds previous versions ('extra_nids' 'old'). The default
# hybrid exists if 'use_hybrid' is true; in release snapshots (snapshot=True),
# which predate 'use_hybrid', if 'nid_hybrid' is set.
def kem_code_point_slots(kem, history=False, snapshot=False):
    name = kem['name_group']
    yield kem, 'nid', name, name, kem.get('iana', False)
    if kem.get('use_hybrid') or (snapshot and 'nid_hybrid' in kem):
        hybrid = default_hybrid_name(kem)
        if hybrid is not None:
            yield kem, 'nid_hybrid', hybrid, hybrid, False
        # An unknown level is only possible for KEMs no longer in liboqs. In a
        # release snapshot, such a hybrid with a code point outside the private
        # use range cannot conflict with any current one, so it is skipped.
        elif not (snapshot and parse_code_point(kem['nid_hybrid'])
                  not in TLS_CODE_POINT_SPACES['kems']['range']):
            print(f"ERROR: cannot determine the security level of {name}: "
                  "add it to oqs-template/oldalgs.yml.")
            exit(1)
    extra_nids = kem.get('extra_nids') or {}
    for entries in ['current'] + (['old'] if history else []):
        for entry in extra_nids.get(entries, []) or []:
            if 'hybrid_group' in entry:
                identity = f"{entry['hybrid_group']}_{name}"
                yield entry, 'nid', entry.get('standard_name', identity), identity, entry.get('iana', False)
            else:
                yield entry, 'nid', name, name, entry.get('iana', False)

# Same for a signature variant; history=True adds previous versions
# ('extra_nids' 'old', 'extra_oids') and composites.
def sig_code_point_slots(variant, history=False, snapshot=False):
    name = variant['name']
    versions = [variant]
    if history:
        versions += (variant.get('extra_nids') or {}).get('old', []) or []
        if isinstance(variant.get('extra_oids'), dict):
            versions.append(variant['extra_oids'])
    for version in versions:
        yield version, 'code_point', name, name, version.get('iana', False)
        for classical_alg in version.get('mix_with', []) or []:
            hybrid = f"{classical_alg['name']}_{name}"
            yield classical_alg, 'code_point', hybrid, hybrid, classical_alg.get('iana', False)
        for composite_alg in (version.get('composite', []) or []) if history else []:
            composite = f"{name}_{composite_alg['name']}"
            yield composite_alg, 'code_point', composite, composite, composite_alg.get('iana', False)

# Yields (algorithm, container, key, name, identity, iana) for all TLS code
# points of a kind. Identities are lowercased, as OpenSSL matches algorithm
# names case-insensitively.
def code_point_slots(config, kind, history=False, snapshot=False):
    slots = kem_code_point_slots if kind == 'kems' else sig_code_point_slots
    for alg in algorithms(config, kind):
        for container, key, name, identity, iana in slots(alg, history, snapshot):
            yield alg, container, key, name, identity.lower(), iana

def snapshot_version(filename):
    return tuple(int(n) for n in filename.rsplit('-', 1)[1].split('.'))

# Returns the code points of a kind used by releases: code point -> identities
# it was assigned to, and identity -> code point in its latest release
def load_released_code_points(kind):
    by_code_point, by_identity = {}, {}
    snapshots = sorted(glob.glob(os.path.join('oqs-template', 'generate.yml-*')), key=snapshot_version)
    for filename in snapshots:
        old_config = yaml.safe_load(file_get_contents(filename, encoding='utf-8'))
        for _, container, key, _, identity, _ in code_point_slots(old_config, kind, history=True, snapshot=True):
            if key in container:
                by_code_point.setdefault(parse_code_point(container[key]), set()).add(identity)
        for _, container, key, _, identity, _ in code_point_slots(old_config, kind, snapshot=True):
            if key in container:
                by_identity[identity] = parse_code_point(container[key])
    return by_code_point, by_identity

# Code points of a kind set in generate.yml (including previous versions)
def code_points_in_use(config, kind):
    return {parse_code_point(container[key])
            for _, container, key, _, _, _ in code_point_slots(config, kind, history=True)
            if container.get(key, 'auto') != 'auto'}

# Private use code points neither in use nor used by any release
def free_code_points(config, kind, by_code_point):
    taken = set(by_code_point) | code_points_in_use(config, kind)
    return [cp for cp in TLS_CODE_POINT_SPACES[kind]['range'] if cp not in taken]

# Replaces each 'auto' code point in generate.yml and saves the file
def assign_auto_code_points(filename):
    text = file_get_contents(filename, encoding='utf-8')
    pattern = re.compile(r"^(?!\s*#)(.*?'?(?:code_point|nid_hybrid|nid)'?:\s*)'auto'", re.MULTILINE)
    matches = len(pattern.findall(text))
    if matches == 0:
        return
    config = yaml.safe_load(text)
    # (kind, name, identity) of each 'auto' code point, in file order
    auto = []
    for kind in [key for key in config if key in TLS_CODE_POINT_SPACES]:
        slots = kem_code_point_slots if kind == 'kems' else sig_code_point_slots
        for alg in algorithms(config, kind):
            order = list(alg)
            alg_slots = [s for s in slots(alg) if s[0].get(s[1]) == 'auto']
            # code points of the algorithm itself come in key order, then those of hybrids
            alg_slots.sort(key=lambda s: order.index(s[1]) if s[0] is alg else
                           order.index('extra_nids' if kind == 'kems' else 'mix_with'))
            auto += [(kind, name, identity.lower()) for _, _, name, identity, _ in alg_slots]
    if len(auto) != matches:
        print("ERROR: unexpected placement of 'auto' code points in generate.yml.")
        exit(1)
    state = {}
    for kind in TLS_CODE_POINT_SPACES:
        by_code_point, by_identity = load_released_code_points(kind)
        state[kind] = (by_code_point, by_identity, code_points_in_use(config, kind),
                       iter(free_code_points(config, kind, by_code_point)))
    entries = iter(auto)
    def assign(match):
        kind, name, identity = next(entries)
        by_code_point, by_identity, in_use, free = state[kind]
        space = TLS_CODE_POINT_SPACES[kind]
        code_point = by_identity.get(identity)
        if (code_point is None or code_point not in space['range'] or code_point in in_use
                or by_code_point[code_point] != {identity}):
            code_point = next(free, None)
            if code_point is None:
                print(f"ERROR: no free {kind} code point left in the private use range.")
                exit(1)
        in_use.add(code_point)
        print(f"Assigned code point {space['format'](code_point)} to {name}")
        return f"{match.group(1)}'{space['format'](code_point)}'"
    file_put_contents(filename, pattern.sub(assign, text), encoding='utf-8')

# Enforces lowercase algorithm names; standardized hybrid KEM names
# ('standard_name') are exempt
def validate_alg_names(config):
    names = [kem['name_group'] for kem in algorithms(config, 'kems')]
    names += [hybrid['hybrid_group'] for kem in algorithms(config, 'kems')
              for hybrid in (kem.get('extra_nids') or {}).get('current', []) or []]
    names += [variant['name'] for variant in algorithms(config, 'sigs')]
    names += [classical_alg['name'] for variant in algorithms(config, 'sigs')
              for classical_alg in variant.get('mix_with', []) or []]
    errors = sorted({name for name in names if name != name.lower()})
    if errors:
        print("ERROR: algorithm names must be lowercase:", ", ".join(errors))
        exit(1)

def validate_tls_code_points(config):
    errors = []
    for kem in config['kems']:
        if 'nid_hybrid' in kem and not kem.get('use_hybrid'):
            errors.append(f"{kem['name_group']}: 'nid_hybrid' is set but 'use_hybrid' is not true.")
    for kind, space in TLS_CODE_POINT_SPACES.items():
        flags = " and ".join(f"'{flag}'" for flag in space['enable'])
        low, high = space['format'](space['range'].start), space['format'](space['range'].stop - 1)
        by_code_point, _ = load_released_code_points(kind)
        in_use = {}
        for alg, container, key, name, identity, iana in code_point_slots(config, kind):
            if not uses_tls(kind, alg):
                if key in container:
                    errors.append(f"{name}: not used in TLS ({flags} not both true), so '{key}' must not be set.")
                continue
            if key not in container:
                errors.append(f"{name}: used in TLS but '{key}' is not set (use 'auto').")
                continue
            code_point = parse_code_point(container[key])
            if code_point in in_use:
                errors.append(f"{name}: code point {space['format'](code_point)} already used by {in_use[code_point]}.")
            in_use[code_point] = name
            if iana:
                continue
            if code_point not in space['range']:
                errors.append(f"{name}: code point {space['format'](code_point)} not in private use range {low}..{high}.")
            elif code_point in by_code_point and identity not in by_code_point[code_point]:
                errors.append(f"{name}: code point {space['format'](code_point)} was used by "
                              f"{', '.join(sorted(by_code_point[code_point]))} in a previous release.")
    if errors:
        print("ERROR: invalid TLS code points in generate.yml:")
        for error in errors:
            print("  " + error)
        exit(1)

assign_auto_code_points(os.path.join('oqs-template', 'generate.yml'))
full_config = load_config(include_disabled_sigs=True, include_disabled_kems=True)
validate_alg_names(full_config)
validate_tls_code_points(full_config)

# extend config with "hybrid_groups" array:
config = load_config() # extend config with "hybrid_groups" array

# complete config with "bit_security" and the default hybrid from
# use_hybrid information
config = complete_config(config)


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
