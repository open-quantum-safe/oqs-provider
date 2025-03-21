#!/usr/bin/env python3
import glob
import subprocess
import os
import jinja2
import jinja2.ext
import yaml
from generate_oid_nid_table import generate_oid_nid_table_main

# For list.append in Jinja templates
Jinja2 = jinja2.Environment(
    loader=jinja2.FileSystemLoader(searchpath="."), extensions=["jinja2.ext.do"]
)
# kemoidcnt = 0


# For files generated, the copyright message can be adapted
# see https://github.com/open-quantum-safe/oqs-provider/issues/2#issuecomment-920904048
# SPDX message to be leading, OpenSSL Copyright notice to be deleted
def fixup_copyright(filename, encoding=None):
    with open(filename, "r", encoding=encoding) as origfile:
        with open(filename + ".new", "w", encoding=encoding) as newfile:
            newfile.write("// SPDX-License-Identifier: Apache-2.0 AND MIT\n\n")
            skipline = False
            checkline = True
            for line in origfile:
                if checkline and " * Copyright" in line:
                    skipline = True
                if "*/" in line:
                    skipline = False
                    checkline = False
                if not skipline:
                    newfile.write(line)
    os.rename(filename + ".new", filename)


def get_kem_nistlevel(alg):
    if "LIBOQS_SRC_DIR" not in os.environ:
        print("Must include LIBOQS_SRC_DIR in environment")
        exit(1)
    # translate family names in generate.yml to directory names for liboqs algorithm datasheets
    if alg["family"] == "CRYSTALS-Kyber":
        datasheetname = "kyber"
    elif alg["family"] == "SIDH":
        datasheetname = "sike"
    elif alg["family"] == "NTRU-Prime":
        datasheetname = "ntruprime"
    else:
        datasheetname = alg["family"].lower().replace("-", "_")
    # load datasheet
    algymlfilename = os.path.join(
        os.environ["LIBOQS_SRC_DIR"],
        "docs",
        "algorithms",
        "kem",
        f"{datasheetname}.yml",
    )
    algyml = yaml.safe_load(file_get_contents(algymlfilename, encoding="utf-8"))

    # hacks to match names
    def matches(name, alg):
        def simplify(s):
            return s.lower().replace("_", "").replace("-", "")

        if "FrodoKEM" in name:
            name = name.replace("FrodoKEM", "Frodo")
        if "Saber-KEM" in name:
            name = name.replace("-KEM", "")
        if "-90s" in name:
            name = name.replace("-90s", "").replace("Kyber", "Kyber90s")
        if simplify(name) == simplify(alg["name_group"]):
            return True
        return False

    # find the variant that matches
    for variant in algyml["parameter-sets"]:
        if matches(variant["name"], alg) or (
            "alias" in variant and matches(variant["alias"], alg)
        ):
            return variant["claimed-nist-level"]
    return None


def get_sig_nistlevel(family, alg):
    if "LIBOQS_SRC_DIR" not in os.environ:
        print("Must include LIBOQS_SRC_DIR in environment")
        exit(1)
    # translate family names in generate.yml to directory names for liboqs algorithm datasheets
    if family["family"] == "CRYSTALS-Dilithium":
        datasheetname = "dilithium"
    elif family["family"] == "SPHINCS-Haraka":
        datasheetname = "sphincs"
    elif family["family"] == "SPHINCS-SHA2":
        datasheetname = "sphincs"
    elif family["family"] == "SPHINCS-SHAKE":
        datasheetname = "sphincs"
    else:
        datasheetname = family["family"].lower().replace("-", "_")
    # load datasheet
    algymlfilename = os.path.join(
        os.environ["LIBOQS_SRC_DIR"],
        "docs",
        "algorithms",
        "sig",
        f"{datasheetname}.yml",
    )
    algyml = yaml.safe_load(file_get_contents(algymlfilename, encoding="utf-8"))

    # hacks to match names
    def matches(name, alg):
        def simplify(s):
            return s.lower().replace("_", "").replace("-", "").replace("+", "")

        if simplify(name) == simplify(alg["name"]):
            return True
        return False

    # find the variant that matches
    for variant in algyml["parameter-sets"]:
        if matches(variant["name"], alg) or (
            "alias" in variant and matches(variant["alias"], alg)
        ):
            return variant["claimed-nist-level"]
    return None


def nist_to_bits(nistlevel):
    if nistlevel == 1 or nistlevel == 2:
        return 128
    elif nistlevel == 3 or nistlevel == 4:
        return 192
    elif nistlevel == 5:
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
    for kem in config["kems"]:
        bits_level = nist_to_bits(get_kem_nistlevel(kem))
        if bits_level is None:
            print(f"Cannot find security level for {kem["family"]} {kem["name_group"]}")
            exit(1)
        kem["bit_security"] = bits_level

        # now add hybrid_nid to hybrid_groups
        phyb = {}
        if bits_level == 128:
            phyb["hybrid_group"] = "p256"
        elif bits_level == 192:
            phyb["hybrid_group"] = "p384"
        elif bits_level == 256:
            phyb["hybrid_group"] = "p521"
        else:
            print(f"Warning: Unknown bit level for {kem["group_name"]}. Cannot assign hybrid.")
            exit(1)
        phyb["bit_security"] = bits_level
        phyb["nid"] = kem["nid_hybrid"]
        if "hybrid_oid" in kem:
            phyb["hybrid_oid"] = kem["hybrid_oid"]
        else:
            phyb["hybrid_oid"] = get_tmp_kem_oid()
        kem["hybrids"].insert(0, phyb)
        if not "oid" in kem:
            kem["oid"] = get_tmp_kem_oid()

    for famsig in config["sigs"]:
        for sig in famsig["variants"]:
            bits_level = nist_to_bits(get_sig_nistlevel(famsig, sig))
            if bits_level is None:
                print(
                    f"Cannot find security level for {famsig["family"]} {sig["name"]}. "
                     "Setting to 0."
                )
                bits_level = 0
            sig["security"] = bits_level
    return config


def run_subprocess(
    command,
    outfilename=None,
    outfilencoding=None,
    working_dir=".",
    expected_returncode=0,
    input_=None,
    ignore_returncode=False,
):
    with (
        open(outfilename, "w", encoding=outfilencoding)
        if outfilename is not None
        else subprocess.PIPE
    ) as output_file:
        result = subprocess.run(
            command,
            input=input_,
            stdout=output_file,
            stderr=subprocess.PIPE,
            cwd=working_dir,
            check=False,
        )

    if not (ignore_returncode) and (result.returncode != expected_returncode):
        if outfilename is None:
            print(result.stdout.decode("utf-8"))
        assert False, f"Got unexpected return code {result.returncode}"


def file_get_contents(filename, encoding=None):
    with open(filename, mode="r", encoding=encoding) as fh:
        return fh.read()


def file_put_contents(filename, s, encoding=None):
    with open(filename, mode="w", encoding=encoding) as fh:
        fh.write(s)


def populate(filename, config, delimiter, overwrite=False):
    fragments = glob.glob(os.path.join("oqs-template", filename, "*.fragment"))
    if overwrite:
        source_file = os.path.join(
            "oqs-template", filename, os.path.basename(filename) + ".base"
        )
        contents = file_get_contents(source_file)
    else:
        contents = file_get_contents(filename)
    for fragment in fragments:
        identifier = os.path.splitext(os.path.basename(fragment))[0]
        if filename.endswith(".md"):
            identifier_start = f"{delimiter} OQS_TEMPLATE_FRAGMENT_{identifier.upper()}_START -->"
        else:
            identifier_start = f"{delimiter} OQS_TEMPLATE_FRAGMENT_{identifier.upper()}_START"
        identifier_end = f"{delimiter} OQS_TEMPLATE_FRAGMENT_{identifier.upper()}_END"
        preamble = contents[: contents.find(identifier_start)]
        postamble = contents[contents.find(identifier_end) :]
        if overwrite:
            contents = (
                preamble
                + Jinja2.get_template(fragment).render({"config": config})
                + postamble.replace(identifier_end + "\n", "")
            )
        else:
            contents = (
                preamble
                + identifier_start
                + Jinja2.get_template(fragment).render({"config": config})
                + postamble
            )
    file_put_contents(filename, contents)


def load_config(include_disabled_sigs=False):
    _config = file_get_contents(
        os.path.join("oqs-template", "generate.yml"), encoding="utf-8"
    )
    _config = yaml.safe_load(_config)
    if not include_disabled_sigs:
        for sig in _config["sigs"]:
            sig["variants"] = [
                variant
                for variant in sig["variants"]
                if ("enable" in variant and variant["enable"])
            ]

    # remove KEMs without NID (old stuff)
    newkems = []
    for kem in _config["kems"]:
        if "nid" in kem:
            newkems.append(kem)
    _config["kems"] = newkems

    # remove SIGs without OID (old stuff)
    for sig in _config["sigs"]:
        newvars = []
        for variant in sig["variants"]:
            if "oid" in variant:
                newvars.append(variant)
        sig["variants"] = newvars

    for kem in _config["kems"]:
        kem["hybrids"] = []
        if "extra_nids" not in kem or "current" not in kem["extra_nids"]:
            continue
        hybrid_nids = set()
        for extra_hybrid in kem["extra_nids"]["current"]:
            if (
                extra_hybrid["hybrid_group"] == "x25519"
                or extra_hybrid["hybrid_group"] == "p256"
                or extra_hybrid["hybrid_group"] == "secp256_r1"
            ):
                extra_hybrid["bit_security"] = 128
            if (
                extra_hybrid["hybrid_group"] == "x448"
                or extra_hybrid["hybrid_group"] == "p384"
                or extra_hybrid["hybrid_group"] == "secp384_r1"
            ):
                extra_hybrid["bit_security"] = 192
            if (
                extra_hybrid["hybrid_group"] == "p521"
                or extra_hybrid["hybrid_group"] == "secp521_r1"
            ):
                extra_hybrid["bit_security"] = 256
            if not "hybrid_oid" in extra_hybrid:
                extra_hybrid["hybrid_oid"] = get_tmp_kem_oid()
            kem["hybrids"].append(extra_hybrid)
            if "hybrid_group" in extra_hybrid:
                extra_hybrid_nid = extra_hybrid["nid"]
                if extra_hybrid_nid in hybrid_nids:
                    print(
                        "ERROR: duplicate hybrid NID for",
                        kem["name_group"],
                        ":",
                        extra_hybrid_nid,
                        "in generate.yml.",
                        "Curve NIDs may only be specified once per KEM.",
                    )
                    exit(1)
                hybrid_nids.add(extra_hybrid_nid)
    return _config


if __name__ == "__main__":

    # extend config with "hybrid_groups" array:
    jinja_config = load_config()  # extend config with "hybrid_groups" array

    # complete config with "bit_security" and "hybrid_group from
    # nid_hybrid information
    jinja_config = complete_config(jinja_config)

    populate("oqsprov/oqsencoders.inc", jinja_config, "/////")
    populate("oqsprov/oqsdecoders.inc", jinja_config, "/////")
    populate("oqsprov/oqs_prov.h", jinja_config, "/////")
    populate("oqsprov/oqsprov.c", jinja_config, "/////")
    populate("oqsprov/oqsprov_capabilities.c", jinja_config, "/////")
    populate("oqsprov/oqs_kmgmt.c", jinja_config, "/////")
    populate("oqsprov/oqs_encode_key2any.c", jinja_config, "/////")
    populate("oqsprov/oqs_decode_der2key.c", jinja_config, "/////")
    populate("oqsprov/oqsprov_keys.c", jinja_config, "/////")
    populate("scripts/common.py", jinja_config, "#####")
    populate("test/test_common.c", jinja_config, "/////")

    jinja_config_markdown = load_config(include_disabled_sigs=True)
    jinja_config_markdown = complete_config(jinja_config_markdown)

    populate("ALGORITHMS.md", jinja_config_markdown, "<!---")
    populate("README.md", jinja_config_markdown, "<!---")
    print("All files generated")
    os.environ["LIBOQS_DOCS_DIR"] = os.path.join(os.environ["LIBOQS_SRC_DIR"], "docs")
    generate_oid_nid_table_main()
