#!/bin/env python
# SPDX-License-Identifier: MIT

import argparse
import json
import jsonschema
import requests
import subprocess
import time
from lxml import html
from urllib.parse import urljoin


REGISTRY_ISD_URL = "https://registry.scion.org/api/v1/isds"
REGISTRY_ASN_URL = "https://registry.scion.org/api/v1/ases"

ANAPAYA_ISD_URL = "https://learn.anapaya.net/docs/resources/assignments/isds/"
ANAPAYA_ASN_URL = "https://learn.anapaya.net/docs/resources/assignments/ases/"

RIPE_STAT_URL = "https://stat.ripe.net/data/"


class AsnRange:
    """Represents a set of one or more ASNs"""
    BITS = 48
    MAX_VALUE = (1 << BITS) - 1
    BGP_ASN_BITS = 32
    MAX_BGP_ASN = (1 << BGP_ASN_BITS) - 1
    GROUP_BITS = 16
    GROUP_MAX_VALUE = (1 << GROUP_BITS) - 1

    def __init__(self, text: str, range_bits: int):
        parts = text.split(":")
        if len(parts) == 1:
            # Expect decimal AS number (BGP style)
            self.asn_int = int(parts[0])
            if self.asn_int < 0 or self.asn_int > self.MAX_BGP_ASN:
                raise ValueError("Invalid decimal ASN")
            if range_bits > 0:
                raise ValueError("BGB ASNs must not have a block range")
        elif len(parts) == 3:
            # Hexadecimal AS number in three 16 bit groups
            self.asn_int = 0
            for group in parts:
                self.asn_int <<= self.GROUP_BITS
                group_value = int(group, base=16)
                if group_value < 0 or group_value > self.GROUP_MAX_VALUE:
                    raise ValueError("Invalid hexadecimal ASN (Invalid group value)")
                self.asn_int |= group_value
        else:
            raise ValueError("Invalid ASN (Wrong number of colon-separated groups)")
        if range_bits > self.BITS:
            raise ValueError("Invalid range")
        self.range_bits = range_bits

    def __int__(self):
        return self.asn_int

    def __str__(self):
        if self.asn_int <= self.MAX_BGP_ASN:
            # BGP style ASN
            return str(self.asn_int)
        else:
            # SCION style hexadecimal ASN in three groups
            return "%x:%x:%x/%d" % (
                (self.asn_int >> 2 * self.GROUP_BITS) & self.GROUP_MAX_VALUE,
                (self.asn_int >> self.GROUP_BITS) & self.GROUP_MAX_VALUE,
                (self.asn_int) & self.GROUP_MAX_VALUE,
                self.BITS - self.range_bits
            )

    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        if type(self) is not type(other):
            return False
        else:
            return self.asn_int == other.asn_int

    def __lt__(self, other):
        assert type(self) is type(other)
        if self.asn_int == other.asn_int:
            return self.range_bits < self.range_bits
        return self.asn_int < other.asn_int

    def __hash__(self):
        return hash(self.asn_int) ^ hash(self.range_bits)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Collect SCION AS information from SCION Registry and other sources")
    parser.add_argument("-c", "--include-comments", action="store_true",
        help="Include comments")
    parser.add_argument("-d", "--include-inactive", action="store_true",
        help="Include deprecated and reserved addresses")
    parser.add_argument("--no-scion2ip", action="store_true",
        help="Do not include SCION-mapped IPv6 prefixes")
    parser.add_argument("--anapaya", action="store_true",
        help="Get more detailed ISD and ASN information from Anapaya")
    parser.add_argument("--ripe", action="store_true",
        help="Fetch BGP ASN information from RIPEstat")
    return parser.parse_args()


def fetch_scion_registry(url, schema, page_limit=100):

    resp = requests.get(url, params={"limit": page_limit, "offset": 0})
    resp.raise_for_status()
    json = resp.json()
    jsonschema.validate(instance=json, schema=schema)
    data = json["data"]
    count = json["count"]

    while len(data) < count:
        params = {"limit": page_limit, "offset": len(data)}
        resp = requests.get(url, params=params)
        resp.raise_for_status()
        json = resp.json()
        jsonschema.validate(instance=json, schema=schema)
        assert json["limit"] == params["limit"]
        assert json["offset"] == params["offset"]
        assert json["count"] == count
        data.extend(json["data"])

    for row in data:
        for k, v in row.items():
            if v == "*Hidden*":
                row[k] = None
        row["origin"] = ["registry"]

    return data


def get_registry_asns():
    resp_schema = {
        "type": "object",
        "properties": {
            "data": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "scion_as": {
                            "type": "string",
                        },
                        "as_name": {
                            "type": "string",
                        },
                        "range_bits": {
                            "type": "integer",
                        },
                        "org_name": {
                            "type": ["string", "null"],
                        },
                        "sponsoring_org_name": {
                            "type": ["string", "null"],
                        }
                    }
                }
            },
            "count": {
                "type": "integer",
            },
            "limit": {
                "type": "integer",
            },
            "offset": {
                "type": "integer",
            }
        }
    }
    return fetch_scion_registry(REGISTRY_ASN_URL, resp_schema, page_limit=500)


def get_registry_isds():
    resp_schema = {
        "type": "object",
        "properties": {
            "data": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "isd": {
                            "type": "integer",
                        },
                        "isd_name": {
                            "type": "string",
                        },
                        "trc": {
                            "type": "null", # change to type of TRCs when TRCs become available
                        },
                        "org_name": {
                            "type": ["string", "null"],
                        },
                        "sponsoring_org_name": {
                            "type": ["string", "null"],
                        }
                    }
                }
            },
            "count": {
                "type": "integer",
            },
            "limit": {
                "type": "integer",
            },
            "offset": {
                "type": "integer",
            }
        }
    }
    return fetch_scion_registry(REGISTRY_ISD_URL, resp_schema, page_limit=100)


def get_anapaya_isds(include_inactive=False, include_comments=False):
    resp = requests.get(ANAPAYA_ISD_URL)
    resp.raise_for_status()
    doc = html.fromstring(resp.content)

    def find_table(doc):
        for table in doc.iter("table"):
            for i, tr in enumerate(table.xpath(r".//tr")):
                if i == 0:
                    header = [cl.text_content().lower() for cl in tr.xpath(r".//th")]
                    if header == ["isd", "name", "comment", "trc bundle"]:
                        return table.xpath(r".//tr")[1:]
        return None

    rows = find_table(doc)
    if rows is None:
        raise RuntimeError("Anapaya ISD table is gone")
    raw = [[" ".join(cl.text_content().split()) for cl in tr.xpath(r".//td")] for tr in rows]

    data = []
    for row in raw:
        isd, name, comment, _ = row
        entry = {
            "isd": int(isd),
            "isd_name": name,
            "active": name != "deprecated" and name != "reserved"
        }
        if not entry["active"] and not include_inactive:
            continue
        if include_comments:
            entry["comments"] = {}
            if comment:
                entry["comments"]["anapaya"] = comment
        data.append(entry)
    return data


def get_anapaya_asns(include_inactive=False, include_comments=False):
    resp = requests.get(ANAPAYA_ASN_URL)
    resp.raise_for_status()
    doc = html.fromstring(resp.content)

    def find_table(doc):
        for table in doc.iter("table"):
            for i, tr in enumerate(table.xpath(r".//tr")):
                if i == 0:
                    header = [cl.text_content().lower() for cl in tr.xpath(r".//th")]
                    if header == ["as", "name", "isds", "comment"]:
                        return table.xpath(r".//tr")[1:]
        return None

    rows = find_table(doc)
    if rows is None:
        raise RuntimeError("Anapaya ASN table is gone")
    raw = [[" ".join(cl.text_content().split()) for cl in tr.xpath(r".//td")] for tr in rows]

    data = []
    for row in raw:
        asn, name, isds, comment = row
        entry = {
            "scion_as": asn,
            "as_name": name,
            "range_bits": 0,
            "isds": [int(isd) for isd in isds.split(",") if isd.strip()],
            "active": name != "deprecated" and name != "reserved"
        }
        if not entry["active"] and not include_inactive:
            continue
        if include_comments:
            entry["comments"] = {}
            if comment:
                entry["comments"]["anapaya"] = comment
        data.append(entry)
    return data


def _empty_name(name):
    return name is None or len(name) == 0


def _merge_value(dst, src, key):
    if _empty_name(dst.get(key)) and not _empty_name(src.get(key)):
        dst[key] = src[key]
    return dst


def merge_isds(a, origin_a, b, origin_b):
    def _add_new_entry(merged, e, origin):
        m = {**e}
        if "origin" not in m:
            m["origin"] = []
            if origin not in m["origin"]:
                m["origin"].append(origin)
        merged[int(m["isd"])] = m

    merged = {}
    for e in a:
        _add_new_entry(merged, e, origin_a)

    for e in b:
        isd = int(e["isd"])
        if isd in merged:
            m = merged[isd]
            m = _merge_value(m, e, "isd_name")
            m = _merge_value(m, e, "org_name")
            m = _merge_value(m, e, "sponsoring_org_name")

            if "comments" in e:
                if "comments" not in m:
                    m["comments"] = {}
                m["comments"].update(e["comments"])

            if origin_b not in m["origin"]:
                m["origin"].append(origin_b)

            for k, v in e.items():
                if k not in m:
                    m[k] = v

        else:
            _add_new_entry(merged, e, origin_b)

    return [x[1] for x in sorted(merged.items())]


def merge_asns(a, origin_a, b, origin_b):
    def _add_new_entry(merged, e, origin):
        m = {**e}
        if "origin" not in m:
            m["origin"] = []
            if origin not in m["origin"]:
                m["origin"].append(origin)
        merged[AsnRange(m["scion_as"], m.get("range_bits", 0))] = m

    merged = {}
    for e in a:
        _add_new_entry(merged, e, origin_a)

    for e in b:
        asn = AsnRange(e["scion_as"], e.get("range_bits", 0))
        if asn in merged:
            m = merged[asn]
            m = _merge_value(m, e, "as_name")
            m = _merge_value(m, e, "org_name")
            m = _merge_value(m, e, "sponsoring_org_name")

            if "comments" in e:
                if "comments" not in m:
                    m["comments"] = {}
                m["comments"].update(e["comments"])

            if origin_b not in m["origin"]:
                m["origin"].append(origin_b)

            for k, v in e.items():
                if k not in m:
                    m[k] = v

        else:
            _add_new_entry(merged, e, origin_b)

    return [x[1] for x in sorted(merged.items())]


def enrich_bgp_asns_ripestat(asns):
    def ripestat_lookup(session, asn: int):
        url = urljoin(RIPE_STAT_URL, "as-overview/data.json")
        resp = session.get(url, params={"resource": f"AS{asn}"})
        resp.raise_for_status()
        data = resp.json().get("data", {})
        asn = {
            "asn": asn,
            "as_name": data.get("holder"),
            "bgp_holder": data.get("holder"),
            "bgp_announced": data.get("announced"),
        }
        return asn

    session = requests.session()
    for e in asns:
        try:
            asn = int(e["scion_as"])
        except ValueError:
            continue
        data = ripestat_lookup(session, asn)
        e = _merge_value(e, data, "as_name")
        if data.get("bgp_holder"):
            e["bgp_holder"] = data["bgp_holder"]
        if data.get("bgp_announced"):
            e["bgp_announced"] = data["bgp_announced"]
        if "ripestat" not in e["origin"]:
            e["origin"].append("ripestat")
        time.sleep(0.5)

    return asns


def isd_asn_to_sm_ip(isd, asn, range_bits):
    res = subprocess.run(["scion2ip", f"{isd}-{asn},::0"], capture_output=True)
    if res.returncode != 0:
        print(res.stderr.decode())
        res.check_returncode()
    prefixLen = 56 - range_bits
    try:
        if int(asn) < 2**19:
            assert range_bits == 0
            prefixLen = 40
    except ValueError:
        pass
    return f"{res.stdout.decode().splitlines()[0]}/{prefixLen}"


def main():
    args = parse_args()

    isds = get_registry_isds()
    if args.anapaya:
        anapaya_isds = get_anapaya_isds(args.include_inactive, args.include_comments)
        isds = merge_isds(isds, "registry", anapaya_isds, "anapaya")

    asns = get_registry_asns()
    if args.ripe:
        asns = enrich_bgp_asns_ripestat(asns)
    if args.anapaya:
        anapaya_asns = get_anapaya_asns(args.include_inactive, args.include_comments)
        asns = merge_asns(asns, "registry", anapaya_asns, "anapaya")

    if not args.no_scion2ip:
        for asn in asns:
            if "isds" in asn:
                prefixes = {}
                for isd in asn["isds"]:
                    prefixes[isd] = isd_asn_to_sm_ip(isd, asn["scion_as"], asn["range_bits"])
                asn["prefixes"] = prefixes

    print(r'{"isds": [')
    print(*(json.dumps(isd, ensure_ascii=False) for isd in isds), sep=",\n", end="\n")
    print(r'],')
    print(r'"asns": [')
    print(*(json.dumps(asn, ensure_ascii=False) for asn in asns), sep=",\n", end="\n")
    print(r']}')


if __name__ == "__main__":
    main()
