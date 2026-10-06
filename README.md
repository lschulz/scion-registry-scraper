SCION Registry Scraper
======================

This Python script downloads the list of registered SCION ISDs and ASNs from the
SCION Registry's public API [1]. Optionally, the list can be augmented with
information provided by Anapaya Systems [2]. As SCION allows registering BGP
ASNs for use with SCION, the script can also query RIPEstat [3] for additional
information on those ASes. The rate at which RIPEstat is queried is capped to 2
request/second. Results are written to stdout as JSON.

If the AS membership in ISDs is known (currently requires --anapaya), the result
will contain SCION-mapped IPv6 prefixes for each AS. Generating these prefixes
requires access to the scion2ip tool [4]. This can be disabled with `--no-scion2ip`.

[1] https://registry.scion.org/api/v1/ <br>
[2] https://learn.anapaya.net/docs/resources/assignments/isds/ and https://learn.anapaya.net/docs/resources/assignments/ases/ <br>
[3] https://stat.ripe.net/ <br>
[4] https://github.com/lschulz/scion-cpp/tree/main/scitra/tools/scion2ip <br>

## Usage ##

```bash
# Make sure you have the required packages (jsonschema, requests, lxml) installed, e.g., in a venv.
python3 -m venv .venv
. .venv/bin/activate
pip install jsonschema requests lxml

./scrape_registry.py --anapaya | tee registry.json
```

Fetching the data from Anapaya is recommended, as Anapaya publishes ISD
memberships which are missing from the SCION Registry.

Some sources provide plain text comments which are not included in the output
by default. To include them, pass the `-c/--include-comments` option.

Some sources list ISDs and/or ASNs that are no longer in use or have been
reserved for future use. These are normally not included in the result, to
include them, pass the `-d/--include-inactive` option.

## Example Output ##

The output of `./scrape_registry.py -cd --anapaya --ripe` as executed on
October 6, 2026 is provided in `data/registry-2026-10-06.json`.

## jq Recipes ##

The resulting JSON file can be inspected with jq.

Pretty-print all ISDs/ASNs.
```bash
jq '.isds[]' registry.json
jq '.asns[]' registry.json
```

Filter by AS name.
```bash
jq --arg name Otto '.asns[] | select(.as_name // "" | contains($name))' registry.json
```

Filter by membership in ISD 71.
```bash
jq --argjson isd 71 '.asns[] | select(.isds // {} | any(contains($isd)))' registry.json
```

Filter by SCION-mapped IPv6 prefix.
```bash
jq --arg p "fc04:7e00:" '.asns[] | select((.prefixes // {}) | any(.[]; startswith($p)))' registry.json
```

Filter for ASNs that are registered with the registry or are not registered.
```bash
jq --arg o registry '.asns[] | select(any(.origin[]?; . == $o))' registry.json
jq --arg o registry '.asns[] | select(any(.origin[]?; . == $o) | not)' registry.json
```
