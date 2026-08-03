# Tests

Two tiers: a dependency-free unit suite and a `tshark`-based integration
test that runs a real capture through the tool end to end.

## Unit suite

Synthetic in-memory frames exercise every decode path in
`xrv9k_pcap_decode.py`. The only requirement is `pytest`.

```bash
pip install pytest      # if not already available
pytest                  # from the repo root or from test/
```

`conftest.py` adds the repo root to `sys.path` so the tests can import
`xrv9k_pcap_decode` regardless of where `pytest` is invoked from.

## Integration test

`run_integration_test.sh` decodes a committed sample capture and verifies
the resulting pcapng with `tshark` — confirming IS-IS, IPv4/BGP/OSPF,
IPv6/ICMPv6, and ARP all dissect correctly, that per-interface and VLAN
subinterface separation works, and that interface naming and the summary
output behave as expected.

**Requirements:** `python3`, plus `tshark` and `capinfos` (both ship with
Wireshark).

```bash
./run_integration_test.sh testdata/sample_capture.pcap testdata/ifh_map.txt
```

Or from the repo root:

```bash
test/run_integration_test.sh test/testdata/sample_capture.pcap test/testdata/ifh_map.txt
```

It prints a colour-coded PASS/FAIL/WARN line per check and exits 0 only if
all checks pass. The `.pcapng` and `_summary.txt` files it writes next to
the input are regenerated on each run and are git-ignored.

`testdata/` holds the sample capture (`sample_capture.pcap`) and its matching
interface-handle map (`ifh_map.txt`).

### Regenerating the sample capture

The steps above run the test against the committed capture. Rebuilding that
capture from scratch — the lab topology, router configuration, and capture
procedure that produce a `sample_capture.pcap` covering every decode path —
is a separate, occasional maintenance task, documented in
[regenerate_sample_capture.md](regenerate_sample_capture.md). You only need
it when the sample capture must change (for example, to cover a new decode
path).
