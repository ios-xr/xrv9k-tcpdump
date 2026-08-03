# xrv9k-tcpdump

Decode an XRv9K `tcpdump` punt/inject capture into a standard pcapng file
that Wireshark and other packet analysers can read.

On XRv9K, XR-native control-plane traffic (BGP, IS-IS, OSPF, ICMPv6, ARP,
…) is punted to and injected from the CPU as UDP datagrams on an internal
IPC interface, each wrapped in a proprietary header. A raw `tcpdump`
capture of that traffic is therefore not directly decodable. `xrv9k_pcap_decode.py`
strips the wrapper and re-emits each frame as a `DLT_LINUX_SLL` packet in a
pcapng file, grouped per interface, so any standard tool can dissect it.

The tool is pure Python 3 standard library — no dependencies to install.

## Capture

Run these on the router, then copy the results to wherever you run the tool.

1. **Enter the XR Linux shell.** From the router exec prompt, type `run`:

   ```
   RP/0/RP0/CPU0:router# run
   [xr-vm_node0_RP0_CPU0:~]$
   ```

2. **Capture the punt/inject traffic** in that Linux shell:

   ```bash
   tcpdump -U -i eth-vf1.3074 -w /misc/scratch/capture.pcap udp portrange 9910-9923
   ```

   `eth-vf1.3074` is the internal IPC (`GUEST_CTRL_ETH`) interface; ports
   9910–9923 cover the four punt/inject priority queues. Stop the capture
   with Ctrl-C once you have collected enough traffic, then copy it off:

   ```bash
   scp router:/misc/scratch/capture.pcap .
   ```

3. **Collect the interface-handle → name mapping** (optional but
   recommended — it labels the pcapng interfaces with their XR names). Run
   this at the XR exec prompt — type `exit` to leave the Linux shell first,
   or use a separate session:

   ```
   RP/0/RP0/CPU0:router# show pfi-ifh database all location 0/0/CPU0 | include ifh
   ```

   Save the output to a text file, e.g. `ifh_map.txt`.

`python3 xrv9k_pcap_decode.py --help-capture` prints these instructions.

## Usage

```bash
python3 xrv9k_pcap_decode.py -m ifh_map.txt capture.pcap
```

This writes `capture.pcapng` alongside the input. Open it in Wireshark, or:

```bash
tshark -r capture.pcapng
```

```
usage: xrv9k_pcap_decode.py [-h] [-m FILE] [-o FILE] [-v] [--help-capture] [INPUT]

positional arguments:
  INPUT                 input .pcap file collected from the router

options:
  -m, --iface-map FILE  handle-to-name mapping file (see --help-capture)
  -o, --output FILE     output .pcapng file (default: INPUT with .pcapng suffix)
  -v, --verbose         print one line per decoded packet to stderr
  --help-capture        print router collection instructions and exit
```

Without `-m`, interfaces are named `if-<handle>` (e.g. `if-0x01000018`);
the pcapng is otherwise identical.

## Scope and limitations

- Decodes IPv4, IPv6, IS-IS, and ARP control-plane traffic in both the
  PUNT (received) and INJECT (sent) directions.
  - Note: most ARP does not appear in these captures — ARP transmitted and
    ARP requests received are generally absent, and only some received ARP
    replies show up. The tool decodes whatever ARP is present, but do not
    expect a complete ARP exchange.
- **BFD is not supported** — BFD traffic is carried on separate ports and
  is not decoded.
- Provided **as-is**, with no formal support or warranty.

## Background

For an introduction to control-plane packet capture with `tcpdump` on
IOS-XR, see the xrdocs.io article
[Use tcpdump on eXR for control plane troubleshooting — part 1](https://xrdocs.io/ncs5500/tutorials/use-tcpdump-on-exr-for-control-plane-troubleshooting-part1).

## Tests

See [test/README.md](test/README.md).

## License

Distributed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for
the full text.
