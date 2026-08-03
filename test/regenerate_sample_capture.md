# Regenerating the sample capture

This document is the maintenance record for `testdata/sample_capture.pcap`
(and its companion `testdata/ifh_map.txt`). It describes the lab topology,
router configuration, and capture procedure used to produce a single
"golden" capture that exercises every decode path in the tool.

You only need this when the sample capture must be rebuilt — e.g. to cover a
new decode path. To *run* the integration test against the existing capture,
see [README.md](README.md); this document is the *how to regenerate the
input* side of that split.

The procedure needs two back-to-back XRv9K routers and is repeatable: the
configuration is fixed and every traffic-generating step is scripted.

---

## 1. What the capture must contain

Each row maps a decode path to the traffic that exercises it. The check IDs
match the labels printed by `run_integration_test.sh`.

| ID  | Decode path                                    | Traffic that exercises it                        |
| --- | ---------------------------------------------- | ------------------------------------------------ |
| T01 | IS-IS PUNT — 802.3 LLC frame                   | IS-IS IIH received from R2 on Gi0/0/0/0          |
| T02 | IS-IS INJECT — LLC prefix prepended            | IS-IS IIH sent by R1 on Gi0/0/0/0                |
| T03 | IPv4 PUNT — Ethernet II frame                  | BGP TCP received from R2 on Gi0/0/0/0            |
| T04 | IPv4 INJECT                                    | BGP TCP sent by R1; OSPF Hello sent on .100/.200 |
| T05 | IPv6 PUNT — Ethernet II frame                  | ICMPv6 NDP / ping6 reply received on Gi0/0/0/0   |
| T06 | IPv6 INJECT                                    | ICMPv6 NDP / ping6 request sent on Gi0/0/0/0     |
| T07 | ARP PUNT — Ethernet II 0x0806                  | ARP Reply/Request received from R2 on Gi0/0/0/2  |
| T08 | ARP INJECT — pkt_type 36                       | ARP Request/Reply sent by R1 on Gi0/0/0/2        |
| T09 | VLAN subinterface separation                   | OSPF hellos on Gi0/0/0/1.100 and Gi0/0/0/1.200   |
| T10 | Multiple interfaces → multiple IDBs            | Traffic on all four active interfaces            |
| T11 | Interface name from mapping file               | `--iface-map` passed to the tool                 |
| T12 | Hex fallback when no mapping                    | Same capture, tool run without `--iface-map`     |
| T13 | pcapng output format                           | Output file format check                         |
| T14 | Unrecognised packets counted, not dropped      | Summary output inspection                        |

---

## 2. Prerequisites

**On the host where the tool runs:**

- Python 3.8+ (standard library only)
- `tshark` 3.0+ and `capinfos` (both ship with Wireshark) for verification
- SSH access to both routers

**On both XRv9K routers:**

- IOS XR with `tcpdump` available in the XR Linux shell
- Back-to-back physical links on `GigabitEthernet0/0/0/0` through
  `GigabitEthernet0/0/0/2` (at least three links in use)
- `/misc/scratch/` writeable with ≥ 50 MB free

---

## 3. Topology

```
         R1                              R2
  ┌──────────────┐                ┌──────────────┐
  │  Gi0/0/0/0   ├────────────────┤  Gi0/0/0/0   │
  │  10.0.0.1/24 │                │  10.0.0.2/24 │
  │  2001:db8::1 │   IS-IS L2     │  2001:db8::2 │
  │  BGP AS65001 │   BGP AS65002  │  BGP AS65002 │
  ├──────────────┤                ├──────────────┤
  │  Gi0/0/0/1   ├────────────────┤  Gi0/0/0/1   │
  │  (trunk)     │   dot1q trunk  │  (trunk)     │
  │              │                │              │
  │   .100 OSPF  │  dot1q 100     │   .100 OSPF  │
  │  10.1.100.1  ├┄┄┄┄┄┄┄┄┄┄┄┄┄┄┤  10.1.100.2  │
  │   .200 OSPF  │  dot1q 200     │   .200 OSPF  │
  │  10.1.200.1  ├┄┄┄┄┄┄┄┄┄┄┄┄┄┄┤  10.1.200.2  │
  ├──────────────┤                ├──────────────┤
  │  Gi0/0/0/2   ├────────────────┤  Gi0/0/0/2   │
  │  10.2.0.1/24 │   ARP only     │  10.2.0.2/24 │
  └──────────────┘                └──────────────┘

  The capture runs on R1.
```

**Interface address summary:**

| Interface                  | R1             | R2             | Protocols       |
| -------------------------- | -------------- | -------------- | --------------- |
| GigabitEthernet0/0/0/0     | 10.0.0.1/24    | 10.0.0.2/24    | IS-IS, BGP      |
|                            | 2001:db8::1/64 | 2001:db8::2/64 | (IPv6 NDP)      |
| GigabitEthernet0/0/0/1     | (trunk, no IP) | (trunk, no IP) | —               |
| GigabitEthernet0/0/0/1.100 | 10.1.100.1/24  | 10.1.100.2/24  | OSPF area 0     |
| GigabitEthernet0/0/0/1.200 | 10.1.200.1/24  | 10.1.200.2/24  | OSPF area 0     |
| GigabitEthernet0/0/0/2     | 10.2.0.1/24    | 10.2.0.2/24    | none (ARP/ping) |
| Loopback0                  | 1.1.1.1/32     | 2.2.2.2/32     | BGP router-id   |

---

## 4. Router configurations

### 4.1 R1

```
hostname R1
!
interface Loopback0
 ipv4 address 1.1.1.1 255.255.255.255
!
interface GigabitEthernet0/0/0/0
 description to-R2
 ipv4 address 10.0.0.1 255.255.255.0
 ipv6 address 2001:db8::1/64
 no shutdown
!
interface GigabitEthernet0/0/0/1
 description to-R2-trunk
 no shutdown
!
interface GigabitEthernet0/0/0/1.100
 encapsulation dot1q 100
 ipv4 address 10.1.100.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/0/0/1.200
 encapsulation dot1q 200
 ipv4 address 10.1.200.1 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/0/0/2
 description to-R2-arp-only
 ipv4 address 10.2.0.1 255.255.255.0
 no shutdown
!
router isis 1
 is-type level-2-only
 net 49.0001.0000.0000.0001.00
 address-family ipv4 unicast
 !
 interface GigabitEthernet0/0/0/0
  circuit-type level-2-only
  point-to-point
  address-family ipv4 unicast
  !
 !
!
router bgp 65001
 bgp router-id 1.1.1.1
 address-family ipv4 unicast
  network 1.1.1.1/32
 !
 neighbor 10.0.0.2
  remote-as 65002
  address-family ipv4 unicast
  !
 !
!
router ospf 1
 router-id 1.1.1.1
 area 0
  interface GigabitEthernet0/0/0/1.100
  !
  interface GigabitEthernet0/0/0/1.200
  !
 !
!
ssh server vrf default
```

### 4.2 R2

```
hostname R2
!
interface Loopback0
 ipv4 address 2.2.2.2 255.255.255.255
!
interface GigabitEthernet0/0/0/0
 description to-R1
 ipv4 address 10.0.0.2 255.255.255.0
 ipv6 address 2001:db8::2/64
 no shutdown
!
interface GigabitEthernet0/0/0/1
 description to-R1-trunk
 no shutdown
!
interface GigabitEthernet0/0/0/1.100
 encapsulation dot1q 100
 ipv4 address 10.1.100.2 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/0/0/1.200
 encapsulation dot1q 200
 ipv4 address 10.1.200.2 255.255.255.0
 no shutdown
!
interface GigabitEthernet0/0/0/2
 description to-R1-arp-only
 ipv4 address 10.2.0.2 255.255.255.0
 no shutdown
!
router isis 1
 is-type level-2-only
 net 49.0001.0000.0000.0002.00
 address-family ipv4 unicast
 !
 interface GigabitEthernet0/0/0/0
  circuit-type level-2-only
  point-to-point
  address-family ipv4 unicast
  !
 !
!
router bgp 65002
 bgp router-id 2.2.2.2
 address-family ipv4 unicast
  network 2.2.2.2/32
 !
 neighbor 10.0.0.1
  remote-as 65001
  address-family ipv4 unicast
  !
 !
!
router ospf 1
 router-id 2.2.2.2
 area 0
  interface GigabitEthernet0/0/0/1.100
  !
  interface GigabitEthernet0/0/0/1.200
  !
 !
!
ssh server vrf default
```

---

## 5. Capture procedure

The capture runs on **R1**. Steps that generate traffic on **R2** are
marked `[R2]`; all others run on R1 unless stated.

### 5.1 Verify starting state

Before starting the capture, confirm all protocols are established. This
avoids capturing protocol bring-up traffic, which varies run to run.

```
RP/0/RP0/CPU0:R1# show isis neighbors
RP/0/RP0/CPU0:R1# show bgp summary
RP/0/RP0/CPU0:R1# show ospf neighbor
```

Expected: IS-IS adjacency Up, BGP Established, OSPF adjacency Full on both
the `.100` and `.200` subinterfaces.

### 5.2 Start the capture

Enter the XR Linux shell from the R1 exec prompt with `run`, then start
`tcpdump`:

```
RP/0/RP0/CPU0:R1# run
[xr-vm_node0_RP0_CPU0:~]$ tcpdump -U -i eth-vf1.3074 \
    -w /misc/scratch/capture.pcap \
    udp portrange 9910-9923
```

Leave this running for the duration of the procedure. The `-U` flag flushes
each packet immediately, so the file is safe to copy while capture is
running.

### 5.3 Wait for periodic traffic

Allow **60 seconds** with no intervention. During this window:

- IS-IS IIH hellos flow every 10 s in both directions on Gi0/0/0/0 —
  covers T01 and T02.
- BGP KEEPALIVE flows every 60 s — covers T03 and T04 for the KEEPALIVE.
  The session's OPEN/UPDATE were already exchanged at establishment (§5.1).
- OSPF hellos flow every 10 s on `.100` and `.200` — covers T04, T09, T10.

### 5.4 Trigger IPv6 traffic

ICMPv6 NDP may already have been exchanged before the capture started. Force
fresh NDP and add ping6 to guarantee IPv6 PUNT and INJECT appear in the
window. On the R1 XR CLI:

```
RP/0/RP0/CPU0:R1# ping ipv6 2001:db8::2 count 5 timeout 2
```

This generates ICMPv6 Echo Request INJECT and Echo Reply PUNT, and
re-triggers Neighbor Solicitation/Advertisement if the NDP cache entry has
expired.

### 5.5 Trigger ARP (critical step)

ARP only appears in the capture on a cache miss, and the cache is likely
warm after the routing protocols have been up. These steps deliberately
force cache misses on Gi0/0/0/2, which carries no routing protocol traffic
that would silently replenish the cache. Without a deliberate trigger, the
ARP INJECT path (T08) may not be exercised at all.

**Step 1 — ARP INJECT from R1 (ARP Request):**

```
RP/0/RP0/CPU0:R1# clear arp-cache interface GigabitEthernet0/0/0/2
RP/0/RP0/CPU0:R1# ping 10.2.0.2 count 3 timeout 2
```

Outcome in the capture:

- **ARP INJECT**: R1 sends an ARP Request for 10.2.0.2. In the capture this
  is carried with `pkt_type=36`; the tool identifies it by the ARP header
  signature `\x00\x01\x08\x00` (htype Ethernet, ptype IPv4).
- **ARP PUNT**: R2's ARP Reply arrives at R1 as a full Ethernet frame; the
  tool decodes it as Ethernet II EtherType 0x0806.

**Step 2 — ARP INJECT from R1 (ARP Reply), via an R2 ARP Request** `[R2]`:

```
RP/0/RP0/CPU0:R2# clear arp-cache interface GigabitEthernet0/0/0/2
RP/0/RP0/CPU0:R2# ping 10.2.0.1 count 3 timeout 2
```

Outcome in the capture on R1:

- **ARP PUNT**: R2's ARP Request for 10.2.0.1 arrives as a full Ethernet
  broadcast frame (EtherType 0x0806).
- **ARP INJECT**: R1's ARP Reply takes the same `pkt_type=36` path; the same
  `\x00\x01\x08\x00` signature identifies it (the opcode is outside the
  4-byte signature window, so Request and Reply match identically).

After both steps the capture contains ARP Request and ARP Reply in both the
PUNT and INJECT directions.

### 5.6 Stop the capture

Interrupt `tcpdump` with Ctrl-C in the R1 Linux shell, then copy the file to
the host that runs the tool:

```bash
scp <r1-mgmt-ip>:/misc/scratch/capture.pcap .
```

### 5.7 Collect the interface handle map

At the R1 XR exec prompt:

```
RP/0/RP0/CPU0:R1# show pfi-ifh database all location 0/0/CPU0 | include ifh
```

Save the full output to a text file. It contains lines such as:

```
Interface GigabitEthernet0/0/0/0, ifh 0x01000018 (1514)
Interface GigabitEthernet0/0/0/1.100, ifh 0x010000e0 (1518)
Interface GigabitEthernet0/0/0/1.200, ifh 0x010000e8 (1518)
Interface GigabitEthernet0/0/0/2, ifh 0x010000d0 (1514)
```

(Actual handle values differ per router; the tool matches on whatever
appears.)

---

## 6. Install and verify

Place the two files where the integration test expects them:

```bash
cp capture.pcap  testdata/sample_capture.pcap
cp <ifh-map>     testdata/ifh_map.txt
```

Then run the integration test (see [README.md](README.md)) and confirm every
check passes:

```bash
./run_integration_test.sh testdata/sample_capture.pcap testdata/ifh_map.txt
```

A green `ALL CHECKS PASSED` with exit code 0 confirms the regenerated
capture exercises every decode path in the table above.
