# Stateful TCP Firewall in Verilog

## Overview
This project implements a **Stateful TCP Firewall** in Verilog that tracks TCP connections using a **BRAM-based state table**. Incoming packets are validated using TCP state transitions, sequence/acknowledgement numbers, connection timeouts, and TCP flags before being allowed or rejected.

---
<img width="376" height="265" alt="image" src="https://github.com/user-attachments/assets/50534750-aedd-4828-add1-53e737898c33" />

## Features
- Stateful TCP connection tracking
- TCP 3-way handshake support
- TCP connection teardown support
- Sequence & Acknowledgement number validation
- TCP timeout management
- BRAM-based state table
- Hash-based lookup
- 8-Way Set Associative organization
- Round Robin replacement policy
- Hash-based stateless policy filter
- CSV-driven packet replay testbench

---





```
Incoming Packet
      │
      ▼
Hash Generation
      │
      ▼
State Table Lookup
      │
 ┌────┴────┐
 │ Match?  │
 └────┬────┘
      │
 Yes  │  No
      ▼
Validate TCP     Stateless Filter
      │               │
      └──────┬────────┘
             ▼
     Allow / Reject / Drop
```

---

## State Table Entry

| Field | Width |
|-------|------:|
| Source IP | 32 |
| Destination IP | 32 |
| Source Port | 16 |
| Destination Port | 16 |
| Protocol | 8 |
| TCP State | 3 |
| Sequence Number | 32 |
| Acknowledgement Number | 32 |
| Expire Time | 64 |
| **Total** | **≈238 bits** |

---

## Memory Organization

- 16 Shards
- 8 Ways per Row
- BRAM-based storage
- Parallel way lookup
- Round Robin write replacement
- One timeout per connection

---

## Hash Function

The firewall hashes the TCP 5-tuple:

- Source IP
- Destination IP
- Source Port
- Destination Port
- Protocol

Both **Forward** and **Reverse** hashes are generated to identify packets from either communication direction.

---

## TCP States

- INVALID
- NEW
- ESTABLISHED
- FIN_WAIT
- CLOSE_WAIT
- TIME_WAIT
- RELATED

---

## Supported TCP Flags

- SYN
- SYN+ACK
- ACK
- FIN
- FIN+ACK
- RST
- PSH
- URG

---

## Timeout Management

| State | Timeout |
|-------|---------|
| NEW | 3600 s |
| ESTABLISHED | 3600 s (refreshed on valid packets) |
| FIN_WAIT | 120 s |
| TIME_WAIT | 30 s |

Expired entries are automatically invalidated.

---

## Stateless Policy Filter

A simplified policy check is implemented using a hash-based filter:

```
hash % 100

0–9   → Reject
10–99 → Allow
```

---

## Round Robin Replacement

When a set is full:

- RR pointer selects the next way.
- New entry overwrites the selected way.
- Pointer advances circularly.

---

## Testbench

The testbench:

- Reads packets from `.mem` generated from CSV.
- Drives packets into the DUT.
- Records ALLOWED / DROPPED / REJECTED results.
- Generates `verilog_results.csv`.
- Produces waveform (`.vcd`) for debugging.

---

## Tools Used

- Verilog HDL
- Xilinx Vivado
- BRAM Inference
- GTKWave / Vivado Simulator

---

## Project Flow

```
CSV Packets
      │
      ▼
Memory File (.mem)
      │
      ▼
Verilog Testbench
      │
      ▼
Stateful Firewall
      │
      ▼
Simulation Results
      │
      ▼
verilog_results.csv
```

---

## Output

Each packet is classified as:

- ALLOWED
- REJECTED
- DROPPED

along with complete simulation statistics.

---
