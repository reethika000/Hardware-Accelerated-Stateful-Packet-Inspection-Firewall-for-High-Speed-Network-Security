# Stateful TCP Firewall Model – Documentation

## Overview

This implementation models a simplified hardware-based stateful TCP firewall in Verilog. The design maintains connection state information in an internal memory and processes one packet at a time. Incoming packets are classified based on TCP flags, protocol number, stored connection information, sequence numbers, acknowledgment numbers, and connection timeout information.

Only TCP packets (`proto = 6`) are processed by the state machine. Any non-TCP packet is dropped.

---

# Module Parameters

| Parameter  | Description                                      | Default |
| ---------- | ------------------------------------------------ | ------- |
| NASSO      | Number of associative entries per table location | 8       |
| NSHARDS    | Number of state table shards                     | 16      |
| ADDR_WIDTH | Address width of each shard                      | 10      |
| TIME_WIDTH | Width of packet timestamp                        | 64      |

The depth of each shard is

```
DEPTH = 2^ADDR_WIDTH
```

For the default configuration,

* Number of shards = 16
* Rows per shard = 1024
* Associativity = 8

---

# Module Inputs

| Signal       | Width      | Description                                                 |
| ------------ | ---------- | ----------------------------------------------------------- |
| clk          | 1          | System clock                                                |
| rst          | 1          | Active-high synchronous reset                               |
| packet_valid | 1          | Indicates a valid packet is present                         |
| src_ip       | 32         | Source IPv4 address                                         |
| dst_ip       | 32         | Destination IPv4 address                                    |
| src_port     | 16         | TCP source port                                             |
| dst_port     | 16         | TCP destination port                                        |
| proto        | 8          | IP protocol number                                          |
| tcp_seq_num  | 32         | TCP sequence number                                         |
| tcp_ack_num  | 32         | TCP acknowledgement number                                  |
| is_SYN       | 1          | SYN flag                                                    |
| is_ACK       | 1          | ACK flag                                                    |
| is_FIN       | 1          | FIN flag                                                    |
| is_RST       | 1          | RST flag                                                    |
| is_PSH       | 1          | PSH flag                                                    |
| is_URG       | 1          | URG flag                                                    |
| icmp_type    | 8          | Present in the interface but not used by the implementation |
| packet_time  | TIME_WIDTH | Current packet timestamp                                    |

---

# Module Outputs

| Signal          | Description                                  |
| --------------- | -------------------------------------------- |
| packet_done     | Packet processing completed                  |
| packet_allowed  | Packet accepted                              |
| packet_dropped  | Packet dropped                               |
| packet_rejected | Packet rejected by stateless filter          |
| newConns        | Number of connections currently in NEW state |

---

# Connection States

The firewall stores one of the following connection states.

| State       | Value |
| ----------- | ----- |
| INVALID     | 0     |
| NEW         | 1     |
| ESTABLISHED | 2     |
| FIN_WAIT    | 3     |
| CLOSE_WAIT  | 4     |
| TIME_WAIT   | 5     |
| RELATED     | 6     |

Only the above state values are defined in the implementation.

---

# State Table Organization

Each state table entry stores

* Source IP
* Destination IP
* Source Port
* Destination Port
* Protocol
* Connection State
* TCP Sequence Number
* TCP Acknowledgement Number
* Expiration Time

The table is implemented as

```
16 Shards
        ↓
1024 Rows per Shard
        ↓
8-Way Associative Entries
```

Each row also maintains a round-robin pointer (`nextWriteIndex`) used when inserting a new connection.

---

# Hashing

The function `lightweight_hash()` computes a 32-bit hash from

* Source IP
* Destination IP
* Source Port
* Destination Port
* Protocol

The function first orders the IP addresses and ports before hashing so that both communication directions generate the same hash value.

The computed hash is divided as

```
Lower 16 bits
    ↓
Shard Index

Upper 16 bits
    ↓
Row Index
```

The final indices are computed as

```
shard_index     = hash_val[15:0] % NSHARDS
slot_index      = hash_val[31:16] % DEPTH

shard_index_rev = hash_rev[15:0] % NSHARDS
slot_index_rev  = hash_rev[31:16] % DEPTH
```

---

# Stateless Filter

Before inserting a new TCP connection, the hash value is passed through

```
stateless_filter()
```

The implementation is

```
(f_hash % 100) >= 10
```

Connections satisfying the condition are accepted by the stateless filter.

Connections failing the condition are rejected.

---

# Packet Classification

The following packet types are generated from the TCP flags.

| Packet Type | Condition                                         |
| ----------- | ------------------------------------------------- |
| pure_SYN    | SYN only                                          |
| pure_ACK    | ACK only                                          |
| pure_FIN    | FIN only                                          |
| syn_ack     | SYN and ACK                                       |
| fin_ack     | FIN and ACK                                       |
| data_pkt    | Packet without SYN, FIN or RST and not a pure ACK |

---

# Packet Processing

For every valid packet:

1. Packet status outputs are cleared.
2. Hash values are calculated.
3. Forward and reverse lookup locations are generated.
4. Packet type is identified.
5. Invalid TCP flag combinations are checked.
6. Only TCP packets (`proto == 6`) are processed.

---

## Invalid Packets

The following packets are immediately dropped.

* SYN + FIN
* SYN + RST
* FIN + RST
* FIN + PSH + URG
* TCP packets containing none of SYN, ACK, FIN or RST

---

## RST Packet

When a packet contains the RST flag,

* Reverse direction lookup is performed first.
* If a match is found, the entry state is changed to INVALID.
* If the connection was in NEW state, `newConns` is decremented.
* If no reverse match is found, forward lookup is performed.
* If a forward match is found, the same operations are performed.
* If neither lookup succeeds, the packet is dropped.

---

## SYN+ACK Packet

The firewall searches the reverse direction.

If

* a matching connection exists,
* the stored state is NEW,
* and

```
tcp_ack_num == stored_sequence_number + 1
```

then

* state changes to ESTABLISHED,
* expiration time is refreshed,
* stored sequence number is updated,
* packet is allowed.

Otherwise the packet is dropped.

---

## ACK and Data Packets

Both forward and reverse directions are checked.

Packets are accepted only when

* the stored state is ESTABLISHED, FIN_WAIT or CLOSE_WAIT,
* the received sequence number is within the allowed receive window.

When accepted,

* stored sequence number may be updated,
* stored acknowledgement number may be updated,
* timeout is refreshed,
* packet is allowed.

Otherwise the packet is dropped.

---

## FIN+ACK Packet

Both directions are checked.

If sequence and acknowledgement numbers satisfy the stored values,

the connection state is updated according to the current state.

Possible transitions are

* FIN_WAIT → TIME_WAIT
* CLOSE_WAIT → TIME_WAIT
* ESTABLISHED → CLOSE_WAIT

The expiration timer is updated according to the transition.

---

## FIN Packet

Both directions are checked.

Depending on the stored state,

possible transitions are

* ESTABLISHED → FIN_WAIT
* CLOSE_WAIT → TIME_WAIT
* ESTABLISHED → CLOSE_WAIT
* FIN_WAIT → TIME_WAIT

The stored sequence number is incremented and the timeout is updated.

---

## New SYN Packet

If no existing connection is found and the packet is a pure SYN,

the stateless filter is evaluated.

If the filter passes,

* the current round-robin position is selected,
* the new connection is written,
* state is initialized to NEW,
* expiration time is initialized,
* the round-robin pointer advances,
* packet is allowed.

If the filter fails,

the packet is rejected.

---

## Non-TCP Packets

Packets with any protocol value other than 6 are dropped.

---

# Testbench

The supplied testbench verifies the firewall using 46 TCP packets stored in an external memory file.

The packet memory is declared as

```
reg [165:0] packet_mem [0:45];
```

Each packet contains

* Source IP
* Destination IP
* Source Port
* Destination Port
* TCP Sequence Number
* TCP Acknowledgement Number
* SYN
* ACK
* FIN
* RST
* PSH
* URG

The packets are loaded using

```
$readmemh("tcp_packets.mem", packet_mem);
```

For every packet the testbench

1. Loads packet fields.
2. Prints packet information.
3. Asserts `packet_valid` for one clock cycle.
4. Waits for the module response.
5. Records exactly one of

* ALLOWED
* DROPPED
* REJECTED
* UNKNOWN
* MULTIPLE

The result is written into

```
verilog_results.csv
```

---

# Verification Statistics

The testbench maintains counters for

* Allowed packets
* Dropped packets
* Rejected packets
* Unknown packets
* Multiple-result packets

After all packets have been processed it reports

* Total packets
* Result distribution
* Current value of `newConns`
* Verification status indicating whether all packets were accounted for, whether any UNKNOWN packets occurred, and whether any packet produced multiple simultaneous results.

---

