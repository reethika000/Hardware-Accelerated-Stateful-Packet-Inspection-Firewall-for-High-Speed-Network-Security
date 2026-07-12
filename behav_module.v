`timescale 1ns / 1ps

module stateful_filter #(
    parameter NASSO = 8,
    parameter NSHARDS = 16,
    parameter ADDR_WIDTH = 10,
    parameter TIME_WIDTH = 64
)(
    input wire clk,
    input wire rst,
    input wire packet_valid,
    input wire [31:0] src_ip,
    input wire [31:0] dst_ip,
    input wire [15:0] src_port,
    input wire [15:0] dst_port,
    input wire [7:0] proto,
    input wire [31:0] tcp_seq_num,
    input wire [31:0] tcp_ack_num,
    input wire is_SYN,
    input wire is_ACK,
    input wire is_FIN,
    input wire is_RST,
    input wire is_PSH,
    input wire is_URG,
    input wire [7:0] icmp_type,
    input wire [TIME_WIDTH-1:0] packet_time,
    output reg packet_done,
    output reg packet_allowed,
    output reg packet_dropped,
    output reg packet_rejected,
    output reg [15:0] newConns
);

localparam INVALID = 3'd0;
localparam NEW = 3'd1;
localparam ESTABLISHED = 3'd2;
localparam FIN_WAIT = 3'd3;
localparam CLOSE_WAIT = 3'd4;
localparam TIME_WAIT = 3'd5;
localparam RELATED = 3'd6;

localparam TIMEOUT_INTERVAL = 3600;
localparam FIN_WAIT_INTERVAL = 120;
localparam TIME_WAIT_INTERVAL = 30;
localparam WND_LENGTH = 65535;
localparam UDP_UNREPLIED = 30;
localparam UDP_REPLIED = 180;

localparam SHARD_WIDTH = $clog2(NSHARDS);
localparam ASSO_WIDTH = $clog2(NASSO);
localparam DEPTH = (1 << ADDR_WIDTH);

reg [31:0] mem_src_ip [0:NSHARDS-1][0:DEPTH-1][0:NASSO-1];
reg [31:0] mem_dst_ip [0:NSHARDS-1][0:DEPTH-1][0:NASSO-1];
reg [15:0] mem_src_port [0:NSHARDS-1][0:DEPTH-1][0:NASSO-1];
reg [15:0] mem_dst_port [0:NSHARDS-1][0:DEPTH-1][0:NASSO-1];
reg [7:0] mem_proto [0:NSHARDS-1][0:DEPTH-1][0:NASSO-1];
reg [2:0] mem_state [0:NSHARDS-1][0:DEPTH-1][0:NASSO-1];
reg [31:0] mem_seq [0:NSHARDS-1][0:DEPTH-1][0:NASSO-1];
reg [31:0] mem_ack [0:NSHARDS-1][0:DEPTH-1][0:NASSO-1];
reg [TIME_WIDTH-1:0] mem_expire [0:NSHARDS-1][0:DEPTH-1][0:NASSO-1];
reg [ASSO_WIDTH-1:0] nextWriteIndex [0:NSHARDS-1][0:DEPTH-1];

reg [31:0] hash_val;
reg [31:0] hash_rev;
reg [SHARD_WIDTH-1:0] shard_index;
reg [SHARD_WIDTH-1:0] shard_index_rev;
reg [ADDR_WIDTH-1:0] slot_index;
reg [ADDR_WIDTH-1:0] slot_index_rev;

reg pure_SYN;
reg pure_ACK;
reg pure_FIN;
reg syn_ack;
reg fin_ack;
reg data_pkt;
reg filter_pass;

reg found;
reg forward_match;
reg reverse_match;
integer match_index;
integer s;
integer r;
integer a;
integer idx;

function [31:0] rol32;
    input [31:0] value;
    input integer shift;
    begin
        rol32 = (value << shift) | (value >> (32-shift));
    end
endfunction

function [31:0] lightweight_hash;
    input [31:0] f_src_ip;
    input [31:0] f_dst_ip;
    input [15:0] f_src_port;
    input [15:0] f_dst_port;
    input [7:0] f_proto;
    reg [31:0] ip0;
    reg [31:0] ip1;
    reg [15:0] port0;
    reg [15:0] port1;
    reg [31:0] lane0;
    reg [31:0] lane1;
    reg [31:0] lane2;
    reg [31:0] lane3;
    reg [31:0] t0;
    reg [31:0] t1;
    reg [31:0] h0;
    reg [31:0] h1;
    reg [31:0] h;
    begin
        if (f_src_ip < f_dst_ip) begin
            ip0 = f_src_ip;
            ip1 = f_dst_ip;
            port0 = f_src_port;
            port1 = f_dst_port;
        end
        else begin
            ip0 = f_dst_ip;
            ip1 = f_src_ip;
            port0 = f_dst_port;
            port1 = f_src_port;
        end

        lane0 = ip0;
        lane1 = ip1;
        lane2 = {port0, port1};
        lane3 = f_proto * 32'h01010101;

        lane0 = lane0 ^ rol32(lane0, 5);
        lane1 = lane1 ^ rol32(lane1, 7);
        lane2 = lane2 ^ rol32(lane2, 9);
        lane3 = lane3 ^ rol32(lane3, 13);

        t0 = lane0 ^ lane1;
        t1 = lane2 ^ lane3;

        lane0 = lane0 ^ t1;
        lane1 = lane1 ^ t1;
        lane2 = lane2 ^ t0;
        lane3 = lane3 ^ t0;

        h0 = lane0 ^ lane2;
        h1 = lane1 ^ lane3;

        h = h0 ^ rol32(h1, 16);
        h = h ^ (h >> 16);
        h = h ^ (h >> 13);
        h = h ^ (h >> 7);

        lightweight_hash = h;
    end
endfunction

function connection_match;
    input [SHARD_WIDTH-1:0] f_shard;
    input [ADDR_WIDTH-1:0] f_row;
    input integer f_asso;
    input [31:0] f_src_ip;
    input [31:0] f_dst_ip;
    input [15:0] f_src_port;
    input [15:0] f_dst_port;
    input [7:0] f_proto;
    input [TIME_WIDTH-1:0] f_time;
    begin
        connection_match =
            (mem_state[f_shard][f_row][f_asso] != INVALID) &&
            (f_time <= mem_expire[f_shard][f_row][f_asso]) &&
            (mem_proto[f_shard][f_row][f_asso] == f_proto) &&
            (mem_src_ip[f_shard][f_row][f_asso] == f_src_ip) &&
            (mem_dst_ip[f_shard][f_row][f_asso] == f_dst_ip) &&
            (mem_src_port[f_shard][f_row][f_asso] == f_src_port) &&
            (mem_dst_port[f_shard][f_row][f_asso] == f_dst_port);
    end
endfunction

function stateless_filter;
    input [31:0] f_hash;
    begin
        stateless_filter = ((f_hash % 100) >= 10);
    end
endfunction

task write_new_entry;
    input [SHARD_WIDTH-1:0] t_shard;
    input [ADDR_WIDTH-1:0] t_row;
    input integer t_asso;
    input [TIME_WIDTH-1:0] timeout_value;
    begin
        mem_src_ip[t_shard][t_row][t_asso] <= src_ip;
        mem_dst_ip[t_shard][t_row][t_asso] <= dst_ip;
        mem_src_port[t_shard][t_row][t_asso] <= src_port;
        mem_dst_port[t_shard][t_row][t_asso] <= dst_port;
        mem_proto[t_shard][t_row][t_asso] <= proto;
        mem_state[t_shard][t_row][t_asso] <= NEW;
        mem_seq[t_shard][t_row][t_asso] <= tcp_seq_num;
        mem_ack[t_shard][t_row][t_asso] <= tcp_ack_num;
        mem_expire[t_shard][t_row][t_asso] <= packet_time + timeout_value;
    end
endtask

always @(*) begin
    hash_val = lightweight_hash(src_ip, dst_ip, src_port, dst_port, proto);
    hash_rev = lightweight_hash(dst_ip, src_ip, dst_port, src_port, proto);

    shard_index = hash_val[15:0] % NSHARDS;
    shard_index_rev = hash_rev[15:0] % NSHARDS;
    slot_index = hash_val[31:16] % DEPTH;
    slot_index_rev = hash_rev[31:16] % DEPTH;

    pure_SYN = is_SYN && !is_ACK && !is_FIN && !is_RST;
    pure_ACK = !is_SYN && is_ACK && !is_FIN && !is_RST;
    pure_FIN = !is_SYN && !is_ACK && is_FIN && !is_RST;
    syn_ack = is_SYN && is_ACK;
    fin_ack = is_FIN && is_ACK;
    data_pkt = !is_SYN && !is_FIN && !is_RST && !pure_ACK;
    filter_pass = stateless_filter(hash_val);
end

always @(posedge clk) begin
    if (rst) begin
        packet_done <= 0;
        packet_allowed <= 0;
        packet_dropped <= 0;
        packet_rejected <= 0;
        newConns <= 0;

        for (s = 0; s < NSHARDS; s = s + 1) begin
            for (r = 0; r < DEPTH; r = r + 1) begin
                nextWriteIndex[s][r] <= 0;
                for (a = 0; a < NASSO; a = a + 1) begin
                    mem_src_ip[s][r][a] <= 0;
                    mem_dst_ip[s][r][a] <= 0;
                    mem_src_port[s][r][a] <= 0;
                    mem_dst_port[s][r][a] <= 0;
                    mem_proto[s][r][a] <= 0;
                    mem_state[s][r][a] <= INVALID;
                    mem_seq[s][r][a] <= 0;
                    mem_ack[s][r][a] <= 0;
                    mem_expire[s][r][a] <= 0;
                end
            end
        end
    end
    else begin
        packet_done <= 0;
        packet_allowed <= 0;
        packet_dropped <= 0;
        packet_rejected <= 0;

        if (packet_valid) begin
            packet_done <= 1;
            found = 0;
            forward_match = 0;
            reverse_match = 0;
            match_index = 0;

            if ((is_SYN && is_FIN) ||
                (is_SYN && is_RST) ||
                (is_FIN && is_RST) ||
                (is_FIN && is_PSH && is_URG) ||
                ((proto == 6) && !(is_SYN || is_ACK || is_FIN || is_RST))) begin
                packet_dropped <= 1;
            end
            else if (proto == 6) begin
                if (is_RST) begin
                    for (a = 0; a < NASSO; a = a + 1) begin
                        if (!found && connection_match(
                            shard_index_rev, slot_index_rev, a,
                            dst_ip, src_ip, dst_port, src_port,
                            proto, packet_time
                        )) begin
                            found = 1;
                            reverse_match = 1;
                            match_index = a;

                            if ((mem_state[shard_index_rev][slot_index_rev][a] == NEW) &&
                                (newConns > 0))
                                newConns <= newConns - 1'b1;

                            mem_state[shard_index_rev][slot_index_rev][a] <= INVALID;
                            packet_allowed <= 1;
                        end
                        else if (!found && connection_match(
                            shard_index, slot_index, a,
                            src_ip, dst_ip, src_port, dst_port,
                            proto, packet_time
                        )) begin
                            found = 1;
                            forward_match = 1;
                            match_index = a;

                            if ((mem_state[shard_index][slot_index][a] == NEW) &&
                                (newConns > 0))
                                newConns <= newConns - 1'b1;

                            mem_state[shard_index][slot_index][a] <= INVALID;
                            packet_allowed <= 1;
                        end
                    end

                    if (!found)
                        packet_dropped <= 1;
                end
                else begin
                    for (a = 0; a < NASSO; a = a + 1) begin
                        if (!found && syn_ack &&
                            connection_match(
                                shard_index_rev, slot_index_rev, a,
                                dst_ip, src_ip, dst_port, src_port,
                                proto, packet_time
                            )) begin

                            found = 1;
                            reverse_match = 1;
                            match_index = a;

                            if ((mem_state[shard_index_rev][slot_index_rev][a] == NEW) &&
                                (tcp_ack_num ==
                                mem_seq[shard_index_rev][slot_index_rev][a] + 1'b1)) begin

                                mem_state[shard_index_rev][slot_index_rev][a]
                                    <= ESTABLISHED;
                                mem_expire[shard_index_rev][slot_index_rev][a]
                                    <= packet_time + TIMEOUT_INTERVAL;
                                mem_seq[shard_index_rev][slot_index_rev][a]
                                    <= tcp_seq_num;
                                packet_allowed <= 1;
                            end
                            else begin
                                packet_dropped <= 1;
                            end
                        end

                        if (!found && (pure_ACK || data_pkt) &&
                            connection_match(
                                shard_index, slot_index, a,
                                src_ip, dst_ip, src_port, dst_port,
                                proto, packet_time
                            )) begin

                            found = 1;
                            forward_match = 1;
                            match_index = a;

                            if (((mem_state[shard_index][slot_index][a] == ESTABLISHED) ||
                                 (mem_state[shard_index][slot_index][a] == FIN_WAIT) ||
                                 (mem_state[shard_index][slot_index][a] == CLOSE_WAIT)) &&
                                (tcp_seq_num >=
                                (mem_seq[shard_index][slot_index][a] - WND_LENGTH))) begin

                                if (tcp_seq_num > mem_seq[shard_index][slot_index][a])
                                    mem_seq[shard_index][slot_index][a] <= tcp_seq_num;

                                if (is_ACK &&
                                    tcp_ack_num > mem_ack[shard_index][slot_index][a])
                                    mem_ack[shard_index][slot_index][a] <= tcp_ack_num;

                                mem_expire[shard_index][slot_index][a]
                                    <= packet_time + TIMEOUT_INTERVAL;
                                packet_allowed <= 1;
                            end
                            else begin
                                packet_dropped <= 1;
                            end
                        end

                        if (!found && (pure_ACK || data_pkt) &&
                            connection_match(
                                shard_index_rev, slot_index_rev, a,
                                dst_ip, src_ip, dst_port, src_port,
                                proto, packet_time
                            )) begin

                            found = 1;
                            reverse_match = 1;
                            match_index = a;

                            if (((mem_state[shard_index_rev][slot_index_rev][a] == ESTABLISHED) ||
                                 (mem_state[shard_index_rev][slot_index_rev][a] == FIN_WAIT) ||
                                 (mem_state[shard_index_rev][slot_index_rev][a] == CLOSE_WAIT)) &&
                                (tcp_seq_num >=
                                (mem_seq[shard_index_rev][slot_index_rev][a] - WND_LENGTH))) begin

                                if (tcp_seq_num >
                                    mem_seq[shard_index_rev][slot_index_rev][a])
                                    mem_seq[shard_index_rev][slot_index_rev][a]
                                        <= tcp_seq_num;

                                if (is_ACK &&
                                    tcp_ack_num >
                                    mem_ack[shard_index_rev][slot_index_rev][a])
                                    mem_ack[shard_index_rev][slot_index_rev][a]
                                        <= tcp_ack_num;

                                mem_expire[shard_index_rev][slot_index_rev][a]
                                    <= packet_time + TIMEOUT_INTERVAL;
                                packet_allowed <= 1;
                            end
                            else begin
                                packet_dropped <= 1;
                            end
                        end

                        if (!found && fin_ack &&
                            connection_match(
                                shard_index, slot_index, a,
                                src_ip, dst_ip, src_port, dst_port,
                                proto, packet_time
                            )) begin

                            found = 1;
                            forward_match = 1;
                            match_index = a;

                            if ((tcp_seq_num >=
                                 mem_seq[shard_index][slot_index][a]) &&
                                (tcp_ack_num >=
                                 mem_ack[shard_index][slot_index][a])) begin

                                if ((mem_state[shard_index][slot_index][a] == FIN_WAIT) ||
                                    (mem_state[shard_index][slot_index][a] == CLOSE_WAIT)) begin
                                    mem_state[shard_index][slot_index][a] <= TIME_WAIT;
                                    mem_expire[shard_index][slot_index][a]
                                        <= packet_time + TIME_WAIT_INTERVAL;
                                end

                                mem_seq[shard_index][slot_index][a]
                                    <= tcp_seq_num + 1'b1;
                                mem_ack[shard_index][slot_index][a]
                                    <= tcp_ack_num;
                                packet_allowed <= 1;
                            end
                            else begin
                                packet_dropped <= 1;
                            end
                        end

                        if (!found && fin_ack &&
                            connection_match(
                                shard_index_rev, slot_index_rev, a,
                                dst_ip, src_ip, dst_port, src_port,
                                proto, packet_time
                            )) begin

                            found = 1;
                            reverse_match = 1;
                            match_index = a;

                            if ((tcp_seq_num >=
                                 mem_seq[shard_index_rev][slot_index_rev][a]) &&
                                (tcp_ack_num >=
                                 mem_ack[shard_index_rev][slot_index_rev][a])) begin

                                if (mem_state[shard_index_rev][slot_index_rev][a]
                                    == ESTABLISHED) begin
                                    mem_state[shard_index_rev][slot_index_rev][a]
                                        <= CLOSE_WAIT;
                                    mem_expire[shard_index_rev][slot_index_rev][a]
                                        <= packet_time + FIN_WAIT_INTERVAL;
                                end
                                else if (mem_state[shard_index_rev][slot_index_rev][a]
                                         == FIN_WAIT) begin
                                    mem_state[shard_index_rev][slot_index_rev][a]
                                        <= TIME_WAIT;
                                    mem_expire[shard_index_rev][slot_index_rev][a]
                                        <= packet_time + TIME_WAIT_INTERVAL;
                                end

                                mem_seq[shard_index_rev][slot_index_rev][a]
                                    <= tcp_seq_num + 1'b1;
                                mem_ack[shard_index_rev][slot_index_rev][a]
                                    <= tcp_ack_num;
                                packet_allowed <= 1;
                            end
                            else begin
                                packet_dropped <= 1;
                            end
                        end

                        if (!found && pure_FIN &&
                            connection_match(
                                shard_index, slot_index, a,
                                src_ip, dst_ip, src_port, dst_port,
                                proto, packet_time
                            )) begin

                            found = 1;
                            forward_match = 1;
                            match_index = a;

                            if (tcp_seq_num >=
                                mem_seq[shard_index][slot_index][a]) begin

                                if (mem_state[shard_index][slot_index][a]
                                    == ESTABLISHED) begin
                                    mem_state[shard_index][slot_index][a]
                                        <= FIN_WAIT;
                                    mem_expire[shard_index][slot_index][a]
                                        <= packet_time + FIN_WAIT_INTERVAL;
                                end
                                else if (mem_state[shard_index][slot_index][a]
                                         == CLOSE_WAIT) begin
                                    mem_state[shard_index][slot_index][a]
                                        <= TIME_WAIT;
                                    mem_expire[shard_index][slot_index][a]
                                        <= packet_time + TIME_WAIT_INTERVAL;
                                end

                                mem_seq[shard_index][slot_index][a]
                                    <= tcp_seq_num + 1'b1;
                                packet_allowed <= 1;
                            end
                            else begin
                                packet_dropped <= 1;
                            end
                        end

                        if (!found && pure_FIN &&
                            connection_match(
                                shard_index_rev, slot_index_rev, a,
                                dst_ip, src_ip, dst_port, src_port,
                                proto, packet_time
                            )) begin

                            found = 1;
                            reverse_match = 1;
                            match_index = a;

                            if (tcp_seq_num >=
                                mem_seq[shard_index_rev][slot_index_rev][a]) begin

                                if (mem_state[shard_index_rev][slot_index_rev][a]
                                    == ESTABLISHED) begin
                                    mem_state[shard_index_rev][slot_index_rev][a]
                                        <= CLOSE_WAIT;
                                    mem_expire[shard_index_rev][slot_index_rev][a]
                                        <= packet_time + FIN_WAIT_INTERVAL;
                                end
                                else if (mem_state[shard_index_rev][slot_index_rev][a]
                                         == FIN_WAIT) begin
                                    mem_state[shard_index_rev][slot_index_rev][a]
                                        <= TIME_WAIT;
                                    mem_expire[shard_index_rev][slot_index_rev][a]
                                        <= packet_time + TIME_WAIT_INTERVAL;
                                end

                                mem_seq[shard_index_rev][slot_index_rev][a]
                                    <= tcp_seq_num + 1'b1;
                                packet_allowed <= 1;
                            end
                            else begin
                                packet_dropped <= 1;
                            end
                        end
                    end

                    if (!found &&
                        (syn_ack || pure_FIN || fin_ack || pure_ACK || data_pkt)) begin
                        packet_dropped <= 1;
                    end
                    else if (!found && pure_SYN) begin
                        if (filter_pass) begin
                            idx = nextWriteIndex[shard_index][slot_index];

                            if (mem_state[shard_index][slot_index][idx] != NEW)
                                newConns <= newConns + 1'b1;

                            write_new_entry(
                                shard_index,
                                slot_index,
                                idx,
                                TIMEOUT_INTERVAL
                            );

                            if (idx == NASSO-1)
                                nextWriteIndex[shard_index][slot_index] <= 0;
                            else
                                nextWriteIndex[shard_index][slot_index] <= idx + 1'b1;

                            packet_allowed <= 1;
                        end
                        else begin
                            packet_rejected <= 1;
                        end
                    end
                end
            end
            else begin
                packet_dropped <= 1;
            end
        end
    end
end

endmodule
