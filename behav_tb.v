`timescale 1ns / 1ps

module stateful_filter_tb;

parameter NASSO = 8;
parameter NSHARDS = 16;
parameter ADDR_WIDTH = 10;
parameter TIME_WIDTH = 64;
parameter NUM_TCP_PACKETS = 46;
parameter PACKET_WIDTH = 166;

reg clk;
reg rst;
reg packet_valid;
reg [31:0] src_ip;
reg [31:0] dst_ip;
reg [15:0] src_port;
reg [15:0] dst_port;
reg [7:0] proto;
reg [31:0] tcp_seq_num;
reg [31:0] tcp_ack_num;
reg is_SYN;
reg is_ACK;
reg is_FIN;
reg is_RST;
reg is_PSH;
reg is_URG;
reg [7:0] icmp_type;
reg [TIME_WIDTH-1:0] packet_time;

wire packet_done;
wire packet_allowed;
wire packet_dropped;
wire packet_rejected;
wire [15:0] newConns;

reg [PACKET_WIDTH-1:0] packet_mem [0:NUM_TCP_PACKETS-1];

integer i;
integer result_file;
integer allowed_count;
integer dropped_count;
integer rejected_count;
integer unknown_count;
integer multiple_result_count;
integer total_result_count;

stateful_filter #(
    .NASSO(NASSO),
    .NSHARDS(NSHARDS),
    .ADDR_WIDTH(ADDR_WIDTH),
    .TIME_WIDTH(TIME_WIDTH)
) dut (
    .clk(clk),
    .rst(rst),
    .packet_valid(packet_valid),
    .src_ip(src_ip),
    .dst_ip(dst_ip),
    .src_port(src_port),
    .dst_port(dst_port),
    .proto(proto),
    .tcp_seq_num(tcp_seq_num),
    .tcp_ack_num(tcp_ack_num),
    .is_SYN(is_SYN),
    .is_ACK(is_ACK),
    .is_FIN(is_FIN),
    .is_RST(is_RST),
    .is_PSH(is_PSH),
    .is_URG(is_URG),
    .icmp_type(icmp_type),
    .packet_time(packet_time),
    .packet_done(packet_done),
    .packet_allowed(packet_allowed),
    .packet_dropped(packet_dropped),
    .packet_rejected(packet_rejected),
    .newConns(newConns)
);

always #5 clk = ~clk;

task clear_packet;
begin
    src_ip = 0;
    dst_ip = 0;
    src_port = 0;
    dst_port = 0;
    proto = 0;
    tcp_seq_num = 0;
    tcp_ack_num = 0;
    is_SYN = 0;
    is_ACK = 0;
    is_FIN = 0;
    is_RST = 0;
    is_PSH = 0;
    is_URG = 0;
    icmp_type = 0;
end
endtask

task load_packet;
    input integer index;
begin
    src_ip = packet_mem[index][165:134];
    dst_ip = packet_mem[index][133:102];
    src_port = packet_mem[index][101:86];
    dst_port = packet_mem[index][85:70];
    tcp_seq_num = packet_mem[index][69:38];
    tcp_ack_num = packet_mem[index][37:6];
    is_SYN = packet_mem[index][5];
    is_ACK = packet_mem[index][4];
    is_FIN = packet_mem[index][3];
    is_RST = packet_mem[index][2];
    is_PSH = packet_mem[index][1];
    is_URG = packet_mem[index][0];
    proto = 8'd6;
    icmp_type = 0;
end
endtask

task send_packet;
begin
    @(negedge clk);
    packet_valid = 1'b1;
    @(posedge clk);
    #1;
    packet_valid = 1'b0;
end
endtask

task print_packet;
    input integer packet_number;
begin
    $display("");
    $display("PACKET %0d", packet_number);
    $display("SRC IP  = %0d.%0d.%0d.%0d",
        src_ip[31:24],
        src_ip[23:16],
        src_ip[15:8],
        src_ip[7:0]);
    $display("DST IP  = %0d.%0d.%0d.%0d",
        dst_ip[31:24],
        dst_ip[23:16],
        dst_ip[15:8],
        dst_ip[7:0]);
    $display("PORTS   = %0d -> %0d", src_port, dst_port);
    $display("SEQ     = %0d", tcp_seq_num);
    $display("ACK     = %0d", tcp_ack_num);
    $display(
        "FLAGS   SYN=%b ACK=%b FIN=%b RST=%b PSH=%b URG=%b",
        is_SYN,
        is_ACK,
        is_FIN,
        is_RST,
        is_PSH,
        is_URG
    );
end
endtask

task write_csv_row;
    input integer packet_number;
    input [8*16-1:0] result;
begin
    $fwrite(
        result_file,
        "%0d,%h,%h,%0d,%0d,%0d,%0d,%b,%b,%b,%b,%b,%b,%0s\n",
        packet_number,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        tcp_seq_num,
        tcp_ack_num,
        is_SYN,
        is_ACK,
        is_FIN,
        is_RST,
        is_PSH,
        is_URG,
        result
    );
end
endtask

initial begin
    $dumpfile("stateful_filter_tb.vcd");
    $dumpvars(0, stateful_filter_tb);

    clk = 0;
    rst = 1;
    packet_valid = 0;
    packet_time = 64'd1000;

    allowed_count = 0;
    dropped_count = 0;
    rejected_count = 0;
    unknown_count = 0;
    multiple_result_count = 0;
    total_result_count = 0;

    clear_packet;

    $readmemh(
        "D:/btp/a_june23/tcp_packets.mem",
        packet_mem
    );

    result_file = $fopen(
        "verilog_results.csv",
        "w"
    );

    if (result_file == 0) begin
        $display("ERROR: could not create verilog_results.csv");
        $finish;
    end

    $fwrite(
        result_file,
        "packet,src_ip,dst_ip,src_port,dst_port,seq,ack,syn,ack_flag,fin,rst,psh,urg,result\n"
    );

    repeat (2) @(posedge clk);

    @(negedge clk);
    rst = 0;

    for (i = 0; i < NUM_TCP_PACKETS; i = i + 1) begin
        load_packet(i);

        print_packet(i + 1);

        send_packet;

        total_result_count =
            packet_allowed +
            packet_dropped +
            packet_rejected;

        if (total_result_count > 1) begin
            multiple_result_count = multiple_result_count + 1;

            $display(
                "RESULT  = ERROR: MULTIPLE RESULTS"
            );

            $display(
                "allowed=%b dropped=%b rejected=%b",
                packet_allowed,
                packet_dropped,
                packet_rejected
            );

            write_csv_row(
                i + 1,
                "MULTIPLE"
            );
        end
        else if (packet_allowed) begin
            allowed_count = allowed_count + 1;

            $display("RESULT  = ALLOWED");

            write_csv_row(
                i + 1,
                "ALLOWED"
            );
        end
        else if (packet_rejected) begin
            rejected_count = rejected_count + 1;

            $display("RESULT  = REJECTED");

            write_csv_row(
                i + 1,
                "REJECTED"
            );
        end
        else if (packet_dropped) begin
            dropped_count = dropped_count + 1;

            $display("RESULT  = DROPPED");

            write_csv_row(
                i + 1,
                "DROPPED"
            );
        end
        else begin
            unknown_count = unknown_count + 1;

            $display("RESULT  = UNKNOWN");

            $display(
                "done=%b allowed=%b dropped=%b rejected=%b",
                packet_done,
                packet_allowed,
                packet_dropped,
                packet_rejected
            );

            $display(
                "DUT found=%b forward_match=%b reverse_match=%b match_index=%0d",
                dut.found,
                dut.forward_match,
                dut.reverse_match,
                dut.match_index
            );

            $display(
                "DUT pure_SYN=%b pure_ACK=%b pure_FIN=%b syn_ack=%b fin_ack=%b data_pkt=%b",
                dut.pure_SYN,
                dut.pure_ACK,
                dut.pure_FIN,
                dut.syn_ack,
                dut.fin_ack,
                dut.data_pkt
            );

            write_csv_row(
                i + 1,
                "UNKNOWN"
            );
        end

        packet_time = packet_time + 1;
    end

    $fclose(result_file);

    $display("");
    $display("================================");
    $display("FINAL VERIFICATION RESULTS");
    $display("================================");
    $display(
        "TOTAL TCP PACKETS = %0d",
        NUM_TCP_PACKETS
    );
    $display(
        "ALLOWED           = %0d",
        allowed_count
    );
    $display(
        "DROPPED           = %0d",
        dropped_count
    );
    $display(
        "REJECTED          = %0d",
        rejected_count
    );
    $display(
        "UNKNOWN           = %0d",
        unknown_count
    );
    $display(
        "MULTIPLE RESULTS  = %0d",
        multiple_result_count
    );
    $display(
        "NEW CONNECTIONS   = %0d",
        newConns
    );
    $display("--------------------------------");
    $display(
        "RESULT TOTAL      = %0d",
        allowed_count +
        dropped_count +
        rejected_count +
        unknown_count +
        multiple_result_count
    );

    if (
        allowed_count +
        dropped_count +
        rejected_count +
        unknown_count +
        multiple_result_count
        == NUM_TCP_PACKETS
    )
        $display("PASS: all packets accounted for");
    else
        $display("FAIL: packet count mismatch");

    if (unknown_count == 0)
        $display("PASS: no UNKNOWN packets");
    else
        $display(
            "FAIL: %0d UNKNOWN packets",
            unknown_count
        );

    if (multiple_result_count == 0)
        $display("PASS: no multiple-result packets");
    else
        $display(
            "FAIL: %0d packets had multiple results",
            multiple_result_count
        );

    $display("");
    $display(
        "Results written to verilog_results.csv"
    );

    #20;
    $finish;
end

endmodule
