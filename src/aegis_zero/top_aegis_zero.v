`timescale 1ns / 1ps
// ============================================================
// top_aegis_zero.v
// Zintegrowany top-level AEGIS-ZERO:
// packet_parser -> bloom_filter -> mphf_lookup -> bram_rule_memory -> decision_unit
//
// Uwagi weryfikacyjne:
// - bloom_pass=0 daje pewne DENY bez odczytu BRAM,
// - bloom_pass=1 uruchamia Warstwe 2,
// - Warstwa 2 koryguje false positive: stored_ip != src_ip -> DENY.
//
// Lacze opoznienia toru (v4 = potokowanie mix32 z rozdzielonym multiply):
//   packet_parser (1) + bloom_filter (6) + mphf_lookup (2)
//   + bram_rule_memory (1) + decision_unit (1) = 11 cykli.
//
// deny_valid_pipe pozostaje 4-bitowe - obie sciezki (DENY i ALLOW)
// startuja z tego samego punktu (valid_bloom), wiec glebsze potokowanie
// Warstwy 1 przesuwa je razem; offset Warstwy 2 (4 cykle) sie nie zmienia.
// ============================================================
module top_aegis_zero (
    input  wire        clk,
    input  wire        rst,

    input  wire        packet_valid,
    input  wire [31:0] src_ip_in,
    input  wire [31:0] dst_ip_in,
    input  wire [15:0] src_port_in,
    input  wire [15:0] dst_port_in,
    input  wire [7:0]  protocol_in,

    output wire [31:0] src_ip,
    output wire [31:0] dst_ip,
    output wire [15:0] src_port,
    output wire [15:0] dst_port,
    output wire [7:0]  protocol,

    output wire        bloom_pass,
    output wire        valid_bloom,

    output wire [13:0] lhd,
    output wire        valid_lhd,
    output wire [31:0] stored_ip,
    output wire        valid_bram,

    output wire        decision,
    output wire        final_decision,
    output wire        valid_out
);

    wire        tuple_valid;
    wire [31:0] src_ip_after_bloom;
    wire [31:0] src_ip_after_mphf;
    wire [31:0] src_ip_after_bram;

    wire        valid_decision_w2;
    wire        decision_w2;

    // Sciezka bloom_pass=0 jest pewnym DENY. Opoznienie 4-cyklowe
    // wyrownuje ja ze sciezka W2: MPHF(2) + BRAM(1) + DECISION(1).
    reg [3:0] deny_valid_pipe;

    packet_parser u_packet_parser (
        .clk(clk),
        .rst(rst),
        .packet_valid(packet_valid),
        .src_ip_in(src_ip_in),
        .dst_ip_in(dst_ip_in),
        .src_port_in(src_port_in),
        .dst_port_in(dst_port_in),
        .protocol_in(protocol_in),
        .src_ip(src_ip),
        .dst_ip(dst_ip),
        .src_port(src_port),
        .dst_port(dst_port),
        .protocol(protocol),
        .tuple_valid(tuple_valid)
    );

    bloom_filter u_bloom_filter (
        .clk(clk),
        .rst(rst),
        .src_ip(src_ip),
        .valid_in(tuple_valid),
        .bloom_pass(bloom_pass),
        .valid_bloom(valid_bloom),
        .src_ip_out(src_ip_after_bloom)
    );

    always @(posedge clk) begin
        if (rst) begin
            deny_valid_pipe <= 4'b0000;
        end else begin
            deny_valid_pipe <= {deny_valid_pipe[2:0], (valid_bloom & ~bloom_pass)};
        end
    end

    mphf_lookup u_mphf_lookup (
        .clk        (clk),
        .rst        (rst),
        .valid_in   (valid_bloom & bloom_pass),
        .src_ip     (src_ip_after_bloom),
        .valid_out  (valid_lhd),
        .idx        (lhd),
        .src_ip_out (src_ip_after_mphf)
    );

    bram_rule_memory u_bram_rule_memory (
        .clk        (clk),
        .rst        (rst),
        .valid_in   (valid_lhd),
        .idx        (lhd),
        .src_ip_in  (src_ip_after_mphf),
        .valid_out  (valid_bram),
        .src_ip_out (src_ip_after_bram),
        .stored_ip  (stored_ip)
    );

    decision_unit u_decision_unit (
        .clk        (clk),
        .rst        (rst),
        .valid_in   (valid_bram),
        .src_ip     (src_ip_after_bram),
        .stored_ip  (stored_ip),
        .valid_out  (valid_decision_w2),
        .decision   (decision_w2)
    );

    assign valid_out      = valid_decision_w2 | deny_valid_pipe[3];
    assign final_decision = valid_decision_w2 ? decision_w2 : 1'b0;
    assign decision       = final_decision;

endmodule
