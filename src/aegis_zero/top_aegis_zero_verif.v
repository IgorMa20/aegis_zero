`timescale 1ns / 1ps
// Wrapper zgodnosci dla starszych skryptow Osoby 4.
// Wlasciwa zintegrowana implementacja jest w top_aegis_zero.v.
module top_aegis_zero_verif (
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
    output wire        final_decision,
    output wire        valid_out
);
    wire decision_unused;

    top_aegis_zero u_top (
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
        .bloom_pass(bloom_pass),
        .valid_bloom(valid_bloom),
        .lhd(lhd),
        .valid_lhd(valid_lhd),
        .stored_ip(stored_ip),
        .valid_bram(valid_bram),
        .decision(decision_unused),
        .final_decision(final_decision),
        .valid_out(valid_out)
    );
endmodule
