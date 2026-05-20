`timescale 1ns / 1ps
module tb_top_aegis_zero;
    reg clk;
    reg rst;
    reg packet_valid;
    reg [31:0] src_ip_in;
    reg [31:0] dst_ip_in;
    reg [15:0] src_port_in;
    reg [15:0] dst_port_in;
    reg [7:0] protocol_in;

    wire [31:0] src_ip;
    wire [31:0] dst_ip;
    wire [15:0] src_port;
    wire [15:0] dst_port;
    wire [7:0] protocol;
    wire bloom_pass;
    wire valid_bloom;
    wire [13:0] lhd;
    wire valid_lhd;
    wire [31:0] stored_ip;
    wire valid_bram;
    wire decision;
    wire final_decision;
    wire valid_out;

    integer pass_count;
    integer fail_count;
    integer timeout_count;
    integer i;
    reg [3:0] expected_pipeline;

    top_aegis_zero uut (
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
        .decision(decision),
        .final_decision(final_decision),
        .valid_out(valid_out)
    );

    always #5 clk = ~clk;

    task wait_for_valid_out;
        begin
            timeout_count = 0;
            while ((valid_out !== 1'b1) && (timeout_count < 50)) begin
                @(posedge clk);
                timeout_count = timeout_count + 1;
            end
        end
    endtask

    task send_packet_check;
        input [31:0] ip;
        input expected_bloom;
        input expected_decision;
        input [255:0] name;
        begin
            @(negedge clk);
            packet_valid = 1'b1;
            src_ip_in    = ip;
            dst_ip_in    = 32'hc0a800fe;
            src_port_in  = 16'd1234;
            dst_port_in  = 16'd80;
            protocol_in  = 8'h06;

            @(negedge clk);
            packet_valid = 1'b0;

            @(posedge valid_bloom);
            #1;
            if (bloom_pass !== expected_bloom) begin
                $display("FAIL %-32s ip=%h expected_bloom=%0b got_bloom=%0b", name, ip, expected_bloom, bloom_pass);
                fail_count = fail_count + 1;
            end

            wait_for_valid_out();
            #1;
            if (valid_out !== 1'b1) begin
                $display("FAIL %-32s ip=%h timeout waiting for valid_out", name, ip);
                fail_count = fail_count + 1;
            end else if (final_decision !== expected_decision) begin
                $display("FAIL %-32s ip=%h expected_decision=%0b got_decision=%0b lhd=%0d stored_ip=%h bloom=%0b", name, ip, expected_decision, final_decision, lhd, stored_ip, bloom_pass);
                fail_count = fail_count + 1;
            end else begin
                $display("PASS %-32s ip=%h bloom=%0b decision=%0b lhd=%0d stored_ip=%h", name, ip, bloom_pass, final_decision, lhd, stored_ip);
                pass_count = pass_count + 1;
            end

            @(negedge clk);
        end
    endtask

    task pipeline_burst_check;
        begin
            $display("SC_PIPE: ciag pakietow co cykl");
            expected_pipeline = 4'b1001; // TP, TN, FP-recovery, TP

            @(negedge clk); packet_valid = 1'b1; src_ip_in = 32'h010393ae; dst_ip_in=32'hc0a800fe; src_port_in=16'd1; dst_port_in=16'd80; protocol_in=8'h06;
            @(negedge clk); packet_valid = 1'b1; src_ip_in = 32'hdeadbeef; dst_ip_in=32'hc0a800fe; src_port_in=16'd2; dst_port_in=16'd80; protocol_in=8'h06;
            @(negedge clk); packet_valid = 1'b1; src_ip_in = 32'hc0a80001; dst_ip_in=32'hc0a800fe; src_port_in=16'd3; dst_port_in=16'd80; protocol_in=8'h06;
            @(negedge clk); packet_valid = 1'b1; src_ip_in = 32'h01041f9f; dst_ip_in=32'hc0a800fe; src_port_in=16'd4; dst_port_in=16'd80; protocol_in=8'h06;
            @(negedge clk); packet_valid = 1'b0;

            for (i = 0; i < 4; i = i + 1) begin
                wait_for_valid_out();
                #1;
                if (valid_out !== 1'b1) begin
                    $display("FAIL SC_PIPE output[%0d] timeout", i);
                    fail_count = fail_count + 1;
                end else if (final_decision !== expected_pipeline[3-i]) begin
                    $display("FAIL SC_PIPE output[%0d] expected_decision=%0b got=%0b", i, expected_pipeline[3-i], final_decision);
                    fail_count = fail_count + 1;
                end else begin
                    $display("PASS SC_PIPE output[%0d] decision=%0b", i, final_decision);
                    pass_count = pass_count + 1;
                end
                @(posedge clk);
            end
        end
    endtask

    initial begin
        clk = 1'b0;
        rst = 1'b1;
        packet_valid = 1'b0;
        src_ip_in = 32'h00000000;
        dst_ip_in = 32'h00000000;
        src_port_in = 16'h0000;
        dst_port_in = 16'h0000;
        protocol_in = 8'h00;
        pass_count = 0;
        fail_count = 0;
        timeout_count = 0;
        expected_pipeline = 4'b0000;

        repeat (4) @(negedge clk);
        rst = 1'b0;

        $display("SC_TP: True Positive -> ALLOW");
        send_packet_check(32'h010393ae, 1'b1, 1'b1, "True Positive bram_rules[0]");
        send_packet_check(32'h01041f9f, 1'b1, 1'b1, "True Positive bram_rules[1]");

        $display("SC_TN: True Negative -> DENY");
        send_packet_check(32'hdeadbeef, 1'b0, 1'b0, "True Negative deadbeef");

        $display("SC_FP: False Positive Recovery / bledny LHD -> DENY");
        send_packet_check(32'hc0a80001, 1'b1, 1'b0, "False Positive recovery");

        $display("SC_EDGE: adresy brzegowe -> DENY");
        send_packet_check(32'h00000000, 1'b0, 1'b0, "0.0.0.0");
        send_packet_check(32'hffffffff, 1'b0, 1'b0, "255.255.255.255");

        pipeline_burst_check();

        $display("SUMMARY tb_top_aegis_zero: pass=%0d fail=%0d", pass_count, fail_count);
        if (fail_count != 0) $stop;
        $finish;
    end
endmodule
