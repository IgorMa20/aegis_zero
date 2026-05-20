`timescale 1ns / 1ps
module tb_bloom_filter_checked;
    reg clk;
    reg rst;
    reg [31:0] src_ip;
    reg valid_in;

    wire bloom_pass;
    wire valid_bloom;

    integer pass_count;
    integer fail_count;

    bloom_filter uut (
        .clk(clk),
        .rst(rst),
        .src_ip(src_ip),
        .valid_in(valid_in),
        .bloom_pass(bloom_pass),
        .valid_bloom(valid_bloom)
    );

    always #5 clk = ~clk;

    task check_ip;
        input [31:0] ip;
        input expected_pass;
        input [255:0] name;
        begin
            @(negedge clk);
            src_ip   = ip;
            valid_in = 1'b1;
            @(negedge clk);
            valid_in = 1'b0;

            @(posedge valid_bloom);
            #1;
            if (bloom_pass !== expected_pass) begin
                $display("FAIL %-32s ip=%h expected_bloom=%0b got=%0b", name, ip, expected_pass, bloom_pass);
                fail_count = fail_count + 1;
            end else begin
                $display("PASS %-32s ip=%h bloom=%0b", name, ip, bloom_pass);
                pass_count = pass_count + 1;
            end
        end
    endtask

    initial begin
        clk = 1'b0;
        rst = 1'b1;
        src_ip = 32'h00000000;
        valid_in = 1'b0;
        pass_count = 0;
        fail_count = 0;

        repeat (3) @(negedge clk);
        rst = 1'b0;

        check_ip(32'h010393ae, 1'b1, "TP bram_rules[0]");
        check_ip(32'h01041f9f, 1'b1, "TP bram_rules[1]");
        check_ip(32'h010b94af, 1'b1, "TP bram_rules[2]");
        check_ip(32'hc0a80001, 1'b1, "FP candidate W2 recovery");
        check_ip(32'hdeadbeef, 1'b0, "TN deadbeef");
        check_ip(32'h00000000, 1'b0, "edge 0.0.0.0");
        check_ip(32'hffffffff, 1'b0, "edge 255.255.255.255");

        $display("SUMMARY tb_bloom_filter_checked: pass=%0d fail=%0d", pass_count, fail_count);
        if (fail_count != 0) $stop;
        $finish;
    end
endmodule
