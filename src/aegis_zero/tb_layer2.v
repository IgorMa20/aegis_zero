`timescale 1ns / 1ps


module tb_layer2;

    reg         clk;
    reg         valid_in;
    reg  [31:0] src_ip;

    wire        valid_lhd;
    wire [13:0] lhd;
    wire [31:0] src_ip_after_mphf;

    wire        valid_bram;
    wire [31:0] src_ip_after_bram;
    wire [31:0] stored_ip;

    wire        valid_out;
    wire        decision;

    integer pass_count;
    integer fail_count;
    integer timeout_count;

    mphf_lookup u_mphf_lookup (
        .clk        (clk),
        .valid_in   (valid_in),
        .src_ip     (src_ip),
        .valid_out  (valid_lhd),
        .idx        (lhd),
        .src_ip_out (src_ip_after_mphf)
    );

    bram_rule_memory u_bram_rule_memory (
        .clk        (clk),
        .valid_in   (valid_lhd),
        .idx        (lhd),
        .src_ip_in  (src_ip_after_mphf),
        .valid_out  (valid_bram),
        .src_ip_out (src_ip_after_bram),
        .stored_ip  (stored_ip)
    );

    decision_unit u_decision_unit (
        .clk        (clk),
        .valid_in   (valid_bram),
        .src_ip     (src_ip_after_bram),
        .stored_ip  (stored_ip),
        .valid_out  (valid_out),
        .decision   (decision)
    );

    always #5 clk = ~clk;

    task wait_for_valid_out;
        begin
            timeout_count = 0;
            #1;
            while ((valid_out !== 1'b1) && (timeout_count < 10)) begin
                @(posedge clk);
                #1;
                timeout_count = timeout_count + 1;
            end
        end
    endtask

    task send_and_check;
        input [31:0]  ip;
        input         expected_dec;
        input [255:0] name;
        begin
            @(negedge clk);
            src_ip   = ip;
            valid_in = 1'b1;

            @(negedge clk);
            valid_in = 1'b0;

            wait_for_valid_out();

            if (valid_out !== 1'b1) begin
                $display("FAIL %-36s ip=%h  timeout waiting for valid_out",
                         name, ip);
                fail_count = fail_count + 1;
            end else if (decision !== expected_dec) begin
                $display("FAIL %-36s ip=%h  expected=%b got=%b  lhd=%0d stored_ip=%h",
                         name, ip, expected_dec, decision, lhd, stored_ip);
                fail_count = fail_count + 1;
            end else begin
                $display("PASS %-36s ip=%h  decision=%b  lhd=%0d stored_ip=%h",
                         name, ip, decision, lhd, stored_ip);
                pass_count = pass_count + 1;
            end

            repeat (2) @(negedge clk);
        end
    endtask

    initial begin
        clk        = 1'b0;
        valid_in   = 1'b0;
        src_ip     = 32'h00000000;
        pass_count = 0;
        fail_count = 0;
        timeout_count = 0;

        repeat (4) @(negedge clk);

        $display("--- TC-W2-01..03: True Positive -> ALLOW ---");
        send_and_check(32'h010393ae, 1'b1, "TC-W2-01 TP bram_rules[0]");
        send_and_check(32'h01041f9f, 1'b1, "TC-W2-02 TP bram_rules[1]");
        send_and_check(32'h010b94af, 1'b1, "TC-W2-03 TP bram_rules[2]");

        $display("--- TC-W2-04..05: True Negative -> DENY ---");
        send_and_check(32'hdeadbeef, 1'b0, "TC-W2-04 TN deadbeef");
        send_and_check(32'hc0ffee00, 1'b0, "TC-W2-05 TN c0ffee00");

        $display("--- TC-W2-06: Adres 0.0.0.0 -> DENY ---");
        send_and_check(32'h00000000, 1'b0, "TC-W2-06 EDGE 0.0.0.0");

        $display("--- TC-W2-07: Adres 255.255.255.255 -> DENY ---");
        send_and_check(32'hffffffff, 1'b0, "TC-W2-07 EDGE 255.255.255.255");

        $display("--- TC-W2-08: Loopback 127.0.0.1 -> DENY ---");
        send_and_check(32'h7f000001, 1'b0, "TC-W2-08 EDGE loopback");

        $display("--- TC-W2-09..10: False Positive -> DENY ---");
        send_and_check(32'haabbccdd, 1'b0, "TC-W2-09 FP aabbccdd");
        send_and_check(32'h12345678, 1'b0, "TC-W2-10 FP 12345678");

        $display("--- Dodatkowe True Positive ---");
        send_and_check(32'h010d438f, 1'b1, "TP bram_rules[3]");
        send_and_check(32'h011cbc1a, 1'b1, "TP bram_rules[4]");

        $display("--- Dodatkowe False Positive -> DENY ---");
        send_and_check(32'hfedcba98, 1'b0, "FP fedcba98");
        send_and_check(32'h0a0b0c0d, 1'b0, "FP 0a0b0c0d");

        $display("");
        $display("SUMMARY tb_layer2: pass=%0d fail=%0d",
                 pass_count, fail_count);
        if (fail_count != 0)
            $stop;
        $finish;
    end

endmodule
