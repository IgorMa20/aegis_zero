`timescale 1ns / 1ps
module tb_mphf_lookup;
    reg clk;
    reg valid_in;
    reg [31:0] dst_ip;

    wire valid_out;
    wire [13:0] idx;
    wire [31:0] dst_ip_out;

    integer pass_count;
    integer fail_count;

    mphf_lookup uut (
        .clk(clk),
        .valid_in(valid_in),
        .dst_ip(dst_ip),
        .valid_out(valid_out),
        .idx(idx),
        .dst_ip_out(dst_ip_out)
    );

    always #5 clk = ~clk;

    task check_idx;
        input [31:0] ip;
        input [13:0] expected_idx;
        input [255:0] name;
        begin
            @(negedge clk);
            dst_ip   = ip;
            valid_in = 1'b1;
            @(negedge clk);
            valid_in = 1'b0;

            @(posedge valid_out);
            #1;
            if ((idx !== expected_idx) || (dst_ip_out !== ip)) begin
                $display("FAIL %-32s ip=%h expected_idx=%0d got_idx=%0d dst_ip_out=%h", name, ip, expected_idx, idx, dst_ip_out);
                fail_count = fail_count + 1;
            end else begin
                $display("PASS %-32s ip=%h idx=%0d", name, ip, idx);
                pass_count = pass_count + 1;
            end
        end
    endtask

    initial begin
        clk = 1'b0;
        valid_in = 1'b0;
        dst_ip = 32'h00000000;
        pass_count = 0;
        fail_count = 0;

        repeat (2) @(negedge clk);

        check_idx(32'h010393ae, 14'd0, "MPHF bram_rules[0]");
        check_idx(32'h01041f9f, 14'd1, "MPHF bram_rules[1]");
        check_idx(32'h010b94af, 14'd2, "MPHF bram_rules[2]");

        $display("SUMMARY tb_mphf_lookup: pass=%0d fail=%0d", pass_count, fail_count);
        if (fail_count != 0) $stop;
        $finish;
    end
endmodule
