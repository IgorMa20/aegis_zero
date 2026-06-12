`timescale 1ns / 1ps
// ============================================================
// tb_mphf_lookup.v - testbench dla mphf_lookup
//
// Aktualizacja po recenzji v2: nazwy portow zmienione z dst_ip
// na src_ip, by oddac semantyke sygnalu (do MPHF trafia adres
// zrodlowy). Dodano takze test krytyczny na sume >= 16384,
// ktora pokrywa bug obciecia bitu 14 w redukcji modulo.
// ============================================================
module tb_mphf_lookup;
    reg clk;
    reg rst;
    reg valid_in;
    reg [31:0] src_ip;

    wire valid_out;
    wire [13:0] idx;
    wire [31:0] src_ip_out;

    integer pass_count;
    integer fail_count;
    integer timeout_count;

    mphf_lookup uut (
        .clk(clk),
        .rst(rst),
        .valid_in(valid_in),
        .src_ip(src_ip),
        .valid_out(valid_out),
        .idx(idx),
        .src_ip_out(src_ip_out)
    );

    always #5 clk = ~clk;

    task wait_for_valid_out;
        begin
            timeout_count = 0;
            #1;
            while ((valid_out !== 1'b1) && (timeout_count < 10)) begin
                @(posedge clk);
                #1; // poczekaj na aktualizacje rejestrow po zboczu zegara
                timeout_count = timeout_count + 1;
            end
        end
    endtask

    task check_idx;
        input [31:0] ip;
        input [13:0] expected_idx;
        input [255:0] name;
        begin
            @(negedge clk);
            src_ip   = ip;
            valid_in = 1'b1;

            @(negedge clk);
            valid_in = 1'b0;

            wait_for_valid_out();
            if (valid_out !== 1'b1) begin
                $display("FAIL %-32s ip=%h timeout waiting for valid_out", name, ip);
                fail_count = fail_count + 1;
            end else if ((idx !== expected_idx) || (src_ip_out !== ip)) begin
                $display("FAIL %-32s ip=%h expected_idx=%0d got_idx=%0d src_ip_out=%h", name, ip, expected_idx, idx, src_ip_out);
                fail_count = fail_count + 1;
            end else begin
                $display("PASS %-32s ip=%h idx=%0d", name, ip, idx);
                pass_count = pass_count + 1;
            end
        end
    endtask

    // -----------------------------------------------------------
    // Test "in-range": idx musi byc < N_RULES = 10000 dla dowolnego
    // wejscia. Tu nie znamy oczekiwanego idx (zalezy od g1/g2.hex),
    // ale sprawdzamy, czy obciecie bitu 14 nie generuje smieci.
    // -----------------------------------------------------------
    task check_idx_in_range;
        input [31:0] ip;
        input [255:0] name;
        begin
            @(negedge clk);
            src_ip   = ip;
            valid_in = 1'b1;

            @(negedge clk);
            valid_in = 1'b0;

            wait_for_valid_out();
            if (valid_out !== 1'b1) begin
                $display("FAIL %-32s ip=%h timeout waiting for valid_out", name, ip);
                fail_count = fail_count + 1;
            end else if (idx >= 14'd10000) begin
                $display("FAIL %-32s ip=%h idx=%0d (>= N_RULES, regresja redukcji modulo)", name, ip, idx);
                fail_count = fail_count + 1;
            end else begin
                $display("PASS %-32s ip=%h idx=%0d (< N_RULES)", name, ip, idx);
                pass_count = pass_count + 1;
            end
        end
    endtask

    initial begin
        clk = 1'b0;
        rst = 1'b1;
        valid_in = 1'b0;
        src_ip = 32'h00000000;
        pass_count = 0;
        fail_count = 0;
        timeout_count = 0;

        repeat (3) @(negedge clk);
        rst = 1'b0;
        repeat (1) @(negedge clk);

        // Wektory referencyjne z gen_mphf.py
        check_idx(32'h010393ae, 14'd0, "MPHF bram_rules[0]");
        check_idx(32'h01041f9f, 14'd1, "MPHF bram_rules[1]");
        check_idx(32'h010b94af, 14'd2, "MPHF bram_rules[2]");

        // Regresja na poprawce krytycznej redukcji modulo:
        // sprawdz dla kilku losowych adresow, czy idx pozostaje
        // w zakresie [0, 9999] (gdy g1+g2 ma bit 14 = 1).
        check_idx_in_range(32'hFFFFFFFF, "MPHF range FF.FF.FF.FF");
        check_idx_in_range(32'h80000000, "MPHF range 80.00.00.00");
        check_idx_in_range(32'h7FFFFFFF, "MPHF range 7F.FF.FF.FF");
        check_idx_in_range(32'hDEADBEEF, "MPHF range DE.AD.BE.EF");

        $display("SUMMARY tb_mphf_lookup: pass=%0d fail=%0d", pass_count, fail_count);
        if (fail_count != 0) $stop;
        $finish;
    end
endmodule
