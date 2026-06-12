`timescale 1ns / 1ps
// ============================================================
// tb_aegis_zero_top.v - Osoba 3: top-level testbench + scoreboard
//
// Cel:
//   Automatyczna weryfikacja calego toru AEGIS-ZERO:
//   packet_parser -> bloom_filter -> mphf_lookup -> bram_rule_memory
//   -> decision_unit.
//
// Co sprawdza scoreboard:
//   1) valid_bloom i bloom_pass dla kazdego poprawnego pakietu,
//   2) LHD/idx z MPHF dla pakietow, ktore przeszly Bloom,
//   3) stored_ip z BRAM dla pakietow skierowanych do Warstwy 2,
//   4) final_decision/valid_out dla kazdego pakietu,
//   5) brak wyjsc dla packet_valid=0,
//   6) reset w trakcie pracy usuwa pakiety bedace w potoku.
//
// Oczekiwane wyniki nie sa wpisane recznie poza nazwami scenariuszy:
// testbench czyta te same pliki .hex co projekt i liczy model referencyjny
// Bloom + MPHF + BRAM. Dzieki temu test pozostaje aktualny po wymianie
// bloom_filter.hex/g1.hex/g2.hex/bram_rules.hex, np. po rozszerzeniu bazy.
// ============================================================
module tb_aegis_zero_top;
    localparam integer BLOOM_WORDS  = 1024;  // v5: BLOOM_BITS=32768 / 32
    localparam integer G_SIZE       = 16384;
    localparam integer N_RULES      = 10000;
    localparam integer MAX_EXPECTED = 4096;
    localparam integer CLK_HALF_NS  = 5;
    localparam integer QUIET_CYCLES = 24;
    localparam integer DRAIN_LIMIT  = 160;

    reg clk;
    reg rst;
    reg packet_valid;
    reg [31:0] src_ip_in;
    reg [31:0] dst_ip_in;
    reg [15:0] src_port_in;
    reg [15:0] dst_port_in;
    reg [7:0]  protocol_in;

    wire [31:0] src_ip;
    wire [31:0] dst_ip;
    wire [15:0] src_port;
    wire [15:0] dst_port;
    wire [7:0]  protocol;
    wire        bloom_pass;
    wire        valid_bloom;
    wire [13:0] lhd;
    wire        valid_lhd;
    wire [31:0] stored_ip;
    wire        valid_bram;
    wire        decision;
    wire        final_decision;
    wire        valid_out;

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

    // Referencyjne kopie pamieci. Czytamy pliki z katalogu roboczego
    // ModelSim; sim_top.do kopiuje tam .hex przed kompilacja/uruchomieniem.
    reg [31:0] ref_bloom_mem [0:BLOOM_WORDS-1];
    reg [31:0] ref_g1_ram    [0:G_SIZE-1];
    reg [31:0] ref_g2_ram    [0:G_SIZE-1];
    reg [31:0] ref_rules_ram [0:N_RULES-1];

    // Kolejka oczekiwanych wynikow dla scoreboardu.
    reg [31:0] q_ip       [0:MAX_EXPECTED-1];
    reg        q_bloom    [0:MAX_EXPECTED-1];
    reg        q_decision [0:MAX_EXPECTED-1];
    reg [13:0] q_idx      [0:MAX_EXPECTED-1];
    reg [31:0] q_stored   [0:MAX_EXPECTED-1];
    reg [8*64-1:0] q_name [0:MAX_EXPECTED-1];

    integer q_tail;
    integer bloom_head;
    integer lhd_head;
    integer bram_head;
    integer decision_head;

    integer packet_count;
    integer bloom_checks;
    integer lhd_checks;
    integer bram_checks;
    integer decision_checks;
    integer pass_count;
    integer fail_count;
    integer cancelled_by_reset;
    integer quiet_checks;
    integer trusted_sent;
    integer i;
    integer drain_wait;
    integer fail_snapshot;
    integer flush_count;
    integer found_fp;
    reg [31:0] rand_state;
    reg [31:0] fp_ip;

    always #(CLK_HALF_NS) clk = ~clk;

    initial begin
        $readmemh("bloom_filter.hex", ref_bloom_mem);
        $readmemh("g1.hex",           ref_g1_ram);
        $readmemh("g2.hex",           ref_g2_ram);
        $readmemh("bram_rules.hex",   ref_rules_ram);
    end

    // ------------------------------------------------------------
    // Model referencyjny: te same funkcje hashujace co w RTL.
    // ------------------------------------------------------------
    function [31:0] mix32;
        input [31:0] x;
        reg [31:0] y;
        begin
            y = x;
            y = y ^ (y >> 16);
            y = y * 32'h85EBCA6B;
            y = y ^ (y >> 13);
            y = y * 32'hC2B2AE35;
            y = y ^ (y >> 16);
            mix32 = y;
        end
    endfunction

    function ref_bloom_pass;
        input [31:0] ip;
        reg [14:0] bit_index0;  // v5: 15-bitowy indeks (BLOOM_BITS=32768)
        reg [14:0] bit_index1;
        reg [14:0] bit_index2;
        reg [31:0] h0;
        reg [31:0] h1;
        reg [31:0] h2;
        reg bit0;
        reg bit1;
        reg bit2;
        begin
            h0 = mix32(ip ^ 32'hA5A5A5A5);
            h1 = mix32(ip ^ 32'h3C3C3C3C);
            h2 = mix32(ip ^ 32'h5A5A5A5A);
            bit_index0 = h0[14:0];
            bit_index1 = h1[14:0];
            bit_index2 = h2[14:0];

            bit0 = (ref_bloom_mem[bit_index0[14:5]] >> bit_index0[4:0]) & 1'b1;
            bit1 = (ref_bloom_mem[bit_index1[14:5]] >> bit_index1[4:0]) & 1'b1;
            bit2 = (ref_bloom_mem[bit_index2[14:5]] >> bit_index2[4:0]) & 1'b1;

            ref_bloom_pass = bit0 & bit1 & bit2;
        end
    endfunction

    function [13:0] ref_mphf_idx;
        input [31:0] ip;
        reg [31:0] x1;
        reg [31:0] h1_val;
        reg [13:0] addr1;
        reg [31:0] rot;
        reg [31:0] x2;
        reg [31:0] h2_val;
        reg [13:0] addr2;
        reg [13:0] g1_data;
        reg [13:0] g2_data;
        reg [14:0] sum;
        reg [14:0] sum_mod;
        begin
            x1     = ip ^ 32'hA5A5A5A5;
            h1_val = (x1 >> 7) ^ (x1 << 13);
            addr1  = h1_val[13:0];

            rot    = {ip[15:0], ip[31:16]};
            x2     = rot ^ 32'h3C3C3C3C;
            h2_val = (x2 >> 11) ^ (x2 << 5);
            addr2  = h2_val[13:0];

            g1_data = ref_g1_ram[addr1][13:0];
            g2_data = ref_g2_ram[addr2][13:0];
            sum     = {1'b0, g1_data} + {1'b0, g2_data};
            sum_mod = (sum >= 15'd10000) ? (sum - 15'd10000) : sum;
            ref_mphf_idx = sum_mod[13:0];
        end
    endfunction

    function ref_decision;
        input [31:0] ip;
        reg        bp;
        reg [13:0] idx;
        reg [31:0] stored;
        begin
            bp     = ref_bloom_pass(ip);
            idx    = ref_mphf_idx(ip);
            stored = ref_rules_ram[idx];
            ref_decision = bp && (stored == ip) && (ip != 32'h00000000);
        end
    endfunction

    function [31:0] lcg_next;
        input [31:0] x;
        begin
            lcg_next = (x * 32'd1664525) + 32'd1013904223;
        end
    endfunction

    task enqueue_expected;
        input [31:0] ip;
        input [8*64-1:0] name;
        reg [13:0] idx;
        reg        bp;
        reg [31:0] stored;
        reg        dec;
        begin
            if (q_tail >= MAX_EXPECTED) begin
                $display("FAIL SCOREBOARD queue overflow at packet_count=%0d", packet_count);
                fail_count = fail_count + 1;
            end else begin
                bp     = ref_bloom_pass(ip);
                idx    = ref_mphf_idx(ip);
                stored = ref_rules_ram[idx];
                dec    = bp && (stored == ip) && (ip != 32'h00000000);

                q_ip[q_tail]       = ip;
                q_bloom[q_tail]    = bp;
                q_idx[q_tail]      = idx;
                q_stored[q_tail]   = stored;
                q_decision[q_tail] = dec;
                q_name[q_tail]     = name;
                q_tail             = q_tail + 1;
                packet_count       = packet_count + 1;
            end
        end
    endtask

    task drive_packet_cycle;
        input [31:0] ip;
        input [8*64-1:0] name;
        begin
            enqueue_expected(ip, name);
            packet_valid = 1'b1;
            src_ip_in    = ip;
            dst_ip_in    = 32'hC0A800FE;
            src_port_in  = 16'd1234 + packet_count[15:0];
            dst_port_in  = 16'd80;
            protocol_in  = 8'h06;
            @(negedge clk);
        end
    endtask

    task send_packet_with_gap;
        input [31:0] ip;
        input [8*64-1:0] name;
        input integer gap_cycles;
        integer g;
        begin
            @(negedge clk);
            drive_packet_cycle(ip, name);
            packet_valid = 1'b0;
            src_ip_in    = 32'h00000000;
            for (g = 0; g < gap_cycles; g = g + 1)
                @(negedge clk);
        end
    endtask

    task wait_until_scoreboard_empty;
        input [8*64-1:0] name;
        begin
            drain_wait = 0;
            while (((bloom_head    < q_tail) ||
                    (lhd_head      < q_tail) ||
                    (bram_head     < q_tail) ||
                    (decision_head < q_tail)) &&
                   (drain_wait < DRAIN_LIMIT)) begin
                @(posedge clk);
                #1;
                drain_wait = drain_wait + 1;
            end

            if ((bloom_head    < q_tail) ||
                (lhd_head      < q_tail) ||
                (bram_head     < q_tail) ||
                (decision_head < q_tail)) begin
                $display("FAIL %-32s scoreboard drain timeout: q_tail=%0d bloom=%0d lhd=%0d bram=%0d decision=%0d",
                         name, q_tail, bloom_head, lhd_head, bram_head, decision_head);
                fail_count = fail_count + 1;
            end
        end
    endtask

    task expect_quiet;
        input integer cycles;
        input [8*64-1:0] name;
        begin
            fail_snapshot = fail_count;
            repeat (cycles) begin
                @(posedge clk);
                #1;
            end

            if (fail_count == fail_snapshot) begin
                $display("PASS %-32s brak valid_bloom/valid_out przez %0d cykli", name, cycles);
                quiet_checks = quiet_checks + 1;
                pass_count = pass_count + 1;
            end else begin
                $display("FAIL %-32s pojawil sie nieoczekiwany impuls valid", name);
            end
        end
    endtask

    // ------------------------------------------------------------
    // Scoreboard: porownuje kolejne impulsy valid_* z kolejka wejsc.
    // ------------------------------------------------------------
    always @(posedge clk) begin
        if (rst) begin
            flush_count = q_tail - decision_head;
            if (flush_count > 0)
                cancelled_by_reset = cancelled_by_reset + flush_count;
            bloom_head    = q_tail;
            lhd_head      = q_tail;
            bram_head     = q_tail;
            decision_head = q_tail;
        end else begin
            #1;

            while ((lhd_head < q_tail) && (q_bloom[lhd_head] === 1'b0))
                lhd_head = lhd_head + 1;
            while ((bram_head < q_tail) && (q_bloom[bram_head] === 1'b0))
                bram_head = bram_head + 1;

            if (valid_bloom === 1'b1) begin
                if (bloom_head >= q_tail) begin
                    $display("FAIL SCOREBOARD unexpected valid_bloom bloom_pass=%0b", bloom_pass);
                    fail_count = fail_count + 1;
                end else begin
                    bloom_checks = bloom_checks + 1;
                    if (bloom_pass !== q_bloom[bloom_head]) begin
                        $display("FAIL BLOOM %-32s ip=%h expected=%0b got=%0b",
                                 q_name[bloom_head], q_ip[bloom_head], q_bloom[bloom_head], bloom_pass);
                        fail_count = fail_count + 1;
                    end else begin
                        $display("PASS BLOOM %-32s ip=%h bloom=%0b",
                                 q_name[bloom_head], q_ip[bloom_head], bloom_pass);
                        pass_count = pass_count + 1;
                    end
                    bloom_head = bloom_head + 1;
                end
            end

            if (valid_lhd === 1'b1) begin
                while ((lhd_head < q_tail) && (q_bloom[lhd_head] === 1'b0))
                    lhd_head = lhd_head + 1;
                if (lhd_head >= q_tail) begin
                    $display("FAIL SCOREBOARD unexpected valid_lhd idx=%0d", lhd);
                    fail_count = fail_count + 1;
                end else begin
                    lhd_checks = lhd_checks + 1;
                    if (lhd !== q_idx[lhd_head]) begin
                        $display("FAIL MPHF  %-32s ip=%h expected_idx=%0d got_idx=%0d",
                                 q_name[lhd_head], q_ip[lhd_head], q_idx[lhd_head], lhd);
                        fail_count = fail_count + 1;
                    end else begin
                        $display("PASS MPHF  %-32s ip=%h idx=%0d",
                                 q_name[lhd_head], q_ip[lhd_head], lhd);
                        pass_count = pass_count + 1;
                    end
                    lhd_head = lhd_head + 1;
                end
            end

            if (valid_bram === 1'b1) begin
                while ((bram_head < q_tail) && (q_bloom[bram_head] === 1'b0))
                    bram_head = bram_head + 1;
                if (bram_head >= q_tail) begin
                    $display("FAIL SCOREBOARD unexpected valid_bram stored_ip=%h", stored_ip);
                    fail_count = fail_count + 1;
                end else begin
                    bram_checks = bram_checks + 1;
                    if (stored_ip !== q_stored[bram_head]) begin
                        $display("FAIL BRAM  %-32s ip=%h expected_stored=%h got_stored=%h idx=%0d",
                                 q_name[bram_head], q_ip[bram_head], q_stored[bram_head], stored_ip, q_idx[bram_head]);
                        fail_count = fail_count + 1;
                    end else begin
                        $display("PASS BRAM  %-32s ip=%h stored=%h idx=%0d",
                                 q_name[bram_head], q_ip[bram_head], stored_ip, q_idx[bram_head]);
                        pass_count = pass_count + 1;
                    end
                    bram_head = bram_head + 1;
                end
            end

            if (valid_out === 1'b1) begin
                if (decision_head >= q_tail) begin
                    $display("FAIL SCOREBOARD unexpected valid_out final_decision=%0b", final_decision);
                    fail_count = fail_count + 1;
                end else begin
                    decision_checks = decision_checks + 1;
                    if (final_decision !== q_decision[decision_head]) begin
                        $display("FAIL DEC   %-32s ip=%h expected_decision=%0b got_decision=%0b exp_bloom=%0b exp_idx=%0d exp_stored=%h",
                                 q_name[decision_head], q_ip[decision_head], q_decision[decision_head], final_decision,
                                 q_bloom[decision_head], q_idx[decision_head], q_stored[decision_head]);
                        fail_count = fail_count + 1;
                    end else begin
                        $display("PASS DEC   %-32s ip=%h decision=%0b exp_bloom=%0b exp_idx=%0d exp_stored=%h",
                                 q_name[decision_head], q_ip[decision_head], final_decision,
                                 q_bloom[decision_head], q_idx[decision_head], q_stored[decision_head]);
                        pass_count = pass_count + 1;
                    end
                    decision_head = decision_head + 1;
                end
            end
        end
    end

    initial begin
        clk = 1'b0;
        rst = 1'b1;
        packet_valid = 1'b0;
        src_ip_in    = 32'h00000000;
        dst_ip_in    = 32'h00000000;
        src_port_in  = 16'h0000;
        dst_port_in  = 16'h0000;
        protocol_in  = 8'h00;

        q_tail = 0;
        bloom_head = 0;
        lhd_head = 0;
        bram_head = 0;
        decision_head = 0;

        packet_count = 0;
        bloom_checks = 0;
        lhd_checks = 0;
        bram_checks = 0;
        decision_checks = 0;
        pass_count = 0;
        fail_count = 0;
        cancelled_by_reset = 0;
        quiet_checks = 0;
        trusted_sent = 0;
        rand_state = 32'h13579BDF;
        fp_ip = 32'hC0A80001;

        $display("============================================================");
        $display("AEGIS-ZERO TOP TESTBENCH - Osoba 3 / scoreboard");
        $display("clk=100 MHz model, expected data from .hex files");
        $display("============================================================");

        repeat (5) @(negedge clk);
        rst = 1'b0;
        repeat (2) @(negedge clk);

        // --------------------------------------------------------
        // SC_00: packet_valid=0 - wejscia sie zmieniaja, ale parser
        // nie powinien wpuscic nic do potoku.
        // --------------------------------------------------------
        $display("\n--- SC_00 VALID=0 / brak pakietu ---");
        src_ip_in = 32'h010393AE;
        packet_valid = 1'b0;
        expect_quiet(QUIET_CYCLES, "SC_00 valid=0");

        // --------------------------------------------------------
        // SC_01: zaufane adresy z aktualnych plikow .hex.
        // W obecnym archiwum Bloom zawiera trzy wpisy ALLOW.
        // Po wygenerowaniu pelnego bloom_filter.hex petla automatycznie
        // znajdzie pierwsze pasujace wpisy z bram_rules.hex.
        // --------------------------------------------------------
        $display("\n--- SC_01 TRUSTED / ALLOW z bram_rules.hex ---");
        trusted_sent = 0;
        for (i = 0; (i < N_RULES) && (trusted_sent < 3); i = i + 1) begin
            if (ref_bloom_pass(ref_rules_ram[i]) && ref_decision(ref_rules_ram[i])) begin
                send_packet_with_gap(ref_rules_ram[i], "SC_01 trusted allow", 2);
                trusted_sent = trusted_sent + 1;
            end
        end
        if (trusted_sent == 0) begin
            $display("FAIL SC_01 no trusted ALLOW entries found in current .hex set");
            fail_count = fail_count + 1;
        end
        wait_until_scoreboard_empty("SC_01 drain");

        // --------------------------------------------------------
        // SC_02: znane niezaufane adresy -> DENY juz na Bloomie.
        // --------------------------------------------------------
        $display("\n--- SC_02 UNTRUSTED / true negative DENY ---");
        send_packet_with_gap(32'hDEADBEEF, "SC_02 true negative deadbeef", 1);
        send_packet_with_gap(32'hC0FFEE00, "SC_02 true negative c0ffee",   1);
        send_packet_with_gap(32'h7F000001, "SC_02 loopback deny",          1);
        wait_until_scoreboard_empty("SC_02 drain");

        // --------------------------------------------------------
        // SC_03: false positive recovery. Bloom przepuszcza, ale
        // BRAM pod indeksem MPHF zawiera inny IP, wiec finalnie DENY.
        // --------------------------------------------------------
        $display("\n--- SC_03 FALSE POSITIVE RECOVERY / Bloom=1, final DENY ---");
        if ((ref_bloom_pass(fp_ip) !== 1'b1) || (ref_decision(fp_ip) !== 1'b0)) begin
            $display("FAIL SC_03 FP candidate %h is not Bloom-positive/final-DENY in current .hex", fp_ip);
            fail_count = fail_count + 1;
        end else begin
            send_packet_with_gap(fp_ip, "SC_03 false positive recovery", 2);
        end
        wait_until_scoreboard_empty("SC_03 drain");

        // --------------------------------------------------------
        // SC_04: adresy brzegowe.
        // --------------------------------------------------------
        $display("\n--- SC_04 EDGE CASES ---");
        send_packet_with_gap(32'h00000000, "SC_04 edge 0.0.0.0",           1);
        send_packet_with_gap(32'hFFFFFFFF, "SC_04 edge 255.255.255.255",   1);
        send_packet_with_gap(32'h00000001, "SC_04 edge low one",           1);
        send_packet_with_gap(32'hE0000001, "SC_04 multicast-like",         1);
        wait_until_scoreboard_empty("SC_04 drain");

        // --------------------------------------------------------
        // SC_05: burst - pakiet co cykl, mieszanka TP/TN/FP.
        // To sprawdza wyrownanie sciezki szybkiego DENY z Warstwa 2.
        // --------------------------------------------------------
        $display("\n--- SC_05 PIPELINE BURST / 1 pakiet na cykl ---");
        @(negedge clk);
        drive_packet_cycle(32'h010393AE, "SC_05 burst trusted0");
        drive_packet_cycle(32'hDEADBEEF, "SC_05 burst tn");
        drive_packet_cycle(32'hC0A80001, "SC_05 burst fp recovery");
        drive_packet_cycle(32'h01041F9F, "SC_05 burst trusted1");
        drive_packet_cycle(32'hFFFFFFFF, "SC_05 burst edge ff");
        drive_packet_cycle(32'h010B94AF, "SC_05 burst trusted2");
        packet_valid = 1'b0;
        wait_until_scoreboard_empty("SC_05 drain");

        // --------------------------------------------------------
        // SC_06: reset w trakcie pracy. Pakiet jest wstrzykniety,
        // potem resetowany zanim wynik dotrze do wyjscia. Scoreboard
        // flushuje oczekiwanie i wymaga ciszy po resecie.
        // --------------------------------------------------------
        $display("\n--- SC_06 RESET DURING OPERATION ---");
        @(negedge clk);
        drive_packet_cycle(32'h010393AE, "SC_06 cancelled by reset");
        packet_valid = 1'b0;
        repeat (3) @(negedge clk);
        rst = 1'b1;
        repeat (4) @(negedge clk);
        rst = 1'b0;
        expect_quiet(QUIET_CYCLES, "SC_06 after reset quiet");
        send_packet_with_gap(32'h010393AE, "SC_06 post-reset allow", 2);
        wait_until_scoreboard_empty("SC_06 drain");

        // --------------------------------------------------------
        // SC_07: deterministyczne losowe adresy. Seed jest jawny, wiec
        // test daje powtarzalny log i latwo go odtworzyc.
        // --------------------------------------------------------
        $display("\n--- SC_07 SEEDED RANDOM / deterministic LCG ---");
        $display("SC_07 seed = 0x%08h", rand_state);
        @(negedge clk);
        for (i = 0; i < 64; i = i + 1) begin
            rand_state = lcg_next(rand_state);
            drive_packet_cycle(rand_state, "SC_07 seeded random");
        end
        packet_valid = 1'b0;
        wait_until_scoreboard_empty("SC_07 drain");

        // --------------------------------------------------------
        // SC_08: powrot do ciszy po pelnym drainie.
        // --------------------------------------------------------
        $display("\n--- SC_08 FINAL QUIET CHECK ---");
        expect_quiet(QUIET_CYCLES, "SC_08 final quiet");

        $display("\n============================================================");
        $display("SUMMARY tb_aegis_zero_top");
        $display("packets_accepted_by_scoreboard = %0d", packet_count);
        $display("bloom_checks                  = %0d", bloom_checks);
        $display("mphf_checks                   = %0d", lhd_checks);
        $display("bram_checks                   = %0d", bram_checks);
        $display("decision_checks               = %0d", decision_checks);
        $display("quiet_checks                  = %0d", quiet_checks);
        $display("cancelled_by_reset            = %0d", cancelled_by_reset);
        $display("pass_count                    = %0d", pass_count);
        $display("fail_count                    = %0d", fail_count);
        if (fail_count == 0) begin
            $display("FINAL_STATUS: PASS");
        end else begin
            $display("FINAL_STATUS: FAIL");
        end
        $display("============================================================");

        if (fail_count != 0)
            $stop;
        $finish;
    end
endmodule
