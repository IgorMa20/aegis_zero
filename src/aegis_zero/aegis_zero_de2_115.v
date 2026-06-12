`timescale 1ns / 1ps
// ============================================================
// aegis_zero_de2_115.v
// Top-level wrapper AEGIS-ZERO dla plytki Terasic DE2-115
// (Cyclone IV E EP4CE115F29C7).
//
// Zegar:
//   - CLOCK_50 (PIN_Y2) -> PLL -> c0=100 MHz, c1=50 MHz
//   - altclkctrl wybiera miedzy c0 a c1 wg SW[16]
//       SW[16]=0 -> 100 MHz (tryb wydajnosciowy)
//       SW[16]=1 ->  50 MHz (tryb bezpieczny, fallback)
//
// Wejscia:
//   - KEY[0] - asynchroniczny reset (active-low)
//   - KEY[1] - LOAD: zatrzasniecie SW[15:0] do polowy src_ip
//   - KEY[2] - INJECT: jednorazowy strzal packet_valid=1
//   - KEY[3] - CLEAR COUNTERS: zerowanie allow/deny
//   - SW[17] - MODE: 0 = manual, 1 = preset
//   - SW[16] - CLK_SEL: 0 = 100 MHz, 1 = 50 MHz
//   - SW[15] - VIEW_STORED: gdy SW[14]=0, HEX pokazuje stored_ip
//   - SW[14] - VIEW_COUNTERS: HEX pokazuje liczniki ALLOW/DENY
//   - SW[15:0] - dane wejsciowe w trybie manual
//                (uwaga: SW[14]/SW[15] sluza tez do wyboru widoku,
//                 wiec podczas LOAD warto miec je na 0, chyba ze
//                 swiadomie ladujemy do bitow 14/15 src_ip)
//   - SW[2:0]  - indeks presetu w trybie preset
//
// Wyswietlanie:
//   - HEX7..HEX0 - mux 3-widokowy wg SW[15]/SW[14]:
//        SW[14]=0, SW[15]=0 -> src_ip_final (32-bit)  [domyslnie]
//        SW[14]=0, SW[15]=1 -> stored_ip z BRAM (32-bit, z ostatniego query)
//        SW[14]=1           -> liczniki: HEX7..4=ALLOW, HEX3..0=DENY
//   - LEDG[0] = ALLOW (decision zatrzasniety)
//   - LEDG[1] = DENY  (decision zatrzasniety)
//   - LEDG[2] = result_valid (po ostatnim INJECT mamy wynik)
//   - LEDG[3] = pll_locked
//   - LEDG[4] = clk_sel  (1 = 50 MHz)
//   - LEDG[5] = half_sel (0 = nastepny LOAD do dolnej polowy, 1 = gornej)
//   - LEDG[6] = mode     (1 = preset)
//   - LEDG[7] = view_stored
//   - LEDG[8] = view_counters
//   - LEDR[0] = valid_out (impuls 1 cykl)
//   - LEDR[1] = inject_pulse
//   - LEDR[2] = load_pulse
//   - LEDR[3] = valid_bloom
//   - LEDR[4] = bloom_pass
//   - LEDR[5] = valid_lhd
//   - LEDR[6] = valid_bram
//   - LEDR[7] = final_decision (przed zatrzasnieciem)
//   - LEDR[17:8] = lustro SW[17:8] (wizualne sprzezenie)
// ============================================================
module aegis_zero_de2_115 (
    input  wire        CLOCK_50,
    input  wire [3:0]  KEY,
    input  wire [17:0] SW,
    output wire [17:0] LEDR,
    output wire [8:0]  LEDG,
    output wire [6:0]  HEX0,
    output wire [6:0]  HEX1,
    output wire [6:0]  HEX2,
    output wire [6:0]  HEX3,
    output wire [6:0]  HEX4,
    output wire [6:0]  HEX5,
    output wire [6:0]  HEX6,
    output wire [6:0]  HEX7
);

    // -----------------------------------------------------------------
    // 1. PLL: 50 MHz -> {100 MHz, 50 MHz}
    // -----------------------------------------------------------------
    wire clk_100;
    wire clk_50;
    wire pll_locked;

    pll_100 u_pll (
        .inclk0(CLOCK_50),
        .c0    (clk_100),
        .c1    (clk_50),
        .locked(pll_locked)
    );

    // -----------------------------------------------------------------
    // 2. Synchronizator selektora zegara
    //    SW[16] jest async wzgledem wszystkich zegarow PLL.
    //    Synchronizujemy go na CLOCK_50, ktore zawsze chodzi.
    // -----------------------------------------------------------------
    reg [2:0] clk_sel_sync;
    initial clk_sel_sync = 3'b000;
    always @(posedge CLOCK_50) begin
        clk_sel_sync <= {clk_sel_sync[1:0], SW[16]};
    end
    wire clk_sel = clk_sel_sync[2];

    // -----------------------------------------------------------------
    // 3. Glitchless clock mux (altclkctrl)
    //    Wyjscie clk_sys jest zegarem calego rdzenia AEGIS-ZERO.
    // -----------------------------------------------------------------
    wire clk_sys;
    clkmux u_clkmux (
        .clk0_100(clk_100),
        .clk1_50 (clk_50),
        .sel     (clk_sel),
        .clk_out (clk_sys)
    );

    // -----------------------------------------------------------------
    // 4. Asynchroniczny reset: KEY[0]=0 albo PLL niezalockowany
    //    Synchronizujemy uwolnienie resetu na clk_sys.
    // -----------------------------------------------------------------
    wire raw_rst = (~KEY[0]) | (~pll_locked);

    reg [3:0] rst_sync;
    initial rst_sync = 4'b1111;
    always @(posedge clk_sys or posedge raw_rst) begin
        if (raw_rst) rst_sync <= 4'b1111;
        else         rst_sync <= {rst_sync[2:0], 1'b0};
    end
    wire rst = rst_sync[3];

    // -----------------------------------------------------------------
    // 5. Debouncery dla KEY[1] (LOAD) i KEY[2] (INJECT)
    //    KEY na DE2-115 jest active-low, wiec wczesniej negujemy.
    // -----------------------------------------------------------------
    wire load_pulse;
    wire inject_pulse;

    debouncer #(.DEBOUNCE_CYCLES(500_000)) u_db_load (
        .clk      (clk_sys),
        .rst      (rst),
        .btn_in   (~KEY[1]),
        .pulse_out(load_pulse)
    );

    debouncer #(.DEBOUNCE_CYCLES(500_000)) u_db_inject (
        .clk      (clk_sys),
        .rst      (rst),
        .btn_in   (~KEY[2]),
        .pulse_out(inject_pulse)
    );

    // -----------------------------------------------------------------
    // 6. Tryb manual: rejestr src_ip_manual ladowany polowkami z SW[15:0]
    //    half_sel = 0 -> kolejny LOAD trafia w bity [15:0]
    //    half_sel = 1 -> kolejny LOAD trafia w bity [31:16]
    //    Po kazdym LOAD half_sel sie obraca.
    // -----------------------------------------------------------------
    reg [31:0] src_ip_manual;
    reg        half_sel;

    always @(posedge clk_sys) begin
        if (rst) begin
            src_ip_manual <= 32'h0000_0000;
            half_sel      <= 1'b0;
        end else if (load_pulse) begin
            if (half_sel == 1'b0) src_ip_manual[15:0]  <= SW[15:0];
            else                  src_ip_manual[31:16] <= SW[15:0];
            half_sel <= ~half_sel;
        end
    end

    // -----------------------------------------------------------------
    // 7. Tryb preset: 8 zaszytych adresow
    //    Indeksy 0-3: znane wpisy ALLOW (z bram_rules.hex)
    //    Indeks 4: FP-candidate z generate_verification_bloom.py
    //              (bloom_pass=1, ale stored_ip != src_ip -> DENY)
    //    Indeksy 5-7: brzegowe DENY
    // -----------------------------------------------------------------
    reg [31:0] preset_ip;
    always @(*) begin
        case (SW[2:0])
            3'd0: preset_ip = 32'h0103_93AE;
            3'd1: preset_ip = 32'h0104_1F9F;
            3'd2: preset_ip = 32'h010B_94AF;
            3'd3: preset_ip = 32'h010D_438F;
            3'd4: preset_ip = 32'hC0A8_0001;
            3'd5: preset_ip = 32'hDEAD_BEEF;
            3'd6: preset_ip = 32'h0808_0808;
            3'd7: preset_ip = 32'h0000_0000;
            default: preset_ip = 32'h0000_0000;
        endcase
    end

    // -----------------------------------------------------------------
    // 8. Wybor zrodla src_ip wg SW[17]
    // -----------------------------------------------------------------
    wire        mode_preset = SW[17];
    wire [31:0] src_ip_final = mode_preset ? preset_ip : src_ip_manual;

    // -----------------------------------------------------------------
    // 9. Instancja rdzenia AEGIS-ZERO
    //    5-tuple poza src_ip jest niewykorzystywany przez decision_unit,
    //    wiec podpinamy zera.
    // -----------------------------------------------------------------
    wire [31:0] core_src_ip_thru, core_dst_ip_thru;
    wire [15:0] core_src_port_thru, core_dst_port_thru;
    wire [7:0]  core_proto_thru;

    wire        core_bloom_pass, core_valid_bloom;
    wire [13:0] core_lhd;
    wire        core_valid_lhd, core_valid_bram;
    wire [31:0] core_stored_ip;
    wire        core_decision, core_final_decision, core_valid_out;

    top_aegis_zero u_core (
        .clk          (clk_sys),
        .rst          (rst),
        .packet_valid (inject_pulse),
        .src_ip_in    (src_ip_final),
        .dst_ip_in    (32'h0),
        .src_port_in  (16'h0),
        .dst_port_in  (16'h0),
        .protocol_in  (8'h0),
        .src_ip       (core_src_ip_thru),
        .dst_ip       (core_dst_ip_thru),
        .src_port     (core_src_port_thru),
        .dst_port     (core_dst_port_thru),
        .protocol     (core_proto_thru),
        .bloom_pass   (core_bloom_pass),
        .valid_bloom  (core_valid_bloom),
        .lhd          (core_lhd),
        .valid_lhd    (core_valid_lhd),
        .stored_ip    (core_stored_ip),
        .valid_bram   (core_valid_bram),
        .decision     (core_decision),
        .final_decision(core_final_decision),
        .valid_out    (core_valid_out)
    );

    // -----------------------------------------------------------------
    // 10. Zatrzask wyniku: valid_out z rdzenia trwa 1 cykl.
    //     Po INJECT czyscimy result_valid; gdy wraca valid_out,
    //     latchujemy decyzje i podnosimy result_valid az do nastepnego INJECT.
    // -----------------------------------------------------------------
    reg decision_latched;
    reg result_valid;

    always @(posedge clk_sys) begin
        if (rst) begin
            decision_latched <= 1'b0;
            result_valid     <= 1'b0;
        end else begin
            if (inject_pulse) begin
                result_valid <= 1'b0;
            end else if (core_valid_out) begin
                decision_latched <= core_final_decision;
                result_valid     <= 1'b1;
            end
        end
    end

    // -----------------------------------------------------------------
    // 10b. Zatrzask stored_ip + liczniki ALLOW/DENY
    //      stored_ip z rdzenia jest wazne tylko w cyklu core_valid_out.
    //      Liczniki zwiekszane sa atomowo wraz z valid_out (bez wyscigu
    //      vs decision_latched). KEY[3] (synchronizowany) zeruje liczniki.
    //      Saturacja na 0xFFFF zapobiega wrap-around.
    // -----------------------------------------------------------------
    reg [31:0] stored_ip_latched;
    always @(posedge clk_sys) begin
        if (rst) begin
            stored_ip_latched <= 32'h0000_0000;
        end else if (core_valid_out) begin
            stored_ip_latched <= core_stored_ip;
        end
    end

    reg [1:0] key3_sync;
    initial key3_sync = 2'b00;
    always @(posedge clk_sys) begin
        key3_sync <= {key3_sync[0], ~KEY[3]};
    end
    wire clear_counters = key3_sync[1];

    reg [15:0] allow_count;
    reg [15:0] deny_count;
    always @(posedge clk_sys) begin
        if (rst | clear_counters) begin
            allow_count <= 16'h0000;
            deny_count  <= 16'h0000;
        end else if (core_valid_out) begin
            if (core_final_decision) begin
                if (allow_count != 16'hFFFF) allow_count <= allow_count + 1'b1;
            end else begin
                if (deny_count  != 16'hFFFF) deny_count  <= deny_count  + 1'b1;
            end
        end
    end

    // -----------------------------------------------------------------
    // 11. HEX display mux: src_ip / stored_ip / liczniki
    //     SW[14]=1 -> widok licznikow (HEX7..4 = ALLOW, HEX3..0 = DENY)
    //     SW[15]=1 (gdy SW[14]=0) -> widok stored_ip z ostatniego query
    //     domyslnie -> widok aktualnego src_ip_final
    //     HEX0 = nibble [3:0], HEX7 = nibble [31:28]
    // -----------------------------------------------------------------
    wire view_counters = SW[14];
    wire view_stored   = SW[15];

    reg [31:0] hex_data;
    always @(*) begin
        if (view_counters)    hex_data = {allow_count, deny_count};
        else if (view_stored) hex_data = stored_ip_latched;
        else                  hex_data = src_ip_final;
    end

    hex_to_7seg u_hex0 (.in(hex_data[3:0]),   .seg(HEX0));
    hex_to_7seg u_hex1 (.in(hex_data[7:4]),   .seg(HEX1));
    hex_to_7seg u_hex2 (.in(hex_data[11:8]),  .seg(HEX2));
    hex_to_7seg u_hex3 (.in(hex_data[15:12]), .seg(HEX3));
    hex_to_7seg u_hex4 (.in(hex_data[19:16]), .seg(HEX4));
    hex_to_7seg u_hex5 (.in(hex_data[23:20]), .seg(HEX5));
    hex_to_7seg u_hex6 (.in(hex_data[27:24]), .seg(HEX6));
    hex_to_7seg u_hex7 (.in(hex_data[31:28]), .seg(HEX7));

    // -----------------------------------------------------------------
    // 12. Mapowanie LED-ow
    // -----------------------------------------------------------------
    assign LEDG[0] = result_valid &  decision_latched;
    assign LEDG[1] = result_valid & ~decision_latched;
    assign LEDG[2] = result_valid;
    assign LEDG[3] = pll_locked;
    assign LEDG[4] = clk_sel;
    assign LEDG[5] = half_sel;
    assign LEDG[6] = mode_preset;
    assign LEDG[7] = view_stored;
    assign LEDG[8] = view_counters;

    assign LEDR[0]    = core_valid_out;
    assign LEDR[1]    = inject_pulse;
    assign LEDR[2]    = load_pulse;
    assign LEDR[3]    = core_valid_bloom;
    assign LEDR[4]    = core_bloom_pass;
    assign LEDR[5]    = core_valid_lhd;
    assign LEDR[6]    = core_valid_bram;
    assign LEDR[7]    = core_final_decision;
    assign LEDR[17:8] = SW[17:8];

endmodule
