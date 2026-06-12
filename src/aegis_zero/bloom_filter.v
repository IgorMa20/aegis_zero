// ============================================================
// bloom_filter.v
// AEGIS-ZERO - Warstwa 1: filtr Bloom'a (wersja potokowana v5)
//
// Wariant mixed - skalowany do produkcyjnego rozmiaru bazy 10k hostow:
// - filtr Bloom'a ma rozmiar 32768 bitow (1024 slowa x 32 bity),
// - funkcja mieszajaca: mix32 inspirowana finalizerem MurmurHash3.
//
// Wymiarowanie (v5): 16x wieksze niz v4 (2048 bitow).
//   FP rate dla 10 000 hostow: ~9% (vs ~100% w v4)
//   FP rate dla 1 000 hostow:  ~0.5%
//   FP rate dla   200 hostow:  ~0.05%
// Dalsze redukcje (do <1% przy 10k) wymagaja BLOOM_BITS >= 131072 oraz
// M9K-based synchronous read z dodatkowym stopniem potoku - dokumentowane
// jako kierunek dalszych prac.
//
// 6-stopniowy potok (v4 = v3 + rozdzielenie multiply od XOR-shift):
//   Stopien 1   : XOR z seedem + pierwszy XOR-shift  y ^ (y >> 16)
//   Stopien 2a  : mnozenie x 0x85EBCA6B (czyste, rejestr wyjsciowy DSP)
//   Stopien 2b  : XOR-shift  y ^ (y >> 13)
//   Stopien 3a  : mnozenie x 0xC2B2AE35 (czyste)
//   Stopien 3b  : finalny XOR-shift  y ^ (y >> 16)
//   Stopien 4   : odczyt bloom_mem, mux bitu, AND trzech bitow -> bloom_pass
//
// Motywacja: ze ścieżki krytycznej z TimeQuest (slow corner) wynikalo, ze
// mnozenie 32x32 + XOR-shift w jednym cyklu daje ~10 ns. Rozdzielenie tych
// operacji na osobne rejestry pozwala Quartusowi wykorzystac wbudowany
// rejestr wyjsciowy bloku Embedded Multiplier 9-bit, dzieki czemu sciezka
// kombinacyjna miedzy rejestrami zawiera albo *jedno mnozenie*, albo
// *jeden XOR-shift*. Spodziewany zysk: Fmax z ~95 MHz do 140-180 MHz.
//
// Latencja modulu: 6 cykli (v3 miala 4). Przepustowosc: 1 pakiet/cykl.
// Side-band: valid_in i src_ip propagowane przez wszystkie 6 stopni.
// ============================================================
module bloom_filter #(
    parameter integer BLOOM_BITS  = 32768,
    parameter integer WORD_WIDTH  = 32,
    parameter integer BLOOM_WORDS = 1024
)(
    input  wire        clk,
    input  wire        rst,

    input  wire [31:0] src_ip,
    input  wire        valid_in,

    output reg         bloom_pass,
    output reg         valid_bloom,
    output reg  [31:0] src_ip_out
);

    (* ramstyle = "M9K" *) reg [WORD_WIDTH-1:0] bloom_mem [0:BLOOM_WORDS-1];

    initial begin
        $readmemh("bloom_filter.hex", bloom_mem);
    end

    // ====================================================================
    // Stopien 1 - XOR z seedem i pierwszy XOR-shift y ^ (y >> 16)
    // ====================================================================
    wire [31:0] x0 = src_ip ^ 32'hA5A5A5A5;
    wire [31:0] x1 = src_ip ^ 32'h3C3C3C3C;
    wire [31:0] x2 = src_ip ^ 32'h5A5A5A5A;

    reg [31:0] s1_h0, s1_h1, s1_h2;
    reg        s1_valid;
    reg [31:0] s1_src_ip;

    always @(posedge clk) begin
        if (rst) begin
            s1_h0     <= 32'h0;
            s1_h1     <= 32'h0;
            s1_h2     <= 32'h0;
            s1_valid  <= 1'b0;
            s1_src_ip <= 32'h0;
        end else begin
            s1_h0     <= x0 ^ (x0 >> 16);
            s1_h1     <= x1 ^ (x1 >> 16);
            s1_h2     <= x2 ^ (x2 >> 16);
            s1_valid  <= valid_in;
            s1_src_ip <= src_ip;
        end
    end

    // ====================================================================
    // Stopien 2a - czyste mnozenie x 0x85EBCA6B
    // Rejestry s2a_* sa kandydatami do "wessania" przez Quartus do
    // wbudowanego rejestru wyjsciowego bloku DSP (Embedded Multiplier 9-bit).
    // ====================================================================
    reg [31:0] s2a_h0, s2a_h1, s2a_h2;
    reg        s2a_valid;
    reg [31:0] s2a_src_ip;

    always @(posedge clk) begin
        if (rst) begin
            s2a_h0     <= 32'h0;
            s2a_h1     <= 32'h0;
            s2a_h2     <= 32'h0;
            s2a_valid  <= 1'b0;
            s2a_src_ip <= 32'h0;
        end else begin
            s2a_h0     <= s1_h0 * 32'h85EBCA6B;
            s2a_h1     <= s1_h1 * 32'h85EBCA6B;
            s2a_h2     <= s1_h2 * 32'h85EBCA6B;
            s2a_valid  <= s1_valid;
            s2a_src_ip <= s1_src_ip;
        end
    end

    // ====================================================================
    // Stopien 2b - XOR-shift y ^ (y >> 13)
    // ====================================================================
    reg [31:0] s2_h0, s2_h1, s2_h2;
    reg        s2_valid;
    reg [31:0] s2_src_ip;

    always @(posedge clk) begin
        if (rst) begin
            s2_h0     <= 32'h0;
            s2_h1     <= 32'h0;
            s2_h2     <= 32'h0;
            s2_valid  <= 1'b0;
            s2_src_ip <= 32'h0;
        end else begin
            s2_h0     <= s2a_h0 ^ (s2a_h0 >> 13);
            s2_h1     <= s2a_h1 ^ (s2a_h1 >> 13);
            s2_h2     <= s2a_h2 ^ (s2a_h2 >> 13);
            s2_valid  <= s2a_valid;
            s2_src_ip <= s2a_src_ip;
        end
    end

    // ====================================================================
    // Stopien 3a - czyste mnozenie x 0xC2B2AE35
    // ====================================================================
    reg [31:0] s3a_h0, s3a_h1, s3a_h2;
    reg        s3a_valid;
    reg [31:0] s3a_src_ip;

    always @(posedge clk) begin
        if (rst) begin
            s3a_h0     <= 32'h0;
            s3a_h1     <= 32'h0;
            s3a_h2     <= 32'h0;
            s3a_valid  <= 1'b0;
            s3a_src_ip <= 32'h0;
        end else begin
            s3a_h0     <= s2_h0 * 32'hC2B2AE35;
            s3a_h1     <= s2_h1 * 32'hC2B2AE35;
            s3a_h2     <= s2_h2 * 32'hC2B2AE35;
            s3a_valid  <= s2_valid;
            s3a_src_ip <= s2_src_ip;
        end
    end

    // ====================================================================
    // Stopien 3b - finalny XOR-shift y ^ (y >> 16)
    // ====================================================================
    reg [31:0] s3_h0, s3_h1, s3_h2;
    reg        s3_valid;
    reg [31:0] s3_src_ip;

    always @(posedge clk) begin
        if (rst) begin
            s3_h0     <= 32'h0;
            s3_h1     <= 32'h0;
            s3_h2     <= 32'h0;
            s3_valid  <= 1'b0;
            s3_src_ip <= 32'h0;
        end else begin
            s3_h0     <= s3a_h0 ^ (s3a_h0 >> 16);
            s3_h1     <= s3a_h1 ^ (s3a_h1 >> 16);
            s3_h2     <= s3a_h2 ^ (s3a_h2 >> 16);
            s3_valid  <= s3a_valid;
            s3_src_ip <= s3a_src_ip;
        end
    end

    // ====================================================================
    // Stopien 4 - odczyt pamieci, mux bitu, AND trzech bitow
    //
    // v5: bit_index = 15 bitow (zakres [0, 32767]), bo BLOOM_BITS = 32768.
    //   word_index = [14:5] (10 bitow, zakres [0, 1023] = BLOOM_WORDS)
    //   bit_offset = [4:0]  (5 bitow, bit wewnatrz 32-bitowego slowa)
    // ====================================================================
    wire [14:0] bit_index0 = s3_h0[14:0];
    wire [14:0] bit_index1 = s3_h1[14:0];
    wire [14:0] bit_index2 = s3_h2[14:0];

    wire [9:0] word_index0 = bit_index0[14:5];
    wire [9:0] word_index1 = bit_index1[14:5];
    wire [9:0] word_index2 = bit_index2[14:5];

    wire [4:0] bit_offset0 = bit_index0[4:0];
    wire [4:0] bit_offset1 = bit_index1[4:0];
    wire [4:0] bit_offset2 = bit_index2[4:0];

    wire [WORD_WIDTH-1:0] word_value0 = bloom_mem[word_index0];
    wire [WORD_WIDTH-1:0] word_value1 = bloom_mem[word_index1];
    wire [WORD_WIDTH-1:0] word_value2 = bloom_mem[word_index2];

    wire bit0 = (word_value0 >> bit_offset0) & 1'b1;
    wire bit1 = (word_value1 >> bit_offset1) & 1'b1;
    wire bit2 = (word_value2 >> bit_offset2) & 1'b1;

    always @(posedge clk) begin
        if (rst) begin
            bloom_pass  <= 1'b0;
            valid_bloom <= 1'b0;
            src_ip_out  <= 32'h0;
        end else begin
            if (s3_valid) begin
                bloom_pass  <= bit0 & bit1 & bit2;
                valid_bloom <= 1'b1;
                src_ip_out  <= s3_src_ip;
            end else begin
                bloom_pass  <= 1'b0;
                valid_bloom <= 1'b0;
                src_ip_out  <= 32'h0;
            end
        end
    end

endmodule
