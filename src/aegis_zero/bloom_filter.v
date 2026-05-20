// ============================================================
// bloom_filter.v
// AEGIS-ZERO - Warstwa 1: filtr Bloom'a (wersja potokowana)
//
// Wariant mixed:
// - filtr Bloom'a ma rozmiar 2048 bitow (64 slowa x 32 bity),
// - funkcja mieszajaca: mix32 inspirowana finalizerem MurmurHash3.
// ============================================================
module bloom_filter #(
    parameter integer BLOOM_BITS  = 2048,
    parameter integer WORD_WIDTH  = 32,
    parameter integer BLOOM_WORDS = 64
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
    // Stopien 1 - XOR z seedem i pierwszy XOR-shift
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
    // Stopien 2 - mnozenie przez 0x85EBCA6B i drugi XOR-shift (>>13)
    // ====================================================================
    wire [31:0] m1_h0 = s1_h0 * 32'h85EBCA6B;
    wire [31:0] m1_h1 = s1_h1 * 32'h85EBCA6B;
    wire [31:0] m1_h2 = s1_h2 * 32'h85EBCA6B;

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
            s2_h0     <= m1_h0 ^ (m1_h0 >> 13);
            s2_h1     <= m1_h1 ^ (m1_h1 >> 13);
            s2_h2     <= m1_h2 ^ (m1_h2 >> 13);
            s2_valid  <= s1_valid;
            s2_src_ip <= s1_src_ip;
        end
    end

    // ====================================================================
    // Stopien 3 - mnozenie przez 0xC2B2AE35 i finalny XOR-shift (>>16)
    // ====================================================================
    wire [31:0] m2_h0 = s2_h0 * 32'hC2B2AE35;
    wire [31:0] m2_h1 = s2_h1 * 32'hC2B2AE35;
    wire [31:0] m2_h2 = s2_h2 * 32'hC2B2AE35;

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
            s3_h0     <= m2_h0 ^ (m2_h0 >> 16);
            s3_h1     <= m2_h1 ^ (m2_h1 >> 16);
            s3_h2     <= m2_h2 ^ (m2_h2 >> 16);
            s3_valid  <= s2_valid;
            s3_src_ip <= s2_src_ip;
        end
    end

    // ====================================================================
    // Stopien 4 - odczyt pamieci, mux bitu, AND trzech bitow
    // ====================================================================
    wire [10:0] bit_index0 = s3_h0[10:0];
    wire [10:0] bit_index1 = s3_h1[10:0];
    wire [10:0] bit_index2 = s3_h2[10:0];

    wire [5:0] word_index0 = bit_index0[10:5];
    wire [5:0] word_index1 = bit_index1[10:5];
    wire [5:0] word_index2 = bit_index2[10:5];

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
