// ============================================================
// bloom_filter.v
// AEGIS-ZERO - Warstwa 1: prototypowy filtr Bloom'a
//
// Wersja prototypowa:
// - filtr jest statyczny,
// - zawartość pamięci ładowana jest z pliku bloom_filter.hex,
// - moduł nie obsługuje dynamicznego dodawania/usuwania wpisów,
// - zastosowano uproszczone funkcje mieszające oparte na XOR
//   i przesunięciach bitowych.
//
// Format pamięci:
// - BLOOM_BITS  = 2048 bitów,
// - WORD_WIDTH  = 32 bity,
// - BLOOM_WORDS = 64 słowa,
// - bit_index   = indeks bitu w filtrze,
// - word_index  = bit_index / 32,
// - bit_offset  = bit_index % 32.
//
// --------------------------------------------------------
// Funkcje mieszające użyte w prototypie.
//
// UWAGA:
// Nie jest to pełna implementacja MurmurHash3.
// Funkcje bazują na operacjach XOR, przesunięciach bitowych
// oraz wyborze fragmentu wyniku. Zostały użyte do testów
// funkcjonalnych struktury filtra Bloom'a, inicjalizacji
// pamięci oraz sygnałów bloom_pass/valid_bloom.
//
// Ograniczenie:
// Takie funkcje mogą nie zapewniać dobrego efektu lawinowego
// i mogą zwiększać liczbę kolizji oraz false positive.
// W wersji docelowej należy zastąpić je silniejszą funkcją
// mieszającą, np. MurmurHash3 albo innym wariantem o lepszej
// dystrybucji indeksów.
// --------------------------------------------------------
//
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
    output reg         valid_bloom
);

    // --------------------------------------------------------
    // Pamięć filtra Bloom'a.
    // Każda linia w bloom_filter.hex odpowiada jednemu słowu 32-bitowemu.
    // --------------------------------------------------------
    reg [WORD_WIDTH-1:0] bloom_mem [0:BLOOM_WORDS-1];

    initial begin
        $readmemh("bloom_filter.hex", bloom_mem);
    end

    // --------------------------------------------------------
    // Funkcje hashujące.
    // W prototypie użyto prostych funkcji możliwych do implementacji
    // w HDL bez ciężkich operacji arytmetycznych.
    //
    // Ponieważ BLOOM_BITS = 2048 = 2^11, do indeksu bitu używane jest
    // 11 najmłodszych bitów wyniku funkcji mieszającej.
    // --------------------------------------------------------

    function [10:0] hash0;
        input [31:0] ip;
        begin
            hash0 = (ip ^ 32'hA5A5A5A5) & 11'h7FF;
        end
    endfunction

    function [10:0] hash1;
        input [31:0] ip;
        reg [31:0] rot;
        begin
            rot = {ip[15:0], ip[31:16]};
            hash1 = (rot ^ 32'h3C3C3C3C) & 11'h7FF;
        end
    endfunction

    function [10:0] hash2;
        input [31:0] ip;
        reg [31:0] mix;
        begin
            mix = (ip >> 7) ^ (ip << 11) ^ 32'h5A5A5A5A;
            hash2 = mix & 11'h7FF;
        end
    endfunction

    // --------------------------------------------------------
    // Indeksy bitów.
    // --------------------------------------------------------
    wire [10:0] bit_index0;
    wire [10:0] bit_index1;
    wire [10:0] bit_index2;

    assign bit_index0 = hash0(src_ip);
    assign bit_index1 = hash1(src_ip);
    assign bit_index2 = hash2(src_ip);

    // --------------------------------------------------------
    // Indeksy słów i przesunięcia bitowe.
    //
    // word_index = bit_index / 32
    // bit_offset = bit_index % 32
    // --------------------------------------------------------
    wire [5:0] word_index0;
    wire [5:0] word_index1;
    wire [5:0] word_index2;

    wire [4:0] bit_offset0;
    wire [4:0] bit_offset1;
    wire [4:0] bit_offset2;

    assign word_index0 = bit_index0[10:5];
    assign word_index1 = bit_index1[10:5];
    assign word_index2 = bit_index2[10:5];

    assign bit_offset0 = bit_index0[4:0];
    assign bit_offset1 = bit_index1[4:0];
    assign bit_offset2 = bit_index2[4:0];

    // --------------------------------------------------------
    // Odczyt bitów z pamięci filtra.
    // --------------------------------------------------------
    wire bit0;
    wire bit1;
    wire bit2;

    assign bit0 = bloom_mem[word_index0][bit_offset0];
    assign bit1 = bloom_mem[word_index1][bit_offset1];
    assign bit2 = bloom_mem[word_index2][bit_offset2];

    // --------------------------------------------------------
    // Decyzja Warstwy 1.
    //
    // Jeśli wszystkie sprawdzane bity są ustawione:
    //   bloom_pass = 1
    //
    // Jeśli przynajmniej jeden bit jest wyzerowany:
    //   bloom_pass = 0
    //
    // bloom_pass = 1 nie oznacza jeszcze ALLOW.
    // Oznacza tylko przejście do Warstwy 2.
    // --------------------------------------------------------
    always @(posedge clk) begin
        if (rst) begin
            bloom_pass  <= 1'b0;
            valid_bloom <= 1'b0;
        end else begin
            if (valid_in) begin
                bloom_pass  <= bit0 & bit1 & bit2;
                valid_bloom <= 1'b1;
            end else begin
                bloom_pass  <= 1'b0;
                valid_bloom <= 1'b0;
            end
        end
    end

endmodule