// ============================================================
// mphf_lookup.v - AEGIS-ZERO Warstwa 2
//
// Oblicza LHD = ( g1[h1(src_ip)] + g2[h2(src_ip)] ) mod 10000
// gdzie 10000 = N_RULES (rozmiar tablicy BRAM regul).
//
//
// Potok 2-cyklowy:
//   cykl 1: odczyt g1_ram[addr1] i g2_ram[addr2] (BRAM sync)
//   cykl 2: obliczenie sumy (15 b) i redukcja modulo 10000
// ============================================================
module mphf_lookup (
    input  wire        clk,
    input  wire        rst,
    input  wire        valid_in,
    input  wire [31:0] src_ip,

    output reg         valid_out,
    output reg  [13:0] idx,
    output reg  [31:0] src_ip_out
);
    parameter G_SIZE  = 16384;
    parameter N_RULES = 10000;

    (* ramstyle = "M9K" *) reg [31:0] g1_ram [0:G_SIZE-1];
    (* ramstyle = "M9K" *) reg [31:0] g2_ram [0:G_SIZE-1];
    initial begin
        $readmemh("g1.hex", g1_ram);
        $readmemh("g2.hex", g2_ram);
    end

    // -----------------------------------------------------------
    // Hash 1 - mlodsze bity wyniku XOR/shift trafiaja do adresu g1
    // -----------------------------------------------------------
    wire [31:0] x1     = src_ip ^ 32'hA5A5A5A5;
    wire [31:0] h1_val = (x1 >> 7) ^ (x1 << 13);
    wire [13:0] addr1  = h1_val[13:0];

    // -----------------------------------------------------------
    // Hash 2 - rotacja 16 b + XOR/shift, niezalezna od hash 1
    // -----------------------------------------------------------
    wire [31:0] rot    = {src_ip[15:0], src_ip[31:16]};
    wire [31:0] x2     = rot ^ 32'h3C3C3C3C;
    wire [31:0] h2_val = (x2 >> 11) ^ (x2 << 5);
    wire [13:0] addr2  = h2_val[13:0];

    // -----------------------------------------------------------
    // Etap potoku 1: synchroniczny odczyt g1/g2 z BRAM (M9K).
    //
    // RAM-y g1/g2 maja wlasny always-block bez resetu i bez bit-slice
    // w odczycie. To jest kanoniczny wzorzec inferencji M9K w Cyclone IV E:
    //   1) brak reset wyzwala on data output (M9K nie obsluguje sync rst),
    //   2) odczyt pelnego slowa - bit-slice [13:0] przesuniety na wyjscie.
    // Wartosci w g1/g2 z gen_mphf.py mieszcza sie w [0, 9999], wiec
    // jedynie 14 najmlodszych bitow ma znaczenie semantyczne.
    // -----------------------------------------------------------
    reg [31:0] g1_word;
    reg [31:0] g2_word;
    always @(posedge clk) begin
        g1_word <= g1_ram[addr1];
        g2_word <= g2_ram[addr2];
    end

    wire [13:0] g1_data = g1_word[13:0];
    wire [13:0] g2_data = g2_word[13:0];

    // -----------------------------------------------------------
    // Side-band channel (valid + src_ip) zsynchronizowany z odczytem
    // RAM - osobny rejestr z resetem, niezalezny od inferencji M9K.
    // -----------------------------------------------------------
    reg        valid_r1;
    reg [31:0] src_ip_r1;
    always @(posedge clk) begin
        if (rst) begin
            valid_r1  <= 1'b0;
            src_ip_r1 <= 32'h0;
        end else begin
            valid_r1  <= valid_in;
            src_ip_r1 <= src_ip;
        end
    end

    // -----------------------------------------------------------
    // Etap potoku 2: suma 15-bitowa i redukcja modulo N_RULES.
    //
    // sum jest 15-bitowe, bo g1_data + g2_data moze maksymalnie
    // wynosic 2 * (2^14 - 1) = 32766. Redukcje modulo 10000
    // realizujemy odejmowaniem warunkowym - przy poprawnie
    // wygenerowanych g1/g2 (oba <= 9999) wystarczy jedno odjecie.
    // -----------------------------------------------------------
    wire [14:0] sum     = {1'b0, g1_data} + {1'b0, g2_data};
    wire [14:0] sum_mod = (sum >= 15'd10000) ? (sum - 15'd10000) : sum;

    always @(posedge clk) begin
        if (rst) begin
            idx        <= 14'h0;
            valid_out  <= 1'b0;
            src_ip_out <= 32'h0;
        end else begin
            idx        <= sum_mod[13:0];
            valid_out  <= valid_r1;
            src_ip_out <= src_ip_r1;
        end
    end

endmodule
