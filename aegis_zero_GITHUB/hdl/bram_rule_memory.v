// ============================================================
// bram_rule_memory.v - AEGIS-ZERO Warstwa 2
// Pamiec regul BRAM: 10 000 wpisow x 32 bity
// Kazdy wpis = autoryzowany adres IPv4 pod indeksem MPHF
// Adresowana indeksem idx z mphf_lookup (= LHD)
// ============================================================
module bram_rule_memory (
    input  wire        clk,
    input  wire        rst,
    input  wire        valid_in,
    input  wire [13:0] idx,
    input  wire [31:0] src_ip_in,

    output reg         valid_out,
    output reg  [31:0] src_ip_out,
    output reg  [31:0] stored_ip
);
    parameter N_RULES = 10000;

    reg [31:0] rules_ram [0:N_RULES-1];
    initial begin
        $readmemh("bram_rules.hex", rules_ram);
    end

		 always @(posedge clk) begin
			  if (rst) begin
            valid_out  <= 1'b0;
            src_ip_out <= 32'h0;
        end else begin
            stored_ip  <= rules_ram[idx];
            valid_out  <= valid_in;
            src_ip_out <= src_ip_in;
        end
    end

endmodule
