// ============================================================
// decision_unit.v - AEGIS-ZERO Warstwa 2
// Koncowa weryfikacja i decyzja ALLOW/DENY
//
// Wejscia:
//   src_ip    - adres zrodlowy z pakietu
//   stored_ip - adres odczytany z BRAM pod indeksem MPHF
//
// Logika decyzji:
//   stored_ip == src_ip AND src_ip != 0  ->  ALLOW (decision=1)
//   stored_ip != src_ip OR  src_ip == 0  ->  DENY  (decision=0)
// ============================================================
module decision_unit (
    input  wire        clk,
    input  wire        rst,
    input  wire        valid_in,
    input  wire [31:0] src_ip,
    input  wire [31:0] stored_ip,

    output reg         valid_out,
    output reg         decision
);
    always @(posedge clk) begin
        if (rst) begin
            valid_out <= 1'b0;
            decision  <= 1'b0;
        end else begin
            valid_out <= valid_in;
            if (valid_in) begin
                if ((src_ip == stored_ip) && (src_ip != 32'h00000000))
                    decision <= 1'b1;
                else
                    decision <= 1'b0;
            end else begin
                decision <= 1'b0;
            end
        end
    end

endmodule
