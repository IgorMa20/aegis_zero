module packet_parser (
    input  wire        clk,
    input  wire        rst,

    input  wire        packet_valid,
    input  wire [31:0] src_ip_in,
    input  wire [31:0] dst_ip_in,
    input  wire [15:0] src_port_in,
    input  wire [15:0] dst_port_in,
    input  wire [7:0]  protocol_in,

    output reg  [31:0] src_ip,
    output reg  [31:0] dst_ip,
    output reg  [15:0] src_port,
    output reg  [15:0] dst_port,
    output reg  [7:0]  protocol,
    output reg         tuple_valid
);

    always @(posedge clk) begin
        if (rst) begin
            src_ip      <= 32'b0;
            dst_ip      <= 32'b0;
            src_port    <= 16'b0;
            dst_port    <= 16'b0;
            protocol    <= 8'b0;
            tuple_valid <= 1'b0;
        end else begin
            if (packet_valid) begin
                src_ip      <= src_ip_in;
                dst_ip      <= dst_ip_in;
                src_port    <= src_port_in;
                dst_port    <= dst_port_in;
                protocol    <= protocol_in;
                tuple_valid <= 1'b1;
            end else begin
                tuple_valid <= 1'b0;
            end
        end
    end

endmodule