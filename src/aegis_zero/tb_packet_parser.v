module tb_packet_parser;

    reg clk;
    reg rst;

    reg        packet_valid;
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
    wire        tuple_valid;

    packet_parser uut (
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
        .tuple_valid(tuple_valid)
    );

    always #5 clk = ~clk;

    initial begin
        clk = 0;
        rst = 1;

        packet_valid = 0;
        src_ip_in = 32'h00000000;
        dst_ip_in = 32'h00000000;
        src_port_in = 16'h0000;
        dst_port_in = 16'h0000;
        protocol_in = 8'h00;

        #20;
        rst = 0;

        // Test 1: TCP packet
        #10;
        packet_valid = 1;
        src_ip_in = 32'hC0A80001;   // 192.168.0.1
        dst_ip_in = 32'hC0A800FE;   // 192.168.0.254
        src_port_in = 16'd12345;
        dst_port_in = 16'd80;
        protocol_in = 8'h06;        // TCP

        #10;
        packet_valid = 0;

        #20;

        if (src_ip !== 32'hC0A80001 ||
            dst_ip !== 32'hC0A800FE ||
            src_port !== 16'd12345 ||
            dst_port !== 16'd80 ||
            protocol !== 8'h06) begin
            $display("TEST FAILED: packet_parser output mismatch");
        end else begin
            $display("TEST PASSED: packet_parser registered tuple correctly");
        end

        // Test 2: no valid input
        #10;
        packet_valid = 0;
        src_ip_in = 32'hDEADBEEF;

        #10;

        if (tuple_valid !== 1'b0) begin
            $display("TEST FAILED: tuple_valid should be 0 when packet_valid is 0");
        end else begin
            $display("TEST PASSED: tuple_valid correctly deasserted");
        end

        #20;
        $finish;
    end

endmodule