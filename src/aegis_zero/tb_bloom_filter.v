module tb_bloom_filter;

    reg clk;
    reg rst;

    reg [31:0] src_ip;
    reg        valid_in;

    wire bloom_pass;
    wire valid_bloom;

    bloom_filter uut (
        .clk(clk),
        .rst(rst),
        .src_ip(src_ip),
        .valid_in(valid_in),
        .bloom_pass(bloom_pass),
        .valid_bloom(valid_bloom)
    );

    always #5 clk = ~clk;

    task test_ip;
        input [31:0] ip;
        input expected_pass;
        begin
            @(negedge clk);
            src_ip = ip;
            valid_in = 1'b1;

            @(negedge clk);
            valid_in = 1'b0;

            @(negedge clk);

            if (valid_bloom !== 1'b1 && bloom_pass !== expected_pass) begin
                $display("TEST FAILED: IP=%h expected=%b got=%b valid=%b",
                         ip, expected_pass, bloom_pass, valid_bloom);
            end else if (bloom_pass !== expected_pass) begin
                $display("TEST FAILED: IP=%h expected=%b got=%b",
                         ip, expected_pass, bloom_pass);
            end else begin
                $display("TEST PASSED: IP=%h bloom_pass=%b", ip, bloom_pass);
            end
        end
    endtask

    initial begin
        clk = 0;
        rst = 1;
        src_ip = 32'h00000000;
        valid_in = 0;

        #20;
        rst = 0;

        // Adresy zakodowane w bloom_filter.hex
        test_ip(32'hC0A80001, 1'b1);
        test_ip(32'hC0A80002, 1'b1);
        test_ip(32'h0A000001, 1'b1);

        // Adres spoza filtra
        test_ip(32'hDEADBEEF, 1'b0);

        // Test valid_in = 0
        @(negedge clk);
        src_ip = 32'hC0A80001;
        valid_in = 1'b0;

        @(negedge clk);

        if (valid_bloom !== 1'b0) begin
            $display("TEST FAILED: valid_bloom should be 0 when valid_in is 0");
        end else begin
            $display("TEST PASSED: valid_bloom correctly deasserted");
        end

        #20;
        $finish;
    end

endmodule