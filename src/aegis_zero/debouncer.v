// ============================================================
// debouncer.v
// Filtr drgan stykow + detektor zbocza narastajacego.
//
// Wejscie btn_in jest najpierw synchronizowane 2-FF na clk,
// nastepnie licznik mierzy ile cykli wejscie utrzymuje sie na
// nowej wartosci. Jesli przez DEBOUNCE_CYCLES stan jest stabilny,
// stable przyjmuje nowa wartosc. Na zboczu narastajacym stable
// generujemy 1-cyklowy impuls pulse_out.
//
// Domyslnie 500 000 cykli zegara = 5 ms @ 100 MHz / 10 ms @ 50 MHz.
// ============================================================
module debouncer #(
    parameter integer DEBOUNCE_CYCLES = 500_000
)(
    input  wire clk,
    input  wire rst,
    input  wire btn_in,
    output reg  pulse_out
);
    localparam integer CNT_WIDTH = (DEBOUNCE_CYCLES <= 1) ? 1 : $clog2(DEBOUNCE_CYCLES);

    reg [1:0]            sync;
    reg [CNT_WIDTH-1:0]  cnt;
    reg                  stable;
    reg                  stable_prev;

    always @(posedge clk) begin
        if (rst) begin
            sync        <= 2'b00;
            cnt         <= {CNT_WIDTH{1'b0}};
            stable      <= 1'b0;
            stable_prev <= 1'b0;
            pulse_out   <= 1'b0;
        end else begin
            sync <= {sync[0], btn_in};

            if (sync[1] == stable) begin
                cnt <= {CNT_WIDTH{1'b0}};
            end else if (cnt == DEBOUNCE_CYCLES - 1) begin
                stable <= sync[1];
                cnt    <= {CNT_WIDTH{1'b0}};
            end else begin
                cnt <= cnt + 1'b1;
            end

            stable_prev <= stable;
            pulse_out   <= stable & ~stable_prev;
        end
    end
endmodule
