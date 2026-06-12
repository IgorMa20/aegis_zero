// ============================================================
// clkmux.v
// Glitchless 2:1 mux zegarow oparty na altclkctrl.
//
// Wejscia:
//   clk0_100 - zegar 100 MHz (PLL c0)
//   clk1_50  - zegar  50 MHz (PLL c1)
//   sel      - 0 -> wybiera clk0_100, 1 -> wybiera clk1_50
//
// Uwaga: clkselect altclkctrl jest synchronizowany wewnetrznie
// przez blok clock control - przelaczanie jest bezglitchowe,
// ale dla pewnosci po zmianie SW[16] zalecany reset KEY[0]
// (reset i tak idzie przez synchronizator 4-FF).
//
// Jesli synteza altclkctrl nie powiedzie sie w tej wersji Quartusa,
// alternatywa awaryjna:
//   assign clk_out = sel ? clk1_50 : clk0_100;
// (zawiera glitche na przelaczeniu - akceptowalne tylko jesli
//  po zmianie SW[16] uzytkownik nacisnie reset KEY[0]).
// ============================================================
module clkmux (
    input  wire clk0_100,
    input  wire clk1_50,
    input  wire sel,
    output wire clk_out
);

    altclkctrl #(
        .clock_type                                ("Auto"),
        .ena_register_mode                         ("none"),
        .implement_in_les                          ("OFF"),
        .intended_device_family                    ("Cyclone IV E"),
        .lpm_hint                                  ("UNUSED"),
        .lpm_type                                  ("altclkctrl"),
        .number_of_clocks                          (2),
        .use_glitch_free_switch_over_implementation("ON"),
        .width_clkselect                           (1)
    ) u_clkctrl (
        .clkselect(sel),
        .ena      (1'b1),
        .inclk    ({clk1_50, clk0_100}),
        .outclk   (clk_out)
    );

endmodule
