// ============================================================
// pll_100.v
// Wrapper Megafunction altpll dla Cyclone IV E.
//
// Wejscie: inclk0 = 50 MHz (CLOCK_50 z plytki DE2-115)
// Wyjscia:
//   c0     = 100 MHz (mult=2)
//   c1     =  50 MHz (mult=1, sluzy jako fallback dla clkmux)
//   locked = sygnal blokady PLL
//
// Uwaga praktyczna:
// Plik jest napisany recznie zeby projekt syntetyzowal sie bez
// koniecznosci uruchamiania IP Catalog. Jesli synteza zglosi blad
// niezgodnosci parametrow altpll w tej wersji Quartusa, najszybsza
// sciezka to:
//   1) Tools -> IP Catalog -> Library/Basic Functions/Clocks; PLLs
//      and Resets/PLL/ALTPLL
//   2) Wybrac Cyclone IV E, wejscie 50 MHz, dwa wyjscia 100/50 MHz,
//      port locked enabled, reszta domyslne, nazwa modulu = pll_100,
//      port inclk0 = inclk0, porty wyjsciowe c0/c1, locked.
//   3) Zamienic ten plik wygenerowanym pll_100.v.
//
// Bazujac na wersji Quartusa Prime Lite 20.1 (wymieniony w README
// i istniejacych .qpf/.qsf) ten zestaw parametrow powinien przejsc
// bez zmian.
// ============================================================
module pll_100 (
    input  wire inclk0,
    output wire c0,
    output wire c1,
    output wire locked
);

    wire [4:0] sub_wire0;
    wire       sub_wire2 = 1'b0;
    wire [1:0] sub_wire3 = {sub_wire2, inclk0};

    altpll altpll_component (
        .inclk    (sub_wire3),
        .clk      (sub_wire0),
        .locked   (locked),
        .activeclock(),
        .areset   (1'b0),
        .clkbad   (),
        .clkena   ({6{1'b1}}),
        .clkloss  (),
        .clkswitch(1'b0),
        .configupdate(1'b0),
        .enable0  (),
        .enable1  (),
        .extclk   (),
        .extclkena({4{1'b1}}),
        .fbin     (1'b1),
        .fbmimicbidir(),
        .fbout    (),
        .fref     (),
        .icdrclk  (),
        .pfdena   (1'b1),
        .phasecounterselect({4{1'b1}}),
        .phasedone(),
        .phasestep(1'b1),
        .phaseupdown(1'b1),
        .pllena   (1'b1),
        .scanaclr (1'b0),
        .scanclk  (1'b0),
        .scanclkena(1'b1),
        .scandata (1'b0),
        .scandataout(),
        .scandone (),
        .scanread (1'b0),
        .scanwrite(1'b0),
        .sclkout0 (),
        .sclkout1 (),
        .vcooverrange(),
        .vcounderrange()
    );

    assign c0 = sub_wire0[0];
    assign c1 = sub_wire0[1];

    defparam
        altpll_component.bandwidth_type           = "AUTO",
        altpll_component.clk0_divide_by           = 1,
        altpll_component.clk0_duty_cycle          = 50,
        altpll_component.clk0_multiply_by         = 2,
        altpll_component.clk0_phase_shift         = "0",
        altpll_component.clk1_divide_by           = 1,
        altpll_component.clk1_duty_cycle          = 50,
        altpll_component.clk1_multiply_by         = 1,
        altpll_component.clk1_phase_shift         = "0",
        altpll_component.compensate_clock         = "CLK0",
        altpll_component.inclk0_input_frequency   = 20000,
        altpll_component.intended_device_family   = "Cyclone IV E",
        altpll_component.lpm_hint                 = "CBX_MODULE_PREFIX=pll_100",
        altpll_component.lpm_type                 = "altpll",
        altpll_component.operation_mode           = "NORMAL",
        altpll_component.pll_type                 = "AUTO",
        altpll_component.port_activeclock         = "PORT_UNUSED",
        altpll_component.port_areset              = "PORT_UNUSED",
        altpll_component.port_clkbad0             = "PORT_UNUSED",
        altpll_component.port_clkbad1             = "PORT_UNUSED",
        altpll_component.port_clkloss             = "PORT_UNUSED",
        altpll_component.port_clkswitch           = "PORT_UNUSED",
        altpll_component.port_configupdate        = "PORT_UNUSED",
        altpll_component.port_fbin                = "PORT_UNUSED",
        altpll_component.port_inclk0              = "PORT_USED",
        altpll_component.port_inclk1              = "PORT_UNUSED",
        altpll_component.port_locked              = "PORT_USED",
        altpll_component.port_pfdena              = "PORT_UNUSED",
        altpll_component.port_phasecounterselect  = "PORT_UNUSED",
        altpll_component.port_phasedone           = "PORT_UNUSED",
        altpll_component.port_phasestep           = "PORT_UNUSED",
        altpll_component.port_phaseupdown         = "PORT_UNUSED",
        altpll_component.port_pllena              = "PORT_UNUSED",
        altpll_component.port_scanaclr            = "PORT_UNUSED",
        altpll_component.port_scanclk             = "PORT_UNUSED",
        altpll_component.port_scanclkena          = "PORT_UNUSED",
        altpll_component.port_scandata            = "PORT_UNUSED",
        altpll_component.port_scandataout         = "PORT_UNUSED",
        altpll_component.port_scandone            = "PORT_UNUSED",
        altpll_component.port_scanread            = "PORT_UNUSED",
        altpll_component.port_scanwrite           = "PORT_UNUSED",
        altpll_component.port_clk0                = "PORT_USED",
        altpll_component.port_clk1                = "PORT_USED",
        altpll_component.port_clk2                = "PORT_UNUSED",
        altpll_component.port_clk3                = "PORT_UNUSED",
        altpll_component.port_clk4                = "PORT_UNUSED",
        altpll_component.port_clk5                = "PORT_UNUSED",
        altpll_component.port_clkena0             = "PORT_UNUSED",
        altpll_component.port_clkena1             = "PORT_UNUSED",
        altpll_component.port_clkena2             = "PORT_UNUSED",
        altpll_component.port_clkena3             = "PORT_UNUSED",
        altpll_component.port_clkena4             = "PORT_UNUSED",
        altpll_component.port_clkena5             = "PORT_UNUSED",
        altpll_component.port_extclk0             = "PORT_UNUSED",
        altpll_component.port_extclk1             = "PORT_UNUSED",
        altpll_component.port_extclk2             = "PORT_UNUSED",
        altpll_component.port_extclk3             = "PORT_UNUSED",
        altpll_component.width_clock              = 5;

endmodule
