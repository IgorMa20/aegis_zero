transcript on
if {[file exists rtl_work]} {
	vdel -lib rtl_work -all
}
vlib rtl_work
vmap work rtl_work

vlog -vlog01compat -work work +incdir+C:/Users/milos/Downloads/aegis_zero_v5/aegis_zero {C:/Users/milos/Downloads/aegis_zero_v5/aegis_zero/decision_unit.v}
vlog -vlog01compat -work work +incdir+C:/Users/milos/Downloads/aegis_zero_v5/aegis_zero {C:/Users/milos/Downloads/aegis_zero_v5/aegis_zero/packet_parser.v}
vlog -vlog01compat -work work +incdir+C:/Users/milos/Downloads/aegis_zero_v5/aegis_zero {C:/Users/milos/Downloads/aegis_zero_v5/aegis_zero/top_aegis_zero.v}
vlog -vlog01compat -work work +incdir+C:/Users/milos/Downloads/aegis_zero_v5/aegis_zero {C:/Users/milos/Downloads/aegis_zero_v5/aegis_zero/bram_rule_memory.v}
vlog -vlog01compat -work work +incdir+C:/Users/milos/Downloads/aegis_zero_v5/aegis_zero {C:/Users/milos/Downloads/aegis_zero_v5/aegis_zero/mphf_lookup.v}
vlog -vlog01compat -work work +incdir+C:/Users/milos/Downloads/aegis_zero_v5/aegis_zero {C:/Users/milos/Downloads/aegis_zero_v5/aegis_zero/bloom_filter.v}

vlog -vlog01compat -work work +incdir+C:/Users/milos/Downloads/aegis_zero_v5/aegis_zero {C:/Users/milos/Downloads/aegis_zero_v5/aegis_zero/tb_aegis_zero_top.v}

vsim -t 1ps -L altera_ver -L lpm_ver -L sgate_ver -L altera_mf_ver -L altera_lnsim_ver -L cycloneive_ver -L rtl_work -L work -voptargs="+acc"  tb_aegis_zero_top

add wave *
view structure
view signals
run -all
