# sim_top.do - test integracyjny calego toru AEGIS-ZERO
transcript file sim_top_transcript.txt
set SCRIPT_DIR [file dirname [file normalize [info script]]]
cd $SCRIPT_DIR
set PROJ_DIR [file normalize [file join $SCRIPT_DIR ../..]]
puts "ModelSim working directory: [pwd]"
puts "Project directory: $PROJ_DIR"
foreach f {bloom_filter.hex g1.hex g2.hex bram_rules.hex} {
    file copy -force [file join $PROJ_DIR $f] .
}
if {[file exists work]} { vdel -lib work -all }
vlib work
vmap work work
vlog -sv [file join $PROJ_DIR packet_parser.v]
vlog -sv [file join $PROJ_DIR bloom_filter.v]
vlog -sv [file join $PROJ_DIR mphf_lookup.v]
vlog -sv [file join $PROJ_DIR bram_rule_memory.v]
vlog -sv [file join $PROJ_DIR decision_unit.v]
vlog -sv [file join $PROJ_DIR top_aegis_zero.v]
vlog -sv [file join $PROJ_DIR tb_aegis_zero_top.v]
vsim -voptargs=+acc work.tb_aegis_zero_top
add wave -divider "INPUT"
add wave sim:/tb_aegis_zero_top/clk
add wave sim:/tb_aegis_zero_top/rst
add wave sim:/tb_aegis_zero_top/packet_valid
add wave -hex sim:/tb_aegis_zero_top/src_ip_in
add wave -divider "PARSER"
add wave -hex sim:/tb_aegis_zero_top/src_ip
add wave -hex sim:/tb_aegis_zero_top/dst_ip
add wave sim:/tb_aegis_zero_top/uut/tuple_valid
add wave -divider "BLOOM"
add wave sim:/tb_aegis_zero_top/valid_bloom
add wave sim:/tb_aegis_zero_top/bloom_pass
add wave -hex sim:/tb_aegis_zero_top/uut/src_ip_bloom_aligned
add wave -divider "MPHF/BRAM"
add wave sim:/tb_aegis_zero_top/valid_lhd
add wave -unsigned sim:/tb_aegis_zero_top/lhd
add wave sim:/tb_aegis_zero_top/valid_bram
add wave -hex sim:/tb_aegis_zero_top/stored_ip
add wave -divider "DECISION"
add wave sim:/tb_aegis_zero_top/final_decision
add wave sim:/tb_aegis_zero_top/decision
add wave sim:/tb_aegis_zero_top/valid_out
run -all
wave zoom full
