# sim_bloom.do - uruchamiaj z katalogu simulation/modelsim albo z dowolnego miejsca przez pelna sciezke
transcript file sim_bloom_transcript.txt
set SCRIPT_DIR [file dirname [file normalize [info script]]]
cd $SCRIPT_DIR
set PROJ_DIR [file normalize [file join $SCRIPT_DIR ../..]]
puts "ModelSim working directory: [pwd]"
puts "Project directory: $PROJ_DIR"
file copy -force [file join $PROJ_DIR bloom_filter.hex] .
if {[file exists work]} { vdel -lib work -all }
vlib work
vmap work work
vlog -sv [file join $PROJ_DIR bloom_filter.v]
vlog -sv [file join $PROJ_DIR tb_bloom_filter_checked.v]
vsim -voptargs=+acc work.tb_bloom_filter_checked
add wave -r sim:/tb_bloom_filter_checked/*
run -all
wave zoom full
