# sim_mphf.do - test jednostkowy MPHF
transcript file sim_mphf_transcript.txt
set SCRIPT_DIR [file dirname [file normalize [info script]]]
cd $SCRIPT_DIR
set PROJ_DIR [file normalize [file join $SCRIPT_DIR ../..]]
puts "ModelSim working directory: [pwd]"
puts "Project directory: $PROJ_DIR"
foreach f {g1.hex g2.hex bram_rules.hex} {
    file copy -force [file join $PROJ_DIR $f] .
}
if {[file exists work]} { vdel -lib work -all }
vlib work
vmap work work
vlog -sv [file join $PROJ_DIR mphf_lookup.v]
vlog -sv [file join $PROJ_DIR tb_mphf_lookup.v]
vsim -voptargs=+acc work.tb_mphf_lookup
add wave -r sim:/tb_mphf_lookup/*
run -all
wave zoom full
