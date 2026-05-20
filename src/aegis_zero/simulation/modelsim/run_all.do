# run_all.do - uruchamia kolejno wszystkie testy Osoby 4
set SCRIPT_DIR [file dirname [file normalize [info script]]]
cd $SCRIPT_DIR
puts "=== BLOOM FILTER UNIT TEST ==="
do sim_bloom.do
puts "=== MPHF UNIT TEST ==="
do sim_mphf.do
puts "=== TOP INTEGRATION TEST ==="
do sim_top.do
