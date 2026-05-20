@echo off
cd /d "%~dp0simulation\modelsim"
echo Working directory: %CD%
vsim -do sim_top.do
