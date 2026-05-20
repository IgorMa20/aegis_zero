@echo off
cd /d "%~dp0"
echo Working directory: %CD%
vsim -do sim_top.do
