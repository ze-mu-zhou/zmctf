@echo off
rem 一体化测试:Windows 侧启动假 OpenAI 服务器 + 运行客户端
cd /d %~dp0
start "fake_openai" /min python tests\fake_openai.py 18080
timeout /t 2 /nobreak > nul
echo === zemu-autodan template ===
bin\zemu-autodan.exe template --backend openai --base-url http://127.0.0.1:18080/v1 --model gpt-4o --corpus tests\corpus_small.json
echo === done ===
rem 只杀窗口标题为 fake_openai 的进程,不误杀其他 python
taskkill /f /fi "WINDOWTITLE eq fake_openai*" > nul 2>&1
