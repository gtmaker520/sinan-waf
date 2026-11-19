@echo off
chcp 65001 >nul 2>nul
setlocal
title 司南防火墙 - 本地测试控制台
cd /d "%~dp0"
set "BTFW_PORT=8899"

:MENU
cls
echo ==============================================================
echo   司南防火墙 SinanWAF - 本地测试控制台
echo   项目目录 : %CD%
echo   插件目录 : %CD%\sinanwaf
echo   沙箱数据 : %CD%\_local_test\data
echo   监听端口 : %BTFW_PORT%
echo ==============================================================
echo.
echo   [1] 启动本地测试（全新空白，推荐，直接回车）
echo   [2] 启动并生成演示数据（仅沙箱内，用来看效果）
echo   [3] 仅运行后端自检（不会保留测试数据）
echo   [4] 清空沙箱数据（恢复全新状态后启动）
echo   [5] 退出
echo.
set "CH="
set /p "CH=请输入序号并回车 [1]: "
if not defined CH set "CH=1"
if "%CH%"=="1" goto START
if "%CH%"=="2" goto DEMO
if "%CH%"=="3" goto SELFTEST
if "%CH%"=="4" goto RESET
if "%CH%"=="5" goto END
echo.
echo   输入无效，请输入 1-5 后重试。
timeout /t 2 >nul
goto MENU

:CHECKPY
if not exist "%~dp0sinanwaf\sinanwaf_main.py" (
  echo.
  echo   [错误] 未找到插件目录：%~dp0sinanwaf
  echo          请把本文件与 sinanwaf 插件文件夹放在同一目录。
  echo.
  pause
  exit /b 1
)
if not exist "%~dp0_local_test\server.py" (
  echo.
  echo   [错误] 未找到本地测试目录：%~dp0_local_test
  echo.
  pause
  exit /b 1
)
set "PYCMD="
where python >nul 2>nul && set "PYCMD=python"
if not defined PYCMD (where py >nul 2>nul && set "PYCMD=py -3")
if not defined PYCMD (
  echo.
  echo   [错误] 未检测到 Python。
  echo          请安装 Python 3 并勾选 "Add Python to PATH"：https://www.python.org/downloads/
  echo.
  pause
  exit /b 1
)
exit /b 0

:START
call :CHECKPY
if errorlevel 1 exit /b 1
echo.
echo   正在启动本地测试服务器（全新空白数据，与插到宝塔后一致）...
echo   浏览器将自动打开；按 Ctrl+C 可停止服务。
echo   若 %BTFW_PORT% 端口被占用，请修改本文件顶部的 set "BTFW_PORT=8899"。
echo.
%PYCMD% "_local_test\server.py"
echo.
echo   服务已停止。
pause
goto MENU

:DEMO
call :CHECKPY
if errorlevel 1 exit /b 1
echo.
echo   正在启动并生成演示数据（攻击日志 + 木马检出，仅写入沙箱）...
echo   演示数据不会进入插件目录，也不会随插件上传。
echo.
%PYCMD% "_local_test\server.py" --demo
echo.
echo   服务已停止。
pause
goto MENU

:SELFTEST
call :CHECKPY
if errorlevel 1 exit /b 1
echo.
echo   正在运行后端自检（初始化沙箱 + 全部接口与下发校验）...
echo   自检结束后会自动清空产生的攻击日志与扫描结果。
echo.
%PYCMD% "_local_test\server.py" --selftest
echo.
pause
goto MENU

:RESET
echo.
echo   将删除全部本地沙箱数据（规则、日志、隔离区、演示样本），恢复全新状态。
set "OK="
set /p "OK=确认请输入 YES 并回车： "
if /I not "%OK%"=="YES" goto MENU
rmdir /s /q "_local_test\data" 2>nul
rmdir /s /q "_local_test\fake_server" 2>nul
echo   沙箱已清空，正在从零启动 ...
timeout /t 1 >nul
goto START

:END
endlocal
exit /b 0
