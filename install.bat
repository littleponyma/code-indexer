@echo off
setlocal enabledelayedexpansion
REM code-indexer installer for Windows

echo [+] code-indexer installer
echo.

REM --- Check Python ---
where python >nul 2>&1
if errorlevel 1 (
    echo [-] Python not found. Install Python 3.10+ from https://python.org
    pause
    exit /b 1
)

for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo [+] Python: %PYVER%

REM --- Project directory ---
cd /d "%~dp0"

REM --- Install Python packages ---
echo [+] Installing Python packages...
python -m pip install --upgrade pip -q
python -m pip install -r requirements.txt -q
echo [+] Python packages installed

REM --- Install Claude Code skill ---
set "SKILL_DIR=%USERPROFILE%\.claude\skills\code-indexer"
echo [+] Installing Claude Code skill to: %SKILL_DIR%
if not exist "%SKILL_DIR%" mkdir "%SKILL_DIR%"
copy /y ".claude\skills\code-indexer\SKILL.md" "%SKILL_DIR%\SKILL.md" >nul 2>&1
copy /y ".claude\skills\code-indexer\INP.py" "%SKILL_DIR%\INP.py" >nul 2>&1
echo [+] Skill installed

REM --- IDA check (optional) ---
echo [+] Checking IDA Pro idalib (optional)...
python -c "import idapro; idapro.get_library_version(); print('  idalib: available')" 2>nul
if errorlevel 1 (
    echo [!] idalib: not found - IDA deep analysis disabled
    echo [!]   To enable: install IDA Pro 9 and set IDA_HOME or install idapro package
)

REM --- Verify ---
echo [+] Verifying installation...
python -c "from indexer.models import Symbol; print('  Core modules: OK')" 2>nul
if errorlevel 1 (
    echo [-] Core modules failed to import
    pause
    exit /b 1
)

echo.
echo [+] =========================================
echo [+]   code-indexer installed successfully!
echo [+] =========================================
echo.
echo [+] Usage:
echo [+]   CLI:    python -m indexer.cli ^<path^>
echo [+]   Skill:  /code-indexer ^<path^>
echo.
echo [+] Tested environments:
echo [+]   Windows 11 + Python 3.13.5
echo [+]   macOS 14  + Python 3.12
echo [+]   Ubuntu 22 + Python 3.10
echo.
pause
