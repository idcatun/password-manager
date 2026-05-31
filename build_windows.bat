@echo off
:: ===========================================================================
:: build_windows.bat  –  Build SecureVault.exe for Windows
::
:: Prerequisites (run once):
::   1. Install RubyInstaller for Windows (64-bit) from https://rubyinstaller.org
::      Choose the version WITH DEVKIT (e.g. Ruby+Devkit 3.2.x)
::   2. During RubyInstaller setup, select "MSYS2 / MinGW" components
::   3. After install, open Start → "Start Command Prompt with Ruby"
::   4. Run:
::        ridk install        <- installs MSYS2 toolchain
::        gem install gtk3    <- installs GTK3 bindings (~5 min, downloads GTK DLLs)
::        gem install ocra    <- installs the exe packager
::   5. Then run THIS script from this folder.
:: ===========================================================================

echo.
echo ================================================================
echo  SecureVault – Windows EXE Builder
echo ================================================================
echo.

:: Check Ruby
ruby --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Ruby not found. Install RubyInstaller from https://rubyinstaller.org
    pause
    exit /b 1
)

:: Check OCRA
ocra --version >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installing OCRA packager...
    gem install ocra
    if errorlevel 1 (
        echo [ERROR] Failed to install OCRA. Check your Ruby/gem setup.
        pause
        exit /b 1
    )
)

:: Check gtk3 gem
ruby -e "require 'gtk3'" >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installing gtk3 gem (this may take a few minutes)...
    gem install gtk3
    if errorlevel 1 (
        echo [ERROR] Failed to install gtk3 gem.
        echo         Make sure ridk install was run first.
        pause
        exit /b 1
    )
)

echo [INFO] All dependencies ready. Building SecureVault.exe...
echo.

:: Run OCRA
:: --windows       : No console window (GUI-only app)
:: --gem-all       : Bundle all installed gem files (includes GTK3 native DLLs)
:: --output        : Output file name
:: --icon          : Optional: set an .ico file here if you have one

ocra securevault.rb ^
    --windows ^
    --gem-all ^
    --output SecureVault.exe ^
    --verbose

if errorlevel 1 (
    echo.
    echo [ERROR] Build failed. See output above for details.
    pause
    exit /b 1
)

echo.
echo ================================================================
echo  BUILD SUCCESSFUL: SecureVault.exe
echo ================================================================
echo.
echo  The executable bundles Ruby + GTK3 + all gems into one file.
echo  Users do NOT need Ruby installed to run it.
echo.
echo  Vault data is stored in: %%USERPROFILE%%\.securevault\
echo.
pause
