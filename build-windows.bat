@echo off
REM Build script for Windows AMD64

echo Building AD-report for Windows AMD64...

REM Check if cross-compilation target is installed
rustup target list --installed | findstr "x86_64-pc-windows-gnu" >nul
if %errorlevel% neq 0 (
    echo Installing Windows AMD64 target...
    rustup target add x86_64-pc-windows-gnu
)

REM Build for Windows
echo Building release binary for Windows...
cargo build --release --target x86_64-pc-windows-gnu

REM Check if build was successful
if %errorlevel% equ 0 (
    echo Build successful!
    echo Windows executable: target\x86_64-pc-windows-gnu\release\ad-report.exe
    dir target\x86_64-pc-windows-gnu\release\ad-report.exe 2>nul || echo Binary not found
) else (
    echo Build failed!
)