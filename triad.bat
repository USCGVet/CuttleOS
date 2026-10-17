@echo off
REM ===========================================================================
REM triad.bat -- Launch the Proteus "3-as-1" Triad Appliance (RAID-SQL + MTD)
REM
REM Spins up 3 independent 4-core Proteus OS VMs (12 vCPUs total, HLT idle):
REM   - OS-1 (SQL-Data-A)       : HTTP :18101 | 4x SMP | AHCI Disk #1
REM   - OS-2 (SQL-Data-B)       : HTTP :18102 | 4x SMP | AHCI Disk #2
REM   - OS-3 (SQL-Parity/Check) : HTTP :18103 | 4x SMP | AHCI Disk #3 + XOR Parity
REM
REM Unified Triad Endpoint & Command Center:
REM   http://127.0.0.1:18080/app
REM   http://127.0.0.1:18080/sql?SELECT+*+FROM+kv
REM
REM Pass --gui to also open the 3 native QEMU 1280x720 console windows.
REM ===========================================================================

setlocal enabledelayedexpansion

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

set "KERNEL_CRATE=%ROOT%\target_enterprise_kernel"
set "IMAGES_DIR=%ROOT%\target\proteus_images"
set "BIOS_IMG=%IMAGES_DIR%\run_bios.img"
set "BASE_ELF=%KERNEL_CRATE%\target\x86_64-unknown-none\release\target_enterprise_kernel"
set "BINMORPH_EXE=%ROOT%\target\release\binmorph.exe"
set "KERNEL_PATH_FILE=%TEMP%\proteus_kernel_elf_path.txt"

if not exist "%BINMORPH_EXE%" (
    echo [0/2] Building release binmorph + factory_builder tools...
    pushd "%ROOT%"
    cargo build --release -p proteus-binmorph -p factory_builder
    popd
)

if not exist "%BASE_ELF%" goto :build_base
if not exist "%BIOS_IMG%" goto :build_base
goto :launch_triad

:build_base
echo [1/2] Building base kernel ELF and BIOS image...
pushd "%ROOT%"
cargo run -p factory_builder --release --quiet -- build-kernel --kernel-crate "%KERNEL_CRATE%" > "%KERNEL_PATH_FILE%"
set /p ELF_PATH=<"%KERNEL_PATH_FILE%"
cargo run -p factory_builder --release --quiet -- --candidate "%ELF_PATH%" --out "%BIOS_IMG%"
popd

:launch_triad
echo [2/2] Starting Proteus 3-as-1 Triad Hypervisor Controller...
python "%ROOT%\tools\triad_controller.py" %*
