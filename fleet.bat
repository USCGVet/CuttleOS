@echo off
REM ===========================================================================
REM fleet.bat -- launch the Cuttle fleet: one provider managing isolated
REM client farms of Triads (3 VMs each).
REM
REM   Plans, jobs and clients : tools\fleet.toml
REM   Provider console        : http://127.0.0.1:18888/fleet
REM   Provider token          : printed below, also target\cuttle_images\fleet\provider_token.txt
REM   Client tokens           : target\cuttle_images\fleet\<client>\client_token.txt
REM
REM QEMU accelerator: `accelerator` in fleet.toml (default auto = WHPX when it
REM works here, else TCG); override with --accel auto|whpx|tcg or CUTTLE_ACCEL.
REM
REM Ctrl+C stops every client farm and its VMs cleanly.
REM ===========================================================================

setlocal

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

set "KERNEL_CRATE=%ROOT%\target_enterprise_kernel"
set "IMAGES_DIR=%ROOT%\target\cuttle_images"
set "BIOS_IMG=%IMAGES_DIR%\run_bios.img"
set "BASE_ELF=%KERNEL_CRATE%\target\x86_64-unknown-none\release\target_enterprise_kernel"
set "BINMORPH_EXE=%ROOT%\target\release\binmorph.exe"
set "KERNEL_PATH_FILE=%TEMP%\cuttle_kernel_elf_path.txt"

if not exist "%BINMORPH_EXE%" (
    echo [0/2] Building release binmorph + factory_builder tools...
    pushd "%ROOT%"
    cargo build --release -p cuttle-binmorph -p factory_builder
    popd
)

if not exist "%BASE_ELF%" goto :build_base
if not exist "%BIOS_IMG%" goto :build_base
goto :launch_fleet

:build_base
echo [1/2] Building base kernel ELF and BIOS image...
if not exist "%IMAGES_DIR%" mkdir "%IMAGES_DIR%"
pushd "%ROOT%"
cargo run -p factory_builder --release --quiet -- build-kernel --kernel-crate "%KERNEL_CRATE%" > "%KERNEL_PATH_FILE%"
set /p ELF_PATH=<"%KERNEL_PATH_FILE%"
cargo run -p factory_builder --release --quiet -- --candidate "%ELF_PATH%" --out "%BIOS_IMG%"
popd

:launch_fleet
echo [2/2] Starting the Cuttle fleet provider...
python "%ROOT%\tools\cuttle_fleet.py" %*
