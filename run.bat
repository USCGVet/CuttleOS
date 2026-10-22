@echo off
REM ===========================================================================
REM run.bat -- fire up the Cuttle OS enterprise unikernel under QEMU.
REM
REM No cargo-test gating, no banner-asserts, no bundle-morph dance. Just:
REM   1. build the kernel ELF
REM   2. package it as a BIOS-bootable disk image
REM   3. boot it under QEMU with the serial console mirrored to this window
REM
REM For the full bundle-morph + verifier flow, use the QEMU smoke test:
REM     cargo test -p factory_builder --test qemu_smoke -- --ignored
REM
REM Accelerator: run.bat [tcg^|whpx^|auto]  (or set CUTTLE_ACCEL). Default tcg:
REM   TCG software emulation is the default for standalone single-VM runs so a
REM   host where WHPX hangs in BIOS reset still boots reliably. Pass whpx or
REM   auto to use Hyper-V hardware virtualization.
REM
REM Requirements:
REM   - QEMU on PATH, or at C:\Program Files\qemu\qemu-system-x86_64.exe
REM   - Nightly Rust toolchain -- target_enterprise_kernel/rust-toolchain.toml
REM     pins the required version.
REM
REM Exit QEMU: press Ctrl+C in this window after the kernel emits
REM            CUTTLE-TE HALT.
REM
REM Note: keep echo strings inside if-blocks free of parentheses; cmd.exe
REM       parses the entire if-block lazily and an unescaped paren inside an
REM       echo will confuse the block-end detector.
REM ===========================================================================

setlocal enabledelayedexpansion

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

set "KERNEL_CRATE=%ROOT%\target_enterprise_kernel"
set "IMAGES_DIR=%ROOT%\target\cuttle_images"
set "BIOS_IMG=%IMAGES_DIR%\run_bios.img"
set "KERNEL_PATH_FILE=%TEMP%\cuttle_kernel_elf_path.txt"

REM ----- accelerator ---------------------------------------------------------
set "ACCEL=%CUTTLE_ACCEL%"
if not "%~1"=="" set "ACCEL=%~1"
if "%ACCEL%"=="" set "ACCEL=tcg"
set "ACCEL_ARGS="
if /i "%ACCEL%"=="auto" set "ACCEL_ARGS=-accel whpx -accel tcg"
if /i "%ACCEL%"=="whpx" set "ACCEL_ARGS=-accel whpx"
if /i "%ACCEL%"=="tcg" set "ACCEL_ARGS=-accel tcg"
if not defined ACCEL_ARGS goto :bad_accel

REM ----- locate QEMU --------------------------------------------------------
set "QEMU="
for /f "delims=" %%i in ('where qemu-system-x86_64 2^>nul') do (
    if not defined QEMU set "QEMU=%%i"
)
if not defined QEMU (
    if exist "C:\Program Files\qemu\qemu-system-x86_64.exe" (
        set "QEMU=C:\Program Files\qemu\qemu-system-x86_64.exe"
    )
)
if not defined QEMU goto :no_qemu
echo Using QEMU: !QEMU!

REM ----- 1/3 build the kernel ELF -------------------------------------------
echo.
echo [1/3] Building kernel ELF via factory_builder build-kernel...
pushd "%ROOT%"
cargo run -p factory_builder --release --quiet -- build-kernel --kernel-crate "%KERNEL_CRATE%" > "%KERNEL_PATH_FILE%"
set "BUILD_RC=%ERRORLEVEL%"
popd
if not "%BUILD_RC%"=="0" goto :build_failed

set /p ELF_PATH=<"%KERNEL_PATH_FILE%"
if "%ELF_PATH%"=="" goto :no_elf_path
if not exist "%ELF_PATH%" goto :missing_elf
echo     kernel ELF: %ELF_PATH%

REM ----- 2/3 package the BIOS image -----------------------------------------
echo.
echo [2/3] Packaging BIOS-bootable image...
if not exist "%IMAGES_DIR%" mkdir "%IMAGES_DIR%"
pushd "%ROOT%"
cargo run -p factory_builder --release --quiet -- --candidate "%ELF_PATH%" --out "%BIOS_IMG%"
set "PKG_RC=%ERRORLEVEL%"
popd
if not "%PKG_RC%"=="0" goto :pkg_failed
echo     BIOS image: %BIOS_IMG%

REM ----- 3/3 launch QEMU ----------------------------------------------------
set "SERIAL_LOG=%IMAGES_DIR%\run_serial.log"
set "VIRTIO_IMG=%IMAGES_DIR%\virtio_hw.img"
set "AHCI_IMG=%IMAGES_DIR%\ahci_hw.img"
set "NVME_IMG=%IMAGES_DIR%\nvme_hw.img"
set "DEVICE_KEY=%ROOT%\device_secret_key.bin"
if not exist "%VIRTIO_IMG%" fsutil file createnew "%VIRTIO_IMG%" 1048576 >nul
if not exist "%AHCI_IMG%" fsutil file createnew "%AHCI_IMG%" 1048576 >nul
if not exist "%NVME_IMG%" fsutil file createnew "%NVME_IMG%" 1048576 >nul
if exist "%DEVICE_KEY%" goto :have_device_key
echo     Generating 32-byte owner-only device_secret_key.bin for local boot...
powershell -NoProfile -Command "$ErrorActionPreference = 'Stop'; $dst = '%DEVICE_KEY%'; $tmp = $dst + '.tmp'; [System.IO.File]::WriteAllBytes($tmp, [byte[]]@()); $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; & icacls.exe $tmp /inheritance:r /grant:r ('*' + $sid + ':(F)') | Out-Null; if ($LASTEXITCODE -ne 0) { Remove-Item -Force $tmp -ErrorAction SilentlyContinue; exit 1 }; $b = New-Object byte[] 32; [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); [System.IO.File]::WriteAllBytes($tmp, $b); Move-Item -Force $tmp $dst"
if not "%ERRORLEVEL%"=="0" goto :no_device_key
if not exist "%DEVICE_KEY%" goto :no_device_key
:have_device_key

echo.
echo [3/3] Launching QEMU (4x SMP vCPUs + 1280x720 console + HTTP :18080 / HTTPS :18443 + SQL).
echo        Dashboard:   http://127.0.0.1:18080/app
echo        SQL Server:  http://127.0.0.1:18080/sql?SELECT+*+FROM+kv
echo        Serial log:  %SERIAL_LOG%
echo        Accelerator: %ACCEL% [%ACCEL_ARGS%]
echo        Exit:        type 'halt' at cuttle^> prompt or close QEMU window
echo ============================================================================
"%QEMU%" ^
    %ACCEL_ARGS% ^
    -cpu max ^
    -smp 4 ^
    -fw_cfg name=opt/cuttle_device_key,file="%DEVICE_KEY%" ^
    -drive format=raw,file="%BIOS_IMG%",if=ide ^
    -drive if=none,id=vd0,format=raw,file="%VIRTIO_IMG%" ^
    -device virtio-blk-pci,drive=vd0,disable-legacy=off,disable-modern=on ^
    -netdev hubport,id=n0,hubid=1 ^
    -device virtio-net-pci,netdev=n0,disable-legacy=off,disable-modern=on ^
    -netdev hubport,id=n1,hubid=1 ^
    -device virtio-net-pci,netdev=n1,disable-legacy=off,disable-modern=on ^
    -netdev user,id=usernet0,hostfwd=tcp:127.0.0.1:18080-10.0.2.15:80,hostfwd=tcp:127.0.0.1:18443-10.0.2.15:443,hostfwd=udp:127.0.0.1:18080-10.0.2.15:8080 ^
    -device virtio-net-pci,netdev=usernet0,mac=52:54:00:12:34:56,disable-legacy=on,disable-modern=off ^
    -drive if=none,id=ahd0,format=raw,file="%AHCI_IMG%" ^
    -device ahci,id=ahci0 ^
    -device ide-hd,drive=ahd0,bus=ahci0.0 ^
    -netdev hubport,id=e0,hubid=2 ^
    -device e1000,netdev=e0 ^
    -netdev hubport,id=e1,hubid=2 ^
    -device e1000,netdev=e1 ^
    -drive if=none,id=nvme0,format=raw,file="%NVME_IMG%" ^
    -device nvme,drive=nvme0,serial=CUTTLE-NVME-HW ^
    -chardev stdio,id=ch0,logfile="%SERIAL_LOG%" ^
    -serial chardev:ch0 ^
    -no-reboot ^
    -m 256M

goto :eof

REM ----- error paths --------------------------------------------------------
:bad_accel
echo.
echo ERROR: unknown accelerator "%ACCEL%". Use auto, whpx or tcg.
exit /b 1

:no_qemu
echo.
echo ERROR: qemu-system-x86_64 not found on PATH or at C:\Program Files\qemu\.
echo Install QEMU from https://www.qemu.org/download/ and add it to PATH,
echo or accept the default Windows install location.
exit /b 1

:build_failed
echo.
echo ERROR: kernel build failed -- exit code %BUILD_RC%.
echo Verify that the nightly toolchain + rust-src component are installed.
echo The kernel crate's rust-toolchain.toml pins the exact version.
exit /b 1

:no_elf_path
echo.
echo ERROR: factory_builder did not emit a kernel ELF path on stdout.
echo Re-run without redirection to inspect the actual output:
echo     cargo run -p factory_builder --release -- build-kernel --kernel-crate "%KERNEL_CRATE%"
exit /b 1

:missing_elf
echo.
echo ERROR: factory_builder reported a kernel ELF path that does not exist:
echo     %ELF_PATH%
exit /b 1

:pkg_failed
echo.
echo ERROR: BIOS packaging failed -- exit code %PKG_RC%.
echo factory_builder couldn't wrap the kernel ELF into a bootable image.
exit /b 1

:no_device_key
echo.
echo ERROR: failed to generate "%DEVICE_KEY%".
exit /b 1
