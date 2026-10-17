# tools/baseline.ps1 — token-efficient build+test summary.
#
# Run from workspace root. Emits ONE line of output on success:
#     build=0 tests=279 failed=0 ignored=13 elapsed=12.3s
#
# On build failure, prints the failure to stderr and exits with cargo's exit
# code so the caller can detect the broken state without parsing.
#
# Usage:
#   powershell -File tools\baseline.ps1            # default: build + test
#   powershell -File tools\baseline.ps1 -BuildOnly # skip tests
#   powershell -File tools\baseline.ps1 -Json      # emit a single JSON line
#
# One-time setup (Windows defaults to Restricted):
#   Set-ExecutionPolicy -Scope CurrentUser RemoteSigned

[CmdletBinding()]
param(
    [switch]$BuildOnly,
    [switch]$Json
)

$ErrorActionPreference = 'Continue'
$sw = [System.Diagnostics.Stopwatch]::StartNew()

# Build. Do NOT redirect stderr — Windows PowerShell 5.1 wraps native-command
# stderr lines as ErrorRecords, which breaks $? and pollutes the output. The
# caller of this script sees cargo's stderr directly if anything goes wrong.
$buildOut = cargo build --workspace
$buildExit = $LASTEXITCODE
if ($buildExit -ne 0) {
    Write-Host "cargo build failed with exit $buildExit" -ForegroundColor Red
    exit $buildExit
}

if ($BuildOnly) {
    $elapsed = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    if ($Json) {
        "{`"build`":$buildExit,`"elapsed`":$elapsed}"
    } else {
        "build=$buildExit elapsed=${elapsed}s"
    }
    exit 0
}

# Test. Stdout-only capture; cargo writes "test result:" lines to stdout.
$testOut = cargo test --workspace
$testExit = $LASTEXITCODE

# Sum across every "test result:" line in the output.
$passed = 0
$failed = 0
$ignored = 0
foreach ($line in $testOut) {
    if ($line -match '^test result:\s+\w+\.\s+(\d+)\s+passed;\s+(\d+)\s+failed;\s+(\d+)\s+ignored') {
        $passed += [int]$Matches[1]
        $failed += [int]$Matches[2]
        $ignored += [int]$Matches[3]
    }
}

$elapsed = [math]::Round($sw.Elapsed.TotalSeconds, 1)

if ($Json) {
    "{`"build`":$buildExit,`"tests_exit`":$testExit,`"passed`":$passed,`"failed`":$failed,`"ignored`":$ignored,`"elapsed`":$elapsed}"
} else {
    "build=$buildExit tests=$passed failed=$failed ignored=$ignored elapsed=${elapsed}s"
}

# Non-zero cargo test exit propagates so the caller can detect failures.
exit $testExit
