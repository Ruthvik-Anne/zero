# Local equivalent of the CI matrix (T-TST-01). The hosted matrix runs the same
# steps natively on all six targets; this script proves the host target end to end
# and cross-checks the portable crates on the other five.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

function Step($name, $block) {
    Write-Host "== $name"
    & $block
    if ($LASTEXITCODE -ne 0) { throw "$name failed with exit code $LASTEXITCODE" }
}

Step 'build (host)' { cargo build --workspace --all-targets }
Step 'lint (clippy -D warnings)' { cargo clippy --workspace --all-targets -- -D warnings }
Step 'test (host)' { cargo test --workspace }
Step 'traceability and architecture' { cargo run -q -p xtask -- check-docs }
Step 'benchmark gate' { cargo run -q -p xtask -- bench --check }
Step 'protocol readers' { node protocol/ts/check.mjs }

$targets = @(
    'aarch64-pc-windows-msvc',
    'x86_64-apple-darwin',
    'aarch64-apple-darwin',
    'x86_64-unknown-linux-gnu',
    'aarch64-unknown-linux-gnu'
)
foreach ($t in $targets) {
    Step "cross-check portable crates ($t)" { cargo check -q -p zero-types -p zero-tui -p zero-arch --target $t }
}

Write-Host "local CI: OK"
