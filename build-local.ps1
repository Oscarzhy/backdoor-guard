$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $root

$go = Get-Command go.exe -ErrorAction Stop
Write-Host "Go: $(& $go.Source version)"

& gofmt -w .\GuardLauncher_v17.go
if ($LASTEXITCODE -ne 0) { throw "gofmt failed: $LASTEXITCODE" }

$oldGOOS = $env:GOOS
$oldGOARCH = $env:GOARCH
$oldCGO = $env:CGO_ENABLED
try {
    $env:GOOS = 'windows'
    $env:GOARCH = 'amd64'
    $env:CGO_ENABLED = '0'

    & go test .\GuardLauncher_v17.go .\GuardLauncher_v17_test.go .\GuardLauncher_windows_test.go
    if ($LASTEXITCODE -ne 0) { throw "go test failed: $LASTEXITCODE" }

    & go vet .\GuardLauncher_v17.go .\GuardLauncher_v17_test.go .\GuardLauncher_windows_test.go
    if ($LASTEXITCODE -ne 0) { throw "go vet failed: $LASTEXITCODE" }

    & go build -trimpath -ldflags='-s -w' -o .\GuardLauncher_v17.16_x64.exe .\GuardLauncher_v17.go
    if ($LASTEXITCODE -ne 0) { throw "go build failed: $LASTEXITCODE" }

    $hash = (Get-FileHash -Algorithm SHA256 .\GuardLauncher_v17.16_x64.exe).Hash.ToLowerInvariant()
    Set-Content -LiteralPath .\GuardLauncher_v17.16_x64.exe.sha256 -Value "$hash  GuardLauncher_v17.16_x64.exe" -Encoding ASCII

    # Refresh the package-wide manifest, including documents under 历史记录/.
    $manifestPath = Join-Path $root 'FILE_HASHES_SHA256.txt'
    $manifestLines = @()
    $packageFiles = Get-ChildItem -LiteralPath $root -File -Recurse | Where-Object { $_.FullName -ne $manifestPath } | Sort-Object FullName
    foreach ($file in $packageFiles) {
        $relative = $file.FullName.Substring($root.Length).TrimStart([char[]]@(92, 47)).Replace('\', '/')
        $fileHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
        $manifestLines += "$fileHash  $relative"
    }
    Set-Content -LiteralPath $manifestPath -Value $manifestLines -Encoding UTF8
    Write-Host "Build succeeded. SHA-256: $hash"
}
finally {
    $env:GOOS = $oldGOOS
    $env:GOARCH = $oldGOARCH
    $env:CGO_ENABLED = $oldCGO
}
