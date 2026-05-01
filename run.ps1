# # ============================================================
# #  run.ps1
# #  Live WebRTC/STUN capture - extracts PEER IPs in real time,
# #  auto-skips STUN servers, then queries ipinfo.io for each
# #  new peer found.
# #
# #  Usage:
# #    .\run.ps1 [OPTIONS]
# #
# #  Options:
# #    -Interface  <id|name>   TShark interface index or name  (default: 1)
# #    -ExclFile   <path>      Exclusion list (.txt or .json)  (optional)
# #    -Duration   <sec>       Auto-stop after N seconds       (default: 0 = forever)
# #    -Help                   Show this help
# #
# #  Fields used from tshark:
# #    ip.src         - source IP of each STUN packet
# #    ip.dst         - destination IP of each STUN packet
# #    stun.att.ipv4  - mapped-address attribute (peer reflexive candidate)
# # ============================================================

param(
    [string]$Interface = "1",
    [string]$ExclFile  = "",
    [int]   $Duration  = 0,
    [switch]$Help
)

# ── Help ─────────────────────────────────────────────────────
if ($Help) {
    Write-Host "run.ps1 - Live WebRTC peer IP extractor + ipinfo lookup"
    Write-Host ""
    Write-Host "Usage:  .\run.ps1 [OPTIONS]"
    Write-Host ""
    Write-Host "  -Interface <id|name>   TShark interface index or name   (default: 1)"
    Write-Host "  -ExclFile  <path>      Exclusion list (.txt or .json)   (optional)"
    Write-Host "  -Duration  <sec>       Auto-stop after N seconds        (default: 0 = unlimited)"
    Write-Host "  -Help                  Show this help"
    Write-Host ""
    Write-Host "Tip - list your TShark interfaces:  tshark -D"
    exit 0
}

# ── Colour helpers ────────────────────────────────────────────
function Write-Log  { param([string]$msg) Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $msg" -ForegroundColor Cyan }
function Write-Warn { param([string]$msg) Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err  { param([string]$msg) Write-Host "[-] $msg" -ForegroundColor Red }
function Write-Ok   { param([string]$msg) Write-Host "[+] $msg" -ForegroundColor Green }

# ── Built-in exclusions (private/reserved ranges) ─────────────
$BuiltinExcluded = @(
    "0.0.0.0",
    "127.",
    "10.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
    "169.254.",
    "224.", "225.", "226.", "227.", "228.", "229.",
    "230.", "231.", "232.", "233.", "234.", "235.",
    "255.255.255.255",
    "::1"
)

# ── Load exclusion file ───────────────────────────────────────
$FileExcluded = @()

if ($ExclFile -ne "") {
    if (-not (Test-Path $ExclFile)) {
        Write-Err "Exclusion file not found: $ExclFile"
        exit 1
    }
    if ($ExclFile -match '\.json$') {
        try {
            $json = Get-Content $ExclFile -Raw | ConvertFrom-Json
            $FileExcluded = $json.excluded
        }
        catch {
            Write-Err "Failed to parse JSON exclusion file: $_"
            exit 1
        }
    }
    else {
        Get-Content $ExclFile | ForEach-Object {
            $line = ($_ -replace '#.*', '').Trim()
            if ($line -ne "") { $FileExcluded += $line }
        }
    }
    Write-Log "Loaded $($FileExcluded.Count) exclusion entries from: $ExclFile"
}

$AllExcluded = $BuiltinExcluded + $FileExcluded

# ── Runtime state ─────────────────────────────────────────────
$SeenPeers      = [System.Collections.Generic.List[string]]::new()
$StunServers    = [System.Collections.Generic.List[string]]::new()
$SeenErrLines   = [System.Collections.Generic.HashSet[string]]::new()  # dedup tshark stderr
$MyPublicIP     = ""

# ── Dependency check ──────────────────────────────────────────
$tsharkExe = Get-Command tshark -ErrorAction SilentlyContinue
if (-not $tsharkExe) {
    Write-Err "tshark not found. Download Wireshark: https://www.wireshark.org/download.html"
    exit 1
}
$tsharkPath = $tsharkExe.Source

# ── Detect our own public IP at startup ───────────────────────
Write-Log "Detecting this machine's public IP via ipinfo.io..."

try {
    $myInfo = Invoke-RestMethod -Uri "https://ipinfo.io/json" `
                                -Method Get `
                                -TimeoutSec 6 `
                                -ErrorAction Stop

    $MyPublicIP = $myInfo.ip
    Write-Ok "My public IP : $MyPublicIP ($($myInfo.city), $($myInfo.country)) - excluded"
    Write-Ok "My org       : $($myInfo.org)"
}
catch {
    Write-Warn "Could not reach ipinfo.io to detect public IP: $_"
    Write-Warn "Your public IP may appear in results - add it manually via -ExclFile"
}

# ── Helpers ───────────────────────────────────────────────────
function IsExcluded {
    param([string]$ip)
    foreach ($excl in $AllExcluded) {
        if ($ip.StartsWith($excl)) { return $true }
    }
    if ($MyPublicIP -ne "" -and $ip -eq $MyPublicIP) { return $true }
    if ($StunServers.Contains($ip)) { return $true }
    return $false
}

function AlreadySeen  { param([string]$ip); return $SeenPeers.Contains($ip) }
function AlreadyStun  { param([string]$ip); return $StunServers.Contains($ip) }

function IsPrivateIP {
    param([string]$ip)
    foreach ($excl in $BuiltinExcluded) {
        if ($ip.StartsWith($excl)) { return $true }
    }
    return $false
}

function IsValidIPv4 {
    param([string]$ip)
    return $ip -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
}

# ── ipinfo.io lookup ──────────────────────────────────────────
function Invoke-IPLookup {
    param([string]$ip)
    $SeenPeers.Add($ip)

    Write-Host ""
    Write-Host "[+] Peer found -> " -ForegroundColor Green -NoNewline
    Write-Host $ip -ForegroundColor Yellow

    try {
        $response = Invoke-RestMethod -Uri "https://ipinfo.io/$ip/json" `
                                      -Method Get `
                                      -TimeoutSec 6 `
                                      -ErrorAction Stop

        Write-Host "  IP       : $ip" -ForegroundColor Yellow
        if ($response.bogon -eq $true) {
            Write-Host "  WARNING: BOGON (private/reserved)" -ForegroundColor Red
        }
        if ($response.hostname) { Write-Host "  Hostname : $($response.hostname)" }
        if ($response.org)      { Write-Host "  Org      : $($response.org)" }
        if ($response.city)     { Write-Host "  Location : $($response.city), $($response.region), $($response.country)" }
        Write-Host "  Raw JSON : $($response | ConvertTo-Json -Compress)"
        Write-Host "------------------------------------------------"
    }
    catch {
        Write-Warn "ipinfo.io returned no data for $ip : $_"
    }
}

# ── Process one line of tshark output ────────────────────────
function Process-Line {
    param([string]$line)
    if ([string]::IsNullOrWhiteSpace($line)) { return }

    $parts   = $line -split '\|', 3
    $src     = if ($parts.Count -gt 0) { $parts[0].Trim() } else { "" }
    $dst     = if ($parts.Count -gt 1) { $parts[1].Trim() } else { "" }
    $stunAtt = if ($parts.Count -gt 2) { $parts[2].Trim() } else { "" }

    # STUN server detection:
    # When src is our private IP and dst is a new public IP,
    # we are sending a Binding Request → dst is the STUN server.
    if ($src -ne "" -and $dst -ne "") {
        if ((IsPrivateIP $src) -and (IsValidIPv4 $dst) -and -not (AlreadyStun $dst) -and -not (IsExcluded $dst)) {
            $StunServers.Add($dst)
            Write-Log "STUN server identified: $dst (we sent a request to it) - excluded"
        }
    }

    # Peer IP candidates
    $candidates = [System.Collections.Generic.List[string]]::new()
    if ($stunAtt -ne "") { $candidates.Add($stunAtt) }
    if ($src     -ne "") { $candidates.Add($src) }
    if ($dst     -ne "") { $candidates.Add($dst) }

    foreach ($ip in $candidates) {
        if (-not (IsValidIPv4 $ip)) { continue }
        if (IsExcluded  $ip)        { continue }
        if (AlreadySeen $ip)        { continue }
        Invoke-IPLookup $ip
    }
}

# ── Print tshark stderr — deduplicated ────────────────────────
# tshark writes "Capturing on 'Wi-Fi'" repeatedly to stderr.
# We use a HashSet to track which lines we have already printed
# and silently drop any line we have seen before.
# Real errors (field names, permission issues) are always new
# lines so they still get through.
function Print-StderrOnce {
    param([string]$errFilePath)

    $errContent = Get-Content $errFilePath -Raw -ErrorAction SilentlyContinue
    if (-not $errContent -or $errContent.Trim() -eq "") { return }

    foreach ($errLine in ($errContent -split "`n")) {
        $errLine = $errLine.Trim()
        if ($errLine -eq "") { continue }

        # Only print if we have never seen this exact line before
        if ($SeenErrLines.Add($errLine)) {
            Write-Host "[tshark] $errLine" -ForegroundColor DarkGray
        }
    }

    Clear-Content $errFilePath -ErrorAction SilentlyContinue
}

function Write-Summary {
    Write-Host ""
    Write-Host "============= Session summary ===============" -ForegroundColor Cyan
    Write-Host "  My public IP (excluded) : $MyPublicIP"
    Write-Host "  STUN servers (excluded) : $($StunServers.Count)"
    foreach ($s in $StunServers) { Write-Host "    - $s" }
    Write-Host "  Peers discovered        : $($SeenPeers.Count)"
    foreach ($p in $SeenPeers) { Write-Host "    - $p" }
    Write-Host "=============================================" -ForegroundColor Cyan
}

# ── Banner ────────────────────────────────────────────────────
Write-Host ""
Write-Host "                                                              " -ForegroundColor Cyan
Write-Host "  ▄▄▄▄▄▄                    ▄▄▄  ▄▄▄                          " -ForegroundColor Cyan
Write-Host " █▀██▀▀▀█▄              █▄ █▀██  ██                           " -ForegroundColor Cyan
Write-Host "   ██▄▄▄█▀             ▄██▄  ██  ██                      ▄    " -ForegroundColor Cyan
Write-Host "   ██▀▀█▄   ▄███▄ ▄███▄ ██   ██████   ▄█▀█▄▀██ ██▀ ▄█▀█▄ ████▄" -ForegroundColor Cyan
Write-Host " ▄ ██  ██   ██ ██ ██ ██ ██   ██  ██   ██▄█▀  ███   ██▄█▀ ██   " -ForegroundColor Cyan
Write-Host " ▀██▀  ▀██▀▄▀███▀▄▀███▀▄██ ▀██▀  ▀██▄▄▀█▄▄▄▄██ ██▄▄▀█▄▄▄▄█▀   " -ForegroundColor Cyan
Write-Host "                                                              " -ForegroundColor Cyan
Write-Host "                                                              " -ForegroundColor Cyan
Write-Host "  +=========================================+" -ForegroundColor Cyan
Write-Host "  |   WebRTC / STUN Live Peer IP Scanner   |" -ForegroundColor Cyan
Write-Host "  +=========================================+" -ForegroundColor Cyan
Write-Host ""
Write-Log "Interface        : $Interface"
Write-Log "Exclusion entries: $($AllExcluded.Count)  (built-in + file)"
Write-Log "Auto-stop        : ${Duration}s  (0 = unlimited)"
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

# ── Build tshark argument string ─────────────────────────────
$argList  = "-i `"$Interface`" -l -Y stun -T fields"
$argList += " -e ip.src"
$argList += " -e ip.dst"
$argList += " -e stun.att.ipv4"
$argList += " -E separator=|"
if ($Duration -gt 0) {
    $argList += " -a duration:$Duration"
}

# ── Temp files ───────────────────────────────────────────────
$tmpOut = [System.IO.Path]::GetTempFileName()
$tmpErr = [System.IO.Path]::GetTempFileName()

# ── Launch tshark ─────────────────────────────────────────────
$tsharkProc = Start-Process `
    -FilePath $tsharkPath `
    -ArgumentList $argList `
    -RedirectStandardOutput $tmpOut `
    -RedirectStandardError  $tmpErr `
    -PassThru `
    -NoNewWindow

Write-Log "tshark running (PID $($tsharkProc.Id))"

Start-Sleep -Milliseconds 800

if ($tsharkProc.HasExited) {
    $errMsg = Get-Content $tmpErr -Raw -ErrorAction SilentlyContinue
    Write-Err "tshark exited immediately (code $($tsharkProc.ExitCode))"
    if ($errMsg) { Write-Err "tshark said: $errMsg" }
    Remove-Item $tmpOut, $tmpErr -ErrorAction SilentlyContinue
    exit 1
}

Write-Log "Capture running - start your WebRTC call now..."
Write-Host ""

# ── Tail-read the temp file ───────────────────────────────────
$fileStream = [System.IO.FileStream]::new(
    $tmpOut,
    [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::Read,
    [System.IO.FileShare]::ReadWrite
)
$reader   = [System.IO.StreamReader]::new($fileStream)
$position = 0L

try {
    while (-not $tsharkProc.HasExited) {

        Print-StderrOnce $tmpErr

        $fileStream.Position = $position
        $line = $reader.ReadLine()

        if ($null -ne $line) {
            $position = $fileStream.Position
            Process-Line $line
        }
        else {
            Start-Sleep -Milliseconds 200
        }
    }

    # Drain remaining lines after tshark exits
    $fileStream.Position = $position
    while ($null -ne ($line = $reader.ReadLine())) {
        Process-Line $line
    }
}
finally {
    $reader.Close()
    $fileStream.Close()
    try { $tsharkProc.Kill() } catch {}
    Remove-Item $tmpOut, $tmpErr -ErrorAction SilentlyContinue
    Write-Summary
}
