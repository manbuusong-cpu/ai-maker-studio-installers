# Run only on a disposable GitHub-hosted Windows VM. Never bypass Windows protections.
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:GITHUB_REPOSITORY -ne 'manbuusong-cpu/ai-maker-studio-installers') { throw 'Disposable authorized CI environment required.' }
$apiToken = $env:GH_TOKEN
if (-not $apiToken) { throw 'Repository-scoped CI authorization required.' }
$headers = @{ Authorization = "Bearer $apiToken"; Accept = 'application/vnd.github+json' }
$api = 'https://api.github.com/repos/manbuusong-cpu/ai-maker-studio-installers'
$expected = '4c93d4032860f6ee0b55a76715761c48605527e95b55ecd5730edd5fe8cf9fa6'
$work = Join-Path $env:PUBLIC ('AIMakerInstallerCheck-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $work
$installer = Join-Path $work 'AI-Maker-Studio-UNSIGNED-Setup.exe'
$user = 'AIMakerCheck'
$report = [ordered]@{ schemaVersion = 1; scope = 'Existing immutable installer on disposable Windows VM'; os = [Environment]::OSVersion.VersionString; runId = $env:GITHUB_RUN_ID; checks = [Collections.Generic.List[object]]::new(); overall = 'BLOCKED'; limitations = @('Interactive SmartScreen reputation is not tested by silent CI installation.', 'No user antivirus/firewall/SmartScreen policy is disabled.', 'A clean scan is not a security certification.') }
function Check($id, $status, $detail) { $report.checks.Add([ordered]@{ id = $id; status = $status; detail = $detail }) }
$createdUser = $false
try {
    $downloadHeaders = @{ Authorization = "Bearer $apiToken"; Accept = 'application/octet-stream' }
    Invoke-WebRequest -Uri "$api/releases/assets/782615221" -Headers $downloadHeaders -OutFile $installer
    $hash = (Get-FileHash $installer -Algorithm SHA256).Hash.ToLowerInvariant()
    if ((Get-Item $installer).Length -ne 137767835 -or $hash -ne $expected) { throw 'Installer integrity mismatch; execution forbidden.' }
    Check 'DOWNLOAD_SHA256' 'PASS' $hash
    Set-Content -Path $installer -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3" -Encoding ascii
    Check 'INTERNET_ZONE_PRESERVED' 'PASS' ((Get-Content $installer -Stream Zone.Identifier) -join '; ')
    $sig = Get-AuthenticodeSignature $installer
    Check 'INSTALLER_AUTHENTICODE' $(if ($sig.Status -eq 'Valid') { 'PASS' } else { 'FAIL' }) ([string]$sig.Status)
    Check 'INTERACTIVE_SMARTSCREEN' 'NOT TESTED' 'User reports unknown publisher; silent CI does not exercise Explorer reputation prompts.'
    $vi = (Get-Item $installer).VersionInfo
    $report.installerMetadata = @{ ProductName = $vi.ProductName; FileVersion = $vi.FileVersion; CompanyName = $vi.CompanyName }
    # Retain authorization only in this parent process, never in native children.
    foreach ($name in @('GH_TOKEN', 'GITHUB_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN')) { Remove-Item "Env:$name" -ErrorAction SilentlyContinue }
    $malwareFound = $false
    try {
        $av = Get-MpComputerStatus
        $report.defender = @{ AMServiceEnabled = $av.AMServiceEnabled; AntivirusEnabled = $av.AntivirusEnabled; SignatureVersion = $av.AntivirusSignatureVersion; SignatureUpdated = [string]$av.AntivirusSignatureLastUpdated }
        if (-not $av.AMServiceEnabled -or -not $av.AntivirusEnabled) { throw 'Defender service unavailable in this hosted image.' }
        $scanner = Get-ChildItem "$env:ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe" -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
        if (-not $scanner) { $scanner = Get-Item "$env:ProgramFiles\Windows Defender\MpCmdRun.exe" }
        # Microsoft documents this scan-only option as ignoring file exclusions and
        # scanning archives. It changes no Defender policy. Any nonzero result
        # blocks execution; detected files are never installed.
        try { Update-MpSignature; $report.defender.SignatureUpdateAttempt = 'Completed' }
        catch { $report.defender.SignatureUpdateAttempt = $_.Exception.Message }
        $currentAv = Get-MpComputerStatus
        $report.defender.SignatureVersion = $currentAv.AntivirusSignatureVersion
        $report.defender.SignatureUpdated = [string]$currentAv.AntivirusSignatureLastUpdated
        $scanOutput = & $scanner.FullName -Scan -ScanType 3 -File $installer -DisableRemediation 2>&1
        $scanCode = $LASTEXITCODE
        $scanText = [string]($scanOutput -join "`n")
        $detections = @(Get-MpThreatDetection | Where-Object { ($_.Resources -join ';') -like "*$work*" })
        if ($scanCode -ne 0 -or $detections.Count -or -not (Test-Path $installer)) {
            $malwareFound = $true
            Check 'DEFENDER_SCAN' 'FAIL' @{ exitCode = $scanCode; threatIds = @($detections.ThreatID); output = [string]($scanOutput -join "`n") }
        } elseif ($scanText -match '(?i)skipped|not scanned|scan failed') {
            Check 'DEFENDER_SCAN' 'NOT TESTED' @{ exitCode = $scanCode; output = $scanText }
        } elseif ($scanText -match '(?i)found no threats') { Check 'DEFENDER_SCAN' 'PASS' @{ exitCode = $scanCode; scope = 'Installer custom archive scan ignoring exclusions; scan-only mode, no threats reported'; output = $scanText } }
        else { Check 'DEFENDER_SCAN' 'NOT TESTED' @{ exitCode = $scanCode; output = [string]($scanOutput -join "`n") } }
    } catch { Check 'DEFENDER_SCAN' 'NOT TESTED' $_.Exception.Message }
    if ($malwareFound) { throw 'Antivirus detection: installer execution forbidden.' }
    if (-not (Test-Path $installer) -or (Get-FileHash $installer -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) { throw 'Installer missing or changed after scanning; execution forbidden.' }
    $password = ConvertTo-SecureString ([Guid]::NewGuid().ToString('N') + 'aA!9') -AsPlainText -Force
    $null = New-LocalUser -Name $user -Password $password -Description 'Disposable AI Maker installer test' -PasswordNeverExpires
    $createdUser = $true
    Add-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-545').Name -Member $user
    # Explicitly create the disposable account's profile before the secondary
    # logon; LoadUserProfile alone did not populate known folders on this image.
    Add-Type @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class InstallerTestProfile {
    [DllImport("userenv.dll", CharSet=CharSet.Unicode)]
    public static extern int CreateProfile(string sid, string user, [Out] StringBuilder path, uint length);
}
'@
    $userSid = (Get-LocalUser -Name $user).SID.Value
    $profileBuffer = [Text.StringBuilder]::new(260)
    $profileResult = [InstallerTestProfile]::CreateProfile($userSid, $user, $profileBuffer, 260)
    if ($profileResult -ne 0) { throw "Disposable profile creation failed: $profileResult" }
    Check 'TEST_PROFILE_CREATED' 'PASS' 'Windows CreateProfile succeeded for disposable account.'
    $credential = [PSCredential]::new("$env:COMPUTERNAME\$user", $password)
    $acl = Get-Acl $work
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new("$env:COMPUTERNAME\$user", 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    Set-Acl $work $acl
    $child = @'
param([string]$Root, [string]$ProfileRoot)
$ErrorActionPreference = 'Stop'
$checks = [Collections.Generic.List[object]]::new()
function Check($id, $status, $detail) { $checks.Add([ordered]@{ id = $id; status = $status; detail = $detail }) }
$install = Join-Path $Root 'installed'
$exe = Join-Path $install 'AI Maker Studio.exe'
$app = $null
$isStandardUser = $false
function EvaluatePage {
    $targets = Invoke-RestMethod 'http://127.0.0.1:9223/json/list' -TimeoutSec 3
    $target = $targets | Where-Object { $_.type -eq 'page' -and $_.url -like 'file:*' } | Select-Object -First 1
    if (-not $target) { throw 'Application renderer target not found.' }
    $ws = [Net.WebSockets.ClientWebSocket]::new()
    $cancel = [Threading.CancellationTokenSource]::new(10000)
    try {
        $ws.ConnectAsync([uri]$target.webSocketDebuggerUrl, $cancel.Token).GetAwaiter().GetResult()
        $expression = "(async()=>{const b=window.studio;if(!b)return {bridge:false,ready:document.readyState};const s=await b.security.getSnapshot();const a=await b.loadAutosave();const c=document.querySelector('canvas');return {bridge:true,ready:document.readyState,root:!!document.getElementById('root')?.children.length,nodeUnavailable:typeof require==='undefined',canvas:!!c,webgl:!!(c&&(c.getContext('webgl2')||c.getContext('webgl'))),version:s.version,platform:s.platform,packaged:s.packaged,privacy:s.privacy,credentialStorage:s.credentials?.storage,autosavePresent:!!a};})()"
        $request = @{ id = 1; method = 'Runtime.evaluate'; params = @{ expression = $expression; awaitPromise = $true; returnByValue = $true } } | ConvertTo-Json -Compress -Depth 10
        $bytes = [Text.Encoding]::UTF8.GetBytes($request)
        $ws.SendAsync([ArraySegment[byte]]::new($bytes), [Net.WebSockets.WebSocketMessageType]::Text, $true, $cancel.Token).GetAwaiter().GetResult()
        do {
            $memory = [IO.MemoryStream]::new()
            do {
                $buffer = [byte[]]::new(65536)
                $received = $ws.ReceiveAsync([ArraySegment[byte]]::new($buffer), $cancel.Token).GetAwaiter().GetResult()
                $memory.Write($buffer, 0, $received.Count)
            } until ($received.EndOfMessage)
            $reply = [Text.Encoding]::UTF8.GetString($memory.ToArray()) | ConvertFrom-Json
        } until ($reply.id -eq 1)
        if ($reply.result.exceptionDetails -or $reply.error) { throw 'Renderer diagnostic evaluation failed.' }
        return $reply.result.result.value
    } finally { $ws.Dispose(); $cancel.Dispose() }
}
try {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Non-administrator test would be invalid.' }
    $isStandardUser = $true
    Check 'STANDARD_USER' 'PASS' 'Process is not an administrator.'
    # Secondary logon inherits runneradmin's environment. Bind it to the profile
    # returned by Windows CreateProfile and independently verify the current SID's
    # ProfileList registration before launching any installer/application.
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $registered = (Get-ItemProperty ("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + $sid)).ProfileImagePath
    if (-not $ProfileRoot -or $registered -ne $ProfileRoot -or -not (Test-Path $ProfileRoot)) { throw 'Current standard-user SID profile does not match Windows registration.' }
    $env:USERPROFILE = $ProfileRoot
    $env:APPDATA = Join-Path $ProfileRoot 'AppData\Roaming'
    $env:LOCALAPPDATA = Join-Path $ProfileRoot 'AppData\Local'
    $env:HOMEDRIVE = [IO.Path]::GetPathRoot($ProfileRoot).TrimEnd('\')
    $env:HOMEPATH = $ProfileRoot.Substring($env:HOMEDRIVE.Length)
    $null = New-Item -ItemType Directory -Path $env:APPDATA, $env:LOCALAPPDATA -Force
    Check 'PROFILE_IDENTITY' 'PASS' 'Profile path verified against the current Windows SID registration.'
    $env:TEMP = Join-Path $Root 'user-temp'
    $env:TMP = $env:TEMP
    $null = New-Item -ItemType Directory -Path $env:TEMP -Force
    $setup = Start-Process -FilePath (Join-Path $Root 'AI-Maker-Studio-UNSIGNED-Setup.exe') -ArgumentList @('/S', "/D=$install") -PassThru
    if (-not $setup.WaitForExit(120000)) { $setup.Kill(); throw 'Installation timed out.' }
    if ($setup.ExitCode -ne 0 -or -not (Test-Path $exe)) { throw "Installation failed: exit $($setup.ExitCode)." }
    Check 'INSTALL_NONADMIN' 'PASS' @{ exitCode = $setup.ExitCode; scope = 'Silent installation on disposable VM; not interactive SmartScreen.' }
    $meta = (Get-Item $exe).VersionInfo
    Check 'APP_IDENTITY_METADATA' $(if ($meta.ProductName -eq 'AI Maker Studio') { 'PASS' } else { 'WARNING' }) @{ ProductName = $meta.ProductName; FileVersion = $meta.FileVersion; CompanyName = $meta.CompanyName }
    $app = Start-Process -FilePath $exe -ArgumentList @('--remote-debugging-address=127.0.0.1','--remote-debugging-port=9223') -PassThru
    $state = $null
    $readyDeadline = [DateTime]::UtcNow.AddSeconds(60)
    do { Start-Sleep -Seconds 2; try { $state = EvaluatePage; if ($state.bridge -and $state.root) { break } } catch { } } while ([DateTime]::UtcNow -lt $readyDeadline)
    if (-not $state -or -not $state.bridge -or -not $state.root) { throw 'Renderer/preload/main IPC did not become ready.' }
    Check 'RENDERER_AND_IPC' 'PASS' $state
    Check 'NODE_ISOLATION' $(if ($state.nodeUnavailable) { 'PASS' } else { 'FAIL' }) 'Renderer Node require must be unavailable.'
    Check 'WINDOWS_WEBGL' $(if ($state.webgl) { 'PASS' } else { 'FAIL' }) 'Real hosted Windows renderer; no GPU disabling flags.'
    Check 'OFFLINE_DEFAULT' $(if (-not $state.privacy.internetEnabled -and -not $state.privacy.automaticUpdateChecks -and -not $state.privacy.diagnosticsEnabled) { 'PASS' } else { 'FAIL' }) $state.privacy
    Check 'ELECTRON_DPAPI_AVAILABILITY' $(if ($state.credentialStorage -eq 'WINDOWS_DPAPI') { 'PASS' } else { 'NOT TESTED' }) $state.credentialStorage
    Add-Type -AssemblyName System.Security
    $plain = [Text.Encoding]::UTF8.GetBytes('AI-Maker-Studio-CI-test-data')
    $encrypted = [Security.Cryptography.ProtectedData]::Protect($plain, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    $decoded = [Security.Cryptography.ProtectedData]::Unprotect($encrypted, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    if ([Convert]::ToBase64String($plain) -ne [Convert]::ToBase64String($decoded)) { throw 'DPAPI OS roundtrip mismatch.' }
    Check 'OS_DPAPI_ROUNDTRIP' 'PASS' 'Same standard user; fixed nonsensitive test bytes.'
} catch { Check 'INSTALL_OR_STARTUP' 'FAIL' $_.Exception.Message }
finally {
    try { if ($app -and -not $app.HasExited) { $null = $app.CloseMainWindow(); if (-not $app.WaitForExit(15000)) { $app.Kill() } } }
    catch { Check 'APP_CLEANUP' 'FAIL' $_.Exception.Message }
    if ($isStandardUser) {
        $sentinel = $null
        try {
            $data = Join-Path $env:APPDATA 'AI Maker Studio'
            $null = New-Item -ItemType Directory -Path $data -Force
            $sentinelPath = Join-Path $data 'ci-preserve-sentinel.txt'
            Set-Content $sentinelPath 'Disposable CI data preservation check.'
            $sentinel = $sentinelPath
        } catch { Check 'USER_DATA_PRESERVED' 'NOT TESTED' $_.Exception.Message }
        try {
            $uninstaller = Join-Path $install 'Uninstall AI Maker Studio.exe'
            if (Test-Path $uninstaller) {
                $remove = Start-Process -FilePath $uninstaller -ArgumentList '/S' -PassThru
                if (-not $remove.WaitForExit(90000)) { $remove.Kill(); throw 'Uninstall timed out.' }
                Start-Sleep -Seconds 4
                Check 'UNINSTALL_NONADMIN' $(if ($remove.ExitCode -eq 0 -and -not (Test-Path $exe)) { 'PASS' } else { 'FAIL' }) @{ exitCode = $remove.ExitCode }
                if ($sentinel) { Check 'USER_DATA_PRESERVED' $(if (Test-Path $sentinel) { 'PASS' } else { 'FAIL' }) 'Only a disposable sentinel was used.' }
            } else { Check 'UNINSTALL_NONADMIN' 'NOT TESTED' 'Uninstaller not found after failed installation.' }
        } catch { Check 'UNINSTALL_NONADMIN' 'FAIL' $_.Exception.Message }
    } else { Check 'UNINSTALL_NONADMIN' 'NOT TESTED' 'Standard-user identity was not established.' }
    $checks | ConvertTo-Json -Depth 15 | Set-Content (Join-Path $Root 'standard-user-report.json') -Encoding UTF8
}
'@
    $childPath = Join-Path $work 'standard-user-check.ps1'
    Set-Content $childPath $child -Encoding UTF8
    $process = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Credential $credential -LoadUserProfile -WorkingDirectory $work -ArgumentList @('-NoProfile', '-NonInteractive', '-File', $childPath, '-Root', $work, '-ProfileRoot', $profileBuffer.ToString()) -PassThru
    if (-not $process.WaitForExit(300000)) { $process.Kill(); throw 'Standard-user test timed out.' }
    $childReport = Join-Path $work 'standard-user-report.json'
    if (Test-Path $childReport) { foreach ($entry in @(Get-Content $childReport -Raw | ConvertFrom-Json)) { $report.checks.Add($entry) } }
    else { Check 'STANDARD_USER_HARNESS' 'NOT TESTED' @{ exitCode = $process.ExitCode; reason = 'Child report missing; no execution-policy changes attempted.' } }
} catch { Check 'WINDOWS_HARNESS' 'FAIL' $_.Exception.Message }
finally {
    if ($createdUser) { Remove-LocalUser -Name $user -ErrorAction SilentlyContinue }
    $report.overall = 'BLOCKED_UNSIGNED_INSTALLER'
    $reportFile = Join-Path $work 'windows-security-report.json'
    $report | ConvertTo-Json -Depth 20 | Set-Content $reportFile -Encoding UTF8
    $name = 'windows-security-report-2026-11-23-run-' + $env:GITHUB_RUN_ID + '.json'
    $url = 'https://uploads.github.com/repos/manbuusong-cpu/ai-maker-studio-installers/releases/455308270/assets?name=' + [uri]::EscapeDataString($name)
    $asset = Invoke-RestMethod -Uri $url -Headers $headers -Method Post -InFile $reportFile -ContentType 'application/json'
    Write-Output ('REPORT_ASSET_ID=' + $asset.id)
    Write-Output ($report | ConvertTo-Json -Depth 20 -Compress)
    $apiToken = $null
}
