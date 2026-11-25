param(
    [string]$LocalInstallerPath = '',
    [ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedSha256 = '4c93d4032860f6ee0b55a76715761c48605527e95b55ecd5730edd5fe8cf9fa6',
    [ValidateRange(1,536870912)][long]$ExpectedBytes = 137767835,
    [ValidatePattern('^0\.[0-9]+\.[0-9]+-dev\.[0-9]+$')][string]$ExpectedVersion = '0.3.1-dev.1',
    [long]$AssetId = 782615221,
    [long]$ReportReleaseId = 455308270,
    [string]$ReportOutputPath = ''
)
# Run only on a disposable GitHub-hosted Windows VM. Never bypass Windows protections.
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or $env:GITHUB_REPOSITORY -ne 'manbuusong-cpu/ai-maker-studio-installers') { throw 'Disposable authorized CI environment required.' }
$apiToken = $env:GH_TOKEN
if (-not $apiToken) { throw 'Repository-scoped CI authorization required.' }
$headers = @{ Authorization = "Bearer $apiToken"; Accept = 'application/vnd.github+json' }
$api = 'https://api.github.com/repos/manbuusong-cpu/ai-maker-studio-installers'
$expected = $ExpectedSha256
$work = Join-Path $env:PUBLIC ('AIMakerInstallerCheck-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $work
$results = Join-Path $work 'output'
$null = New-Item -ItemType Directory -Path $results, (Join-Path $work 'installed'), (Join-Path $work 'user-temp')
$installer = Join-Path $work 'AI-Maker-Studio-UNSIGNED-Setup.exe'
$user = 'AIMakerCheck'
$report = [ordered]@{ schemaVersion = 1; scope = 'Existing immutable installer on disposable Windows VM'; os = [Environment]::OSVersion.VersionString; runId = $env:GITHUB_RUN_ID; checks = [Collections.Generic.List[object]]::new(); overall = 'BLOCKED'; limitations = @('Interactive SmartScreen reputation is not tested by silent CI installation.', 'No user antivirus/firewall/SmartScreen policy is disabled.', 'A clean scan is not a security certification.') }
function Check($id, $status, $detail) {
    $report.checks.Add([ordered]@{ id = $id; status = $status; detail = $detail })
    Write-Output ("CHECK " + $id + " " + $status)
}
$createdUser = $false
$process = $null
$profileCreated = $false
$report.launchMethod = 'Bounded native ProcessStartInfo.UseShellExecute=false; functional CI only, not Explorer/SmartScreen reputation validation.'
$report.functionalResult = 'NOT TESTED'
try {
    $downloadHeaders = @{ Authorization = "Bearer $apiToken"; Accept = 'application/octet-stream' }
    if ($LocalInstallerPath) {
        $local = [IO.Path]::GetFullPath($LocalInstallerPath)
        $tempRoot = [IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\') + '\'
        if (-not $local.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or -not $local.EndsWith('.exe', [StringComparison]::OrdinalIgnoreCase) -or ((Get-Item -LiteralPath $local).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Only the owned CI temporary EXE is accepted.' }
        Copy-Item -LiteralPath $local -Destination $installer
    } else { Invoke-WebRequest -Uri "$api/releases/assets/$AssetId" -Headers $downloadHeaders -OutFile $installer }
    $hash = (Get-FileHash $installer -Algorithm SHA256).Hash.ToLowerInvariant()
    if ((Get-Item $installer).Length -ne $ExpectedBytes -or $hash -ne $expected) { throw 'Installer integrity mismatch; execution forbidden.' }
    $report.artifact = @{ sha256 = $hash; bytes = (Get-Item $installer).Length; version = $ExpectedVersion }
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
    $scanPassed = $false
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
        } elseif ($scanText -match '(?i)found no threats') { $scanPassed = $true; Check 'DEFENDER_SCAN' 'PASS' @{ exitCode = $scanCode; scope = 'Installer custom archive scan ignoring exclusions; scan-only mode, no threats reported'; output = $scanText } }
        else { Check 'DEFENDER_SCAN' 'NOT TESTED' @{ exitCode = $scanCode; output = [string]($scanOutput -join "`n") } }
    } catch { Check 'DEFENDER_SCAN' 'NOT TESTED' $_.Exception.Message }
    if ($malwareFound -or -not $scanPassed) { throw 'Explicit Defender scan PASS required before isolated execution.' }
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
    $profileCreated = $true
    Check 'TEST_PROFILE_CREATED' 'PASS' 'Windows CreateProfile succeeded for disposable account.'
    $credential = [PSCredential]::new("$env:COMPUTERNAME\$user", $password)
    # Read-only installer/harness; only owned result/install/temp directories are writable.
    function Set-TestAccess($target, $directory, $writeTest) {
        $access = if ($directory) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
        $access.SetAccessRuleProtection($true, $false)
        $inherit = if ($directory) { [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
        foreach ($sidText in @('S-1-5-18', 'S-1-5-32-544', [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)) {
            $sid = [Security.Principal.SecurityIdentifier]::new($sidText)
            $access.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', $inherit, 'None', 'Allow'))
        }
        $rights = if ($writeTest) { 'Modify' } else { 'ReadAndExecute' }
        $access.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($userSid), $rights, $inherit, 'None', 'Allow'))
        Set-Acl -LiteralPath $target -AclObject $access
    }
    Set-TestAccess $work $true $false
    Set-TestAccess $installer $false $false
    foreach ($owned in @($results, (Join-Path $work 'installed'), (Join-Path $work 'user-temp'))) { Set-TestAccess $owned $true $true }
    $child = @'
param([string]$Root, [string]$ProfileRoot, [string]$ExpectedHash, [string]$AppVersion)
$ErrorActionPreference = 'Stop'
$checks = [Collections.Generic.List[object]]::new()
$resultDirectory = Join-Path $Root 'output'
$launches = [Collections.Generic.List[object]]::new()
$childFailed = $false
function Check($id, $status, $detail) {
    $checks.Add([ordered]@{ id = $id; status = $status; detail = $detail })
    $checks | ConvertTo-Json -Depth 15 | Set-Content (Join-Path $resultDirectory 'standard-user-report.json') -Encoding UTF8
}
function Stage($phase) {
    @{ phase = $phase; time = [DateTime]::UtcNow.ToString('o') } | ConvertTo-Json | Set-Content (Join-Path $resultDirectory 'standard-user-progress.json') -Encoding UTF8
}
$install = Join-Path $Root 'installed'
$exe = Join-Path $install 'AI Maker Studio.exe'
$app = $null
$isStandardUser = $false
function Start-NativeTestProcess([string]$File, [string]$Arguments, [string]$Label) {
    Stage ($Label + '_START')
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $File
    $info.Arguments = $Arguments
    $info.WorkingDirectory = $Root
    $info.UseShellExecute = $false
    $info.ErrorDialog = $false
    $native = [Diagnostics.Process]::new()
    $native.StartInfo = $info
    try {
        if (-not $native.Start()) { throw 'Native process did not start.' }
    } catch {
        Check ($Label + '_LAUNCH') 'FAIL' @{ message = $_.Exception.Message; nativeErrorCode = $_.Exception.InnerException.NativeErrorCode }
        throw # No elevated retry, shell fallback, policy change or MOTW removal.
    }
    $launches.Add(@{ phase = $Label; pid = $native.Id; startedUtc = [DateTime]::UtcNow.ToString('o'); useShellExecute = $false })
    $launches | ConvertTo-Json | Set-Content (Join-Path $resultDirectory 'native-launches.json') -Encoding UTF8
    Stage ($Label + '_RUNNING')
    return $native
}
function Stop-OwnedTestProcess($native) {
    if ($native -and -not $native.HasExited) {
        $null = $native.CloseMainWindow()
        if (-not $native.WaitForExit(10000)) {
            $cleanup = & "$env:SystemRoot\System32\taskkill.exe" /PID $native.Id /T /F 2>&1
            if ($LASTEXITCODE -ne 0 -and -not $native.HasExited) { throw 'Owned application process tree could not be stopped.' }
            Check 'APP_CLOSE' 'WARNING' 'Test application required bounded process-tree cleanup.'
        }
    }
}
function EvaluatePage([string]$Mode = 'state') {
    $listeners = @(Get-NetTCPConnection -LocalPort 9223 -State Listen -ErrorAction Stop)
    if (-not $listeners.Count -or @($listeners | Where-Object { $_.OwningProcess -ne $app.Id -or $_.LocalAddress -notin @('127.0.0.1', '::1') }).Count) { throw 'CDP listener is not confined to the owned test app and loopback.' }
    $targets = Invoke-RestMethod 'http://127.0.0.1:9223/json/list' -TimeoutSec 3
    $expectedUrl = [uri]::new((Join-Path $install 'resources\app.asar\apps\desktop\dist\index.html')).AbsoluteUri
    $target = $targets | Where-Object { $_.type -eq 'page' -and $_.url -eq $expectedUrl } | Select-Object -First 1
    if (-not $target) { throw 'Expected packaged application renderer target not found.' }
    $socketUri = [uri]$target.webSocketDebuggerUrl
    if ($socketUri.Scheme -ne 'ws' -or $socketUri.Host -ne '127.0.0.1' -or $socketUri.Port -ne 9223) { throw 'Unexpected CDP WebSocket endpoint.' }
    $ws = [Net.WebSockets.ClientWebSocket]::new()
    $cancel = [Threading.CancellationTokenSource]::new(10000)
    try {
        $null = $ws.ConnectAsync([uri]$target.webSocketDebuggerUrl, $cancel.Token).GetAwaiter().GetResult()
        $expression = "(async()=>{const b=window.studio;if(!b)return {bridge:false,ready:document.readyState,root:!!document.getElementById('root')?.children.length,title:document.title,body:document.body?.innerText?.slice(0,500)};const s=await b.security.getSnapshot();const a=await b.loadAutosave();const c=document.querySelector('canvas');return {bridge:true,ready:document.readyState,root:!!document.getElementById('root')?.children.length,nodeUnavailable:typeof require==='undefined',canvas:!!c,webgl:!!(c&&(c.getContext('webgl2')||c.getContext('webgl'))),projectName:a?JSON.parse(a).name:null,renderedProjectName:document.querySelector('.header-path strong')?.textContent?.trim(),version:s.version,platform:s.platform,packaged:s.packaged,privacy:s.privacy,credentialStorage:s.credentials?.storage,autosavePresent:!!a,resources:performance.getEntriesByType('resource').slice(-10).map(r=>({name:new URL(r.name).pathname.split('/').pop(),bytes:r.decodedBodySize}))};})()"
        if ($Mode -eq 'persistence') {
            $expression = "(async()=>{const b=window.studio;const p=JSON.parse(await b.loadAutosave());p.name='Windows CI persistence check';await b.autosave(JSON.stringify(p));return {saved:JSON.parse(await b.loadAutosave()).name==='Windows CI persistence check'};})()"
        }
        $request = @{ id = 1; method = 'Runtime.evaluate'; params = @{ expression = $expression; awaitPromise = $true; returnByValue = $true } } | ConvertTo-Json -Compress -Depth 10
        $bytes = [Text.Encoding]::UTF8.GetBytes($request)
        $null = $ws.SendAsync([ArraySegment[byte]]::new($bytes), [Net.WebSockets.WebSocketMessageType]::Text, $true, $cancel.Token).GetAwaiter().GetResult()
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
    Stage 'VERIFY_STANDARD_USER'
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
    if (@('GH_TOKEN','GITHUB_TOKEN','ACTIONS_RUNTIME_TOKEN','ACTIONS_ID_TOKEN_REQUEST_TOKEN') | Where-Object { [Environment]::GetEnvironmentVariable($_) }) { throw 'A CI authorization token reached the standard-user process.' }
    Check 'CHILD_SECRETS_ABSENT' 'PASS' 'Repository authorization is absent from the child environment.'
    Check 'PROFILE_IDENTITY' 'PASS' 'Profile path verified against the current Windows SID registration.'
    # Do not inherit PowerShell 7's module paths into the Windows PowerShell 5.1 child.
    $env:PSModulePath = (Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules') + [IO.Path]::PathSeparator + (Join-Path $PSHOME 'Modules')
    foreach ($systemCommand in @('Get-FileHash','Get-NetTCPConnection','Get-AuthenticodeSignature')) { $null = Get-Command $systemCommand -ErrorAction Stop }
    Check 'CHILD_SYSTEM_MODULES' 'PASS' 'Only Windows PowerShell system module directories are used.'

    $env:TEMP = Join-Path $Root 'user-temp'
    $env:TMP = $env:TEMP
    $null = New-Item -ItemType Directory -Path $env:TEMP -Force
    Stage 'DPAPI_ROUNDTRIP'
    Add-Type -AssemblyName System.Security
    $plain = [Text.Encoding]::UTF8.GetBytes('AI-Maker-Studio-CI-test-data')
    $encrypted = [Security.Cryptography.ProtectedData]::Protect($plain, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    $decoded = [Security.Cryptography.ProtectedData]::Unprotect($encrypted, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    if ([Convert]::ToBase64String($plain) -ne [Convert]::ToBase64String($decoded)) { throw 'DPAPI OS roundtrip mismatch.' }
    Check 'OS_DPAPI_ROUNDTRIP' 'PASS' 'Same standard user; fixed nonsensitive test bytes. Does not test the Electron credential vault.'
    $sourceInstaller = Join-Path $Root 'AI-Maker-Studio-UNSIGNED-Setup.exe'
    if ((Get-FileHash $sourceInstaller -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ExpectedHash) { throw 'Child installer hash mismatch.' }
    if ((Get-Content $sourceInstaller -Stream Zone.Identifier -Raw) -notmatch 'ZoneId=3') { throw 'Internet zone marker was lost.' }
    Check 'CHILD_INSTALLER_INTEGRITY' 'PASS' 'Hash and Internet zone rechecked immediately before launch; source is read-only.'
    # Exact executable invocation is a functional CI test, not an Explorer reputation test.
    # /D remains the final NSIS argument; the fixed GUID test path has no spaces.
    $setup = Start-NativeTestProcess $sourceInstaller ("/S /D=$install") 'INSTALLER'
    if (-not $setup.WaitForExit(90000)) { Stop-OwnedTestProcess $setup; throw 'Installation timed out.' }
    if ($setup.ExitCode -ne 0 -or -not (Test-Path $exe)) { throw "Installation failed: exit $($setup.ExitCode)." }
    Check 'INSTALL_NONADMIN' 'PASS' @{ exitCode = $setup.ExitCode; scope = 'Silent installation on disposable VM; not interactive SmartScreen.' }
    $meta = (Get-Item $exe).VersionInfo
    Check 'APP_IDENTITY_METADATA' $(if ($meta.ProductName -eq 'AI Maker Studio') { 'PASS' } else { 'WARNING' }) @{ ProductName = $meta.ProductName; FileVersion = $meta.FileVersion; CompanyName = $meta.CompanyName }
    Check 'APP_AUTHENTICODE' $(if ((Get-AuthenticodeSignature $exe).Status -eq 'Valid') { 'PASS' } else { 'FAIL' }) ([string](Get-AuthenticodeSignature $exe).Status)
    Stage 'APPLICATION_START'
    $app = Start-NativeTestProcess $exe ("--remote-debugging-address=127.0.0.1 --remote-debugging-port=9223 --enable-logging=file --log-file=$resultDirectory\electron.log") 'APPLICATION'
    $state = $null
    $lastReadyError = $null
    Stage 'RENDERER_READY'
    $readyDeadline = [DateTime]::UtcNow.AddSeconds(45)
    do { Start-Sleep -Seconds 2; try { $state = EvaluatePage; if ($state.bridge -and $state.root -and $state.autosavePresent) { break } } catch { $lastReadyError = $_.Exception.Message } } while ([DateTime]::UtcNow -lt $readyDeadline)
    if (-not $state -or -not $state.bridge -or -not $state.root) { throw ('Renderer/preload/main IPC did not become ready. Last diagnostic: ' + $lastReadyError + '; state: ' + ($state | ConvertTo-Json -Depth 5 -Compress)) }
    if ($state.platform -ne 'win32' -or $state.packaged -ne $true -or $state.version -ne $AppVersion) { throw 'Unexpected Windows packaged app identity.' }
    Check 'PACKAGED_WINDOWS_IDENTITY' 'PASS' @{ version = $state.version; platform = $state.platform; packaged = $state.packaged }
    Check 'RENDERER_AND_IPC' 'PASS' $state
    Check 'NODE_ISOLATION' $(if ($state.nodeUnavailable) { 'PASS' } else { 'FAIL' }) 'Renderer Node require must be unavailable.'
    Check 'WINDOWS_WEBGL' $(if ($state.webgl) { 'PASS' } else { 'FAIL' }) 'Real hosted Windows renderer; no GPU disabling flags.'
    Check 'OFFLINE_DEFAULT' $(if ($state.privacy.schemaVersion -eq 1 -and $state.privacy.internetEnabled -eq $false -and $state.privacy.automaticUpdateChecks -eq $false -and $state.privacy.diagnosticsEnabled -eq $false) { 'PASS' } else { 'FAIL' }) $state.privacy
    Check 'ELECTRON_DPAPI_AVAILABILITY' $(if ($state.credentialStorage -eq 'WINDOWS_DPAPI') { 'PASS' } else { 'NOT TESTED' }) $state.credentialStorage
    $saved = EvaluatePage 'persistence'
    if ($saved.saved -ne $true) { throw 'Trusted project autosave roundtrip failed.' }
    Check 'AUTOSAVE_ROUNDTRIP' 'PASS' 'Validated synthetic project name saved and read back through real preload/main IPC.'
    Stop-OwnedTestProcess $app
    $autosaveFile = Join-Path $env:APPDATA 'AI Maker Studio\autosave.aimaker.json'
    $projectHash = (Get-FileHash $autosaveFile -Algorithm SHA256).Hash
    if ((Get-Content $autosaveFile -Raw | ConvertFrom-Json).name -ne 'Windows CI persistence check') { throw 'Persisted project file mismatch.' }
    $app = Start-NativeTestProcess $exe ("--remote-debugging-address=127.0.0.1 --remote-debugging-port=9223 --enable-logging=file --log-file=$resultDirectory\electron.log") 'APPLICATION_RESTART'
    $state = $null; $restartDeadline = [DateTime]::UtcNow.AddSeconds(45)
    do { Start-Sleep -Seconds 2; try { $state = EvaluatePage; if ($state.bridge -and $state.root -and $state.projectName -eq 'Windows CI persistence check' -and $state.renderedProjectName -eq 'Windows CI persistence check') { break } } catch { } } while ([DateTime]::UtcNow -lt $restartDeadline)
    if (-not $state.bridge -or -not $state.root -or $state.projectName -ne 'Windows CI persistence check' -or $state.renderedProjectName -ne 'Windows CI persistence check') { throw 'Project did not survive actual packaged-app restart.' }
    Check 'PROJECT_RESTART' 'PASS' 'Synthetic project restored from the actual app userData directory after EXE restart.'
} catch { $childFailed = $true; Check 'INSTALL_OR_STARTUP' 'FAIL' $_.Exception.Message }
finally {
    Stage 'CLEANUP'
    try { Stop-OwnedTestProcess $app }
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
                # Use the registered per-user command. In-place _?= execution
                # makes this builder's running-app check see the uninstaller
                # itself under INSTDIR; normal NSIS launch copies it to TEMP.
                $prefix = '"' + $uninstaller + '"'
                $registration = @(Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq 'AI Maker Studio' -and $_.DisplayVersion -eq $AppVersion -and $_.QuietUninstallString -and $_.QuietUninstallString.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) })
                if ($registration.Count -ne 1) { throw 'Exact per-user uninstall registration not found.' }
                $quietArguments = $registration[0].QuietUninstallString.Substring($prefix.Length).Trim()
                if ($quietArguments -notmatch '^/currentuser\s+/S$') { throw 'Unexpected registered uninstall flags; no shell or elevated retry allowed.' }
                Check 'REGISTERED_UNINSTALL_COMMAND' 'PASS' 'Exact registered executable and /currentuser /S arguments; no in-place override.'
                $remove = Start-NativeTestProcess $uninstaller $quietArguments 'UNINSTALLER'
                if (-not $remove.WaitForExit(60000)) { Stop-OwnedTestProcess $remove; throw 'Uninstall timed out.' }
                $removeDeadline = [DateTime]::UtcNow.AddSeconds(30)
                while ((Test-Path $exe) -and [DateTime]::UtcNow -lt $removeDeadline) { Start-Sleep -Milliseconds 250 }
                $stillRegistered = Test-Path -LiteralPath $registration[0].PSPath
                Check 'UNINSTALL_NONADMIN' $(if ($remove.ExitCode -eq 0 -and -not (Test-Path $exe) -and -not $stillRegistered) { 'PASS' } else { 'FAIL' }) @{ exitCode = $remove.ExitCode; executableRemoved = -not (Test-Path $exe); registrationRemoved = -not $stillRegistered }
                if ($sentinel) { Check 'SENTINEL_PRESERVED' $(if (Test-Path $sentinel) { 'PASS' } else { 'FAIL' }) 'Disposable sentinel only; actual project check is separate.' }
                if ($projectHash -and (Test-Path $autosaveFile)) {
                    Check 'PROJECT_PRESERVED_AFTER_UNINSTALL' $(if ((Get-FileHash $autosaveFile -Algorithm SHA256).Hash -eq $projectHash) { 'PASS' } else { 'FAIL' }) 'Actual synthetic autosave SHA-256 unchanged by uninstall.'
                } elseif ($projectHash) { Check 'PROJECT_PRESERVED_AFTER_UNINSTALL' 'FAIL' 'Uninstall removed the actual project file.' }
                else { Check 'PROJECT_PRESERVED_AFTER_UNINSTALL' 'NOT TESTED' 'No actual project hash was obtained before uninstall.' }
            } else { Check 'UNINSTALL_NONADMIN' 'NOT TESTED' 'Uninstaller not found after failed installation.' }
        } catch { Check 'UNINSTALL_NONADMIN' 'FAIL' $_.Exception.Message }
    } else { Check 'UNINSTALL_NONADMIN' 'NOT TESTED' 'Standard-user identity was not established.' }
    $checks | ConvertTo-Json -Depth 15 | Set-Content (Join-Path $resultDirectory 'standard-user-report.json') -Encoding UTF8
    Stage 'FINISHED'
}
if ($childFailed -or @($checks | Where-Object { $_.status -eq 'FAIL' -and $_.id -ne 'APP_AUTHENTICODE' }).Count) { exit 1 }
exit 0
'@
    $childPath = Join-Path $work 'standard-user-check.ps1'
    Set-Content $childPath $child -Encoding UTF8
    Set-TestAccess $childPath $false $false
    $process = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Credential $credential -LoadUserProfile -WorkingDirectory $work -ArgumentList @('-NoProfile', '-NonInteractive', '-File', $childPath, '-Root', $work, '-ProfileRoot', $profileBuffer.ToString(), '-ExpectedHash', $expected, '-AppVersion', $ExpectedVersion) -PassThru
    $null = $process.Handle # Cache the native handle before secondary-logon child exit.
    if (-not $process.WaitForExit(360000)) {
        $null = & "$env:SystemRoot\System32\taskkill.exe" /PID $process.Id /T /F 2>&1
        $report.childTimedOut = $true
        Check 'STANDARD_USER_HARNESS' 'NOT TESTED' 'Secondary-logon test exceeded isolated VM time limit. Inspect partial checks and last stage; not an application acceptance result.'
    }
    $report.childExitCode = if ($process.HasExited) { $process.ExitCode } else { $null }
    $progressFile = Join-Path $results 'standard-user-progress.json'
    if (Test-Path $progressFile) { $report.standardUserProgress = Get-Content $progressFile -Raw | ConvertFrom-Json }
    $launchFile = Join-Path $results 'native-launches.json'
    if (Test-Path $launchFile) { $report.nativeLaunches = @(Get-Content $launchFile -Raw | ConvertFrom-Json) }
    $childReport = Join-Path $results 'standard-user-report.json'
    if (Test-Path $childReport) { foreach ($entry in @(Get-Content $childReport -Raw | ConvertFrom-Json)) { $report.checks.Add($entry) } }
    else { Check 'STANDARD_USER_HARNESS' 'NOT TESTED' @{ exitCode = $process.ExitCode; reason = 'Child report missing; no execution-policy changes attempted.' } }
} catch { Check 'WINDOWS_HARNESS' 'FAIL' $_.Exception.Message }
finally {
    if ($createdUser) {
        try {
            $ownedProcesses = @(Get-Process -IncludeUserName -ErrorAction Stop | Where-Object { $_.UserName -eq "$env:COMPUTERNAME\$user" })
            foreach ($ownedProcess in $ownedProcesses) { Stop-Process -Id $ownedProcess.Id -Force -ErrorAction Stop }
            $remainingProcesses = @(Get-Process -IncludeUserName -ErrorAction Stop | Where-Object { $_.UserName -eq "$env:COMPUTERNAME\$user" })
            if ($remainingProcesses.Count) { throw 'Disposable-account processes remain.' }
            Check 'DISPOSABLE_PROCESS_CLEANUP' 'PASS' @{ stopped = $ownedProcesses.Count }
        } catch { Check 'DISPOSABLE_PROCESS_CLEANUP' 'FAIL' $_.Exception.Message }
        try {
            if ($profileCreated) {
                $profile = Get-CimInstance Win32_UserProfile -Filter ("SID='" + $userSid + "'")
                if ($profile -and $profile.LocalPath -eq $profileBuffer.ToString() -and -not $profile.Loaded) { $profile | Remove-CimInstance -ErrorAction Stop; Check 'DISPOSABLE_PROFILE_CLEANUP' 'PASS' 'Only the profile created in this run was removed.' }
                else { Check 'DISPOSABLE_PROFILE_CLEANUP' 'WARNING' 'Temporary profile remains loaded; VM disposal removes it.' }
            }
            Remove-LocalUser -Name $user -ErrorAction Stop
            Check 'DISPOSABLE_ACCOUNT_CLEANUP' 'PASS' 'Only the account created in this run was removed.'
        } catch { Check 'DISPOSABLE_ACCOUNT_CLEANUP' 'FAIL' $_.Exception.Message }
    }
    $required = @('INSTALL_NONADMIN','PACKAGED_WINDOWS_IDENTITY','RENDERER_AND_IPC','NODE_ISOLATION','WINDOWS_WEBGL','OFFLINE_DEFAULT','AUTOSAVE_ROUNDTRIP','PROJECT_RESTART','UNINSTALL_NONADMIN','PROJECT_PRESERVED_AFTER_UNINSTALL')
    $missing = @($required | Where-Object { $id = $_; -not @($report.checks | Where-Object { $_.id -eq $id -and $_.status -eq 'PASS' }).Count })
    $report.functionalResult = if ($missing.Count -eq 0 -and $report.childExitCode -eq 0 -and -not $report.childTimedOut -and $report.standardUserProgress.phase -eq 'FINISHED') { 'PASS' } else { 'INCOMPLETE' }
    $report.unpassedFunctionalChecks = $missing
    $report.lifecycleResult = if (@($report.checks | Where-Object { $_.id -like 'DISPOSABLE_*' -and $_.status -eq 'FAIL' }).Count) { 'FAIL' } elseif (@($report.checks | Where-Object { $_.id -like 'DISPOSABLE_*' -and $_.status -eq 'WARNING' }).Count) { 'WARNING' } else { 'PASS' }
    $report.productionTrust = 'UNSIGNED_PRODUCTION_BLOCKED'
    $report.acceptanceScope = 'Authorized personal-use functional test only; interactive SmartScreen and trusted publisher are separate.'
    $report.overall = if ($report.functionalResult -eq 'PASS' -and $report.lifecycleResult -ne 'FAIL') { 'PERSONAL_FUNCTIONAL_PASS_UNSIGNED' } else { 'PERSONAL_FUNCTIONAL_INCOMPLETE_UNSIGNED' }
    $reportFile = Join-Path $work 'windows-security-report.json'
    $report | ConvertTo-Json -Depth 20 | Set-Content $reportFile -Encoding UTF8
    if ($ReportOutputPath) {
        $output = [IO.Path]::GetFullPath($ReportOutputPath)
        $tempRoot = [IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\') + '\'
        if (-not $output.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or -not $output.EndsWith('.json')) { throw 'Report output must remain in the owned CI temporary directory.' }
        Copy-Item -LiteralPath $reportFile -Destination $output
    }
    if ($ReportReleaseId -gt 0) {
        $name = 'windows-functional-report-' + [DateTime]::UtcNow.ToString('yyyy-MM-dd') + '-run-' + $env:GITHUB_RUN_ID + '.json'
        $url = 'https://uploads.github.com/repos/manbuusong-cpu/ai-maker-studio-installers/releases/' + $ReportReleaseId + '/assets?name=' + [uri]::EscapeDataString($name)
        $asset = Invoke-RestMethod -Uri $url -Headers $headers -Method Post -InFile $reportFile -ContentType 'application/json'
        Write-Output ('REPORT_ASSET_ID=' + $asset.id)
    }
    Write-Output ($report | ConvertTo-Json -Depth 20 -Compress)
    $apiToken = $null
}
if ($report.functionalResult -ne 'PASS' -or $report.lifecycleResult -eq 'FAIL') { exit 1 }
