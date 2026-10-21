<# :
@echo off
powershell -NoProfile -ExecutionPolicy Bypass -Command "& ([ScriptBlock]::Create((Get-Content -Raw '%~f0'))) %*"
exit /b %ERRORLEVEL%
#>
param([string]$Mode)

# ==============================================================================
# Qoder Privacy Hardening Tool v2.1 (Production Hardened)
#
# Supported Qoder Versions:
#  - v0.4.8+ (Signatures: s4i, Vvt, _ee, I9l)
#  - v0.4.3  (Signatures: vLi, MTt, G$, tvl)
#
# Hardening Specifications:
#  - Dynamic Qoder path resolution (portable across all user profiles)
#  - Multi-version profile auto-detection
#  - Strict fail-closed verification on unknown versions or layout changes
#  - Exact uniqueness constraint (count === 1) on all patch targets
#  - Atomic writes with pre-modification and pre-restore safety backups
#  - Cryptographic verification before and after every state transition
# ==============================================================================

function Resolve-QoderRoot {
    $candidates = @(
        "$env:LOCALAPPDATA\Programs\Qoder",
        "$env:ProgramFiles\Qoder",
        "${env:ProgramFiles(x86)}\Qoder"
    )
    $cmd = Get-Command Qoder.exe -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) {
        $candidates = @((Split-Path -Parent $cmd.Source)) + $candidates
    }
    foreach ($c in $candidates) {
        if ($c -and (Test-Path (Join-Path $c "Qoder.exe"))) {
            return (Resolve-Path $c).Path
        }
    }
    return $null
}

function Get-Sha256($path) {
    if (-not (Test-Path $path)) { return "" }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($path)
    $bytes = $sha.ComputeHash($stream)
    $stream.Close()
    return [BitConverter]::ToString($bytes).Replace("-", "")
}

function Count-Occurrences($text, $pattern) {
    if ([string]::IsNullOrEmpty($text) -or [string]::IsNullOrEmpty($pattern)) { return 0 }
    $count = 0
    $idx = 0
    while (($idx = $text.IndexOf($pattern, $idx, [StringComparison]::Ordinal)) -ne -1) {
        $count++
        $idx += $pattern.Length
    }
    return $count
}

# Resolve Qoder installation path portably
$qoderRoot = Resolve-QoderRoot
if (-not $qoderRoot) {
    Write-Host "[FATAL ERROR] Could not locate Qoder installation." -ForegroundColor Red
    Write-Host "Expected location: %LOCALAPPDATA%\Programs\Qoder or in system PATH." -ForegroundColor Red
    exit 1
}

$qoderExe = Join-Path $qoderRoot "Qoder.exe"
$qoderVersion = "Unknown"
if (Test-Path $qoderExe) {
    $verInfo = (Get-Item $qoderExe).VersionInfo
    $qoderVersion = if ($verInfo.ProductVersion) { $verInfo.ProductVersion } else { $verInfo.FileVersion }
}

$targetDir  = Join-Path $qoderRoot "resources\app.asar.unpacked\node_modules\@qoder-ai\qoder-agent-sdk\dist\_worker"
$targetFile = Join-Path $targetDir "qoder-worker-runtime.obf.mjs"

# Multi-version signature profiles
$profiles = @(
    @{
        Name = "0.4.8+"
        Defs = @(
            @{
                Id            = "s4i"
                Name          = "1. businessFinish.report (Prompt Leak)"
                Description   = "POST https://api2.qoder.sh/algo/api/v2/service/business/finish"
                UnpatchedSig  = "async function s4i(A){let{sessionId:e,businessInfo:t}=A;"
                ReplaceTarget = "async function s4i(A){let{sessionId:e,businessInfo:t}=A;"
                ReplaceWith   = "async function s4i(A){return;let{sessionId:e,businessInfo:t}=A;"
                PatchedSig    = "async function s4i(A){return;let{sessionId:e,businessInfo:t}=A;"
            },
            @{
                Id            = "Vvt"
                Name          = "2. codeStatistics.track (Code Metrics)"
                Description   = "POST https://center.qoder.sh/api/v1/tracking (code metrics)"
                UnpatchedSig  = 'Vvt=class{constructor(A){this.pipeline=A}async track(A){let e=di.builder().operation("codeStatistics.track")'
                ReplaceTarget = "Vvt=class{constructor(A){this.pipeline=A}async track(A){"
                ReplaceWith   = "Vvt=class{constructor(A){this.pipeline=A}async track(A){return;"
                PatchedSig    = 'Vvt=class{constructor(A){this.pipeline=A}async track(A){return;let e=di.builder().operation("codeStatistics.track")'
            },
            @{
                Id            = "_ee"
                Name          = "3. _ee Dispatcher (Git Remote & Metadata)"
                Description   = "POST https://center.qoder.sh/api/v1/tracking (git_remote + turn metadata)"
                UnpatchedSig  = "async function _ee(A){A.beforeSend?.();let e=await h9l"
                ReplaceTarget = "async function _ee(A){A.beforeSend?.();let e=await h9l"
                ReplaceWith   = "async function _ee(A){A.beforeSend?.();return;let e=await h9l"
                PatchedSig    = "async function _ee(A){A.beforeSend?.();return;let e=await h9l"
            },
            @{
                Id            = "I9l"
                Name          = "4. I9l Transport (Network Sink)"
                Description   = "POST https://center.qoder.sh/api/v1/tracking (transport sink)"
                UnpatchedSig  = 'async function I9l(A,e="aiCodeTracking.report",t,i){if(i?.(),!Kd())'
                ReplaceTarget = 'async function I9l(A,e="aiCodeTracking.report",t,i){if(i?.(),!Kd())'
                ReplaceWith   = 'async function I9l(A,e="aiCodeTracking.report",t,i){return;if(i?.(),!Kd())'
                PatchedSig    = 'async function I9l(A,e="aiCodeTracking.report",t,i){return;if(i?.(),!Kd())'
            }
        )
    },
    @{
        Name = "0.4.3"
        Defs = @(
            @{
                Id            = "vLi"
                Name          = "1. businessFinish.report (Prompt Leak)"
                Description   = "POST https://api2.qoder.sh/algo/api/v2/service/business/finish"
                UnpatchedSig  = "async function vLi(A){let{sessionId:e,businessInfo:t}=A;"
                ReplaceTarget = "async function vLi(A){let{sessionId:e,businessInfo:t}=A;"
                ReplaceWith   = "async function vLi(A){return;let{sessionId:e,businessInfo:t}=A;"
                PatchedSig    = "async function vLi(A){return;let{sessionId:e,businessInfo:t}=A;"
            },
            @{
                Id            = "MTt"
                Name          = "2. codeStatistics.track (Code Metrics)"
                Description   = "POST https://center.qoder.sh/api/v1/tracking (code metrics)"
                UnpatchedSig  = 'MTt=class{constructor(A){this.sender=A}async track(A){await this.sender.send(yi.builder().operation("codeStatistics.track")'
                ReplaceTarget = "MTt=class{constructor(A){this.sender=A}async track(A){"
                ReplaceWith   = "MTt=class{constructor(A){this.sender=A}async track(A){return;"
                PatchedSig    = 'MTt=class{constructor(A){this.sender=A}async track(A){return;await this.sender.send(yi.builder().operation("codeStatistics.track")'
            },
            @{
                Id            = "G$"
                Name          = "3. G$ Dispatcher (Git Remote & Metadata)"
                Description   = "POST https://center.qoder.sh/api/v1/tracking (git_remote + turn metadata)"
                UnpatchedSig  = "async function G`$(A){A.beforeSend?.();let e=await Avl"
                ReplaceTarget = "async function G`$(A){A.beforeSend?.();let e=await Avl"
                ReplaceWith   = "async function G`$(A){A.beforeSend?.();return;let e=await Avl"
                PatchedSig    = "async function G`$(A){A.beforeSend?.();return;let e=await Avl"
            },
            @{
                Id            = "tvl"
                Name          = "4. tvl Transport (Network Sink)"
                Description   = "POST https://center.qoder.sh/api/v1/tracking (transport sink)"
                UnpatchedSig  = 'async function tvl(A,e="aiCodeTracking.report",t,i){if(i?.(),!Jd())'
                ReplaceTarget = 'async function tvl(A,e="aiCodeTracking.report",t,i){if(i?.(),!Jd())'
                ReplaceWith   = 'async function tvl(A,e="aiCodeTracking.report",t,i){return;if(i?.(),!Jd())'
                PatchedSig    = 'async function tvl(A,e="aiCodeTracking.report",t,i){return;if(i?.(),!Jd())'
            }
        )
    }
)

function Evaluate-RuntimeState($content) {
    $bestEval = $null

    foreach ($prof in $profiles) {
        $results = @()
        $patchedCount = 0
        $unpatchedCount = 0
        $hasAmbiguous = $false

        foreach ($p in $prof.Defs) {
            $cPatched   = Count-Occurrences $content $p.PatchedSig
            $cUnpatched = Count-Occurrences $content $p.UnpatchedSig

            if ($cPatched -gt 1 -or $cUnpatched -gt 1) {
                $hasAmbiguous = $true
            }

            $isPatched   = ($cPatched -eq 1 -and $cUnpatched -eq 0)
            $isUnpatched = ($cUnpatched -eq 1 -and $cPatched -eq 0)

            if ($isPatched)   { $patchedCount++ }
            if ($isUnpatched) { $unpatchedCount++ }

            $results += [PSCustomObject]@{
                Id             = $p.Id
                Name           = $p.Name
                Description    = $p.Description
                IsPatched      = $isPatched
                IsUnpatched    = $isUnpatched
                PatchedCount   = $cPatched
                UnpatchedCount = $cUnpatched
            }
        }

        $state = "UNKNOWN"
        if (-not $hasAmbiguous) {
            if ($patchedCount -eq 4 -and $unpatchedCount -eq 0) {
                $state = "HARDENED"
            } elseif ($unpatchedCount -eq 4 -and $patchedCount -eq 0) {
                $state = "PRISTINE"
            } elseif ($patchedCount -gt 0 -or $unpatchedCount -gt 0) {
                $state = "PARTIAL"
            }
        }

        $evalObj = @{
            ProfileName    = $prof.Name
            PatchDefs      = $prof.Defs
            State          = $state
            VectorStates   = $results
            HasAmbiguous   = $hasAmbiguous
            MatchedVectors = ($patchedCount + $unpatchedCount)
        }

        if ($evalObj.MatchedVectors -eq 4 -and (-not $hasAmbiguous)) {
            return $evalObj
        }

        if ($null -eq $bestEval -or $evalObj.MatchedVectors -gt $bestEval.MatchedVectors) {
            $bestEval = $evalObj
        }
    }

    return $bestEval
}

function Show-Header([string]$profileName = "Auto-Detect") {
    Clear-Host
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "                     QODER PRIVACY HARDENING TOOL v2.1                          " -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "Qoder Root  : $qoderRoot" -ForegroundColor Gray
    Write-Host "Qoder Ver   : $qoderVersion" -ForegroundColor Gray
    Write-Host "Profile     : $profileName" -ForegroundColor Gray
    Write-Host "Target File : $targetFile`n" -ForegroundColor Gray
}

function Test-PrivacyStatus {
    if (-not (Test-Path $targetFile)) {
        Show-Header
        Write-Host "[ERROR] Target runtime file not found:" -ForegroundColor Red
        Write-Host "  $targetFile" -ForegroundColor Red
        Write-Host "Status: UNKNOWN VERSION / MISSING RUNTIME`n" -ForegroundColor Red
        return 1
    }

    $item = Get-Item $targetFile
    $hash = Get-Sha256 $targetFile
    $content = [System.IO.File]::ReadAllText($targetFile, [System.Text.Encoding]::UTF8)

    $eval = Evaluate-RuntimeState $content
    $state = $eval.State
    $profName = "$($eval.ProfileName) (Detected)"

    Show-Header $profName
    Write-Host "--- RUNNING PRIVACY VERIFICATION AUDIT ---`n" -ForegroundColor Yellow

    $stateColor = switch ($state) {
        "HARDENED" { [ConsoleColor]::Green }
        "PRISTINE" { [ConsoleColor]::Cyan }
        "PARTIAL"  { [ConsoleColor]::Yellow }
        default    { [ConsoleColor]::Red }
    }

    Write-Host "Qoder Version : $qoderVersion" -ForegroundColor White
    Write-Host "Patch Profile : $($eval.ProfileName)" -ForegroundColor White
    Write-Host "Runtime SHA256: $hash" -ForegroundColor White
    Write-Host "File Size     : $($item.Length) bytes" -ForegroundColor White
    Write-Host "Runtime State : " -NoNewline -ForegroundColor White
    Write-Host "$state" -ForegroundColor $stateColor

    Write-Host "`nTelemetry Vector Signatures:" -ForegroundColor White
    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor DarkGray

    foreach ($v in $eval.VectorStates) {
        $statusText = ""
        $color = [ConsoleColor]::Gray

        if ($v.IsPatched) {
            $statusText = "[PROTECTED / PATCHED]"
            $color = [ConsoleColor]::Green
        } elseif ($v.IsUnpatched) {
            $statusText = "[EXPOSED / UNPATCHED]"
            $color = [ConsoleColor]::Red
        } elseif ($v.PatchedCount -gt 1 -or $v.UnpatchedCount -gt 1) {
            $statusText = "[AMBIGUOUS SIGNATURE (>1 MATCH)]"
            $color = [ConsoleColor]::Red
        } else {
            $statusText = "[UNRECOGNIZED SIGNATURE]"
            $color = [ConsoleColor]::Yellow
        }

        Write-Host "$($v.Name.PadRight(44)) : " -NoNewline
        Write-Host "$statusText" -ForegroundColor $color
        Write-Host "   Endpoint: $($v.Description)" -ForegroundColor DarkGray
    }

    Write-Host "--------------------------------------------------------------------------------" -ForegroundColor DarkGray

    $backups = @(Get-ChildItem -Path $targetDir -Filter "qoder-worker-runtime.obf.mjs.bak.*" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    $safetyBackups = @(Get-ChildItem -Path $targetDir -Filter "qoder-worker-runtime.obf.mjs.safety.*" -ErrorAction SilentlyContinue)
    $totalBackups = $backups.Count + $safetyBackups.Count

    Write-Host "`nBackups Available: $totalBackups ($($backups.Count) rollback point(s), $($safetyBackups.Count) safety backup(s))" -ForegroundColor White
    if ($backups.Count -gt 0) {
        foreach ($b in $backups | Select-Object -First 3) {
            Write-Host "  - $($b.Name) ($($b.LastWriteTime))" -ForegroundColor DarkGray
        }
    }

    Write-Host "`nSummary & Assessment:" -ForegroundColor White
    if ($state -eq "HARDENED") {
        Write-Host "[PASS] The known telemetry code paths targeted by this tool are neutralized." -ForegroundColor Green
        Write-Host "       Runtime network verification is recommended after Qoder updates." -ForegroundColor Green
        return 0
    } elseif ($state -eq "PRISTINE") {
        Write-Host "[AUDIT] Runtime is in PRISTINE original state. All telemetry code paths are active." -ForegroundColor Cyan
        Write-Host "        Run with --apply to apply privacy hardening." -ForegroundColor Yellow
        return 0
    } elseif ($state -eq "PARTIAL") {
        Write-Host "[WARNING] Runtime is partially hardened. Some telemetry signatures are unpatched." -ForegroundColor Yellow
        Write-Host "          Run with --apply to complete hardening." -ForegroundColor Yellow
        return 2
    } else {
        Write-Host "[ERROR] UNSUPPORTED / UNKNOWN VERSION. Runtime signatures do not match known layouts." -ForegroundColor Red
        Write-Host "        Tool will fail closed to prevent runtime corruption." -ForegroundColor Red
        return 1
    }
}

function DryRun-PrivacyPatch {
    if (-not (Test-Path $targetFile)) {
        Show-Header
        Write-Host "[FATAL ERROR] Target runtime file not found:" -ForegroundColor Red
        Write-Host "  $targetFile" -ForegroundColor Red
        return 1
    }

    $preHash = Get-Sha256 $targetFile
    $content = [System.IO.File]::ReadAllText($targetFile, [System.Text.Encoding]::UTF8)

    $eval = Evaluate-RuntimeState $content
    $state = $eval.State
    $profName = "$($eval.ProfileName) (Detected)"
    $patchDefs = $eval.PatchDefs

    Show-Header $profName
    Write-Host "--- RUNNING DRY-RUN SIMULATION (NO DISK MODIFICATIONS) ---`n" -ForegroundColor Yellow

    Write-Host "Patch Profile  : $($eval.ProfileName)" -ForegroundColor White
    Write-Host "Current SHA256 : $preHash" -ForegroundColor White
    Write-Host "Current State  : $state`n" -ForegroundColor White

    if ($state -eq "HARDENED") {
        Write-Host "[INFO] All 4 patches are ALREADY applied. Runtime is already in HARDENED state." -ForegroundColor Green
        return 0
    }

    if ($eval.HasAmbiguous) {
        Write-Host "[DRY-RUN FAILED] Ambiguous signatures detected in runtime file." -ForegroundColor Red
        return 1
    }

    if ($state -ne "PRISTINE" -and $state -ne "PARTIAL") {
        Write-Host "[DRY-RUN FAILED] UNSUPPORTED / UNKNOWN VERSION" -ForegroundColor Red
        return 1
    }

    Write-Host "1. Validating Signature Uniqueness Constraints:" -ForegroundColor White
    foreach ($p in $patchDefs) {
        $cPatched   = Count-Occurrences $content $p.PatchedSig
        $cUnpatched = Count-Occurrences $content $p.UnpatchedSig
        $cTarget    = Count-Occurrences $content $p.ReplaceTarget
        if ($cPatched -eq 0) {
            if ($cUnpatched -eq 1 -and $cTarget -eq 1) {
                Write-Host "   [OK] $($p.Id) - Exactly 1 unpatched match found." -ForegroundColor Green
            } else {
                Write-Host "   [FAIL] $($p.Id) - Expected 1 match, found: unpatched=$cUnpatched, target=$cTarget" -ForegroundColor Red
                return 1
            }
        } else {
            Write-Host "   [SKIP] $($p.Id) - Already patched (1 occurrence)." -ForegroundColor DarkGray
        }
    }

    $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $simBackup = "$targetFile.bak.$timestamp"
    Write-Host "`n2. Simulating Pre-patch Backup Step:" -ForegroundColor White
    Write-Host "   Destination : $simBackup" -ForegroundColor Cyan

    Write-Host "`n3. Simulating Surgical Patch Operations (In-Memory):" -ForegroundColor White
    $newContent = $content
    foreach ($p in $patchDefs) {
        $cPatched = Count-Occurrences $newContent $p.PatchedSig
        if ($cPatched -eq 0) {
            $idx = $newContent.IndexOf($p.ReplaceTarget, [StringComparison]::Ordinal)
            $newContent = $newContent.Substring(0, $idx) + $p.ReplaceWith + $newContent.Substring($idx + $p.ReplaceTarget.Length)
            Write-Host "   [SIMULATED PATCH] $($p.Name)" -ForegroundColor Green
        }
    }

    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($newContent)
    $simPostHash = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace("-", "")
    $postEval = Evaluate-RuntimeState $newContent

    Write-Host "`n4. Simulating Post-Patch Audit Verification:" -ForegroundColor White
    Write-Host "   Simulated Post-Patch SHA256: $simPostHash" -ForegroundColor White
    Write-Host "   Simulated Runtime State    : $($postEval.State)" -ForegroundColor Green

    if ($postEval.State -ne "HARDENED") {
        Write-Host "[DRY-RUN FAILED] Post-patch validation failed!" -ForegroundColor Red
        return 1
    }

    Write-Host "`n================================================================================" -ForegroundColor Green
    Write-Host "[DRY-RUN SUCCESS] All checks passed cleanly!" -ForegroundColor Green
    Write-Host "  * Detected Profile: $($eval.ProfileName)" -ForegroundColor Green
    Write-Host "  * All 4 telemetry signatures match with exact uniqueness (count == 1)." -ForegroundColor Green
    Write-Host "  * NO live files were modified in this dry-run." -ForegroundColor Cyan
    Write-Host "================================================================================`n" -ForegroundColor Green
    return 0
}

function Apply-PrivacyPatch {
    if (-not (Test-Path $targetFile)) {
        Show-Header
        Write-Host "[FATAL ERROR] Target runtime file not found:" -ForegroundColor Red
        Write-Host "  $targetFile" -ForegroundColor Red
        exit 1
    }

    $content = [System.IO.File]::ReadAllText($targetFile, [System.Text.Encoding]::UTF8)
    $preHash = Get-Sha256 $targetFile

    $eval = Evaluate-RuntimeState $content
    $state = $eval.State
    $profName = "$($eval.ProfileName) (Detected)"
    $patchDefs = $eval.PatchDefs

    Show-Header $profName
    Write-Host "--- APPLYING PRIVACY HARDENING PATCHES ---`n" -ForegroundColor Yellow

    if ($state -eq "HARDENED") {
        Write-Host "[INFO] All 4 patches are ALREADY applied. Runtime is already in HARDENED state." -ForegroundColor Green
        Write-Host "Current SHA256: $preHash" -ForegroundColor White
        return 0
    }

    if ($eval.HasAmbiguous) {
        Write-Host "[FATAL ERROR] Ambiguous signatures detected in runtime file." -ForegroundColor Red
        Write-Host "One or more targets matched multiple locations. Failing closed without changes." -ForegroundColor Red
        exit 1
    }

    if ($state -ne "PRISTINE" -and $state -ne "PARTIAL") {
        Write-Host "[FATAL ERROR] UNSUPPORTED / UNKNOWN VERSION" -ForegroundColor Red
        Write-Host "Runtime layout does not match known Qoder engine signatures." -ForegroundColor Red
        Write-Host "File has NOT been modified." -ForegroundColor Red
        exit 1
    }

    # Verify each unpatched vector to be modified occurs EXACTLY once
    foreach ($p in $patchDefs) {
        $cPatched = Count-Occurrences $content $p.PatchedSig
        if ($cPatched -eq 0) {
            $cUnpatched = Count-Occurrences $content $p.UnpatchedSig
            $cTarget    = Count-Occurrences $content $p.ReplaceTarget
            if ($cUnpatched -ne 1 -or $cTarget -ne 1) {
                Write-Host "[FATAL ERROR] Signature mismatch for target '$($p.Id)'." -ForegroundColor Red
                Write-Host "Expected exactly 1 occurrence, found: unpatched=$cUnpatched, replaceTarget=$cTarget." -ForegroundColor Red
                Write-Host "Failing closed. File has NOT been modified." -ForegroundColor Red
                exit 1
            }
        }
    }

    # Step 1: Create atomic pre-patch backup BEFORE any modifications
    $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $backupFile = "$targetFile.bak.$timestamp"

    Write-Host "Creating pre-patch backup..." -ForegroundColor White
    [System.IO.File]::WriteAllText($backupFile, $content, [System.Text.Encoding]::UTF8)

    $backupHash = Get-Sha256 $backupFile
    if ($backupHash -ne $preHash) {
        Write-Host "[FATAL ERROR] Backup verification failed! Hash mismatch." -ForegroundColor Red
        Remove-Item -Path $backupFile -Force -ErrorAction SilentlyContinue
        exit 1
    }
    Write-Host "[BACKUP VERIFIED] $(Split-Path -Leaf $backupFile) (SHA256: $backupHash)" -ForegroundColor Cyan

    # Step 2: Apply surgical patches strictly to verified targets
    $newContent = $content
    $patchCount = 0

    foreach ($p in $patchDefs) {
        $cPatched = Count-Occurrences $newContent $p.PatchedSig
        if ($cPatched -eq 0) {
            $idx = $newContent.IndexOf($p.ReplaceTarget, [StringComparison]::Ordinal)
            if ($idx -eq -1) {
                Write-Host "[FATAL ERROR] Target string lost during sequential patch for $($p.Id)!" -ForegroundColor Red
                exit 1
            }
            $newContent = $newContent.Substring(0, $idx) + $p.ReplaceWith + $newContent.Substring($idx + $p.ReplaceTarget.Length)
            $patchCount++
            Write-Host "[PATCH APPLIED] $($p.Name)" -ForegroundColor Green
        } else {
            Write-Host "[ALREADY PATCHED] $($p.Name)" -ForegroundColor Gray
        }
    }

    # Step 3: Write atomically to temporary file, then swap
    $tempFile = "$targetFile.tmp.$([Guid]::NewGuid().ToString('N'))"
    try {
        [System.IO.File]::WriteAllText($tempFile, $newContent, [System.Text.Encoding]::UTF8)
        Move-Item -Path $tempFile -Destination $targetFile -Force
    } catch {
        Write-Host "[FATAL ERROR] Failed to write updated file: $_" -ForegroundColor Red
        if (Test-Path $tempFile) { Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue }
        exit 1
    }

    # Step 4: Strict post-patch verification
    $postHash = Get-Sha256 $targetFile
    $postContent = [System.IO.File]::ReadAllText($targetFile, [System.Text.Encoding]::UTF8)
    $postEval = Evaluate-RuntimeState $postContent

    if ($postEval.State -ne "HARDENED") {
        Write-Host "[CRITICAL ERROR] Post-patch validation failed! Runtime is not HARDENED." -ForegroundColor Red
        Write-Host "Restoring pre-patch backup immediately..." -ForegroundColor Yellow
        Copy-Item -Path $backupFile -Destination $targetFile -Force
        $revertedHash = Get-Sha256 $targetFile
        Write-Host "Restored original runtime file (SHA256: $revertedHash)." -ForegroundColor Yellow
        exit 1
    }

    Write-Host "`n[SUCCESS] Privacy hardening successfully applied and verified." -ForegroundColor Green
    Write-Host "Applied Profile  : $($eval.ProfileName)" -ForegroundColor Cyan
    Write-Host "Pre-patch SHA256 : $preHash" -ForegroundColor White
    Write-Host "Post-patch SHA256: $postHash" -ForegroundColor Green
    Write-Host "Backup preserved : $(Split-Path -Leaf $backupFile)" -ForegroundColor White
    Write-Host "[NOTE] Please restart Qoder (or run Developer: Reload Window) for changes to take effect.`n" -ForegroundColor Yellow
    return 0
}

function Restore-Backup {
    Show-Header
    Write-Host "--- RESTORING FROM PREVIOUS BACKUP ---`n" -ForegroundColor Yellow

    if (-not (Test-Path $targetFile)) {
        Write-Host "[ERROR] Target runtime directory not accessible." -ForegroundColor Red
        exit 1
    }

    $backups = @(Get-ChildItem -Path $targetDir -Filter "qoder-worker-runtime.obf.mjs.bak.*" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    if ($backups.Count -eq 0) {
        Write-Host "[ERROR] No rollback backup files found in $targetDir" -ForegroundColor Red
        exit 1
    }

    $selectedBackup = $backups[0]
    Write-Host "Available Backups ($($backups.Count)): " -ForegroundColor White
    for ($i = 0; $i -lt [Math]::Min($backups.Count, 5); $i++) {
        $marker = if ($i -eq 0) { " [LATEST - WILL RESTORE]" } else { "" }
        Write-Host "  [$i] $($backups[$i].Name) ($($backups[$i].LastWriteTime))$marker" -ForegroundColor Gray
    }

    Write-Host "`nSelected Backup to Restore:" -ForegroundColor White
    Write-Host "  Name     : $($selectedBackup.Name)" -ForegroundColor Cyan
    Write-Host "  Path     : $($selectedBackup.FullName)" -ForegroundColor Cyan
    Write-Host "  Modified : $($selectedBackup.LastWriteTime)" -ForegroundColor Cyan

    try {
        $stream = [System.IO.File]::OpenRead($selectedBackup.FullName)
        $stream.Close()
    } catch {
        Write-Host "[FATAL ERROR] Selected backup file cannot be read: $_" -ForegroundColor Red
        exit 1
    }

    $backupHash = Get-Sha256 $selectedBackup.FullName
    Write-Host "  SHA256   : $backupHash" -ForegroundColor Cyan

    # Step 1: Create a safety backup of the CURRENT runtime state before restoring
    $currentHash = Get-Sha256 $targetFile
    $safetyTimestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $safetyBackup = "$targetFile.safety.$safetyTimestamp"

    Write-Host "`nCreating pre-restore safety backup..." -ForegroundColor White
    Copy-Item -Path $targetFile -Destination $safetyBackup -Force
    $safetyHash = Get-Sha256 $safetyBackup

    if ($safetyHash -ne $currentHash) {
        Write-Host "[FATAL ERROR] Safety backup creation failed! Aborting restore." -ForegroundColor Red
        Remove-Item -Path $safetyBackup -Force -ErrorAction SilentlyContinue
        exit 1
    }
    Write-Host "[SAFETY BACKUP VERIFIED] $(Split-Path -Leaf $safetyBackup) (SHA256: $safetyHash)" -ForegroundColor Cyan

    # Step 2: Atomic restoration
    $tempRestore = "$targetFile.tmp.restore.$([Guid]::NewGuid().ToString('N'))"
    try {
        Copy-Item -Path $selectedBackup.FullName -Destination $tempRestore -Force
        Move-Item -Path $tempRestore -Destination $targetFile -Force
    } catch {
        Write-Host "[FATAL ERROR] Restore copy failed: $_" -ForegroundColor Red
        if (Test-Path $tempRestore) { Remove-Item -Path $tempRestore -Force -ErrorAction SilentlyContinue }
        exit 1
    }

    # Step 3: Verify restored file hash
    $restoredHash = Get-Sha256 $targetFile
    if ($restoredHash -ne $backupHash) {
        Write-Host "[CRITICAL ERROR] Restored file hash does not match backup hash!" -ForegroundColor Red
        Write-Host "Reverting to pre-restore safety backup..." -ForegroundColor Yellow
        Copy-Item -Path $safetyBackup -Destination $targetFile -Force
        exit 1
    }

    Write-Host "`n[SUCCESS] Runtime successfully restored from backup." -ForegroundColor Green
    Write-Host "Restored SHA256: $restoredHash" -ForegroundColor Green
    Write-Host "Safety backup  : $(Split-Path -Leaf $safetyBackup)`n" -ForegroundColor White
    return 0
}

# CLI Argument routing
if ($Mode -eq "--test" -or $Mode -eq "-t") {
    $exitCode = Test-PrivacyStatus
    exit $exitCode
} elseif ($Mode -eq "--dry-run" -or $Mode -eq "-d") {
    $exitCode = DryRun-PrivacyPatch
    exit $exitCode
} elseif ($Mode -eq "--apply" -or $Mode -eq "-a") {
    $exitCode = Apply-PrivacyPatch
    exit $exitCode
} elseif ($Mode -eq "--restore" -or $Mode -eq "-r") {
    $exitCode = Restore-Backup
    exit $exitCode
}

# Interactive Menu
do {
    Show-Header
    Write-Host "Choose an action:"
    Write-Host "  [1] Test / Verify privacy hardening status"
    Write-Host "  [2] Dry-run simulation (validate patches & backup logic without modifying files)"
    Write-Host "  [3] Apply privacy hardening patches (auto-backup)"
    Write-Host "  [4] Restore from latest backup (with pre-restore safety snapshot)"
    Write-Host "  [5] Exit`n"

    $choice = Read-Host "Select option [1-5]"
    switch ($choice) {
        "1" { Test-PrivacyStatus; Pause }
        "2" { DryRun-PrivacyPatch; Pause }
        "3" { Apply-PrivacyPatch; Pause }
        "4" { Restore-Backup; Pause }
        "5" { exit 0 }
        default { Write-Host "Invalid option." -ForegroundColor Red; Start-Sleep -Seconds 1 }
    }
} while ($choice -ne "5")
