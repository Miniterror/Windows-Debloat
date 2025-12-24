# ============================================================================
# 1. SYSTEM SETUP & CORE CONFIGURATION
# ============================================================================

# --- Admin check ------------------------------------------------------------
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Run this script as Administrator." -ForegroundColor Red
    Exit
}

# --- Basic helpers -----------------------------------------------------------
function Write-Info { param($m) Write-Host "[INFO] $m" -ForegroundColor Cyan }
function Write-OK   { param($m) Write-Host "[ OK ] $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Write-Err  { param($m) Write-Host "[ERR ] $m" -ForegroundColor Red }

# --- EU detection (for Edge removal) ----------------------------------------
$IsEU = $false
try {
    $region = (Get-WinHomeLocation).GeoId
    if ($region -in 0x3C,0x3D,0x3E,0x3F,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E) {
        $IsEU = $true
    }
} catch {}

Write-Info "EU region detected: $IsEU"

# ============================================================================
# 1.1 SERVICES & SECURITY
# ============================================================================

Write-Info "Disabling SysMain and DiagTrack..."
Stop-Service SysMain -Force -ErrorAction SilentlyContinue
Set-Service SysMain -StartupType Disabled
Stop-Service DiagTrack -Force -ErrorAction SilentlyContinue
Set-Service DiagTrack -StartupType Disabled

Write-Info "Disabling SMBv1..."
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue

Write-Info "Disabling VBS / HVCI..."
reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f > $null
reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 0 /f > $null

# Increase SvcHost split threshold
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v SvcHostSplitThresholdInKB /t REG_DWORD /d 67108864 /f > $null

# ============================================================================
# 1.2 LOCALE / TIMEZONE / LANGUAGE
# ============================================================================

Write-Info "Setting locale/timezone/language..."
tzutil /s "W. Europe Standard Time"
Set-WinSystemLocale nl-NL
Set-WinUserLanguageList nl-NL -Force
Set-Culture nl-NL
Set-WinHomeLocation -GeoId 176

# ============================================================================
# 1.3 THEME & ACCENT COLOR
# ============================================================================

Write-Info "Applying dark theme & accent color..."

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v SystemUsesLightTheme /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v AppsUseLightTheme   /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v ColorPrevalence    /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 0 /f > $null

# Accent color (Windows blauw)
try {
    Add-Type -AssemblyName 'System.Drawing'
    $color = [System.Drawing.ColorTranslator]::FromHtml('#0078D4')
    $bytes = @($color.R,$color.G,$color.B,$color.A)
    $dword = [System.BitConverter]::ToUInt32($bytes,0)

    Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent' -Name StartColorMenu  -Value $dword
    Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent' -Name AccentColorMenu -Value $dword
    Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\DWM' -Name AccentColor -Value $dword
} catch {
    Write-Warn "Accent color failed to apply."
}

Write-OK "System setup & core configuration complete."
# ============================================================================
# 2. PRIVACY & TELEMETRY HARDENING
# ============================================================================

Write-Info "Applying privacy and telemetry restrictions..."

# ============================================================================
# 2.1 CORE TELEMETRY
# ============================================================================

# Disable telemetry
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f > $null

# Disable feedback prompts
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f > $null

# Disable activity history
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v UploadUserActivities /t REG_DWORD /d 0 /f > $null

# ============================================================================
# 2.2 PRIVACY FEATURES
# ============================================================================

# Disable Advertising ID
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f > $null

# Disable clipboard sync
reg add "HKCU\Software\Microsoft\Clipboard" /v EnableClipboardHistory /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Clipboard" /v EnableCloudClipboard   /t REG_DWORD /d 0 /f > $null

# Disable background apps
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f > $null

# Disable location services
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v DisableLocation /t REG_DWORD /d 1 /f > $null

# ============================================================================
# 2.3 SEARCH, SPOTLIGHT, CLOUDCONTENT
# ============================================================================

# Disable Bing search in Start
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v DisableSearchBoxSuggestions /t REG_DWORD /d 1 /f > $null

# Disable Windows Spotlight
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures        /t REG_DWORD /d 1 /f > $null
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightOnActionCenter /t REG_DWORD /d 1 /f > $null
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightOnSettings     /t REG_DWORD /d 1 /f > $null
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightOnLockScreen   /t REG_DWORD /d 1 /f > $null

# Disable CloudContent ads
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableConsumerFeatures /t REG_DWORD /d 1 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding      /t REG_DWORD /d 1 /f > $null

# Disable suggested apps
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_IrisRecommendations /t REG_DWORD /d 0 /f > $null

# ============================================================================
# 2.4 AI / RECALL / ONLINE SERVICE EXPERIENCE
# ============================================================================

# Disable Recall & AI data collection
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsAI" /v DisableAIDataCollection /t REG_DWORD /d 1 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsAI" /v DisableAIRecall         /t REG_DWORD /d 1 /f > $null

# Disable Online Service Experience Packs
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v AllowOnlineServiceExperience /t REG_DWORD /d 0 /f > $null

# Disable Suggested Actions
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform" /v Disabled /t REG_DWORD /d 1 /f > $null

# ============================================================================
# 2.5 APP PRIVACY PERMISSIONS
# ============================================================================

$privacyKeys = @(
    "LetAppsAccessLocation",
    "LetAppsAccessCamera",
    "LetAppsAccessMicrophone",
    "LetAppsAccessContacts",
    "LetAppsAccessCalendar",
    "LetAppsAccessCallHistory",
    "LetAppsAccessEmail",
    "LetAppsAccessMessaging",
    "LetAppsAccessRadios",
    "LetAppsAccessMotion",
    "LetAppsAccessNotifications",
    "LetAppsAccessTasks",
    "LetAppsAccessBluetooth"
)

foreach ($key in $privacyKeys) {
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$key" /v Value /t REG_SZ /d Deny /f > $null
}

# ============================================================================
# 2.6 BLOCK APP RECOMMENDATIONS (TikTok, WhatsApp, Spotify, Messenger)
# ============================================================================

$cdm = "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"

reg add $cdm /v SubscribedContent-353699Enabled /t REG_DWORD /d 0 /f > $null
reg add $cdm /v SubscribedContent-353700Enabled /t REG_DWORD /d 0 /f > $null
reg add $cdm /v PreInstalledAppsEnabled           /t REG_DWORD /d 0 /f > $null
reg add $cdm /v PreInstalledAppsEverEnabled       /t REG_DWORD /d 0 /f > $null

# ============================================================================
# 2.7 DEFAULT USER PRIVACY (APPLIES TO NEW ACCOUNTS)
# ============================================================================

Write-Info "Applying privacy settings to Default User profile..."

reg load HKU\DefaultUser "$env:SystemDrive\Users\Default\NTUSER.DAT" > $null

reg add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f > $null
reg add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353699Enabled /t REG_DWORD /d 0 /f > $null
reg add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353700Enabled /t REG_DWORD /d 0 /f > $null

reg unload HKU\DefaultUser > $null

Write-OK "Privacy & telemetry hardening applied."
# ============================================================================
# 3. WINDOWS SHELL CLEANUP
# ============================================================================

Write-Info "Starting Windows shell cleanup..."

# ============================================================================
# 3.1 APPX REMOVAL (BLOATWARE)
# ============================================================================

Write-Info "Removing AppX bloatware..."

$appsToRemove = @(
    "*Clipchamp*",
    "*MSTeams*",
    "*MicrosoftTeams*",
    "*TikTok*",
    "*Spotify*",
    "*WhatsApp*",
    "*ZuneMusic*",
    "*ZuneVideo*",
    "*XboxApp*",
    "*XboxGamingOverlay*",
    "*XboxIdentityProvider*",
    "*GetHelp*",
    "*GetStarted*",
    "*People*",
    "*Solitaire*"
)

foreach ($app in $appsToRemove) {
    Get-AppxPackage -AllUsers $app | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $app } |
        Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
}

# ============================================================================
# 3.2 REMOVE WIDGETS & COPILOT
# ============================================================================

Write-Info "Disabling Widgets and Copilot..."

# Widgets
reg add "HKLM\Software\Policies\Microsoft\Dsh" /v AllowNewsAndInterests /t REG_DWORD /d 0 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Widgets" /v AllowWidgets /t REG_DWORD /d 0 /f > $null

# Copilot
reg add "HKCU\Software\Microsoft\Windows\Shell\Copilot" /v IsCopilotAvailable /t REG_DWORD /d 0 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f > $null

# ============================================================================
# 3.3 START MENU & TASKBAR CLEANUP
# ============================================================================

Write-Info "Cleaning Start menu and taskbar..."

# Remove all pinned Start items
$startLayout = @"
{
  "pinnedList": []
}
"@
$startPath = "$env:LOCALAPPDATA\Microsoft\Windows\Shell\LayoutModification.json"
$startLayout | Out-File -FilePath $startPath -Encoding ASCII -Force

# Remove taskbar suggestions
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarMn /t REG_DWORD /d 0 /f > $null

# ============================================================================
# 3.4 EXPLORER TWEAKS
# ============================================================================

Write-Info "Applying Explorer tweaks..."

# Disable recent files
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v ShowRecent /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v ShowFrequent /t REG_DWORD /d 0 /f > $null

# Disable file grouping in Downloads
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v GroupBy /t REG_SZ /d "System.Null" /f > $null

# Classic context menu
reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" /v "" /t REG_SZ /d "" /f > $null
reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /v "" /t REG_SZ /d "" /f > $null

# ============================================================================
# 3.5 REMOVE ONEDRIVE COMPLETELY
# ============================================================================

Write-Info "Removing OneDrive..."

# Kill OneDrive processes
taskkill /F /IM OneDrive.exe /T > $null 2>&1

# Uninstall OneDrive
$oneDriveSetup = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
if (Test-Path $oneDriveSetup) {
    Start-Process $oneDriveSetup "/uninstall" -Wait
}

# Remove leftover folders
$oneDriveFolders = @(
    "$env:LOCALAPPDATA\Microsoft\OneDrive",
    "$env:PROGRAMDATA\Microsoft OneDrive",
    "$env:SystemDrive\OneDriveTemp"
)

foreach ($folder in $oneDriveFolders) {
    if (Test-Path $folder) { Remove-Item $folder -Recurse -Force -ErrorAction SilentlyContinue }
}

# Remove Explorer OneDrive entry
reg delete "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > $null 2>&1
reg delete "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > $null 2>&1

# ============================================================================
# 3.6 REMOVE MICROSOFT EDGE (EU ONLY)
# ============================================================================

if ($IsEU) {
    Write-Info "EU region detected — removing Microsoft Edge..."

    $edgePaths = @(
        "$env:ProgramFiles (x86)\Microsoft\Edge\Application\*",
        "$env:ProgramFiles\Microsoft\Edge\Application\*"
    )

    foreach ($path in $edgePaths) {
        $setup = Join-Path $path "Installer\setup.exe"
        if (Test-Path $setup) {
            Start-Process $setup -ArgumentList "--uninstall --system-level --force-uninstall" -Wait -ErrorAction SilentlyContinue
        }
    }
} else {
    Write-Warn "Not in EU — Edge removal skipped."
}

Write-OK "Windows shell cleanup complete."
# ============================================================================
# 4. APPLICATION INSTALLATION & FINALIZATION
# ============================================================================

Write-Info "Starting application installation..."

# Helper: detect installed apps
function Test-AppInstalled {
    param([string]$Name)

    $paths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($path in $paths) {
        try {
            Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
                ForEach-Object {
                    if ($_.DisplayName -and ($_.DisplayName -like "*$Name*")) {
                        return $true
                    }
                }
        } catch {}
    }
    return $false
}

# ============================================================================
# 4.1 GOOGLE CHROME
# ============================================================================

if (-not (Test-AppInstalled "Google Chrome")) {
    Write-Info "Installing Google Chrome..."

    $chromeInstaller = "$env:TEMP\chrome_installer.exe"
    Invoke-WebRequest "https://dl.google.com/chrome/install/latest/chrome_installer.exe" -OutFile $chromeInstaller -UseBasicParsing -ErrorAction SilentlyContinue

    Start-Process $chromeInstaller -ArgumentList "/silent","/install" -Wait -ErrorAction SilentlyContinue
    Write-OK "Chrome installed."
} else {
    Write-Info "Chrome already installed."
}

# ============================================================================
# 4.2 7-ZIP
# ============================================================================

if (-not (Test-AppInstalled "7-Zip")) {
    Write-Info "Installing 7-Zip..."

    $zipInstaller = "$env:TEMP\7zip_installer.exe"
    Invoke-WebRequest "https://www.7-zip.org/a/7z2408-x64.exe" -OutFile $zipInstaller -UseBasicParsing -ErrorAction SilentlyContinue

    Start-Process $zipInstaller -ArgumentList "/S" -Wait -ErrorAction SilentlyContinue
    Write-OK "7-Zip installed."
} else {
    Write-Info "7-Zip already installed."
}

# ============================================================================
# 4.3 NOTEPAD++
# ============================================================================

if (-not (Test-AppInstalled "Notepad++")) {
    Write-Info "Installing Notepad++..."

    $npInstaller = "$env:TEMP\npp_installer.exe"
    $apiUrl = "https://api.github.com/repos/notepad-plus-plus/notepad-plus-plus/releases/latest"
    $headers = @{ "User-Agent" = "Mozilla/5.0" }

    try {
        $release = Invoke-RestMethod -Uri $apiUrl -Headers $headers -ErrorAction Stop
        $asset = $release.assets | Where-Object { $_.name -match "Installer.*x64.*\.exe$" } | Select-Object -First 1
        Start-BitsTransfer -Source $asset.browser_download_url -Destination $npInstaller -ErrorAction Stop

        Start-Process $npInstaller -ArgumentList "/S" -Wait -ErrorAction SilentlyContinue
        Write-OK "Notepad++ installed."
    } catch {
        Write-Err "Failed to install Notepad++."
    }
} else {
    Write-Info "Notepad++ already installed."
}

# ============================================================================
# 4.4 DISCORD
# ============================================================================

if (-not (Test-AppInstalled "Discord")) {
    Write-Info "Installing Discord..."

    $discordInstaller = "$env:TEMP\discord_installer.exe"
    Invoke-WebRequest "https://discord.com/api/download?platform=win" -OutFile $discordInstaller -UseBasicParsing -ErrorAction SilentlyContinue

    Start-Process $discordInstaller -ArgumentList "/S" -Wait -ErrorAction SilentlyContinue
    Write-OK "Discord installed."
} else {
    Write-Info "Discord already installed."
}

# ============================================================================
# 4.5 STEAM
# ============================================================================

if (-not (Test-AppInstalled "Steam")) {
    Write-Info "Installing Steam..."

    $steamInstaller = "$env:TEMP\steam_installer.exe"
    Invoke-WebRequest "https://cdn.cloudflare.steamstatic.com/client/installer/SteamSetup.exe" -OutFile $steamInstaller -UseBasicParsing -ErrorAction SilentlyContinue

    Start-Process $steamInstaller -ArgumentList "/S" -Wait -ErrorAction SilentlyContinue
    Write-OK "Steam installed."
} else {
    Write-Info "Steam already installed."
}

# ============================================================================
# 4.6 CLEANUP INSTALLERS
# ============================================================================

Write-Info "Cleaning up installers..."
Get-ChildItem "$env:TEMP" -Filter "*installer*.exe" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
Write-OK "Installer cleanup complete."

# ============================================================================
# 4.7 TASKBAR CACHE CLEANUP
# ============================================================================

Write-Info "Cleaning taskbar cache..."

$taskbarCache = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

Get-ChildItem $taskbarCache -Filter "taskbar*.db" -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue

# ============================================================================
# 4.8 EXPLORER SILENT RESTART
# ============================================================================

Write-Info "Restarting Explorer..."

$signature = @"
using System;
using System.Runtime.InteropServices;

public class RestartShell {
    [DllImport("user32.dll", SetLastError=true)]
    public static extern int SendMessageTimeout(
        IntPtr hWnd, int Msg, IntPtr wParam, IntPtr lParam,
        int flags, int timeout, out IntPtr result);
}
"@

Add-Type $signature -ErrorAction SilentlyContinue

$HWND_BROADCAST = [IntPtr]0xffff
$WM_SETTINGCHANGE = 0x1A
[IntPtr]$result = 0

[RestartShell]::SendMessageTimeout(
    $HWND_BROADCAST,
    $WM_SETTINGCHANGE,
    0,
    0,
    2,
    5000,
    [ref]$result
) | Out-Null

Write-OK "Explorer restarted."

# ============================================================================
# 4.9 FINAL REBOOT
# ============================================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host "   SYSTEM OPTIMIZATION COMPLETE" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host ""
Write-Host " Your system will reboot in 15 seconds." -ForegroundColor Cyan
Write-Host ""
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host ""

Start-Sleep -Seconds 15
shutdown /r /t 0
