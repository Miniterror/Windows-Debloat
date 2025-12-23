# 0. ADMIN CHECK, LOGGING, HELPERS
# ============================================================================

# Admin check
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host "[ERROR] Run this script as Administrator." -ForegroundColor Red
    Write-Host ""
    Write-Host "This window will close in 10 seconds..." -ForegroundColor Yellow
    Start-Sleep -Seconds 10
    exit 1
}

# Logging helpers
function Write-Info($msg)   { Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Write-OK($msg)     { Write-Host "[ OK ]  $msg" -ForegroundColor Green }
function Write-Remove($msg) { Write-Host "[DEL]  $msg" -ForegroundColor Magenta }

# Start transcript
$Desktop = [Environment]::GetFolderPath("Desktop")
$LogFile = Join-Path $Desktop "Full-SuperDebloat.log"
Start-Transcript -Path $LogFile -Append
Write-Info "Full SuperDebloat started at $(Get-Date)"


# 1. EU-DETECTIE (VOOR EDGE-LOGICA)
# ============================================================================

Write-Info "Checking if system is an EU-regulated build..."

$dmaFlag = (Get-ItemProperty -Path "HKLM:\System\Setup\MoSetup" -Name "EnableEUDMA" -ErrorAction SilentlyContinue).EnableEUDMA
$geoId   = (Get-ItemProperty -Path "HKCU:\Control Panel\International\Geo" -Name "Nation" -ErrorAction SilentlyContinue).Nation

$EU_GeoIDs = @(4,8,20,28,31,40,56,70,100,112,124,191,196,203,208,233,246,250,268,276,300,348,352,372,380,428,440,442,470,498,499,528,616,620,642,643,688,703,705,724,752,804,807)

$IsEU = $false

if ($dmaFlag -eq 1) {
    Write-OK "EU DMA flag detected."
    $IsEU = $true
} elseif ($EU_GeoIDs -contains $geoId) {
    Write-OK "GeoID indicates EU region ($geoId)."
    $IsEU = $true
} else {
    Write-Info "System does NOT appear to be EU — Edge removal will be skipped."
}

Set-Variable -Name "IsEU" -Value $IsEU -Scope Global


# 2. APPX / PROVISIONED PACKAGE REMOVAL
# ============================================================================

function Remove-AppPackagesSelectors {
    param ([string[]] $Selectors)

    foreach ($selector in $Selectors) {
        Write-Info "Removing AppX / Provisioned: $selector"

        Get-AppxPackage -AllUsers |
            Where-Object { $_.Name -eq $selector -or $_.Name -like $selector } |
            ForEach-Object {
                Write-Remove "Removing AppxPackage: $($_.Name)"
                Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction SilentlyContinue
            }

        Get-AppxProvisionedPackage -Online |
            Where-Object { $_.DisplayName -eq $selector -or $_.PackageName -like $selector } |
            ForEach-Object {
                Write-Remove "Removing Provisioned: $($_.PackageName)"
                Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction SilentlyContinue
            }
    }
}

$allAppxSelectors = @(
    "Microsoft.XboxApp*","Microsoft.Xbox.TCUI*","Microsoft.XboxGameOverlay*","Microsoft.XboxGamingOverlay*",
    "Microsoft.XboxIdentityProvider*","Microsoft.XboxSpeechToTextOverlay*","Microsoft.GamingApp*",
    "Microsoft.Microsoft3DViewer*","Microsoft.MixedReality.Portal*","Microsoft.SkypeApp*",
    "Microsoft.MicrosoftSolitaireCollection*","Microsoft.GetHelp*","Microsoft.Getstarted*",
    "Microsoft.ZuneMusic*","Microsoft.ZuneVideo*","Microsoft.People*","Microsoft.WindowsMaps*",
    "Microsoft.BingWeather*","Microsoft.BingNews*","Microsoft.News*","Microsoft.Todos*",
    "Microsoft.WindowsFeedbackHub*","Microsoft.WindowsSoundRecorder*","Microsoft.MicrosoftStickyNotes*",
    "Microsoft.OutlookForWindows*","Microsoft.PowerAutomateDesktop*","Microsoft.WindowsNotepad*",
    "Microsoft.BingSearch","Microsoft.WindowsCamera","Microsoft.WindowsAlarms",
    "Microsoft.Copilot","Microsoft.549981C3F5F10","Microsoft.Windows.DevHome",
    "MicrosoftCorporationII.MicrosoftFamily","Microsoft.MicrosoftOfficeHub",
    "Microsoft.Office.OneNote","Microsoft.People","Microsoft.SkypeApp",
    "MicrosoftTeams","MSTeams","Microsoft.Wallet","Microsoft.YourPhone",
    "*Clipchamp*"
)

Remove-AppPackagesSelectors -Selectors $allAppxSelectors

# 3. WINDOWS CAPABILITIES & OPTIONAL FEATURES
# ============================================================================

Write-Info "Removing Windows Capabilities..."

$capabilities = @(
    'Browser.InternetExplorer',
    'OneCoreUAP.OneSync',
    'Language.Speech',
    'Language.TextToSpeech',
    'App.StepsRecorder',
    'Hello.Face.18967',
    'Hello.Face.Migration.18967',
    'Hello.Face.20134',
    'Microsoft.Windows.WordPad'
)

foreach ($selector in $capabilities) {
    Get-WindowsCapability -Online |
        Where-Object { ($_.Name -split '~')[0] -eq $selector -and $_.State -notin 'NotPresent','Removed' } |
        ForEach-Object {
            Write-Remove "Removing capability: $($_.Name)"
            Remove-WindowsCapability -Online -Name $_.Name -ErrorAction Continue
        }
}

Write-Info "Disabling Windows Optional Features..."

$features = @('Recall')

foreach ($selector in $features) {
    Get-WindowsOptionalFeature -Online |
        Where-Object { $_.FeatureName -eq $selector -and $_.State -notin 'Disabled','DisabledWithPayloadRemoved' } |
        ForEach-Object {
            Write-Remove "Disabling feature: $($_.FeatureName)"
            Disable-WindowsOptionalFeature -Online -FeatureName $_.FeatureName -Remove -NoRestart -ErrorAction Continue
        }
}

# 4. PRIVACY, TELEMETRY, DIAGNOSTICS, CONTENT DELIVERY
# ============================================================================

Write-Info "Applying privacy & telemetry policies..."

# Telemetry / Error reporting
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f > $null
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f > $null

# Advertising ID
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f > $null

# Text/ink collection
reg add "HKCU\Software\Microsoft\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f > $null
reg add "HKCU\Software\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f > $null

# Background apps
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f > $null

# Activity history
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v UploadUserActivities /t REG_DWORD /d 0 /f > $null

# Cloud clipboard
reg add "HKCU\Software\Microsoft\Clipboard" /v CloudClipboard /t REG_DWORD /d 0 /f > $null

# ContentDeliveryManager (ads/suggestions)
$cdmKeys = @(
    "SystemPaneSuggestionsEnabled","SoftLandingEnabled","RotatingLockScreenEnabled",
    "RotatingLockScreenOverlayEnabled","SilentInstalledAppsEnabled",
    "SubscribedContent-338393Enabled","SubscribedContent-353699Enabled",
    "SubscribedContent-353700Enabled","PreInstalledAppsEnabled",
    "PreInstalledAppsEverEnabled"
)
foreach ($key in $cdmKeys) {
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v $key /t REG_DWORD /d 0 /f > $null
}

# Tailored experiences
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f > $null

# Location
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v DisableLocation /t REG_DWORD /d 1 /f > $null

# App privacy access
$privacyKeys = @(
    "LetAppsAccessMotion","LetAppsAccessBluetooth","LetAppsAccessDocumentsLibrary",
    "LetAppsAccessPicturesLibrary","LetAppsAccessVideosLibrary","LetAppsAccessFileSystem",
    "LetAppsAccessUnpairedDevices","LetAppsAccessUserDictionary","LetAppsAccessPhoneCallHistory",
    "LetAppsAccessPhoneCalls","LetAppsAccessVoiceActivation","LetAppsAccessRadios","LetAppsAccessSensors"
)
foreach ($key in $privacyKeys) {
    reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v $key /t REG_DWORD /d 2 /f > $null
}

Write-Host "[INFO] Applying O&O ShutUp10++ Recommended Tweaks..."

# Disable Telemetry
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f > $null

# Disable Feedback Notifications
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f > $null

# Disable Advertising ID
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f > $null

# Disable Tailored Experiences
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f > $null

# Disable Location Tracking
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v DisableLocation /t REG_DWORD /d 1 /f > $null

reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v UploadUserActivities /t REG_DWORD /d 0 /f > $null

$AppPrivacy = "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy"

$permissions = @(
    "LetAppsAccessCamera",
    "LetAppsAccessMicrophone",
    "LetAppsAccessContacts",
    "LetAppsAccessCalendar",
    "LetAppsAccessEmail",
    "LetAppsAccessTasks",
    "LetAppsAccessPhoneCallHistory",
    "LetAppsAccessRadios",
    "LetAppsAccessMotion",
    "LetAppsAccessFileSystem",
    "LetAppsAccessPicturesLibrary",
    "LetAppsAccessVideosLibrary",
    "LetAppsAccessDocumentsLibrary",
    "LetAppsAccessUnpairedDevices"
)

foreach ($perm in $permissions) {
    reg add $AppPrivacy /v $perm /t REG_DWORD /d 2 /f > $null
}

# Disable automatic driver updates (O&O Recommended)
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v ExcludeWUDriversInQualityUpdate /t REG_DWORD /d 1 /f > $null

# Disable driver searching through Windows Update
reg add "HKLM\Software\Policies\Microsoft\Windows\DriverSearching" /v DontSearchWindowsUpdate /t REG_DWORD /d 1 /f > $null

# Disable Delivery Optimization P2P
reg add "HKLM\Software\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f > $null

# Disable SmartScreen for Windows
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 0 /f > $null

# Disable SmartScreen for Edge
reg add "HKLM\Software\Policies\Microsoft\Edge" /v SmartScreenEnabled /t REG_DWORD /d 0 /f > $null

# Disable Cortana
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f > $null

# Disable Cloud Search
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v AllowCloudSearch /t REG_DWORD /d 0 /f > $null

# Disable Web Search in Start Menu
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v DisableSearch /t REG_DWORD /d 1 /f > $null

# Disable Consumer Experience
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableConsumerFeatures /t REG_DWORD /d 1 /f > $null

# Disable Automatic App Install
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableAutomaticAppInstall /t REG_DWORD /d 1 /f > $null

# Disable Suggestions in Start
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f > $null

reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f > $null

# Disable handwriting data collection
reg add "HKCU\Software\Microsoft\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f > $null
reg add "HKCU\Software\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f > $null

# Disable background apps
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f > $null

# Disable Cloud Clipboard
reg add "HKCU\Software\Microsoft\Clipboard" /v CloudClipboard /t REG_DWORD /d 0 /f > $null

# Disable Recent Items & Frequent Folders
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v ShowRecent /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v ShowFrequent /t REG_DWORD /d 0 /f > $null

Write-Host "[OK] O&O Recommended Tweaks Applied."
# 5. WINDOWS UPDATE, DRIVERS, ONEDRIVE, DELIVERY OPTIMIZATION
# ============================================================================

Write-Info "Configuring Windows Update & driver policies..."

# Driver updates via Windows Update uitschakelen
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v ExcludeWUDriversInQualityUpdate /t REG_DWORD /d 1 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\DriverSearching" /v DontSearchWindowsUpdate /t REG_DWORD /d 1 /f > $null

# Delivery Optimization
reg add "HKLM\Software\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f > $null

# OneDrive sync uitschakelen
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f > $null

# Sync settings uitschakelen
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync" /v SyncSettings /t REG_DWORD /d 0 /f > $null

# 6. COPILOT, WIDGETS, TASKBAR, START, LAYOUT XML FIXES
# ============================================================================

Write-Info "Disabling Copilot and Widgets / cleaning Taskbar & Start..."

# Copilot policies
reg add "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f > $null

# Copilot-knop verbergen
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowCopilotButton /t REG_DWORD /d 0 /f > $null

# Widgets uitschakelen
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarDa /t REG_DWORD /d 0 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Dsh" /v AllowNewsAndInterests /t REG_DWORD /d 0 /f > $null

Get-AppxPackage -AllUsers *WindowsWidgets* | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
Get-AppxPackage -AllUsers *WebExperience* | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue

# Taskbar cleanup
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v StoreAppsOnTaskbar /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackDocs /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackProgs /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSyncProviderNotifications /t REG_DWORD /d 0 /f > $null

# Taskbar alignment left
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAl /t REG_DWORD /d 0 /f > $null

# Taskbar pins folder leegmaken
$taskbarPins = "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
if (Test-Path $taskbarPins) {
    Write-Info "Clearing taskbar pins..."
    Get-ChildItem $taskbarPins | Remove-Item -Force -ErrorAction SilentlyContinue
}

# File Explorer opnieuw pinnen
$explorerPath = "C:\Windows\explorer.exe"
$verb = "taskbarpin"

$shell = New-Object -ComObject Shell.Application
$item = $shell.Namespace((Split-Path $explorerPath)).ParseName((Split-Path $explorerPath -Leaf))
$item.InvokeVerb($verb)

# Repinning task uitschakelen
schtasks /Change /TN "Microsoft\Windows\Shell\TaskbarLayoutModification" /Disable 2>$null

# Start menu pins via policy
Write-Info "Clearing Start menu pins..."
$keyStartPolicy = 'Registry::HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Start'
New-Item -Path $keyStartPolicy -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -LiteralPath $keyStartPolicy -Name 'ConfigureStartPins' -Value '{"pinnedList":[]}' -Type String

# LinkedIn AppX volledig verwijderen (fallback)
Get-AppxPackage -AllUsers *LinkedIn* | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -like "*LinkedIn*"} | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue

# Layout XML's (LinkedIn + Store pin)
Write-Info "Cleaning default Start layout (LinkedIn/Store pins)..."

$layoutFiles = @(
    "C:\Windows\System32\DefaultLayouts.xml",
    "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml"
)

foreach ($file in $layoutFiles) {
    if (Test-Path $file) {
        takeown /F $file /A > $null
        icacls $file /grant administrators:F /T > $null

        $content = Get-Content $file
        $content = $content -replace 'LinkedIn', ''
        $content = $content -replace 'Microsoft.WindowsStore', ''

        $content | Set-Content $file -Force

        Write-Remove "Sanitized layout: $file"
    }
}

# Taskbar layout laten rebuilden
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" /f > $null

Write-Info "Applying additional performance, privacy and Explorer tweaks..."

# Disable SysMain (Superfetch)
Write-Info "Disabling SysMain service..."
Stop-Service SysMain -Force -ErrorAction SilentlyContinue
Set-Service SysMain -StartupType Disabled

# Disable Diagnostics Tracking service (DiagTrack)
Write-Info "Disabling Diagnostics Tracking service..."
Stop-Service DiagTrack -Force -ErrorAction SilentlyContinue
Set-Service DiagTrack -StartupType Disabled

# Disable 'Recent files' and 'Frequent folders' in Explorer
Write-Info "Disabling recent/frequent items in Explorer..."
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v ShowRecent /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v ShowFrequent /t REG_DWORD /d 0 /f > $null

# Disable 'Recently added apps' in Start menu
Write-Info "Disabling recently added apps in Start..."
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_NotifyNewApps /t REG_DWORD /d 0 /f > $null

# Disable SMBv1 (legacy, insecure protocol)
Write-Info "Disabling SMBv1 protocol..."
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue

# 7. VBS / CORE ISOLATION / SVCHOST SPLIT
# ============================================================================

Write-Info "Disabling VBS / Core Isolation..."

# Virtualization-Based Security
reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f > $null

# HVCI (Memory Integrity)
reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 0 /f > $null
reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v EnabledBootId /t REG_DWORD /d 0 /f > $null
reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v WasEnabledBy /t REG_DWORD /d 0 /f > $null

Write-Info "Applying SvcHostSplitThresholdInKB..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v SvcHostSplitThresholdInKB /t REG_DWORD /d 67108864 /f > $null


# 8. LOCALE, TIMEZONE, LANGUAGE
# ============================================================================

Write-Info "Setting locale/timezone to NL / W. Europe..."

tzutil /s "W. Europe Standard Time"
Set-WinSystemLocale nl-NL
Set-WinUserLanguageList nl-NL -Force
Set-Culture nl-NL
Set-WinHomeLocation -GeoId 176  # Nederland


# 9. THEME / ACCENT COLOR
# ============================================================================

Write-Info "Applying dark theme & accent color..."

$lightThemeSystem   = 0
$lightThemeApps     = 0
$accentColorOnStart = 0
$enableTransparency = 0
$htmlAccentColor    = '#0078D4'   # Windows blauw

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v SystemUsesLightTheme /t REG_DWORD /d $lightThemeSystem /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v AppsUseLightTheme   /t REG_DWORD /d $lightThemeApps /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v ColorPrevalence    /t REG_DWORD /d $accentColorOnStart /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d $enableTransparency /f > $null

try {
    Add-Type -AssemblyName 'System.Drawing'
    $accentColor = [System.Drawing.ColorTranslator]::FromHtml($htmlAccentColor)

    function ConvertTo-DWord {
        param([System.Drawing.Color]$Color)
        [byte[]] $bytes = @($Color.R,$Color.G,$Color.B,$Color.A)
        return [System.BitConverter]::ToUInt32($bytes,0)
    }

    Set-ItemProperty -LiteralPath 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent' -Name 'StartColorMenu'  -Value (ConvertTo-DWord -Color $accentColor) -Type 'DWord' -Force
    Set-ItemProperty -LiteralPath 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent' -Name 'AccentColorMenu' -Value (ConvertTo-DWord -Color $accentColor) -Type 'DWord' -Force
    Set-ItemProperty -LiteralPath 'Registry::HKCU\Software\Microsoft\Windows\DWM' -Name 'AccentColor' -Value (ConvertTo-DWord -Color $accentColor) -Type 'DWord' -Force
} catch {
    Write-Info "Accent color application failed — continuing..."
}


# 10. DEFAULT USER HIVE TWEAKS
# ============================================================================

Write-Info "Applying DefaultUser hive tweaks..."

$defaultNtUser = "C:\Users\Default\NTUSER.DAT"

if (Test-Path $defaultNtUser) {
    reg load HKU\DefaultUser "$defaultNtUser" > $null

    # Copilot uit voor nieuwe users
    reg add "HKU\DefaultUser\Software\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f > $null

    # Notepad store banner
    reg add "HKU\DefaultUser\Software\Microsoft\Notepad" /v ShowStoreBanner /t REG_DWORD /d 0 /f > $null

    # GameDVR
    reg add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f > $null

    # Explorer defaults
    reg add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f > $null
    reg add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f > $null
    reg add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAl /t REG_DWORD /d 0 /f > $null

    # ContentDeliveryManager defaults
    $cdmNames = @(
        'ContentDeliveryAllowed','FeatureManagementEnabled','OEMPreInstalledAppsEnabled',
        'PreInstalledAppsEnabled','PreInstalledAppsEverEnabled','SilentInstalledAppsEnabled',
        'SoftLandingEnabled','SubscribedContentEnabled','SubscribedContent-310093Enabled',
        'SubscribedContent-338387Enabled','SubscribedContent-338388Enabled',
        'SubscribedContent-338389Enabled','SubscribedContent-338393Enabled',
        'SubscribedContent-353694Enabled','SubscribedContent-353696Enabled',
        'SubscribedContent-353698Enabled','SystemPaneSuggestionsEnabled'
    )
    foreach ($name in $cdmNames) {
        reg add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v $name /t REG_DWORD /d 0 /f > $null
    }

    # Keyboard indicators (NumLock aan)
    foreach ($root in 'HKU\.DEFAULT','HKU\DefaultUser') {
        reg add "$root\Control Panel\Keyboard" /v InitialKeyboardIndicators /t REG_SZ /d 2 /f > $null
    }

    # Mouse acceleration uit
    reg add "HKU\DefaultUser\Control Panel\Mouse" /v MouseSpeed      /t REG_SZ /d 0 /f > $null
    reg add "HKU\DefaultUser\Control Panel\Mouse" /v MouseThreshold1 /t REG_SZ /d 0 /f > $null
    reg add "HKU\DefaultUser\Control Panel\Mouse" /v MouseThreshold2 /t REG_SZ /d 0 /f > $null

    # Search suggestions uit
    reg add "HKU\DefaultUser\Software\Policies\Microsoft\Windows\Explorer" /v DisableSearchBoxSuggestions /t REG_DWORD /d 1 /f > $null

    # Accentkleur op titelbalken uit
    reg add "HKU\DefaultUser\Software\Microsoft\Windows\DWM" /v ColorPrevalence /t REG_DWORD /d 0 /f > $null

    reg unload HKU\DefaultUser > $null
} else {
    Write-Info "Default NTUSER.DAT not found — skipping DefaultUser tweaks."
}


# 11. EDGE POLICIES + EU-CONDITIONAL EDGE REMOVAL
# ============================================================================

Write-Info "Applying Edge policies..."

reg add "HKLM\Software\Policies\Microsoft\Edge" /v HideFirstRunExperience /t REG_DWORD /d 1 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Edge\Recommended" /v BackgroundModeEnabled /t REG_DWORD /d 0 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Edge\Recommended" /v StartupBoostEnabled /t REG_DWORD /d 0 /f > $null
reg add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v DoNotUpdateToEdgeWithChromium /t REG_DWORD /d 1 /f > $null

if ($IsEU) {
    Write-Info "EU build detected — removing Microsoft Edge browser..."

    $edgePaths = @(
        "C:\Program Files (x86)\Microsoft\Edge\Application",
        "C:\Program Files\Microsoft\Edge\Application"
    )

    foreach ($path in $edgePaths) {
        if (Test-Path $path) {
            $setup = Get-ChildItem $path -Recurse -Filter "setup.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($setup) {
                Write-Info "Executing Edge uninstall from: $($setup.FullName)"
                & $setup.FullName --uninstall --system-level --force-uninstall --verbose-logging
                Write-OK "Edge uninstall command executed."
            }
        }
    }
} else {
    Write-Info "Skipping Edge removal — not an EU-regulated build."
}


# 12. EXPLORER / SEARCH / CLASSIC CONTEXT MENU / WEB INTEGRATION
# ============================================================================

Write-Info "Applying Explorer tweaks..."

# File Explorer naar This PC
Set-ItemProperty -LiteralPath 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'LaunchTo' -Type DWord -Value 1

# Taskbar search box verbergen
Set-ItemProperty -LiteralPath 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Search' -Name 'SearchboxTaskbarMode' -Type DWord -Value 0

# Edge desktop shortcuts weg
$edgeLinkUser   = Join-Path $env:USERPROFILE "Desktop\Microsoft Edge.lnk"
$edgeLinkPublic = "C:\Users\Public\Desktop\Microsoft Edge.lnk"
Remove-Item -LiteralPath $edgeLinkUser   -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $edgeLinkPublic -ErrorAction SilentlyContinue

# Classic context menu (Win11)
reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /ve /f > $null

# Explorer web integratie
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowRecommendedSection /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowCloudFilesInHome /t REG_DWORD /d 0 /f > $null


# 13. ONEDRIVE FULL REMOVAL
# ============================================================================

Write-Info "Removing OneDrive completely..."

taskkill /IM OneDrive.exe /F 2>$null

Get-AppxPackage -AllUsers *OneDrive* | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue

if (Test-Path "$env:SystemRoot\SysWOW64\OneDriveSetup.exe") {
    & "$env:SystemRoot\SysWOW64\OneDriveSetup.exe" /uninstall
}
if (Test-Path "$env:SystemRoot\System32\OneDriveSetup.exe") {
    & "$env:SystemRoot\System32\OneDriveSetup.exe" /uninstall
}

Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "$env:USERPROFILE\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue

reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v OneDrive /f 2>$null

# (optioneel) OneDrive uit de Explorer navigatieboom
reg add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v System.IsPinnedToNameSpaceTree /t REG_DWORD /d 0 /f 2>$null

# 14. EXTENDED PRIVACY / ANTI-AD / ANTI-CLOUD / ANTI-SPOTLIGHT / ANTI-RECALL
# ============================================================================

Write-Info "Applying extended privacy and anti-advertising hardening..."

# Suggested apps in Start (25H2)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_IrisRecommendations /t REG_DWORD /d 0 /f > $null

# Online Service Experience Packs
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v AllowOnlineServiceExperience /t REG_DWORD /d 0 /f > $null

# Recall / AI
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsAI" /v DisableAIDataCollection /t REG_DWORD /d 1 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsAI" /v DisableAIRecall /t REG_DWORD /d 1 /f > $null

# Suggested Actions
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform" /v Disabled /t REG_DWORD /d 1 /f > $null

# App Installer suggestions (Store MSIX)
reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v NoUseStoreOpenWith /t REG_DWORD /d 1 /f > $null

# Web search in Start (Bing)
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v DisableSearchBoxSuggestions /t REG_DWORD /d 1 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v DisableSearch /t REG_DWORD /d 1 /f > $null

# Cloud Content (ads in Settings, Start, lock screen)
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableConsumerFeatures /t REG_DWORD /d 1 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f > $null

# Windows Spotlight overal uit
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f > $null
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightOnActionCenter /t REG_DWORD /d 1 /f > $null
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightOnSettings /t REG_DWORD /d 1 /f > $null
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightOnLockScreen /t REG_DWORD /d 1 /f > $null

# App prelaunch (Edge, Mail, Calendar)
reg add "HKLM\Software\Policies\Microsoft\Windows\EdgeUI" /v AllowPrelaunch /t REG_DWORD /d 0 /f > $null

# Automatic App reinstall
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableAutomaticAppInstall /t REG_DWORD /d 1 /f > $null

# Extra Clipchamp/Teams removal (fallback)
Get-AppxPackage -AllUsers *Clipchamp* | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
Get-AppxPackage -AllUsers *MSTeams*   | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue

# Windows Backup cloud prompts
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v DisableWindowsBackup /t REG_DWORD /d 1 /f > $null

# Block WhatsApp/Messenger/TikTok/Spotify recommendations
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353699Enabled /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353700Enabled /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEnabled /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEverEnabled /t REG_DWORD /d 0 /f > $null

# Disable Get Started / Privacy Experience
reg add "HKLM\Software\Policies\Microsoft\Windows\OOBE" /v DisablePrivacyExperience /t REG_DWORD /d 1 /f > $null

# Suggested apps in Start (25H2)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_IrisRecommendations /t REG_DWORD /d 0 /f > $null

Write-OK "Extended privacy and anti-advertising hardening applied."

# 15. APPLICATION INSTALLATION (Chrome, 7-Zip, Notepad++) + DEFAULT BROWSER
# ============================================================================
# Safer, fixed version:
# - Fixes temp path escaping (uses Join-Path)
# - Improves Test-AppInstalled to check HKLM/HKLM Wow6432Node and HKCU
# - Verifies downloads before running installers
# - Uses Start-Process -FilePath and explicit ArgumentList
# - Adds basic error handling and informative output

function Write-Info { param($m) Write-Host "[INFO]  $m" -ForegroundColor Cyan }
function Write-OK   { param($m) Write-Host "[OK]    $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Write-Err  { param($m) Write-Host "[ERROR] $m" -ForegroundColor Red }

Write-Info "Checking required applications..."

# Helper: Check if an app exists in uninstall registry (HKLM 64/32-bit and HKCU)
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
        } catch {
            # ignore inaccessible keys
        }
    }
    return $false
}

# -------------------------
# GOOGLE CHROME
# -------------------------
$chromeInstalled = Test-AppInstalled "Google Chrome"

if (-not $chromeInstalled) {
    Write-Info "Installing Google Chrome (silent)..."
    $chromeInstaller = Join-Path $env:TEMP 'chrome_installer.exe'
    try {
        Invoke-WebRequest -Uri "https://dl.google.com/chrome/install/latest/chrome_installer.exe" -OutFile $chromeInstaller -UseBasicParsing -ErrorAction Stop
        if (-not (Test-Path -Path $chromeInstaller)) { throw "Download failed: $chromeInstaller not found." }
        Start-Process -FilePath $chromeInstaller -ArgumentList "/silent","/install" -Wait -ErrorAction Stop
        Write-OK "Google Chrome installed."

        # Set Chrome as default ONLY if it was installed now
        Write-Info "Setting Chrome as default browser..."
        $chromeExe = Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'
        if (Test-Path -Path $chromeExe) {
            Start-Process -FilePath $chromeExe -ArgumentList '--make-default-browser'
            Write-OK "Chrome set as default browser."
        } else {
            Write-Warn "Chrome executable not found after installation."
        }

    } catch {
        Write-Err "Failed to install Google Chrome: $($_.Exception.Message)"
    }
} else {
    Write-Info "Google Chrome already installed — skipping installation and default-browser setup."
}

# -------------------------
# 7-ZIP
# -------------------------
if (-not (Test-AppInstalled "7-Zip")) {
    Write-Info "Installing 7-Zip (silent)..."
    $zipInstaller = Join-Path $env:TEMP '7zip_installer.exe'
    try {
        Invoke-WebRequest -Uri "https://www.7-zip.org/a/7z2408-x64.exe" -OutFile $zipInstaller -UseBasicParsing -ErrorAction Stop
        if (-not (Test-Path -Path $zipInstaller)) { throw "Download failed: $zipInstaller not found." }
        Start-Process -FilePath $zipInstaller -ArgumentList "/S" -Wait -ErrorAction Stop
        Write-OK "7-Zip installed."
    } catch {
        Write-Err "Failed to install 7-Zip: $($_.Exception.Message)"
    }
} else {
    Write-Info "7-Zip already installed — skipping."
}

# -------------------------
# NOTEPAD++
# -------------------------

# Force TLS 1.2 for GitHub downloads (prevents connection drops)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if (-not (Test-AppInstalled "Notepad++")) {
    Write-Info "Installing Notepad++ (silent)..."
    $npInstaller = Join-Path $env:TEMP 'npp_installer.exe'

    # Stable, always-working URL for latest 64-bit installer
    $nppUrl = "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/latest/download/npp.64-bit.Installer.exe"

    try {
        Invoke-WebRequest -Uri $nppUrl -OutFile $npInstaller -UseBasicParsing -ErrorAction Stop
        if (-not (Test-Path -Path $npInstaller)) { throw "Download failed: $npInstaller not found." }
        Start-Process -FilePath $npInstaller -ArgumentList "/S" -Wait -ErrorAction Stop
        Write-OK "Notepad++ installed."
    } catch {
        Write-Err "Failed to install Notepad++: $($_.Exception.Message)"
    }
} else {
    Write-Info "Notepad++ already installed — skipping."
}

# -------------------------
# DISCORD
# -------------------------

if (-not (Test-AppInstalled "Discord")) {
    Write-Info "Installing Discord (silent)..."

    # Download to a safe location (TEMP sometimes causes permission issues)
    $discordInstaller = "$env:USERPROFILE\Downloads\discord_installer.exe"
    $discordUrl = "https://discord.com/api/download?platform=win&format=exe"

    try {
        Invoke-WebRequest -Uri $discordUrl -OutFile $discordInstaller -UseBasicParsing -ErrorAction Stop
        if (-not (Test-Path -Path $discordInstaller)) { throw "Download failed: $discordInstaller not found." }
        Start-Process -FilePath $discordInstaller -ArgumentList "/S" -Wait -ErrorAction Stop
        Write-OK "Discord installed."
    } catch {
        Write-Err "Failed to install Discord: $($_.Exception.Message)"
    }
} else {
    Write-Info "Discord already installed — skipping."
}

# -------------------------
# STEAM
# -------------------------
if (-not (Test-AppInstalled "Steam")) {
    Write-Info "Installing Steam (silent)..."
    $steamInstaller = Join-Path $env:TEMP 'steam_installer.exe'
    $steamUrl = "https://cdn.cloudflare.steamstatic.com/client/installer/SteamSetup.exe"

    try {
        Invoke-WebRequest -Uri $steamUrl -OutFile $steamInstaller -UseBasicParsing -ErrorAction Stop
        if (-not (Test-Path -Path $steamInstaller)) { throw "Download failed: $steamInstaller not found." }
        Start-Process -FilePath $steamInstaller -ArgumentList "/S" -Wait -ErrorAction Stop
        Write-OK "Steam installed."
    } catch {
        Write-Err "Failed to install Steam: $($_.Exception.Message)"
    }
} else {
    Write-Info "Steam already installed — skipping."
}

Write-OK "Application installation and configuration complete."

# 16. TASKBAR CACHE CLEANUP + EXPLORER RESTART
# ============================================================================
Write-Host "Cleaning taskbar cache..."

$taskbarCache = Join-Path $env:LOCALAPPDATA "Microsoft\Windows\Explorer"

try {
    # Stop explorer if running
    $expl = Get-Process -Name explorer -ErrorAction SilentlyContinue
    if ($expl) {
        Write-Host "Stopping Explorer..."
        $expl | Stop-Process -Force -ErrorAction Stop

        # Wait for explorer to exit (timeout in seconds)
        $timeout = 10
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while ((Get-Process -Name explorer -ErrorAction SilentlyContinue) -ne $null -and $sw.Elapsed.TotalSeconds -lt $timeout) {
            Start-Sleep -Milliseconds 250
        }
    }

    # Remove taskbar cache files if folder exists
    if (Test-Path -Path $taskbarCache) {
        Write-Host "Removing taskbar cache files from $taskbarCache"
        Get-ChildItem -Path $taskbarCache -Filter "taskbar*.db" -File -ErrorAction SilentlyContinue |
            ForEach-Object {
                try {
                    Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop
                    Write-Host "Removed $($_.Name)"
                } catch {
                    Write-Warning "Could not remove $($_.Name): $($_.Exception.Message)"
                }
            }
    } else {
        Write-Host "Taskbar cache folder not found: $taskbarCache"
    }

    # Start Explorer and verify
    Write-Host "Starting Explorer..."
    Start-Process -FilePath "explorer.exe"
    Start-Sleep -Seconds 2

    if (Get-Process -Name explorer -ErrorAction SilentlyContinue) {
        Write-Host "Explorer restarted successfully."
    } else {
        Write-Error "Explorer did not start. Check shell registry and user context."
    }
} catch {
    Write-Error "Taskbar cleanup failed: $($_.Exception.Message)"
}

# 17. AUTOMATIC REBOOT WITH BANNER
# ============================================================================

$rebootDelay = 15

Write-Host ""
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host "   SYSTEM MAINTENANCE COMPLETE" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host ""
Write-Host " Your system will automatically reboot in $rebootDelay seconds." -ForegroundColor Cyan
Write-Host " Please save any open work immediately." -ForegroundColor Cyan
Write-Host ""
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host ""

Start-Sleep -Seconds $rebootDelay
shutdown /r /t 0

