# ============================================================================
# 1. ADMIN CHECK, LOGGING, EU DETECTION (DMA + GEOID)
# ============================================================================

try {
    $isAdmin = (New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $isAdmin = $false
}

if (-not $isAdmin) {
    Write-Host "[ERROR]  Run this script as Administrator." -ForegroundColor Red
    exit 1
}

function Write-Info($msg)    { Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Write-OK($msg)      { Write-Host "[ OK ]  $msg" -ForegroundColor Green }
function Write-Remove($msg)  { Write-Host "[DEL]  $msg" -ForegroundColor Magenta }

# Logging
$Desktop = [Environment]::GetFolderPath("Desktop")
$LogFile = Join-Path $Desktop "Full-SuperDebloat.log"
Start-Transcript -Path $LogFile -Append
Write-Info "Full SuperDebloat started at $(Get-Date)"

# ---------------------------
# EU Detection (DMA + GeoID)
# ---------------------------

Write-Info "Checking if system is an EU-regulated build..."

# DMA flag
$dmaFlag = 0
try {
    $dmaFlag = (Get-ItemProperty -Path "HKLM:\System\Setup\MoSetup" -Name "EnableEUDMA" -ErrorAction SilentlyContinue).EnableEUDMA
} catch {}

# GeoID
$geoId = 0
try {
    $geoId = (Get-ItemProperty -Path "HKCU:\Control Panel\International\Geo" -Name "Nation" -ErrorAction SilentlyContinue).Nation
} catch {}

# EU GeoID list
$EU_GeoIDs = @(4,8,20,28,31,40,56,70,100,112,124,191,196,203,208,233,246,250,268,276,300,348,352,372,380,428,440,442,470,498,499,528,616,620,642,643,688,703,705,724,752,804,807)

$IsEU = $false

if ($dmaFlag -eq 1) {
    Write-OK "EU DMA flag detected — system is EU-regulated."
    $IsEU = $true
} elseif ($EU_GeoIDs -contains $geoId) {
    Write-OK "GeoID indicates EU region ($geoId)."
    $IsEU = $true
} else {
    Write-Info "WARNING: System does NOT appear to be an EU build — Edge browser removal will be skipped."
}

Set-Variable -Name "IsEU" -Value $IsEU -Scope Global
# ============================================================================
# 2. APPX / PROVISIONED PACKAGES REMOVAL
# ============================================================================

function Remove-AppPackagesSelectors {
    param ([string[]] $Selectors)

    foreach ($selector in $Selectors) {
        Write-Info "Removing AppX / Provisioned for: $selector"

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
    'Microsoft.BingSearch','Microsoft.WindowsCamera','Microsoft.WindowsAlarms',
    'Microsoft.Copilot','Microsoft.549981C3F5F10','Microsoft.Windows.DevHome',
    'MicrosoftCorporationII.MicrosoftFamily','Microsoft.MicrosoftOfficeHub',
    'Microsoft.Office.OneNote','Microsoft.People','Microsoft.SkypeApp',
    'MicrosoftTeams','MSTeams','Microsoft.Wallet','Microsoft.YourPhone'
)

Remove-AppPackagesSelectors -Selectors $allAppxSelectors
# ============================================================================
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
# ============================================================================
# 4. PRIVACY, TELEMETRY, DIAGNOSTICS
# ============================================================================

Write-Info "Applying privacy & telemetry policies..."

# Telemetry
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f > $null
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f > $null

# Advertising & tracking
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f > $null
reg add "HKCU\Software\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f > $null

# Activity history
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v UploadUserActivities /t REG_DWORD /d 0 /f > $null

# Clipboard cloud
reg add "HKCU\Software\Microsoft\Clipboard" /v CloudClipboard /t REG_DWORD /d 0 /f > $null

# ContentDeliveryManager
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SoftLandingEnabled /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenEnabled /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenOverlayEnabled /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338393Enabled /t REG_DWORD /d 0 /f > $null

# Tailored experiences
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f > $null

# Location
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v DisableLocation /t REG_DWORD /d 1 /f > $null

# AppPrivacy
$privacyKeys = @(
    "LetAppsAccessMotion","LetAppsAccessBluetooth","LetAppsAccessDocumentsLibrary",
    "LetAppsAccessPicturesLibrary","LetAppsAccessVideosLibrary","LetAppsAccessFileSystem",
    "LetAppsAccessUnpairedDevices","LetAppsAccessUserDictionary","LetAppsAccessPhoneCallHistory",
    "LetAppsAccessPhoneCalls","LetAppsAccessVoiceActivation","LetAppsAccessRadios","LetAppsAccessSensors"
)

foreach ($key in $privacyKeys) {
    reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v $key /t REG_DWORD /d 2 /f > $null
}
# ============================================================================
# 5. WINDOWS UPDATE, DRIVERS, ONEDRIVE, DELIVERY OPTIMIZATION
# ============================================================================

Write-Info "Configuring Windows Update & Drivers..."

reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v ExcludeWUDriversInQualityUpdate /t REG_DWORD /d 1 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\DriverSearching" /v DontSearchWindowsUpdate /t REG_DWORD /d 1 /f > $null

# Delivery Optimization
reg add "HKLM\Software\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f > $null

# OneDrive policies
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f > $null

# Sync settings
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync" /v SyncSettings /t REG_DWORD /d 0 /f > $null
# ============================================================================
# 6. COPILOT, WIDGETS, TASKBAR UI, START MENU
# ============================================================================

Write-Info "Disabling Copilot, Widgets and shell clutter..."

# ---------------------------
# Copilot Policies
# ---------------------------

reg add "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f > $null

# Hide Copilot button
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowCopilotButton /t REG_DWORD /d 0 /f > $null

# ---------------------------
# Widgets Disable
# ---------------------------

# Disable Widgets taskbar icon
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarDa /t REG_DWORD /d 0 /f > $null

# Disable News & Interests backend
reg add "HKLM\Software\Policies\Microsoft\Dsh" /v AllowNewsAndInterests /t REG_DWORD /d 0 /f > $null

# Remove Widgets AppX packages
Get-AppxPackage -AllUsers *WindowsWidgets* | ForEach-Object {
    Write-Remove "Removing Widgets Appx: $($_.Name)"
    Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction SilentlyContinue
}

# Remove WebExperienceHost (Widgets/Copilot backend)
Get-AppxPackage -AllUsers *WebExperience* | ForEach-Object {
    Write-Remove "Removing WebExperience Appx: $($_.Name)"
    Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction SilentlyContinue
}

# ---------------------------
# Taskbar UI Cleanup
# ---------------------------

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v StoreAppsOnTaskbar /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackDocs /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackProgs /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSyncProviderNotifications /t REG_DWORD /d 0 /f > $null

# Force taskbar alignment to left
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAl /t REG_DWORD /d 0 /f > $null

# ---------------------------
# Remove Taskbar Pins
# ---------------------------

$taskbarPins = "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
if (Test-Path $taskbarPins) {
    Write-Info "Clearing taskbar pins..."
    Get-ChildItem $taskbarPins | Remove-Item -Force -ErrorAction SilentlyContinue
}

# Prevent Windows from repinning Store, Edge, etc.
schtasks /Change /TN "Microsoft\Windows\Shell\TaskbarLayoutModification" /Disable 2>$null

# Mark taskbar as modified
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" /v FavoritesRemovedChanges /t REG_DWORD /d 1 /f > $null

# ---------------------------
# Start Menu Pins
# ---------------------------

Write-Info "Clearing Start menu pins..."

$key = 'Registry::HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Start'
New-Item -Path $key -ItemType 'Directory' -ErrorAction 'SilentlyContinue' | Out-Null
Set-ItemProperty -LiteralPath $key -Name 'ConfigureStartPins' -Value '{"pinnedList":[]}' -Type 'String'
# ============================================================================
# 7. VBS / CORE ISOLATION / SVCHOST SPLIT
# ============================================================================

Write-Info "Disabling VBS / Core Isolation..."

reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 0 /f > $null
reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d 0 /f > $null
reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "EnabledBootId" /t REG_DWORD /d 0 /f > $null
reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "WasEnabledBy" /t REG_DWORD /d 0 /f > $null

Write-Info "Applying SvcHostSplitThresholdInKB..."

reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v SvcHostSplitThresholdInKB /t REG_DWORD /d 67108864 /f > $null
# ============================================================================
# 8. LOCALE, TIMEZONE, LANGUAGE
# ============================================================================

Write-Info "Setting locale/timezone to NL / W. Europe..."

tzutil /s "W. Europe Standard Time"
Set-WinSystemLocale nl-NL
Set-WinUserLanguageList nl-NL -Force
Set-Culture nl-NL
Set-WinHomeLocation -GeoId 176
# ============================================================================
# 9. THEME / ACCENT COLOR
# ============================================================================

Write-Info "Applying dark theme & accent color..."

$lightThemeSystem = 0
$lightThemeApps   = 0
$accentColorOnStart = 0
$enableTransparency = 0
$htmlAccentColor = '#0078D4'

# Basic theme toggles
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
    Write-Info "Accent color application failed (no System.Drawing?) – continuing..."
}
# ============================================================================
# 10. DEFAULT USER HIVE TWEAKS
# ============================================================================

Write-Info "Applying DefaultUser hive tweaks..."

$defaultNtUser = "C:\Users\Default\NTUSER.DAT"

if (Test-Path $defaultNtUser) {
    reg load HKU\DefaultUser "$defaultNtUser" > $null

    reg add "HKU\DefaultUser\Software\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f > $null
    reg add "HKU\DefaultUser\Software\Microsoft\Notepad" /v ShowStoreBanner /t REG_DWORD /d 0 /f > $null
    reg add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f > $null

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

    # Keyboard indicators
    foreach ($root in 'HKU\.DEFAULT','HKU\DefaultUser') {
        reg add "$root\Control Panel\Keyboard" /v InitialKeyboardIndicators /t REG_SZ /d 2 /f > $null
    }

    # Mouse accel off
    reg add "HKU\DefaultUser\Control Panel\Mouse" /v MouseSpeed      /t REG_SZ /d 0 /f > $null
    reg add "HKU\DefaultUser\Control Panel\Mouse" /v MouseThreshold1 /t REG_SZ /d 0 /f > $null
    reg add "HKU\DefaultUser\Control Panel\Mouse" /v MouseThreshold2 /t REG_SZ /d 0 /f > $null

    reg add "HKU\DefaultUser\Software\Policies\Microsoft\Windows\Explorer" /v DisableSearchBoxSuggestions /t REG_DWORD /d 1 /f > $null
    reg add "HKU\DefaultUser\Software\Microsoft\Windows\DWM" /v ColorPrevalence /t REG_DWORD /d 0 /f > $null

    reg unload HKU\DefaultUser > $null
} else {
    Write-Info "Default NTUSER.DAT not found, skipping DefaultUser tweaks."
}
# ============================================================================
# 11. EDGE POLICIES + EU-CONDITIONAL EDGE REMOVAL
# ============================================================================

Write-Info "Applying Edge policies..."

# Disable first-run experience
reg add "HKLM\Software\Policies\Microsoft\Edge" /v HideFirstRunExperience /t REG_DWORD /d 1 /f > $null

# Disable background mode + startup boost
reg add "HKLM\Software\Policies\Microsoft\Edge\Recommended" /v BackgroundModeEnabled /t REG_DWORD /d 0 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Edge\Recommended" /v StartupBoostEnabled /t REG_DWORD /d 0 /f > $null

# Prevent forced Edge reinstalls
reg add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v DoNotUpdateToEdgeWithChromium /t REG_DWORD /d 1 /f > $null

# ---------------------------
# EU-Conditional Edge Removal
# ---------------------------

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
# ============================================================================
# 12. EXPLORER / SEARCH / CONTEXT MENU
# ============================================================================

Write-Info "Applying current user Explorer tweaks..."

# Open File Explorer to This PC
Set-ItemProperty -LiteralPath 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'LaunchTo' -Type 'DWord' -Value 1

# Hide taskbar search box
Set-ItemProperty -LiteralPath 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Search' -Name 'SearchboxTaskbarMode' -Type 'DWord' -Value 0

# Remove Edge desktop shortcuts
$edgeLinkUser   = Join-Path $env:USERPROFILE "Desktop\Microsoft Edge.lnk"
$edgeLinkPublic = "C:\Users\Public\Desktop\Microsoft Edge.lnk"
Remove-Item -LiteralPath $edgeLinkUser   -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $edgeLinkPublic -ErrorAction SilentlyContinue

# Enable classic right-click menu (Windows 11)
reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /ve /f > $null
# ============================================================================
# 13. ONEDRIVE FULL REMOVAL
# ============================================================================

Write-Info "Removing OneDrive completely..."

# Kill OneDrive process
taskkill /IM OneDrive.exe /F 2>$null

# Remove OneDrive AppX
Get-AppxPackage -AllUsers *OneDrive* | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue

# Run official uninstallers
if (Test-Path "$env:SystemRoot\SysWOW64\OneDriveSetup.exe") {
    & "$env:SystemRoot\SysWOW64\OneDriveSetup.exe" /uninstall
}
if (Test-Path "$env:SystemRoot\System32\OneDriveSetup.exe") {
    & "$env:SystemRoot\System32\OneDriveSetup.exe" /uninstall
}

# Remove leftover folders
Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "$env:USERPROFILE\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue

# Remove startup entry
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v OneDrive /f 2>$null
# ============================================================================
# 14. REMOVE GET STARTED SYSTEM APP
# ============================================================================

Write-Info "Removing Get Started system app..."

$gsPaths = Get-ChildItem "C:\Windows\SystemApps" -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like "MicrosoftWindows.Getstarted*" }

foreach ($folder in $gsPaths) {
    Write-Remove "Removing: $($folder.FullName)"
    takeown /F $folder.FullName /R /D Y | Out-Null
    icacls $folder.FullName /grant administrators:F /T | Out-Null
    Remove-Item $folder.FullName -Recurse -Force -ErrorAction SilentlyContinue
}
# ============================================================================
# 15. TASKBAR CACHE CLEANUP + EXPLORER RESTART
# ============================================================================

Write-Info "Cleaning taskbar cache..."

$taskbarCache = Join-Path $env:LOCALAPPDATA "Microsoft\Windows\Explorer"
Get-ChildItem $taskbarCache -Filter "taskbar*.db" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

Write-Info "Restarting Explorer..."
Get-Process -Name 'explorer' -ErrorAction SilentlyContinue | Stop-Process -Force

Write-OK "Explorer restarted."
# ============================================================================
# 16. AUTOMATIC REBOOT WITH BANNER
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
