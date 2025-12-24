# ============================================================================
# 0. ADMIN CHECK, LOGGING, HELPER FUNCTIONS
# ============================================================================
# Admin check
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host "[ERROR] Run this script as Administrator." -ForegroundColor Red
    Write-Host ""
    Write-Host "This window will close in 5 seconds..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
    exit 1
}

# Logging helpers
function Write-Info($msg)   { Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Write-OK($msg)     { Write-Host "[ OK ]  $msg" -ForegroundColor Green }
function Write-Remove($msg) { Write-Host "[DEL]  $msg" -ForegroundColor Magenta }
function Write-Warn($msg)   { Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err($msg)    { Write-Host "[ERR!] $msg" -ForegroundColor Red }

# Start transcript logging op het bureaublad
$Desktop = [Environment]::GetFolderPath("Desktop")
$LogFile = Join-Path $Desktop "Full-SuperDebloat.log"
Start-Transcript -Path $LogFile -Append
Write-Info "Full SuperDebloat started at $(Get-Date)"


# ============================================================================
# 1. EU-DETECTIE (voor Edge-verwijdering)
# ============================================================================

Write-Info "Checking if system is an EU-regulated build..."

$dmaFlag = (Get-ItemProperty -Path "HKLM:\System\Setup\MoSetup" `
    -Name "EnableEUDMA" -ErrorAction SilentlyContinue).EnableEUDMA

$geoId = (Get-ItemProperty -Path "HKCU:\Control Panel\International\Geo" `
    -Name "Nation" -ErrorAction SilentlyContinue).Nation

# Lijst van EU GeoID's
$EU_GeoIDs = @(4,8,20,28,31,40,56,70,100,112,124,191,196,203,208,233,246,250,
               268,276,300,348,352,372,380,428,440,442,470,498,499,528,616,
               620,642,643,688,703,705,724,752,804,807)

$IsEU = $false

if ($dmaFlag -eq 1) {
    Write-OK "EU DMA flag detected."
    $IsEU = $true
}
elseif ($EU_GeoIDs -contains $geoId) {
    Write-OK "GeoID indicates EU region ($geoId)."
    $IsEU = $true
}
else {
    Write-Info "System does NOT appear to be EU — Edge removal will be skipped."
}

# Maak variabele globaal beschikbaar
Set-Variable -Name "IsEU" -Value $IsEU -Scope Global
# ============================================================================
# 2. APPX / PROVISIONED PACKAGE REMOVAL
# ============================================================================

function Remove-AppPackagesSelectors {
    param ([string[]] $Selectors)

    foreach ($selector in $Selectors) {
        Write-Info "Removing AppX / Provisioned: $selector"

        # Verwijder AppX voor alle bestaande gebruikers
        Get-AppxPackage -AllUsers |
            Where-Object { $_.Name -eq $selector -or $_.Name -like $selector } |
            ForEach-Object {
                Write-Remove "Removing AppxPackage: $($_.Name)"
                Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction SilentlyContinue
            }

        # Verwijder provisioned packages (voor nieuwe gebruikers)
        Get-AppxProvisionedPackage -Online |
            Where-Object { $_.DisplayName -eq $selector -or $_.PackageName -like $selector } |
            ForEach-Object {
                Write-Remove "Removing Provisioned: $($_.PackageName)"
                Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction SilentlyContinue
            }
    }
}

# Lijst van te verwijderen AppX apps
# (opgeschoond, geen dubbele entries)
$allAppxSelectors = @(
    # Xbox
    "Microsoft.XboxApp*","Microsoft.Xbox.TCUI*","Microsoft.XboxGameOverlay*",
    "Microsoft.XboxGamingOverlay*","Microsoft.XboxIdentityProvider*",
    "Microsoft.XboxSpeechToTextOverlay*","Microsoft.GamingApp*",

    # Overige Microsoft apps
    "Microsoft.Microsoft3DViewer*","Microsoft.MixedReality.Portal*",
    "Microsoft.SkypeApp*","Microsoft.MicrosoftSolitaireCollection*",
    "Microsoft.GetHelp*","Microsoft.Getstarted*","Microsoft.ZuneMusic*",
    "Microsoft.ZuneVideo*","Microsoft.People*","Microsoft.WindowsMaps*",
    "Microsoft.BingWeather*","Microsoft.BingNews*","Microsoft.News*",
    "Microsoft.Todos*","Microsoft.WindowsFeedbackHub*",
    "Microsoft.WindowsSoundRecorder*","Microsoft.MicrosoftStickyNotes*",
    "Microsoft.OutlookForWindows*","Microsoft.PowerAutomateDesktop*",
    "Microsoft.WindowsNotepad*",

    # System apps / bloat
    "Microsoft.BingSearch","Microsoft.WindowsCamera","Microsoft.WindowsAlarms",
    "Microsoft.Copilot","Microsoft.549981C3F5F10","Microsoft.Windows.DevHome",
    "MicrosoftCorporationII.MicrosoftFamily","Microsoft.MicrosoftOfficeHub",
    "Microsoft.Office.OneNote","Microsoft.People","Microsoft.SkypeApp",
    "MicrosoftTeams","MSTeams","Microsoft.Wallet","Microsoft.YourPhone",

    # Clipchamp
    "*Clipchamp*"
)

# Voer de verwijdering uit
Remove-AppPackagesSelectors -Selectors $allAppxSelectors
# ============================================================================
# 3. PRIVACY & TELEMETRY HARDENING
# ============================================================================

# Disable telemetry (0 = Security only)
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f > $null

# Disable feedback notifications
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f > $null

# Disable Activity Feed
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f > $null

# Prevent publishing activities
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f > $null

# Prevent uploading activities to Microsoft
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v UploadUserActivities /t REG_DWORD /d 0 /f > $null

# Disable Advertising ID
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f > $null

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f > $null

# Disable cloud clipboard sync
reg add "HKCU\Software\Microsoft\Clipboard" /v CloudClipboard /t REG_DWORD /d 0 /f > $null

# Disable all background apps
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f > $null

# Disable location tracking
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v DisableLocation /t REG_DWORD /d 1 /f > $null

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
    "LetAppsAccessUnpairedDevices",
    "LetAppsAccessUserDictionary",
    "LetAppsAccessSensors",
    "LetAppsAccessBluetooth"
)

foreach ($perm in $permissions) {
    reg add $AppPrivacy /v $perm /t REG_DWORD /d 2 /f > $null
}
# ============================================================================
# 4. WINDOWS UPDATE & DRIVER POLICIES
# ============================================================================

Write-Info "Applying Windows Update, Driver, DO and OneDrive policies..."

# Disable driver updates via Windows Update
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v ExcludeWUDriversInQualityUpdate /t REG_DWORD /d 1 /f > $null

# Disable driver searching through Windows Update
reg add "HKLM\Software\Policies\Microsoft\Windows\DriverSearching" /v DontSearchWindowsUpdate /t REG_DWORD /d 1 /f > $null

# Disable Delivery Optimization (P2P updates)
reg add "HKLM\Software\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f > $null

# Disable OneDrive file sync
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f > $null

# ============================================================================
# 5. COPILOT, WIDGETS, TASKBAR, START MENU
# ============================================================================
Write-Info "Disabling Copilot, Widgets and cleaning Taskbar & Start..."

# Disable Copilot (HKCU + HKLM)
reg add "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f > $null

# Hide Copilot button
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowCopilotButton /t REG_DWORD /d 0 /f > $null

# Disable Widgets
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarDa /t REG_DWORD /d 0 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Dsh" /v AllowNewsAndInterests /t REG_DWORD /d 0 /f > $null

# Remove Widgets packages
Get-AppxPackage -AllUsers *WindowsWidgets* | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
Get-AppxPackage -AllUsers *WebExperience* | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue

# ============================================================================
# 6. TASKBAR CLEANUP
# ============================================================================

# Hide Task View button
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f > $null

# Disable pinned Store apps on taskbar
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v StoreAppsOnTaskbar /t REG_DWORD /d 0 /f > $null

# Disable Start menu tracking (recent docs & apps)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackDocs /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackProgs /t REG_DWORD /d 0 /f > $null

# Disable Sync Provider notifications in Explorer
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSyncProviderNotifications /t REG_DWORD /d 0 /f > $null

# Taskbar alignment (0 = left)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAl /t REG_DWORD /d 0 /f > $null

# Clear pinned taskbar items
$taskbarPins = "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
if (Test-Path $taskbarPins) {
    Write-Info "Clearing taskbar pins..."
    Get-ChildItem $taskbarPins | Remove-Item -Force -ErrorAction SilentlyContinue
}

# Re-pin File Explorer
$explorerPath = "C:\Windows\explorer.exe"
$shell = New-Object -ComObject Shell.Application
$item = $shell.Namespace((Split-Path $explorerPath)).ParseName((Split-Path $explorerPath -Leaf))
$item.InvokeVerb("taskbarpin")

# Disable automatic repinning
schtasks /Change /TN "Microsoft\Windows\Shell\TaskbarLayoutModification" /Disable 2>$null


# ============================================================================
# 7. START MENU CLEANUP
# ============================================================================

Write-Info "Clearing Start menu pins..."

$keyStartPolicy = 'Registry::HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Start'
New-Item -Path $keyStartPolicy -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -LiteralPath $keyStartPolicy -Name 'ConfigureStartPins' -Value '{"pinnedList":[]}' -Type String
# ============================================================================
# 5. LINKEDIN / STORE LAYOUT CLEANUP
# ============================================================================

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


# ============================================================================
# 6. PERFORMANCE SERVICES (SysMain / DiagTrack)
# ============================================================================

Write-Info "Disabling SysMain and DiagTrack services..."

Stop-Service SysMain -Force -ErrorAction SilentlyContinue
Set-Service SysMain -StartupType Disabled

Stop-Service DiagTrack -Force -ErrorAction SilentlyContinue
Set-Service DiagTrack -StartupType Disabled


# ============================================================================
# 7. EXPLORER TWEAKS (Recent/Frequent items)
# ============================================================================

Write-Info "Disabling recent/frequent items in Explorer..."

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v ShowRecent /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v ShowFrequent /t REG_DWORD /d 0 /f > $null

# Disable "Recently added apps" in Start
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_NotifyNewApps /t REG_DWORD /d 0 /f > $null

# ============================================================================
# 8. SMBv1 (legacy protocol) uitschakelen
# ============================================================================

Write-Info "Disabling SMBv1 protocol..."
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue


# ============================================================================
# 9. VBS / CORE ISOLATION / HVCI
# ============================================================================
Write-Info "Disabling VBS / Core Isolation..."

# Disable VBS
reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f > $null

# Disable HVCI (Memory Integrity)
reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 0 /f > $null
reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v EnabledBootId /t REG_DWORD /d 0 /f > $null
reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v WasEnabledBy /t REG_DWORD /d 0 /f > $null

# Increase SvcHost split threshold (performance)
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v SvcHostSplitThresholdInKB /t REG_DWORD /d 67108864 /f > $null

# ============================================================================
# 10. LOCALE / TIMEZONE / LANGUAGE
# ============================================================================

Write-Info "Setting locale/timezone to NL / W. Europe..."

tzutil /s "W. Europe Standard Time"
Set-WinSystemLocale nl-NL
Set-WinUserLanguageList nl-NL -Force
Set-Culture nl-NL
Set-WinHomeLocation -GeoId 176  # Nederland


# ============================================================================
# 11. THEME / ACCENT COLOR
# ============================================================================
Write-Info "Applying dark theme & accent color..."

$lightThemeSystem   = 0
$lightThemeApps     = 0
$accentColorOnStart = 0
$enableTransparency = 0
$htmlAccentColor    = '#0078D4'   # Windows blauw

# Apply theme settings
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v SystemUsesLightTheme /t REG_DWORD /d $lightThemeSystem /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v AppsUseLightTheme   /t REG_DWORD /d $lightThemeApps /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v ColorPrevalence    /t REG_DWORD /d $accentColorOnStart /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d $enableTransparency /f > $null

# Convert HTML color to DWORD
try {
    Add-Type -AssemblyName 'System.Drawing'
    $accentColor = [System.Drawing.ColorTranslator]::FromHtml($htmlAccentColor)

    function ConvertTo-DWord {
        param([System.Drawing.Color]$Color)
        [byte[]] $bytes = @($Color.R,$Color.G,$Color.B,$Color.A)
        return [System.BitConverter]::ToUInt32($bytes,0)
    }

    # Apply accent color
    Set-ItemProperty -LiteralPath 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent' -Name 'StartColorMenu'  -Value (ConvertTo-DWord -Color $accentColor) -Type 'DWord' -Force
    Set-ItemProperty -LiteralPath 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent' -Name 'AccentColorMenu' -Value (ConvertTo-DWord -Color $accentColor) -Type 'DWord' -Force
    Set-ItemProperty -LiteralPath 'Registry::HKCU\Software\Microsoft\Windows\DWM' -Name 'AccentColor' -Value (ConvertTo-DWord -Color $accentColor) -Type 'DWord' -Force
} catch {
    Write-Warn "Accent color application failed — continuing..."
}
# ============================================================================
# 12. DEFAULTUSER HIVE TWEAKS
# ============================================================================
Write-Info "Applying DefaultUser hive tweaks..."

$defaultNtUser = "C:\Users\Default\NTUSER.DAT"

if (Test-Path $defaultNtUser) {

    # Mount DefaultUser hive
    reg load HKU\DefaultUser "$defaultNtUser" > $null

    # Disable Copilot for new users
    reg add "HKU\DefaultUser\Software\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f > $null

    # Disable Notepad Store banner
    reg add "HKU\DefaultUser\Software\Microsoft\Notepad" /v ShowStoreBanner /t REG_DWORD /d 0 /f > $null

    # Disable GameDVR
    reg add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f > $null

    # Show file extensions
    reg add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f > $null

    # Hide Task View button
    reg add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f > $null

    # Taskbar alignment left
    reg add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAl /t REG_DWORD /d 0 /f > $null


    # ============================================================================
    # 13. CONTENT DELIVERY MANAGER DEFAULTS (ads, suggestions, bloat)
    # ============================================================================

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


    # ============================================================================
    # 14. KEYBOARD & MOUSE DEFAULTS
    # ============================================================================

    # Enable NumLock by default
    foreach ($root in 'HKU\.DEFAULT','HKU\DefaultUser') {
        reg add "$root\Control Panel\Keyboard" /v InitialKeyboardIndicators /t REG_SZ /d 2 /f > $null
    }

    # Disable mouse acceleration
    reg add "HKU\DefaultUser\Control Panel\Mouse" /v MouseSpeed      /t REG_SZ /d 0 /f > $null
    reg add "HKU\DefaultUser\Control Panel\Mouse" /v MouseThreshold1 /t REG_SZ /d 0 /f > $null
    reg add "HKU\DefaultUser\Control Panel\Mouse" /v MouseThreshold2 /t REG_SZ /d 0 /f > $null


    # ============================================================================
    # 15. SEARCH SUGGESTIONS (Bing in Start)
    # ============================================================================

    reg add "HKU\DefaultUser\Software\Policies\Microsoft\Windows\Explorer" /v DisableSearchBoxSuggestions /t REG_DWORD /d 1 /f > $null


    # ============================================================================
    # 16. TITLEBAR ACCENT COLOR
    # ============================================================================

    reg add "HKU\DefaultUser\Software\Microsoft\Windows\DWM" /v ColorPrevalence /t REG_DWORD /d 0 /f > $null

    # Unmount hive
    reg unload HKU\DefaultUser > $null

} else {
    Write-Warn "Default NTUSER.DAT not found — skipping DefaultUser tweaks."
}

# ============================================================================
# 17. EDGE POLICIES
# ============================================================================
Write-Info "Applying Edge policies..."

# Hide first-run experience
reg add "HKLM\Software\Policies\Microsoft\Edge" /v HideFirstRunExperience /t REG_DWORD /d 1 /f > $null

# Disable background mode
reg add "HKLM\Software\Policies\Microsoft\Edge\Recommended" /v BackgroundModeEnabled /t REG_DWORD /d 0 /f > $null

# Disable Startup Boost
reg add "HKLM\Software\Policies\Microsoft\Edge\Recommended" /v StartupBoostEnabled /t REG_DWORD /d 0 /f > $null

# Block forced update to Chromium Edge
reg add "HKLM\Software\Policies\Microsoft\EdgeUpdate" /v DoNotUpdateToEdgeWithChromium /t REG_DWORD /d 1 /f > $null
# ============================================================================
# 17. EDGE REMOVAL (EU‑ONLY)
# ============================================================================

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
# 18. EXPLORER / SEARCH / CLASSIC CONTEXT MENU / WEB INTEGRATION
# ============================================================================
Write-Info "Applying Explorer tweaks..."

# File Explorer opens to This PC
Set-ItemProperty -LiteralPath 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'LaunchTo' -Type DWord -Value 1

# Hide search box in taskbar
Set-ItemProperty -LiteralPath 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Search' -Name 'SearchboxTaskbarMode' -Type DWord -Value 0

# Remove Edge desktop shortcuts
$edgeLinkUser   = Join-Path $env:USERPROFILE "Desktop\Microsoft Edge.lnk"
$edgeLinkPublic = "C:\Users\Public\Desktop\Microsoft Edge.lnk"
Remove-Item -LiteralPath $edgeLinkUser   -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $edgeLinkPublic -ErrorAction SilentlyContinue

# Enable classic context menu (Win11 → Win10 style)
reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /ve /f > $null

# Disable Recommended section in Explorer Home
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowRecommendedSection /t REG_DWORD /d 0 /f > $null

# Disable cloud files in Explorer Home
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowCloudFilesInHome /t REG_DWORD /d 0 /f > $null


# ============================================================================
# 19. ONEDRIVE FULL REMOVAL
# ============================================================================
Write-Info "Removing OneDrive completely..."

# Kill running OneDrive processes
taskkill /IM OneDrive.exe /F 2>$null

# Remove AppX packages
Get-AppxPackage -AllUsers *OneDrive* | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue

# Uninstall OneDrive via setup.exe (both 32-bit and 64-bit)
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

# Remove OneDrive autorun entry
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v OneDrive /f 2>$null

# Remove OneDrive from Explorer navigation pane
reg add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v System.IsPinnedToNameSpaceTree /t REG_DWORD /d 0 /f 2>$null

# ============================================================================
# 20. EXTENDED PRIVACY / ANTI-AD / ANTI-CLOUD / ANTI-SPOTLIGHT / ANTI-RECALL
# ============================================================================
Write-Info "Applying extended privacy and anti-advertising hardening..."

# Disable suggested apps in Start (25H2)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_IrisRecommendations /t REG_DWORD /d 0 /f > $null

# Disable Online Service Experience Packs
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v AllowOnlineServiceExperience /t REG_DWORD /d 0 /f > $null

# Disable Recall / AI data collection
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsAI" /v DisableAIDataCollection /t REG_DWORD /d 1 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsAI" /v DisableAIRecall /t REG_DWORD /d 1 /f > $null

# Disable Suggested Actions
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform" /v Disabled /t REG_DWORD /d 1 /f > $null

# Disable App Installer suggestions (Store MSIX)
reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v NoUseStoreOpenWith /t REG_DWORD /d 1 /f > $null

# Disable web search in Start (Bing)
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v DisableSearchBoxSuggestions /t REG_DWORD /d 1 /f > $null

# Disable Cloud Content (ads in Settings, Start, lock screen)
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableConsumerFeatures /t REG_DWORD /d 1 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f > $null

# Disable Windows Spotlight everywhere
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures        /t REG_DWORD /d 1 /f > $null
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightOnActionCenter /t REG_DWORD /d 1 /f > $null
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightOnSettings     /t REG_DWORD /d 1 /f > $null
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightOnLockScreen   /t REG_DWORD /d 1 /f > $null

# Disable automatic app reinstall
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableAutomaticAppInstall /t REG_DWORD /d 1 /f > $null

# Extra Clipchamp/Teams removal (fallback)
Get-AppxPackage -AllUsers *Clipchamp* | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
Get-AppxPackage -AllUsers *MSTeams*   | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue

# Disable Windows Backup cloud prompts
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v DisableWindowsBackup /t REG_DWORD /d 1 /f > $null


# ============================================================================
# 21. BLOCK WHATSAPP / MESSENGER / TIKTOK / SPOTIFY RECOMMENDATIONS
# ============================================================================
Write-Info "Blocking app recommendations (WhatsApp, TikTok, Spotify, Messenger)..."

$cdmBlock = "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"

reg add $cdmBlock /v SubscribedContent-353699Enabled /t REG_DWORD /d 0 /f > $null
reg add $cdmBlock /v SubscribedContent-353700Enabled /t REG_DWORD /d 0 /f > $null
reg add $cdmBlock /v PreInstalledAppsEnabled           /t REG_DWORD /d 0 /f > $null
reg add $cdmBlock /v PreInstalledAppsEverEnabled       /t REG_DWORD /d 0 /f > $null

Write-OK "Extended privacy and anti-advertising hardening applied."
# ============================================================================
# 23. APPLICATION INSTALLATION (Chrome, 7-Zip, Notepad++, Discord, Steam)
# ============================================================================

Write-Info "Checking required applications..."

# Helper: detect installed apps via uninstall registry keys
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

# ----------------------------------------------------------------------------
# GOOGLE CHROME
# ----------------------------------------------------------------------------

if (-not (Test-AppInstalled "Google Chrome")) {
    Write-Info "Installing Google Chrome (silent)..."
    $chromeInstaller = Join-Path $env:TEMP 'chrome_installer.exe'

    try {
        Invoke-WebRequest -Uri "https://dl.google.com/chrome/install/latest/chrome_installer.exe" `
            -OutFile $chromeInstaller -UseBasicParsing -ErrorAction Stop

        Start-Process -FilePath $chromeInstaller -ArgumentList "/silent","/install" -Wait -ErrorAction Stop
        Write-OK "Google Chrome installed."

        # Set Chrome as default browser
        Write-Info "Setting Chrome as default browser..."
        $chromeExe = Join-Path $env:ProgramFiles 'Google\Chrome\Application\chrome.exe'
        if (Test-Path $chromeExe) {
            Start-Process -FilePath $chromeExe -ArgumentList '--make-default-browser'
            Write-OK "Chrome set as default browser."
        } else {
            Write-Warn "Chrome executable not found after installation."
        }

    } catch {
        Write-Err "Failed to install Google Chrome: $($_.Exception.Message)"
    }
} else {
    Write-Info "Google Chrome already installed — skipping."
}

# ----------------------------------------------------------------------------
# 7-ZIP
# ----------------------------------------------------------------------------

if (-not (Test-AppInstalled "7-Zip")) {
    Write-Info "Installing 7-Zip (silent)..."
    $zipInstaller = Join-Path $env:TEMP '7zip_installer.exe'

    try {
        Invoke-WebRequest -Uri "https://www.7-zip.org/a/7z2408-x64.exe" `
            -OutFile $zipInstaller -UseBasicParsing -ErrorAction Stop

        Start-Process -FilePath $zipInstaller -ArgumentList "/S" -Wait -ErrorAction Stop
        Write-OK "7-Zip installed."

    } catch {
        Write-Err "Failed to install 7-Zip: $($_.Exception.Message)"
    }
} else {
    Write-Info "7-Zip already installed — skipping."
}

# ----------------------------------------------------------------------------
# NOTEPAD++
# ----------------------------------------------------------------------------

if (-not (Test-AppInstalled "Notepad++")) {
    Write-Info "Installing Notepad++ (silent)..."

    $npInstaller = Join-Path $env:TEMP 'npp_installer.exe'
    $apiUrl = "https://api.github.com/repos/notepad-plus-plus/notepad-plus-plus/releases/latest"

    try {
        Write-Info "Fetching latest Notepad++ release info from GitHub API..."
        $headers = @{ "User-Agent" = "Mozilla/5.0" }

        $release = Invoke-RestMethod -Uri $apiUrl -Headers $headers -ErrorAction Stop

        $asset = $release.assets |
            Where-Object { $_.name -match "Installer.*x64.*\.exe$" } |
            Select-Object -First 1

        if (-not $asset) { throw "Could not locate Notepad++ installer in GitHub API response." }

        $nppUrl = $asset.browser_download_url
        Write-Info "Downloading Notepad++ from: $nppUrl"

        Start-BitsTransfer -Source $nppUrl -Destination $npInstaller -ErrorAction Stop

        Start-Process -FilePath $npInstaller -ArgumentList "/S" -Wait -ErrorAction Stop
        Write-OK "Notepad++ installed."

    } catch {
        Write-Err "Failed to install Notepad++: $($_.Exception.Message)"
    }
} else {
    Write-Info "Notepad++ already installed — skipping."
}

# ----------------------------------------------------------------------------
# DISCORD
# ----------------------------------------------------------------------------

if (-not (Test-AppInstalled "Discord")) {
    Write-Info "Installing Discord (silent)..."

    $discordInstaller = Join-Path $env:TEMP 'discord_installer.exe'
    $discordUrl = "https://discord.com/api/download?platform=win"

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $headers = @{ "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" }

        Invoke-WebRequest -Uri $discordUrl -OutFile $discordInstaller -Headers $headers -ErrorAction Stop

        Start-Process -FilePath $discordInstaller -ArgumentList "/S" -Wait -ErrorAction Stop
        Write-OK "Discord installed."

    } catch {
        Write-Err "Failed to install Discord: $($_.Exception.Message)"
    }
} else {
    Write-Info "Discord already installed — skipping."
}

# ----------------------------------------------------------------------------
# STEAM
# ----------------------------------------------------------------------------

if (-not (Test-AppInstalled "Steam")) {
    Write-Info "Installing Steam (silent)..."

    $steamInstaller = Join-Path $env:TEMP 'steam_installer.exe'
    $steamUrl = "https://cdn.cloudflare.steamstatic.com/client/installer/SteamSetup.exe"

    try {
        Invoke-WebRequest -Uri $steamUrl -OutFile $steamInstaller -UseBasicParsing -ErrorAction Stop

        Start-Process -FilePath $steamInstaller -ArgumentList "/S" -Wait -ErrorAction Stop
        Write-OK "Steam installed."

    } catch {
        Write-Err "Failed to install Steam: $($_.Exception.Message)"
    }
} else {
    Write-Info "Steam already installed — skipping."
}

Write-OK "Application installation and configuration complete."
# ============================================================================
# 24. TASKBAR CACHE CLEANUP
# ============================================================================
Write-Host "Cleaning taskbar cache..."

$taskbarCache = Join-Path $env:LOCALAPPDATA "Microsoft\Windows\Explorer"

try {
    # Stop Explorer
    $expl = Get-Process -Name explorer -ErrorAction SilentlyContinue
    if ($expl) {
        Write-Host "Stopping Explorer..."
        $expl | Stop-Process -Force -ErrorAction Stop

        # Wacht tot Explorer volledig gestopt is
        $timeout = 10
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while ((Get-Process -Name explorer -ErrorAction SilentlyContinue) -ne $null -and $sw.Elapsed.TotalSeconds -lt $timeout) {
            Start-Sleep -Milliseconds 250
        }
    }

    # Verwijder taskbar cache bestanden
    if (Test-Path $taskbarCache) {
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


    # ============================================================================
    # 25. EXPLORER SILENT RESTART
    # ============================================================================
    Write-Host "Restarting Explorer silently..."

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

    Write-Host "Explorer restarted successfully (silent)."

} catch {
    Write-Error "Taskbar cleanup failed: $($_.Exception.Message)"
}


# ============================================================================
# 26. AUTOMATIC REBOOT WITH BANNER
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

