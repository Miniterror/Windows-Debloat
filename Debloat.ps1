# 0. ADMIN CHECK, LOGGING, HELPERS
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

$EU_GeoIDs = @(4,8,20,28,31,40,56,70,100,112,124,176,191,196,203,208,233,246,250,268,276,300,348,352,372,380,428,440,442,470,498,499,528,616,620,642,643,688,703,705,724,752,804,807)

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
    "*Clipchamp*","*WindowsWidgets*","*WebExperience*"
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

# 4. POWER PLAN & POWER SETTINGS
# ============================================================================
Write-Info "Applying custom power plan settings..."

# Get active power scheme
$ActiveScheme = (powercfg /getactivescheme) -replace '.*GUID: ([a-f0-9\-]+).*','$1'

#Turn off display -> Never (0 minutes)
powercfg /setdcvalueindex $ActiveScheme SUB_VIDEO VIDEOIDLE 0
powercfg /setacvalueindex $ActiveScheme SUB_VIDEO VIDEOIDLE 0

#Sleep -> Never (0 minutes)
powercfg /setdcvalueindex $ActiveScheme SUB_SLEEP STANDBYIDLE 0
powercfg /setacvalueindex $ActiveScheme SUB_SLEEP STANDBYIDLE 0

#Disable Fast Startup
Write-Info "Disabling Fast Startup..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 0 /f > $null

#Power button action -> Shut down (value 3)
# Battery (DC) and Plugged in (AC)
powercfg /setdcvalueindex $ActiveScheme SUB_BUTTONS PBUTTONACTION 3
powercfg /setacvalueindex $ActiveScheme SUB_BUTTONS PBUTTONACTION 3

#Lid close action -> Do nothing (value 0)
powercfg /setdcvalueindex $ActiveScheme SUB_BUTTONS LIDACTION 0
powercfg /setacvalueindex $ActiveScheme SUB_BUTTONS LIDACTION 0

# Apply changes
powercfg /setactive $ActiveScheme

Write-OK "Custom power plan settings applied."

# 5. PRIVACY, TELEMETRY, DIAGNOSTICS, CONTENT DELIVERY
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

Write-Host "[INFO] Applying O&O ShutUp10++ Recommended Tweaks..."
# Disable Tailored Experiences
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f > $null

# Disable Location Tracking
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v DisableLocation /t REG_DWORD /d 1 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v UploadUserActivities /t REG_DWORD /d 0 /f > $null

$AppPrivacy = "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy"

$permissions = @(
    "LetAppsAccessCamera","LetAppsAccessContacts","LetAppsAccessCalendar",
    "LetAppsAccessEmail","LetAppsAccessTasks","LetAppsAccessPhoneCallHistory","LetAppsAccessRadios",
    "LetAppsAccessMotion","LetAppsAccessFileSystem","LetAppsAccessPicturesLibrary","LetAppsAccessVideosLibrary",
    "LetAppsAccessDocumentsLibrary","LetAppsAccessUnpairedDevices","LetAppsAccessBluetooth",
	"LetAppsAccessUserDictionary","LetAppsAccessPhoneCalls","LetAppsAccessVoiceActivation","LetAppsAccessSensors"
)

foreach ($perm in $permissions) {
    reg add $AppPrivacy /v $perm /t REG_DWORD /d 2 /f > $null
}

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

# Disable Automatic App Install
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableAutomaticAppInstall /t REG_DWORD /d 1 /f > $null

# Disable background apps
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f > $null

# Disable Cloud Clipboard
reg add "HKCU\Software\Microsoft\Clipboard" /v CloudClipboard /t REG_DWORD /d 0 /f > $null

Write-Host "[OK] O&O Recommended Tweaks Applied."
Write-Info "Applying extended privacy and anti-advertising hardening..."

# Disable Voice Access
reg add "HKLM\Software\Policies\Microsoft\Accessibility\VoiceAccess" /v EnableVoiceAccess /t REG_DWORD /d 0 /f > $null

# Suggested apps in Start (25H2)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_IrisRecommendations /t REG_DWORD /d 0 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\SmartActionPlatform" /v DisableSmartActions /t REG_DWORD /d 1 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform" /v Disabled /t REG_DWORD /d 1 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v SettingsExperienceHost_ShowRecommendations /t REG_DWORD /d 0 /f > $null

# Online Service Experience Packs
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v AllowOnlineServiceExperience /t REG_DWORD /d 0 /f > $null

# Recall / AI
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsAI" /v DisableAIDataCollection /t REG_DWORD /d 1 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsAI" /v DisableAIRecall /t REG_DWORD /d 1 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsAI" /v DisableAIDataCollectionUpload /t REG_DWORD /d 1 /f > $null

# App Installer suggestions (Store MSIX)
reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v NoUseStoreOpenWith /t REG_DWORD /d 1 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\AppInstaller" /v EnableAppInstallerAutoUpdate /t REG_DWORD /d 0 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\AppInstaller" /v EnableExperimentalFeatures /t REG_DWORD /d 0 /f > $null

# Web search in Start (Bing)
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v DisableSearchBoxSuggestions /t REG_DWORD /d 1 /f > $null

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

# Windows Backup cloud prompts
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v DisableWindowsBackup /t REG_DWORD /d 1 /f > $null

# Disable Get Started / Privacy Experience
reg add "HKLM\Software\Policies\Microsoft\Windows\OOBE" /v DisablePrivacyExperience /t REG_DWORD /d 1 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\OOBE" /v DisableReinstallRecommendedApps /t REG_DWORD /d 1 /f > $null

Write-OK "Extended privacy and anti-advertising hardening applied."

# 6. WINDOWS UPDATE, DRIVERS, ONEDRIVE, DELIVERY OPTIMIZATION
# ============================================================================

Write-Info "Configuring Windows Update & driver policies..."

# Driver updates via Windows Update uitschakelen
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v ExcludeWUDriversInQualityUpdate /t REG_DWORD /d 1 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\DriverSearching" /v DontSearchWindowsUpdate /t REG_DWORD /d 1 /f > $null

# OneDrive sync uitschakelen
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f > $null

# Sync settings uitschakelen
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync" /v SyncSettings /t REG_DWORD /d 0 /f > $null

# 7. COPILOT, WIDGETS, TASKBAR, START, LAYOUT XML FIXES
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

# Taskbar cleanup
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v StoreAppsOnTaskbar /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackDocs /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackProgs /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSyncProviderNotifications /t REG_DWORD /d 0 /f > $null

# Taskbar alignment left
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAl /t REG_DWORD /d 0 /f > $null

# Clear Taskbar pins folder
$taskbarPins = "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"

if (Test-Path $taskbarPins) {
    Write-Info "Clearing taskbar pins..."
    try {
        Get-ChildItem $taskbarPins -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    } catch {}
} else {
    Write-Info "Taskbar pins folder not found, skipping..."
}

# Re-pin File Explorer safely
$explorerPath = "C:\Windows\explorer.exe"
$verb = "taskbarpin"

try {
    $shell = New-Object -ComObject Shell.Application -ErrorAction Stop
    $folder = $shell.Namespace((Split-Path $explorerPath))
    $item = $folder.ParseName((Split-Path $explorerPath -Leaf))

    if ($item.Verbs() | Where-Object { $_.Name.Replace("&","") -eq $verb }) {
        Write-Info "Pinning File Explorer to taskbar..."
        $item.InvokeVerb($verb)
    } else {
        Write-Info "Explorer already pinned or verb unavailable, skipping..."
    }
} catch {
    Write-Info "Unable to pin Explorer (COM not available), skipping..."
}

# List of tasks to disable
Write-Information "Disabling Shell and layout-related scheduled tasks..."
$tasks = @(
    "\Microsoft\Windows\Shell\TaskbarLayoutModification",
    "\Microsoft\Windows\Shell\FamilySafetyMonitor",
    "\Microsoft\Windows\Shell\FamilySafetyRefreshTask",
    "\Microsoft\Windows\Shell\FamilySafetyUpload",
    "\Microsoft\Windows\Shell\CreateObjectTask",
    "\Microsoft\Windows\Shell\UpdateUserPictureTask",
    "\Microsoft\Windows\Shell\StartTileData",
    "\Microsoft\Windows\Shell\LayoutModification"
)

foreach ($task in $tasks) {

    # Split path and name for PowerShell cmdlets
    $taskPath = ($task.Substring(0, $task.LastIndexOf("\") + 1))
    $taskName = ($task.Substring($task.LastIndexOf("\") + 1))

    try {
        # Try to retrieve the task
        $scheduledTask = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop
    }
    catch {
        Write-Information "Task not found: $task (skipping)"
        continue
    }

    # Check if already disabled
    if ($scheduledTask.State -eq "Disabled") {
        Write-Information "Already disabled: $task"
        continue
    }

    try {
        Write-Information "Disabling task: $task"
        Disable-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop
        Write-Information "Successfully disabled: $task"
    }
    catch {
        Write-Information ("Failed to disable {0}: {1}" -f $task, $_.Exception.Message)
    }
}

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

        # Take ownership and grant rights
        takeown /F $file /A > $null 2>&1
        icacls $file /grant administrators:F /T > $null 2>&1

        # Read XML as a single string to avoid breaking formatting
        $content = Get-Content $file -Raw -ErrorAction SilentlyContinue

        if ($content) {
            $content = $content -replace 'LinkedIn', ''
            $content = $content -replace 'Microsoft.WindowsStore', ''

            Set-Content -Path $file -Value $content -Force -Encoding UTF8

            Write-Remove "Sanitized layout: $file"
        }
    }
}

# Taskbar layout laten rebuilden
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" /f > $null 2>&1

# File Explorer naar This PC
Set-ItemProperty -LiteralPath 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'LaunchTo' -Type DWord -Value 1

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

Write-Info "Applying additional performance, privacy and Explorer tweaks..."

# Disable SysMain (Superfetch)
Write-Info "Disabling SysMain service..."
Stop-Service SysMain -Force -ErrorAction SilentlyContinue
Set-Service SysMain -StartupType Disabled

# Disable Diagnostics Tracking service (DiagTrack)
Write-Info "Disabling Diagnostics Tracking service..."
Stop-Service DiagTrack -Force -ErrorAction SilentlyContinue
Set-Service DiagTrack -StartupType Disabled

# Block Microsoft Store automatic reinstallations
Write-Info "Blocking Microsoft Store automatic reinstallations..."
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v AutoDownload /t REG_DWORD /d 2 /f > $null
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v DisableOSUpgrade /t REG_DWORD /d 1 /f > $null
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v DisableStoreApps /t REG_DWORD /d 1 /f > $null

# Disable 'Recent files' and 'Frequent folders' in Explorer
Write-Info "Disabling recent/frequent items in Explorer..."
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v ShowRecent /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v ShowFrequent /t REG_DWORD /d 0 /f > $null

# Disable 'Recently added apps' in Start menu
Write-Info "Disabling recently added apps in Start..."
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_NotifyNewApps /t REG_DWORD /d 0 /f > $null

# Fully disable web search in Start menu
Write-Info "Disabling web search in Start..."
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f > $null

# Disable SMBv1 (legacy, insecure protocol)
Write-Info "Disabling SMBv1 protocol..."
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue

# Disable Xbox Game Bar and Game DVR
Write-Output "Disabling Xbox Game Bar and Game DVR..."

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameBar" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameBar" `
    -Name "AllowGameBar" -Value 0 -Type DWord -Force

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" `
    -Name "AllowGameDVR" -Value 0 -Type DWord -Force

New-Item -Path "HKCU:\Software\Microsoft\GameBar" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" `
    -Name "ShowStartupPanel" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" `
    -Name "GamePanelStartupTipIndex" -Value 3 -Type DWord -Force

New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" `
    -Name "AppCaptureEnabled" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" `
    -Name "GameDVR_Enabled" -Value 0 -Type DWord -Force

New-Item -Path "HKCU:\Software\Microsoft\GameBar" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" `
    -Name "UseNexusForGameBarEnabled" -Value 0 -Type DWord -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" `
    -Name "AllowAutoGameMode" -Value 0 -Type DWord -Force

Write-Output "Xbox Game Bar has been disabled."

# 8. VBS / CORE ISOLATION / SVCHOST SPLIT
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

# 9. LOCALE, TIMEZONE, LANGUAGE
# ============================================================================

Write-Info "Setting timezone and Dutch regional formats..."

# Timezone
tzutil /s "W. Europe Standard Time"

# Keep English system language
Set-WinSystemLocale en-US

# Keep only English as user language (no extra inputs)
$LangList = New-WinUserLanguageList en-US
$LangList[0].Handwriting = $false
Set-WinUserLanguageList $LangList -Force

# Set Dutch regional culture (date/time/number formatting)
Set-Culture nl-NL
Set-WinHomeLocation -GeoId 176  # Netherlands

# Force Dutch date/time formats
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sShortDate -Value "dd-MM-yyyy"
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sLongDate -Value "dddd d MMMM yyyy"
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sTimeFormat -Value "HH:mm:ss"
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sShortTime -Value "HH:mm"
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name iTime -Value 1
Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name iDate -Value 1

Write-Info "Forcing time synchronization..."

Stop-Service w32time
Start-Service w32time
w32tm /resync /force

# 10. THEME / ACCENT COLOR
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

# 11. EDGE POLICIES + EU-CONDITIONAL EDGE REMOVAL
# ============================================================================

Write-Info "Starting Edge neutralization for EU build..."

if ($IsEU) {
    reg add "HKLM\Software\Policies\Microsoft\Edge" /v HideFirstRunExperience /t REG_DWORD /d 1 /f > $null
    reg add "HKLM\Software\Policies\Microsoft\Edge" /v DefaultBrowserSettingEnabled /t REG_DWORD /d 0 /f > $null
    reg add "HKLM\Software\Policies\Microsoft\Edge\Recommended" /v BackgroundModeEnabled /t REG_DWORD /d 0 /f > $null
    reg add "HKLM\Software\Policies\Microsoft\Edge\Recommended" /v StartupBoostEnabled /t REG_DWORD /d 0 /f > $null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /v UpdateDefault /t REG_DWORD /d 0 /f > $null
    reg add "HKLM\SOFTWARE\Microsoft\EdgeUpdate" /v UpdateDefault /t REG_DWORD /d 0 /f > $null

    foreach ($svc in @("edgeupdate", "edgeupdatem")) {
        $service = Get-Service $svc -ErrorAction SilentlyContinue
        if ($service) {
            Stop-Service $svc -Force -ErrorAction SilentlyContinue
            Set-Service $svc -StartupType Disabled
        }
    }

    schtasks /Delete /TN "\Microsoft\EdgeUpdate\MicrosoftEdgeUpdateTaskMachineCore" /F > $null 2>&1
    schtasks /Delete /TN "\Microsoft\EdgeUpdate\MicrosoftEdgeUpdateTaskMachineUA" /F > $null 2>&1

    $edgeShortcuts = @(
        "$env:PUBLIC\Desktop\Microsoft Edge.lnk",
        "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk",
        "$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk"
    )

    foreach ($shortcut in $edgeShortcuts) {
        if (Test-Path $shortcut) {
            Remove-Item $shortcut -Force -ErrorAction SilentlyContinue
        }
    }

    # Remove taskbar pin via registry
    $taskbarReg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband"
    if (Test-Path $taskbarReg) {
        Remove-ItemProperty -Path $taskbarReg -Name "Favorites" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $taskbarReg -Name "FavoritesResolve" -ErrorAction SilentlyContinue
    }

    $srpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers"
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers" /v DefaultLevel /t REG_DWORD /d 0x40000 /f > $null

    $pathsToBlock = @(
        "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        "C:\Program Files\Microsoft\Edge\Application\msedge.exe"
    )

    $ruleId = 10000
    foreach ($path in $pathsToBlock) {
        if (Test-Path $path) {
            $ruleKey = "$srpPath\0\Paths\$ruleId"
            New-Item -Path $ruleKey -Force | Out-Null
            New-ItemProperty -Path $ruleKey -Name "ItemData" -Value $path -PropertyType String -Force | Out-Null
            New-ItemProperty -Path $ruleKey -Name "SaferFlags" -Value 0 -PropertyType DWord -Force | Out-Null
            $ruleId++
        }
    }

    # This assumes Chrome; replace with your browser if needed.
    $assoc = @(
        "http", "https", "html", "htm", "pdf"
    )

    foreach ($ext in $assoc) {
        reg add "HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$ext\UserChoice" `
            /v ProgId /t REG_SZ /d "ChromeHTML" /f > $null
    }

    Write-OK "Edge neutralization completed. Edge is now hidden, blocked, and non-functional."

} else {
    Write-Info "Non-EU build detected — skipping Edge neutralization."
}

# 12. ONEDRIVE FULL REMOVAL
# ============================================================================
Write-Info "Checking for OneDrive installation..."

# Detect OneDrive presence
$OneDriveInstalled = (
    (Get-AppxPackage -AllUsers *OneDrive* -ErrorAction SilentlyContinue) -or
    (Test-Path "$env:SystemRoot\SysWOW64\OneDriveSetup.exe") -or
    (Test-Path "$env:SystemRoot\System32\OneDriveSetup.exe") -or
    (Test-Path "$env:LOCALAPPDATA\Microsoft\OneDrive") -or
    (Test-Path "$env:PROGRAMDATA\Microsoft OneDrive") -or
    (Test-Path "$env:USERPROFILE\OneDrive")
)

if (-not $OneDriveInstalled) {
    Write-Info "OneDrive is not installed. Skipping removal section."
    return
}

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

# 13. APPLICATION INSTALLATION (Optimized)
# =====================================================================

function Write-Info { param($m) Write-Host "[INFO]  $m" -ForegroundColor Cyan }
function Write-OK   { param($m) Write-Host "[OK]    $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Write-Err  { param($m) Write-Host "[ERROR] $m" -ForegroundColor Red }

Write-Info "Checking required applications..."

# =====================================================================
# Helper: Check if an app exists in uninstall registry
# =====================================================================
function Test-AppInstalled {
    param([string]$Name)

    $paths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($path in $paths) {
        try {
            $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                if ($item.DisplayName -and $item.DisplayName -like "*$Name*") {
                    return $true
                }
            }
        } catch {}
    }
    return $false
}

# =====================================================================
# Helper: Download + Install EXE/MSI
# =====================================================================
function Install-FromUrl {
    param(
        [string]$Name,
        [string]$Url,
        [string]$Arguments = "/S"
    )

    if (Test-AppInstalled $Name) {
        Write-Info "$Name already installed — skipping."
        return
    }

    Write-Info "Installing $Name..."

    $installer = Join-Path $env:TEMP "$($Name.Replace(' ','_')).exe"

    try {
        Invoke-WebRequest -Uri $Url -OutFile $installer -UseBasicParsing -ErrorAction Stop
        Start-Process -FilePath $installer -ArgumentList $Arguments -Wait -ErrorAction Stop
        Write-OK "$Name installed."
    }
    catch {
        Write-Err "Failed to install ${Name}: $($_.Exception.Message)"
    }

    if (Test-Path $installer) { Remove-Item $installer -Force -ErrorAction SilentlyContinue }
}

# =====================================================================
# GOOGLE CHROME
# =====================================================================
Install-FromUrl -Name "Google Chrome" `
    -Url "https://dl.google.com/chrome/install/latest/chrome_installer.exe" `
    -Arguments "/silent /install"

# =====================================================================
# 7-ZIP
# =====================================================================
Install-FromUrl -Name "7-Zip" `
    -Url "https://www.7-zip.org/a/7z2408-x64.exe" `
    -Arguments "/S"

# =====================================================================
# NOTEPAD++
# =====================================================================
if (-not (Test-AppInstalled "Notepad++")) {
    Write-Info "Installing Notepad++..."

    $npInstaller = Join-Path $env:TEMP 'npp_installer.exe'
    $apiUrl = "https://api.github.com/repos/notepad-plus-plus/notepad-plus-plus/releases/latest"

    try {
        $headers = @{ "User-Agent" = "Mozilla/5.0" }
        $release = Invoke-RestMethod -Uri $apiUrl -Headers $headers -ErrorAction Stop

        $asset = $release.assets |
            Where-Object { $_.name -match "Installer.*x64.*\.exe$" } |
            Select-Object -First 1

        Start-BitsTransfer -Source $asset.browser_download_url -Destination $npInstaller -ErrorAction Stop
        Start-Process -FilePath $npInstaller -ArgumentList "/S" -Wait -ErrorAction Stop

        Write-OK "Notepad++ installed."
    }
    catch {
        Write-Err "Failed to install Notepad++: $($_.Exception.Message)"
    }

    if (Test-Path $npInstaller) { Remove-Item $npInstaller -Force }
}
else {
    Write-Info "Notepad++ already installed — skipping."
}

# =====================================================================
# DISCORD
# =====================================================================
Install-FromUrl -Name "Discord" `
    -Url "https://discord.com/api/download?platform=win" `
    -Arguments "/S"

# =====================================================================
# STEAM
# =====================================================================
Install-FromUrl -Name "Steam" `
    -Url "https://cdn.cloudflare.steamstatic.com/client/installer/SteamSetup.exe" `
    -Arguments "/S"

# =====================================================================
# PUTTY
# =====================================================================
if (-not (Test-AppInstalled "PuTTY")) {
    Write-Info "Installing PuTTY..."

    $puttyInstaller = Join-Path $env:TEMP 'putty.msi'
    $puttyUrl = "https://the.earth.li/~sgtatham/putty/0.81/w64/putty-64bit-0.81-installer.msi"

    try {
        Invoke-WebRequest -Uri $puttyUrl -OutFile $puttyInstaller -ErrorAction Stop
        Start-Process "msiexec.exe" -ArgumentList "/i `"$puttyInstaller`" /qn" -Wait
        Write-OK "PuTTY installed."
    }
    catch {
        Write-Err "Failed to install PuTTY: $($_.Exception.Message)"
    }

    if (Test-Path $puttyInstaller) { Remove-Item $puttyInstaller -Force }
}
else {
    Write-Info "PuTTY already installed — skipping."
}

# =====================================================================
# HWiNFO64 (Winget)
# =====================================================================
if (-not (Test-AppInstalled "HWiNFO64")) {
    Write-Info "Installing HWiNFO64..."
    try {
        winget install --id REALiX.HWiNFO --source winget --silent --accept-package-agreements --accept-source-agreements
        Write-OK "HWiNFO64 installed."
    }
    catch {
        Write-Err "Failed to install HWiNFO64: $($_.Exception.Message)"
    }
}
else {
    Write-Info "HWiNFO64 already installed — checking for updates..."
    try {
        $upgrade = winget upgrade --id REALiX.HWiNFO --source winget --silent --accept-package-agreements --accept-source-agreements
        if ($upgrade -match "No available upgrade") {
            Write-OK "HWiNFO64 is already up to date."
        } else {
            Write-OK "HWiNFO64 upgraded."
        }
    }
    catch {
        Write-Err "Failed to upgrade HWiNFO64: $($_.Exception.Message)"
    }
}

# =====================================================================
# ADB tools (C:\ADB)
# =====================================================================
Write-Info "Checking Android Platform Tools (ADB)..."

$adbUrl   = "https://dl.google.com/android/repository/platform-tools-latest-windows.zip"
$zipPath  = "$env:TEMP\platform-tools.zip"
$tempPath = "$env:TEMP\platform-tools-temp"
$destPath = "C:\ADB"

if (Test-Path "$destPath\adb.exe") {
    Write-Info "ADB already installed — skipping."
}
else {
    try {
        Invoke-WebRequest -Uri $adbUrl -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
        if (Test-Path $tempPath) { Remove-Item $tempPath -Recurse -Force }
        if (-not (Test-Path $destPath)) { New-Item -ItemType Directory -Path $destPath | Out-Null }

        Expand-Archive -Path $zipPath -DestinationPath $tempPath -Force
        Move-Item -Path "$tempPath\platform-tools\*" -Destination $destPath -Force

        Remove-Item $zipPath -Force
        Remove-Item $tempPath -Recurse -Force

        Write-OK "ADB installed into $destPath."
    }
    catch {
        Write-Err "ADB installation failed: $($_.Exception.Message)"
    }
}

# =====================================================================
# Lenovo Legion Toolkit
# =====================================================================
if (-not (Test-AppInstalled "Lenovo Legion Toolkit")) {
    Write-Info "Installing Lenovo Legion Toolkit..."

    $apiUrl = "https://api.github.com/repos/BartoszCichecki/LenovoLegionToolkit/releases/latest"
    $release = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing
    $asset = $release.assets | Where-Object { $_.name -like "*.exe" } | Select-Object -First 1

    $installerPath = "$env:TEMP\$($asset.name)"

    try {
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $installerPath -UseBasicParsing
        Start-Process -FilePath $installerPath -ArgumentList "/VERYSILENT /NORESTART"
        Write-OK "Lenovo Legion Toolkit installation started."

        Start-Sleep -Seconds 15
        Remove-Item $installerPath -Force
    }
    catch {
        Write-Err "Failed to install Lenovo Legion Toolkit: $($_.Exception.Message)"
    }
}
else {
    Write-Info "Lenovo Legion Toolkit already installed — skipping."
}

# =====================================================================
# EPIC GAMES LAUNCHER
# =====================================================================
if (-not (Test-AppInstalled "Epic Games Launcher")) {
    Write-Info "Installing Epic Games Launcher..."

    $epicInstaller = Join-Path $env:TEMP "EpicInstaller.msi"
    $epicUrl = "https://launcher-public-service-prod06.ol.epicgames.com/launcher/api/installer/download/EpicGamesLauncherInstaller.msi"

    try {
        Invoke-WebRequest -Uri $epicUrl -OutFile $epicInstaller -UseBasicParsing -ErrorAction Stop
        Start-Process "msiexec.exe" -ArgumentList "/i `"$epicInstaller`" /qn" -Wait -ErrorAction Stop
        Write-OK "Epic Games Launcher installed."
    }
    catch {
        Write-Err "Failed to install Epic Games Launcher: $($_.Exception.Message)"
    }

    if (Test-Path $epicInstaller) { Remove-Item $epicInstaller -Force }
}
else {
    Write-Info "Epic Games Launcher already installed — skipping."
}

# 14. DEFAULT WALLPAPER
# ============================================================================
Write-Info "Setting custom wallpaper..."

# Define paths
$WallpaperUrl  = "https://wallpapercave.com/wp/wp10423643.png"
$WallpaperPath = "$env:PUBLIC\Pictures\CustomWallpaper.jpg"
$WallpaperPng  = "$env:PUBLIC\Pictures\CustomWallpaper.png"

# Download the image
Invoke-WebRequest -Uri $WallpaperUrl -OutFile $WallpaperPath -UseBasicParsing

# Convert JPEG to PNG
Add-Type -AssemblyName System.Drawing
$image = [System.Drawing.Image]::FromFile($WallpaperPath)
$image.Save($WallpaperPng, [System.Drawing.Imaging.ImageFormat]::Png)
$image.Dispose()

# Ensure Windows doesn't compress the wallpaper
reg add "HKCU\Control Panel\Desktop" /v JPEGImportQuality /t REG_DWORD /d 100 /f > $null

# Set wallpaper style (10 = Fill)
reg add "HKCU\Control Panel\Desktop" /v WallpaperStyle /t REG_SZ /d 10 /f > $null
reg add "HKCU\Control Panel\Desktop" /v TileWallpaper /t REG_SZ /d 0 /f > $null

# Apply wallpaper using SystemParametersInfo
Add-Type @"
using System.Runtime.InteropServices;
public class Wallpaper {
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
}
"@
[Wallpaper]::SystemParametersInfo(20, 0, $WallpaperPng, 3)

Write-OK "Custom wallpaper applied with full quality (PNG)."

# 15. TASKBAR CACHE CLEANUP + EXPLORER RESTART
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

    # Fully silent Explorer restart (no window opens)
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

Write-Host "Removing leftover system folders..." -ForegroundColor Cyan

# Remove the simple folders
$folders = @(
    "C:\inetpub",
    "C:\PerfLogs"
)

foreach ($folder in $folders) {
    if (Test-Path $folder) {
        try {
            Remove-Item $folder -Recurse -Force -ErrorAction Stop
            Write-Host "Removed $folder" -ForegroundColor Green
        }
        catch {
            Write-Host "Could not remove ${folder}: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

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




