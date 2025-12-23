function Write-Info($msg)    { Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Write-OK($msg)      { Write-Host "[ OK ]  $msg" -ForegroundColor Green }
function Write-Remove($msg)  { Write-Host "[DEL]  $msg" -ForegroundColor Magenta }

$Desktop = [Environment]::GetFolderPath("Desktop")
$LogFile = Join-Path $Desktop "debloat.log"
Start-Transcript -Path $LogFile -Append
Write-Info "Debloat started at $(Get-Date)"

function Remove-AppPackages {
    param ([string[]] $Patterns)
    foreach ($pattern in $Patterns) {
        Write-Info "Searching for: $pattern"
        Get-AppxPackage -AllUsers | Where-Object { $_.Name -like $pattern } | ForEach-Object {
            Write-Remove "Removing AppxPackage: $($_.Name)"
            Remove-AppxPackage -Package $_.PackageFullName -ErrorAction SilentlyContinue
        }
        Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -like $pattern } | ForEach-Object {
            Write-Remove "Removing Provisioned: $($_.PackageName)"
            Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction SilentlyContinue
        }
    }
}

Remove-AppPackages -Patterns @(
    "Microsoft.XboxApp*","Microsoft.Xbox.TCUI*","Microsoft.XboxGameOverlay*","Microsoft.XboxGamingOverlay*",
    "Microsoft.XboxIdentityProvider*","Microsoft.XboxSpeechToTextOverlay*","Microsoft.GamingApp*",
    "Microsoft.Microsoft3DViewer*","Microsoft.MixedReality.Portal*","Microsoft.SkypeApp*",
    "Microsoft.MicrosoftSolitaireCollection*","Microsoft.GetHelp*","Microsoft.Getstarted*",
    "Microsoft.ZuneMusic*","Microsoft.ZuneVideo*","Microsoft.People*","Microsoft.WindowsMaps*",
    "Microsoft.BingWeather*","Microsoft.BingNews*","Microsoft.News*","Microsoft.Todos*",
    "Microsoft.WindowsFeedbackHub*","Microsoft.WindowsSoundRecorder*","Microsoft.MicrosoftStickyNotes*",
    "Microsoft.OutlookForWindows*","Microsoft.PowerAutomateDesktop*","Microsoft.WindowsNotepad*"
)

reg add "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f > $null
Remove-AppPackages -Patterns @("MicrosoftWindows.Client.WebExperience*")

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v StoreAppsOnTaskbar /t REG_DWORD /d 0 /f > $null

$taskbarPins = "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
if (Test-Path $taskbarPins) { Get-ChildItem $taskbarPins | Remove-Item -Force -ErrorAction SilentlyContinue }

reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v DisableLocation /t REG_DWORD /d 1 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f > $null
reg add "HKCU\Software\Microsoft\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f > $null
reg add "HKCU\Software\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v UploadUserActivities /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Clipboard" /v CloudClipboard /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SoftLandingEnabled /t REG_DWORD /d 0 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v ExcludeWUDriversInQualityUpdate /t REG_DWORD /d 1 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\DriverSearching" /v DontSearchWindowsUpdate /t REG_DWORD /d 1 /f > $null
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f > $null

$privacyKeys = @(
    "LetAppsAccessMotion","LetAppsAccessBluetooth","LetAppsAccessDocumentsLibrary",
    "LetAppsAccessPicturesLibrary","LetAppsAccessVideosLibrary","LetAppsAccessFileSystem",
    "LetAppsAccessUnpairedDevices","LetAppsAccessUserDictionary","LetAppsAccessPhoneCallHistory",
    "LetAppsAccessPhoneCalls","LetAppsAccessVoiceActivation","LetAppsAccessRadios","LetAppsAccessSensors"
)
foreach ($key in $privacyKeys) {
    reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v $key /t REG_DWORD /d 2 /f > $null
}

reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync" /v SyncSettings /t REG_DWORD /d 0 /f > $null
reg add "HKLM\Software\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f > $null
reg add "HKLM\Software\Microsoft\WcmSvc\wifinetworkmanager\config" /v AutoConnectAllowedOEM /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackDocs /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackProgs /t REG_DWORD /d 0 /f > $null

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v ScoobeSystemSettingEnabled /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338393Enabled /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenEnabled /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenOverlayEnabled /t REG_DWORD /d 0 /f > $null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f > $null
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSyncProviderNotifications /t REG_DWORD /d 0 /f > $null
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v SvcHostSplitThresholdInKB /t REG_DWORD /d 67108864 /f > $null

tzutil /s "W. Europe Standard Time"
Set-WinSystemLocale nl-NL
Set-WinUserLanguageList nl-NL -Force
Set-Culture nl-NL
Set-WinHomeLocation -GeoId 176

Write-OK "Debloat complete. Rebooting in 10 seconds..."
Stop-Transcript
Start-Sleep -Seconds 10
Restart-Computer -Force
