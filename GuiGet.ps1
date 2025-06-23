param (
    [string]$settings_url = "https://github.com/SarkisFesliyan/WingetUpdaterGui/blob/main/Default_Update_Settings.json?raw=true", # null if you arent going to pull down from a URL
    [string]$settings_local = "$((Get-Location).path)\GuiGet Update Settings.json", # Null if you arent going to pull down from a local file
    [bool]$settings_encrypted = $false, # True if the settings file is encrypted, false if not
    [System.Array]$key = $null, # EXISTING_32_4IVBYTE_ARRAY_KEY E.g. @([byte]161, [byte]52, [byte]181, ...)
    [System.Array]$iv = $null # EXISTING_16_BYTE_ARRAY_IV E.g. @([byte]44, [byte]23, [byte]120, ...)
)

###################
#### Settings #####
###################
# Assign to global variables
$Global:settings_encrypted = $settings_encrypted
$Global:key = $key
$Global:iv = $iv
$Global:settings_url = $settings_url
$Global:settings_local = $settings_local

####################
#### Functions #####
####################
function RotateLogs {
    # Function to rotate logs based on size
    $logFile = Join-Path -Path $global:Settings.Logging."Log Directory".Value -ChildPath $global:Settings.Logging."Log File Name".Value
    $maxSizeBytes = $global:Settings.Logging."Log Max Size MB".Value * 1MB
    $maxFiles = $global:Settings.Logging."Log Max Files".Value

    # Check if log file exceeds max size
    if ((Test-Path $logFile) -and ((Get-Item $logFile).Length -ge $maxSizeBytes)) {
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Log file exceeds $maxSizeBytes MB. Rotating logs..." | Out-File -FilePath $logFile -Append

        # Rename old logs (shift them up)
        for ($i = $maxFiles - 1; $i -gt 0; $i--) {
            $oldLog = "$logFile.$i"
            $newLog = "$logFile.$($i + 1)"

            if (Test-Path $oldLog) {
                Rename-Item -Path $oldLog -NewName $newLog -Force
            }
        }

        # Move current log to `.1`
        if (Test-Path $logFile) {
            Rename-Item -Path $logFile -NewName "$logFile.1" -Force
        }
    }
}

function SetupLogs {
    param(
        [string]$logDirectory,
        [string]$logFilename
    )

    if (!(Test-Path "$ENV:LocalAppData\GuiGet error.log"  )) {
        try {
            New-Item -Path "$ENV:LocalAppData\GuiGet error.log" -Force | Out-Null
        }
        catch [EXCEPTION] {
            write-host "Error in SetupLogs function" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
            write-host "Message       : $($_.Exception.Message)" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
            write-host "StackTrace    : $($_.Exception.StackTrace)" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
            write-host "Line Number   : $($_.InvocationInfo.ScriptLineNumber)" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
            write-host "Line          : $($_.InvocationInfo.Line)" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
            write-host "Script Name   : $($_.InvocationInfo.ScriptName)" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
            write-host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Failed to create log directory: $_" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
            Exit 12
        }
    }

    # Create directory if it doesn't exist
    if (!(Test-Path $logDirectory)) {
        try {
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Creating log directory: $logDirectory" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
            New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null
        }
        catch [EXCEPTION] {
            write-host "Error in SetupLogs function" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
            write-host "Message       : $($_.Exception.Message)" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
            write-host "StackTrace    : $($_.Exception.StackTrace)" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
            write-host "Line Number   : $($_.InvocationInfo.ScriptLineNumber)" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
            write-host "Line          : $($_.InvocationInfo.Line)" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
            write-host "Script Name   : $($_.InvocationInfo.ScriptName)" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
            write-host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Failed to create log directory: $_" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
            Exit 12
        }
    }

    RotateLogs
}
function WriteLog {
    param([string]$message)
    try {
        # Format log message
        $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $message"

        write-host "$logEntry"
        
        $logPath = "$($global:Settings."Logging"."Log Directory".Value)\$($global:Settings."Logging"."Log File Name".Value)"

        # Ensure LogPath is set
        if (!(Test-Path $global:Settings."Logging"."Log Directory".Value)) {
            write-host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): RS:$(([runspace]::DefaultRunspace).id), THREAD: Error: Log path is not set. Run SetupLogs first." | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
        }

        $logEntry | Out-File -FilePath $logPath -Append 
    } 
    catch [Exception] {
        write-host "Error in WriteLog function"
        write-host "Message       : $($_.Exception.Message)" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
        write-host "StackTrace    : $($_.Exception.StackTrace)" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
        write-host "Line Number   : $($_.InvocationInfo.ScriptLineNumber)" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
        write-host "Line          : $($_.InvocationInfo.Line)" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
        write-host "Script Name   : $($_.InvocationInfo.ScriptName)" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
    }
}

function ConvertTo-HashtableRecursively {
    param (
        [Parameter(Mandatory)]
        $InputObject
    )

    if ($InputObject -is [PSCustomObject]) {
        $hashtable = @{}
        foreach ($key in $InputObject.PSObject.Properties.Name) {
            $hashtable[$key] = ConvertTo-HashtableRecursively -InputObject $InputObject.$key
        }
        return $hashtable
    }
    else {
        return $InputObject
    }
}

function DecryptFileContent {
    param (
        [string]$EncryptedFile,
        [byte[]]$Key,
        [byte[]]$IV
    )

    # Read the encrypted file content
    $cipherBytes = [System.IO.File]::ReadAllBytes($EncryptedFile)
    Write-Host "Cipher bytes size: $($cipherBytes.Length) bytes"

    # Create AES decryption object
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $Key
    $aes.IV = $IV

    # Decrypt the content
    try {
        $decryptor = $aes.CreateDecryptor()
        #$ms = New-Object System.IO.MemoryStream($cipherBytes)
        $ms = [System.IO.MemoryStream]::new($cipherBytes)
        $cs = New-Object System.Security.Cryptography.CryptoStream($ms, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)
        $sr = New-Object System.IO.StreamReader($cs, [System.Text.Encoding]::UTF8)
        $plaintext = $sr.ReadToEnd()
        $sr.Close()
        Write-Host "Decryption successful."
        return $plaintext
    }
    catch {
        Write-Host "Error during decryption: $_"
        return $null
    }
}


# Decrypt the content
function DecryptFromBytes {
    param (
        [byte[]]$CipherBytes,
        [byte[]]$Key,
        [byte[]]$IV
    )

    # Create AES decryption object
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $Key
    $aes.IV = $IV

    try {
        $decryptor = $aes.CreateDecryptor()
        $ms = [System.IO.MemoryStream]::new($CipherBytes)
        $cs = New-Object System.Security.Cryptography.CryptoStream($ms, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)
        $sr = New-Object System.IO.StreamReader($cs, [System.Text.Encoding]::UTF8)
        $plaintext = $sr.ReadToEnd()
        $sr.Close()
        Write-Host "Decryption successful."
        return $plaintext
    }
    catch {
        Write-Host "Error during decryption: $_"
        return $null
    }
}



function ConfigureSettings {

    if (!(TestInternetConnection)) {
        WriteLog "ConfigureSettings - No internet connection, exiting" 
        Exit 30
    }

    # If settings_url is provided, fetch settings from the URL
    $FindSettingsLogMessage = ""
    if (!([string]::IsNullOrEmpty($global:settings_url))) {
        try {
            $FindSettingsLogMessage += "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): ConfigureSettings - Fetching settings from URL: $global:settings_url"

            if ($Global:Settings_Encrypted) {
                $FindSettingsLogMessage += "`n$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): ConfigureSettings - Decrypting settings file"
                $webClient = New-Object System.Net.WebClient
                $cipherBytes = $webClient.DownloadData($global:settings_url)
                $global:Settings = DecryptFromBytes -CipherBytes $cipherBytes -Key $Global:key -IV $Global:iv
            }
            else {
                $Request = Invoke-WebRequest -Uri $global:settings_url -UseBasicParsing
                if ($Request.StatusCode -eq 200) {
                    $FindSettingsLogMessage += "`n$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): ConfigureSettings - Settings loaded from  URL."
                    $global:Settings = $Request.content
                } 
                else {
                    $FindSettingsLogMessage += "`n$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): ConfigureSettings - Failed to load settings from fallback URL: $($Request.RawContent)"
                }
            }

            $FindSettingsLogMessage += "`n$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): ConfigureSettings - Settings loaded from URL."
        } 
        catch {
            $FindSettingsLogMessage += "`n$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): ConfigureSettings - Failed to fetch settings from URL: $_"
        }
    }
    # If settings_url is not provided, check for a local settings file
    elseif ( !([string]::IsNullOrEmpty($global:settings_local)) -and (Test-Path $global:settings_local) ) {
        try {
            $FindSettingsLogMessage += "ConfigureSettings - Loading settings from local file: $global:settings_local"
            if ($Global:Settings_Encrypted) {
                $FindSettingsLogMessage += "`n$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): ConfigureSettings - Decrypting settings file"
                $global:Settings = DecryptFileContent -EncryptedFile $global:settings_local -Key $global:Key -IV $global:IV
            } 
            else {
                $FindSettingsLogMessage += "`n$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): ConfigureSettings - Loading settings from local file"
                $global:Settings = Get-Content -Path $global:settings_local -Raw -ErrorAction Stop 
            } 
            $FindSettingsLogMessage += "`n$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): ConfigureSettings - Settings loaded from local file."
            
        } 
        catch {
            $FindSettingsLogMessage += "`n$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): ConfigureSettings - Failed to load settings from local file: $_"
        }
    } 
    else {
        $FindSettingsLogMessage += "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): ConfigureSettings - No settings source provided. exiting"
    }

    # replace all of the variables in the settings with the actual values
    $ReplaceSettingVariablesLog = ReplaceSettingVariables

    # Convert to shared hash table for use between runspaces
    try {
        #$global:Settings = [hashtable]::Synchronized(($global:Settings | ConvertFrom-Json))
        $global:Settings = $global:Settings | ConvertFrom-Json
        $global:Settings = ConvertTo-HashtableRecursively -InputObject $global:Settings

        # Synchronize the Hashtable
        $Global:Settings = [hashtable]::Synchronized($global:Settings)
        $global:Settings.UpdateJobs = [System.Collections.ArrayList]@() # Store update jobs here
        $Global:Settings.MainWindowOpen = $False # store main thread host for use in runspaces
    } 
    catch [Exception] {
        write-host "Error in ConfigureSettings function" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
        write-host "Message       : $($_.Exception.Message)" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
        write-host "StackTrace    : $($_.Exception.StackTrace)" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
        write-host "Line Number   : $($_.InvocationInfo.ScriptLineNumber)" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
        write-host "Line          : $($_.InvocationInfo.Line)" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
        write-host "Script Name   : $($_.InvocationInfo.ScriptName)" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
        write-host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): ConfigureSettings - Failed to create log directory: $_" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
        write-host $FindSettingsLogMessage | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
        write-host $ReplaceSettingVariablesLog | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
        write-host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): ConfigureSettings - Failed to convert settings to JSON: $_, $($_.Exception.Message), $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
        Exit 12
    }

    # Setup logs now that we know where to store the data
    SetupLogs -logDirectory $global:Settings.Logging."Log Directory".Value -logFilename $global:Settings.Logging."Log File Name".Value

    WriteLog $FindSettingsLogMessage
    WriteLog $ReplaceSettingVariablesLog

    # Setup notifications
    if ($Global:Settings."Powershell Modules"."BurntToast".Enabled) { 
        ImportOrInstallModule "BurntToast"
        SetupNotificationCenter }
}

function ReplaceSettingVariables {
    $LogMessage = "ReplaceSettingVariables - Gettings replacement variables from json file"
    
    # Convert to hash table for easy access
    $TemporarySettings = $global:Settings | ConvertFrom-Json

    # Get all the replacement variables from top level of the settings
    $ReplacementVariables = $TemporarySettings.ReplacementVariables

    # Remove description key from the replacement variables
    $ReplacementVariables.PSObject.Properties.Remove("Description")

    $LogMessage += "`n$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): ReplaceSettingVariables - Creating Keys based on types"
    # loop through all the settings and replace the variables
    foreach ($key in $ReplacementVariables.PSObject.Properties) {
        if ($key.Value -eq "ENV") {
            $replacementValue = $([Environment]::GetEnvironmentVariable($Key.Name)).replace("\", "\\")
            $LogMessage += "`n$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): ReplaceSettingVariables - Key: $($key.Name) - Value: $($key.Value) -> $replacementValue"
        }
        elseif ($key.Value -eq "JSON") {
            $replacementValue = $TemporarySettings."$($key.Name)"
            $LogMessage += "`n$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): ReplaceSettingVariables - Key: $($key.Name) - Value: $($key.Value) -> $replacementValue"
        }
        else {
            $replacementValue = $key.Value
            $LogMessage += "`n$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): ReplaceSettingVariables - Key: $($key.Name) - Value: $($key.Value) -> $replacementValue"
        }
        $global:Settings = $global:Settings -replace "{ $($key.Name) }", $replacementValue
    }
    return $LogMessage
}
function CheckElevation {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)
    if ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        return $true 
    }
    else { 
        return $false 
    }   
}

function Force64Bit {
    # Ensure the script runs in 64-bit PowerShell
    if (-not ([Environment]::Is64BitProcess)) {
        write-host "Session isn't 64bit, Starting 64bit powershell session" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
        # Join all original arguments back into a string
        $escapedArgs = $MyInvocation.UnboundArguments | ForEach-Object { "`"$_`"" } -join " "
        
        Start-Process -FilePath "$env:windir\SysNative\WindowsPowerShell\v1.0\powershell.exe" `
            -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`" $escapedArgs" `
            -Verb RunAs
        Exit 64
    }
}

function GetLoggedOnUsers {
    $Results = query user 2>$null

    # Check if $results is null or empty
    if ($null -eq $results -or $results.Count -eq 0) {
        return @()
    }

    # Get the header by selecting first row only
    $Head = $Results | Select-Object -First 1 
    $Headers = @()
    $counter = 0
    $currentHeader = ""
    # Capture the lenght of the header line
    For ($I = 0; $I -lt $Head.length + 1; $I++) {
        if ($Head[$I] -eq " ") {
            # Add to the counter so we know how many spaces were dealing with
            $counter++
        }
        elseif ($Head[$I] -ne " ") {
            # Reset counter so we know were at a word
            $counter = 0
        }

        # Add the current character to the current header
        $currentHeader += $Head[$I]

        # Check if we have 2 spaces in a row or if we are at the end of the line
        if ($counter -eq 2 -or $I -eq $Head.length) {
            $Headers += $currentHeader.trim()
            $currentHeader = ""
        }
    }

    # Capture how long each header is and the spaces until the next character
    $Properties = @()
    For ($I = 0; $I -ne $Headers.Count; $I++) {
        $Properties += (@{
                Name  = $Headers[$I]
                Start = $Head.IndexOf($Headers[$I])
                End   = $(
                    IF ($Head.IndexOf($Headers[$I + 1]) -eq -1) {
                        $Head.Length
                    }
                    Else {
                        $Head.IndexOf($Headers[$I + 1]) - 1
                    }
                )
            })
    }

    # Find longest line to adjust END property for last header
    $longest_line = 0
    foreach ( $line in $Results ) {
        if ( $line.length -gt $longest_line ) {
            $longest_line = $line.length
        }
    }
    $properties[-1].end = $longest_line

    # Capture the results
    $NewResults = @()
    # Start at 1 to skip first line header
    For ($I = 1; $I -lt $Results.length; $I++) {
        #write-output($Results[$i])
        $PSObj = @{}
        $Line = $Results[$i]

        # Go through each header property and grab start and stop values
        Foreach ($property in $Properties) {
            $PSObj += @{$Property.Name = ($Line[$Property.Start..$Property.End] -join '').trim() }        
        }

        $NewResults += $PSObj
    }

    return , $NewResults
}

# Function to replace all special characters in a string with "_"
function ReplaceSpecialCharacters {
    param (
        [string]$InputString
    )
    # Define a hashtable for digit-to-word conversion
    $numberWords = @{
        '0' = 'Zero'
        '1' = 'One'
        '2' = 'Two'
        '3' = 'Three'
        '4' = 'Four'
        '5' = 'Five'
        '6' = 'Six'
        '7' = 'Seven'
        '8' = 'Eight'
        '9' = 'Nine'
    }

    $CleanedString = $InputString -replace '[^a-zA-Z0-9_]', '_'

    # button names dont like startings with numbers lol
    if ($CleanedString -match '^\d') {
        $CleanedString = $numberWords["$($CleanedString[0])"] + $CleanedString.Substring(1)
    } 
    return $CleanedString
}

function GetIdleTime {
    Add-Type @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace PInvoke.Win32 {

    public static class UserInput {

        [DllImport("user32.dll", SetLastError=false)]
        private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

        [StructLayout(LayoutKind.Sequential)]
        private struct LASTINPUTINFO {
            public uint cbSize;
            public int dwTime;
        }

        public static DateTime LastInput {
            get {
                DateTime bootTime = DateTime.UtcNow.AddMilliseconds(-Environment.TickCount);
                DateTime lastInput = bootTime.AddMilliseconds(LastInputTicks);
                return lastInput;
            }
        }

        public static TimeSpan IdleTime {
            get {
                return DateTime.UtcNow.Subtract(LastInput);
            }
        }

        public static int LastInputTicks {
            get {
                LASTINPUTINFO lii = new LASTINPUTINFO();
                lii.cbSize = (uint)Marshal.SizeOf(typeof(LASTINPUTINFO));
                GetLastInputInfo(ref lii);
                return lii.dwTime;
            }
        }
    }
}
'@
    #WriteLog ("Last input " + [PInvoke.Win32.UserInput]::LastInput)
    #WriteLog ("Idle for " + [PInvoke.Win32.UserInput]::IdleTime)
    return @{
        "Last Input" = [PInvoke.Win32.UserInput]::LastInput
        "Idle Time"  = [PInvoke.Win32.UserInput]::IdleTime
    }
}

function GetScreenSaverStatus {
    $SreenSaverStatus = Get-Wmiobject win32_desktop | Select-Object -ExpandProperty ScreenSaverActive
    foreach ($status in $SreenSaverStatus) {
        if ($status -eq $true) {
            return $true
        }
    }
    return $false
}

function HidePowershellWindow {
    Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;
    
    public class Win32 {
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetConsoleWindow();
    }
"@
    $consolePtr = [Win32]::GetConsoleWindow()
    [Win32]::ShowWindow($consolePtr, 0)
}

function InstallChocolatey {
    WriteLog "InstallChocolatey - Installing Chocolatey"
    $choco = Get-Command choco.exe -ErrorAction SilentlyContinue
    if ($choco) {
        WriteLog "InstallChocolatey - Chocolatey is in path, skipping install"
        return
    }
    else {
        WriteLog "InstallChocolatey - Chocolatey is not in path, installing"
        Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    }
}

function InstallNugetPackageProvider {
    WriteLog "InstallNugetPackageProvider - Checking for NuGet package provider"
    if (!(Get-PackageProvider | Where-Object { $_.Name -eq 'NuGet' })) {
        WriteLog "InstallNugetPackageProvider - NuGet package provider not found, installing"
        SetPowershellExecutionToBypass
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ForceBootstrap 
    }
}

function ImportOrInstallModule {
    param (
        [string]$moduleName
    )
    WriteLog "ImportorInstallModule - $moduleName"
    InstallNugetPackageProvider
    
    # Check if the module is already loaded
    if (Get-Module -Name $moduleName) {
        WriteLog "ImportorInstallModule - $moduleName module is already imported."
        return  # Exit function if already loaded
    }
    try {
        SetPowershellExecutionToBypass
        
        # Check if the module is available but not loaded
        $Module = Get-Module -ListAvailable -Name $moduleName
        if (-not $Module) {
            # TODO: Enable beta versions if needed
            # Module is not installed, install/import it
            if ($moduleName -notin $Global:Settings."Powershell Modules".keys) {
                WriteLog "ImportorInstallModule - $moduleName module not found in settings. Installing latest version."
                Install-Module -Name $moduleName -Force -AllowClobber
                Import-Module -Name $moduleName -ErrorAction Stop
                return
            }
            
            if ($Global:Settings."Powershell Modules"."$moduleName"."Version" -eq "Latest") {
                WriteLog "ImportorInstallModule - $moduleName module Version is set to Latest. Installing latest version."
                Install-Module -Name $moduleName -Force -AllowClobber
                Import-Module -Name $moduleName -ErrorAction Stop
                return
            }
            else {
                $RequiredVersion = $Global:Settings."Powershell Modules"."$moduleName"."Version"
                WriteLog "ImportorInstallModule - $moduleName module Version is set to $RequiredVersion. Installing $RequiredVersion."
                Install-Module -Name $moduleName -RequiredVersion $RequiredVersion -Force -AllowClobber
                
                #Import-Module -Name $moduleName -ErrorAction Stop
                Import-Module -FullyQualifiedName @{ ModuleName = $moduleName; ModuleVersion = $RequiredVersion } -ErrorAction Stop

                return
            }
        } 

        # Module is installed but not loaded, check for updates. Multiple paths might exist but the first is always loaded
        WriteLog "ImportorInstallModule - $moduleName module found but not imported."
        if ($moduleName -notin $Global:Settings."Powershell Modules".keys) {
            WriteLog "ImportorInstallModule - $moduleName module not found in settings. importing as is"
            Import-Module -Name $moduleName -ErrorAction Stop
            return
        }
        
        # Check if the module version is set to "Latest" in settings
        if ($Global:Settings."Powershell Modules"."$moduleName"."Version" -eq "Latest") {
            $latestModuleVersion = (Find-Module -Name $moduleName).Version
            if ($Module[0].Version -lt $latestModuleVersion) {
                WriteLog "ImportorInstallModule - $moduleName module Version $($Module[0].Version) -lt Latest: $latestModuleVersion. Updating..."
                Update-Module -Name $moduleName -Force 
                Import-Module -Name $moduleName -ErrorAction Stop
                return
            } 
            else {
                WriteLog "ImportorInstallModule - $moduleName module $($Module[0].Version) is up to date. importing..."
                Import-Module -Name $moduleName -ErrorAction Stop
                return
            }
        }

        # If the module version is not set to "Latest", check if the installed version is less than the required version
        $RequiredVersion = [Version]$Global:Settings."Powershell Modules"."$moduleName"."Version"
        $InstalledVersions = Get-Module -ListAvailable -Name $moduleName | Select-Object -ExpandProperty Version

        if ($InstalledVersions -notcontains $RequiredVersion) {
            WriteLog "ImportorInstallModule - $moduleName required version $RequiredVersion not installed. Installing..."
            Install-Module -Name $moduleName -RequiredVersion $RequiredVersion -Force -AllowClobber
        }

        WriteLog "ImportorInstallModule - Importing $moduleName version $RequiredVersion..."
        Import-Module -FullyQualifiedName @{ ModuleName = $moduleName; ModuleVersion = $RequiredVersion } -ErrorAction Stop

    }
    catch [Exception] {
        WriteLog "Error in ImportOrInstallModule function" 
        WriteLog "Message       : $($_.Exception.Message)" 
        WriteLog "StackTrace    : $($_.Exception.StackTrace)" 
        WriteLog "Line Number   : $($_.InvocationInfo.ScriptLineNumber)" 
        WriteLog "Line          : $($_.InvocationInfo.Line)" 
        WriteLog "Script Name   : $($_.InvocationInfo.ScriptName)"
    }
}

function InstallWinget {    
    try {
        For ($I = 0; $I -lt 2; $I++) {      
            if ($global:Settings."Powershell Modules"."Microsoft.WinGet.Client".Enabled) {
                WriteLog "InstallWinget - Checking for Nuget"
                InstallNugetPackageProvider
                WriteLog "InstallWinget - trying to install winget module because of settings"
                ImportOrInstallModule "Microsoft.WinGet.Client"
                
            } 

            # Find main location for winget
            $DesktopAppInstaller = "$ENV:Programfiles\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe"
            $SystemContext = Resolve-Path "$DesktopAppInstaller"

            # Check for System location and set
            if ($SystemContext) { $SystemContext = $SystemContext[-1].Path }

            # Check if the user location is set
            $UserContext = Get-Command winget.exe -ErrorAction SilentlyContinue

            # If you can use the user locaiton, sweet. if not use the system context. If it doesnt exist try installing it
            if ($UserContext -and $Global:Settings."Winget CLI"."Context" -eq "User") { 
                WriteLog "InstallWinget - Winget is in path, UserContext" 
                $Global:WingetLocation = $UserContext.source
                break
                
            }
            elseif (Test-Path "$SystemContext\AppInstallerCLI.exe") { 
                $env:Path += ";$SystemContext" 
                $Global:WingetLocation = "$SystemContext\AppInstallerCLI.exe"
                break
            }
            elseif (Test-Path "$SystemContext\winget.exe") { 
                $env:Path += ";$SystemContext" 
                $Global:WingetLocation = "$SystemContext\winget.exe"
                break
            }
            else { 
                WriteLog "InstallWinget - Winget wasnt found trying to install"
                if ($global:Settings."Powershell Modules"."Microsoft.WinGet.Client".Enabled) {
                    WriteLog "InstallWinget - Checking for Nuget"
                    InstallNugetPackageProvider
                    WriteLog "InstallWinget - trying to install winget module because of settings"
                    ImportOrInstallModule "Microsoft.WinGet.Client"
                    Repair-WinGetPackageManager
                } 
                else {
                    WriteLog "InstallWinget - trying to install winget from github url"
                    $WINGET_URL = "https://api.github.com/repos/microsoft/winget-cli/releases/latest"
                    $DOWNLOAD_URL = $(Invoke-RestMethod $WINGET_URL).assets.browser_download_url |
                    Where-Object { $_.EndsWith(".msixbundle") }

                    # Download the installer:
                    Invoke-WebRequest -URI $DOWNLOAD_URL -OutFile winget.msixbundle -UseBasicParsing

                    # Install winget:
                    Add-AppxPackage winget.msixbundle

                    # Remove the installer:
                    Remove-Item winget.msixbundle
                }
            }
        }
    }
    catch [Exception] {
        WriteLog "Error in InstallWinget function" 
        WriteLog "Message       : $($_.Exception.Message)" 
        WriteLog "StackTrace    : $($_.Exception.StackTrace)" 
        WriteLog "Line Number   : $($_.InvocationInfo.ScriptLineNumber)" 
        WriteLog "Line          : $($_.InvocationInfo.Line)" 
        WriteLog "Script Name   : $($_.InvocationInfo.ScriptName)"
        Exit 1
    }
        
}
function WingetConvertObjToHash {
    param (
        [scriptblock]$Command,
        [string]$stopString = $Null  # Sometimes we want to stop at a specific point
    )
    $Results = Invoke-Command -ScriptBlock $Command | ForEach-Object { $_.replace("$([char]915)$([char]199)$([char]170)", " ") }

    # Find where winget splits the data
    $Line = ($Results | Select-String -SimpleMatch "---").LineNumber
    if ($null -eq $Line) {
        # If no line was found then no package is there
        Return @()
    }
    $Results = $Results | Select-Object -Skip ($Line - 2) | Foreach-Object {
        $Skip = $False
        For ($I = 0; $I -ne $_.length; $I++) {
            if (([int][char]$_[$i]) -gt 200) {
                $Skip = $True
            }
        }
        If ($Skip -eq $False) {
            $_
        }
    }
    $Head = $Results | Select-Object -First 1
    $Headers = @($Head -split ' ' | Where-Object { $_.length -gt 0 } | ForEach-Object { $_.Trim() })
    $Properties = @()
    For ($I = 0; $I -ne $Headers.Count; $I++) {
        $Properties += [pscustomobject]@{
            Name  = $Headers[$I]
            Start = $Head.IndexOf($Headers[$I])
            End   = $(
                if ($Head.IndexOf($Headers[$I + 1]) -eq -1) {
                    $Head.Length
                }
                else {
                    $Head.IndexOf($Headers[$I + 1]) - 1
                }
            )
        }
    }

    # Find longest line to adjust END property for last header
    $longest_line = 0
    foreach ( $line in $Results ) {
        if ( $line.length -gt $longest_line ) {
            $longest_line = $line.length
        }
    }
    $properties[-1].end = $longest_line
    
    $NewResults = @()

    For ($I = 2; $I -lt $Results.count; $I++) {
        $PSObj = @{}
        $Line = $Results[$I]
        if ( $stopString ) {
            if ( $Line -match "$stopString" ) {
                break
            }
        }
        Foreach ($property in $Properties) {
            $PSObj += @{$Property.Name = ($Line[$Property.Start..$Property.End] -join '').trim() }        
        }
        $NewResults += $PSObj
    }
    Return , $NewResults #if only 1 result powershell tries to unpack list. comma stops unpacking
}

function CheckAddtionalSources {
    #TODO: Adjust winget module version
    #TODO: Check choco sources
    if ($global:Settings."Powershell Modules"."Microsoft.WinGet.Client".Enabled) {
        #ImportOrInstallModule "Microsoft.WinGet.Client"
        WriteLog "CheckAddtionalSources - Using Winget Module"
        $wingetSourceList = get-wingetsource
    } 
    else {
        WriteLog "CheckAddtionalSources - Winget CLI"
        $wingetSourceList = WingetConvertObjToHash -Command { & $global:WingetLocation source list }
    }
    
    foreach ( $source in $global:Settings."Additional Sources".Sources) {
        $FoundFlag = $False
        foreach ( $currentSource in $wingetSourceList) {
            if ( $source.URL -eq $currentSource.Argument) {
                WriteLog "CheckAddtionalSources - Found :$($source.URL) in winget sources"
                $FoundFlag = $True
                break
            }
        }
        
        # Did not find additional source?
        if (!($FoundFlag)) {
            WriteLog "CheckAddtionalSources - Adding $($source.Name) - $($source.URL) to winget sources"
            if ($global:Settings."Powershell Modules"."Microsoft.WinGet.Client".Enabled) {
                Add-WinGetSource -Name "$($source.Name)" -Arg "$($source.URL)" -Type "$($source.Type)"
            } 
            else {
                & $global:WingetLocation source add --name "$($source.Name)" --arg "$($source.URL)" --type "$($source.Type)"
            }
        }
    }
}

function NormalizeVersion {
    param ([string]$version)

    if ($version -match '(\d+(?:\.\d+)+)') {
        # Standard versioning scheme
        $normalizedVersion = [version]$matches[1]

        # Force missing components (Build and Revision) to 0
        $major = $normalizedVersion.Major
        $minor = if ($normalizedVersion.Minor -eq -1) { 0 } else { $normalizedVersion.Minor }
        $build = if ($normalizedVersion.Build -eq -1) { 0 } else { $normalizedVersion.Build }
        $revision = if ($normalizedVersion.Revision -eq -1) { 0 } else { $normalizedVersion.Revision }

        return [version]"$major.$minor.$build.$revision"
    }
    elseif ($version -match '^\d{8}$') {
        # Date-based versioning like 20240507
        return [datetime]::ParseExact($version, 'yyyyMMdd', $null)
    }
    elseif ($version -match '^> (.+)$') {
        # Handle versions like '> 3.12.0'
        return [version]$matches[1]
    }
    elseif ($version -is [Int]) {
        # Handle simple numbers
        return [int]$version
    }
    else {
        return $version  # Leave as string for custom comparison
    }
}

function InstallPackageManager {
    # Call the function to check and install winget if necessary
    if ( $global:Settings."Package Manager".value -eq "Winget") {
        InstallWinget
    }
    if ( $global:Settings."Package Manager".value -eq "Chocolatey") {
        InstallChocolatey
    }
}

function TestInternetConnection {
    param (
        [string]$TestUrl = "https://www.google.com",
        [int]$TimeoutSeconds = 5
    )

    try {
        $request = [System.Net.WebRequest]::Create($TestUrl)
        $request.Timeout = $TimeoutSeconds * 1000
        $response = $request.GetResponse()
        $response.Close()
        return $true
    }
    catch {
        return $false
    }
}

function GetInstalledWingetApps {
    if ($global:Settings."Powershell Modules"."Microsoft.WinGet.Client".Enabled) {
        #ImportOrInstallModule "Microsoft.WinGet.Client"
        # Retrieve the installed packages
        $wingetInstalledApps = Get-WingetPackage
        # Available versions are in an array and need to have logic to figure out which one is the biggest version
        # not all version numbers are able to be compared when converted to system.version type. custom logic is needed

        # Create an array to store the modified objects
        $modifiedApps = @()

        # Loop through each package
        foreach ($app in $wingetInstalledApps) {
            #writelog "GetInstalledWingetApps - $($app.name) : Installed: $(NormalizeVersion $app.InstalledVersion) - Available: $(NormalizeVersion $app.AvailableVersions[0])"
            # Create a new custom object with the original properties and the additional 'Available' property
            $customApp = @{
                Name              = $app.Name
                Id                = $app.Id
                Version           = $app.InstalledVersion
                Available         = $null  # Add your custom property
                Source            = $app.Source
                InstallStatus     = $app.CheckInstalledStatus()
                IsUpdateAvailable = $app.IsUpdateAvailable

                # You can include other properties if needed
            }
            # Check if the available versions even exist
            if (($app.AvailableVersions).Length -eq 0) {
                $modifiedApps += $customApp
                #TODO Check if the version displayed is whats in registry?
                Continue
            }
            if ($app.AvailableVersions[0] -eq "Unknown" -and ($app.AvailableVersions).Length -eq 1 ) {
                $modifiedApps += $customApp
                WriteLog "GetInstalledWingetApps - $($app.name) Unable to compare versions, Available Version: $($app.AvailableVersions)"
                Continue
            }

            #WriteLog "GetInstalledWingetApps - $($app.Name) : Installed: $($app.InstalledVersion) - Available: $($app.AvailableVersions)"
            # Lets assume the first available version is the biggest one for now
            $AvailableVersion = $app.AvailableVersions[0]


            # Check if installed version is less then available
            $versionOne = NormalizeVersion $app.InstalledVersion
            $versionTwo = NormalizeVersion $AvailableVersion
            WriteLog "GetInstalledWingetApps - $($app.Id) Normalized Installed Version: $versionOne | Available Normalized Version: $versionTwo"

            # If both were converted to [version], compare them
            if ($versionOne -is [version] -and $versionTwo -is [version]) {
                if ($versionOne -lt $versionTwo) {
                    $customApp.Available = $versionTwo
                }
                else {
                    $customApp.Available = $versionOne
                }
            } 
            elseif ($versionOne -is [datetime] -and $versionTwo -is [datetime]) {
                # Compare date-based versions
                if ($versionOne -lt $versionTwo) {
                    $customApp.Available = $versionTwo
                }
                else {
                    $customApp.Available = $versionOne
                }
            }
            elseif ($versionOne -is [Int] -and $versionTwo -is [Int]) {
                # Compare date-based versions
                if ($versionOne -lt $versionTwo) {
                    $customApp.Available = $versionTwo
                }
                else {
                    $customApp.Available = $versionOne
                }
            }
            else {
                # Custom string comparison or other logic here
                WriteLog "GetInstalledWingetApps - VERSION COMPAIRSON ERROR!!! $($app.name) Unable to compare versions, Installed Normalized Version: $versionOne Available Normalized Version: $versionTwo"
                $customApp.Available = $versionTwo 
            }
            $modifiedApps += , $customApp
        }

        return , $modifiedApps
    }
    
    # if not using the winget module
    $wingetInstalledApps = WingetConvertObjToHash -Command { & $global:WingetLocation list --accept-source-agreements }
    return , $wingetInstalledApps
}

function FuzzySkipApp {
    param (
        $upgradableWingetApps
    )
    # Fuzzy check the skip list
    foreach ($fuzzyApp in $global:Settings."Application Skip List"."Skip List") {
        if ($fuzzyApp -match "\*") {
            $pattern = $fuzzyApp.Trim("*")
            WriteLog "FuzzySkipApp - Fuzzy match found: $fuzzyApp (pattern: $pattern)"
            foreach ($app in $upgradableWingetApps) {
                if ($app.Id -match $pattern) {
                    WriteLog "FuzzySkipApp - Removing app: $($app.Id) (matched pattern: $pattern)"
                }
            }
            $upgradableWingetApps = $upgradableWingetApps | Where-Object { $_.Id -notmatch $pattern }
        }
    }
    
    return , $upgradableWingetApps
}

function GetUpgradableApps {
    if ($global:Settings."Powershell Modules"."Microsoft.WinGet.Client".Enabled) {
        $upgradableWingetApps = GetInstalledWingetApps
        $upgradableWingetApps = $upgradableWingetApps | where-object { $_.IsUpdateAvailable -eq $True -and $_.Id -notin $global:Settings."Application Skip List"."Skip List" }
        $upgradableWingetApps = FuzzySkipApp -upgradableWingetApps $upgradableWingetApps
        

        if ( $upgradableWingetApps.length -eq 1 ) {
            #force return of a list
            return , @($upgradableWingetApps)
        }
        return , $upgradableWingetApps
    }

    # if not using the winget module
    $upgradableWingetApps = WingetConvertObjToHash -Command { & $global:WingetLocation list --upgrade-available --accept-source-agreements } -stopString "upgrades available."
    $upgradableWingetApps = , $upgradableWingetApps | Where-Object { $_.Id -notin $global:Settings."Application Skip List"."Skip List" }
    $upgradableWingetApps = FuzzySkipApp -upgradableWingetApps $upgradableWingetApps

    if ( $upgradableWingetApps.length -eq 1 ) {
        #force return of a list
        return , @($upgradableWingetApps)
    }

    return , $upgradableWingetApps
}

function GetLastLoggedInUser {
    # Read from LogonUI to get last logged-in user (can be slightly outdated)
    $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI'
    $lastLoggedIn = (Get-ItemProperty -Path $regPath -Name LastLoggedOnUser -ErrorAction SilentlyContinue).LastLoggedOnUser
    
    return $lastLoggedIn.Split('\')[-1]  # Return only the username part
}

function CheckGuiActivation {
    # Get the list of all user sessions
    $userSessions = GetLoggedOnUsers
    # Check if there are any user sessions
    if ($userSessions.Count -gt 0) {
        WriteLog "CheckGuiActivation - The following user sessions are active: "
        # Use this variable for write log once
        $FirstRun = $true
        $WaitTimer = 0
        while ($true) {
            # Check if there is a user session that matches the desired state
            $UserSessionFlag = $false
            foreach ($user in $userSessions) {
                if ($FirstRun) {
                    # Write log of each user session
                    foreach ($key in $user.Keys) {
                        WriteLog "CheckGuiActivation - $key : $($user[$key])"
                    }
                    # Turn off the first run flag
                    $FirstRun = $false
                }
                
                # Check if the user state is in the desired state
                if ($user.STATE -in $global:settings."User Experience"."User State Gui Activation".States) {
                    WriteLog "CheckGuiActivation - User state is $($user.STATE), flipping usesessionflag to true"
                    $UserSessionFlag = $true
                }
            }

            # Check if we are waiting for the user state
            if ($UserSessionFlag) {
                if ($user.STATE -in $global:settings."User Experience"."User State Gui Activation"."Wait For User State".States) {
                    WriteLog "CheckGuiActivation - Sleeping for $($global:settings."User Experience"."User State Gui Activation"."Wait For User State"."Sleep Time") seconds"
                    
                    Start-Sleep -Seconds $global:settings."User Experience"."User State Gui Activation"."Wait For User State"."Sleep Time"
                    $WaitTimer += $global:settings."User Experience"."User State Gui Activation"."Wait For User State"."Sleep Time"
                    WriteLog "CheckGuiActivation - Waiting for user state to be $($global:settings."User Experience"."User State Gui Activation"."Wait For User State".States). current wait time is $WaitTimer/ $($global:settings."User Experience"."User State Gui Activation"."Wait For User State"."Max Wait Time")"
                    if ($WaitTimer -ge $global:settings."User Experience"."User State Gui Activation"."Wait For User State"."Max Wait Time") {
                        WriteLog "CheckGuiActivation - Max wait time of $($global:settings."User Experience"."User State Gui Activation"."Wait For User State"."Max Wait Time") seconds reached. Exiting."
                        return $false
                    }

                    # Continue to check for user state 
                    WriteLog "CheckGuiActivation - Continuing to check for user state"
                    continue
                }
                
                # User is in active state, continue
                WriteLog "CheckGuiActivation - User is in active state, continuing"
                return $true 

            }
            # Break, no user sessions are active
            WriteLog "CheckGuiActivation - No user sessions are active."
            break
        }
        
        
    } 
    else {
        WriteLog "CheckGuiActivation - No user sessions are active."
        return $false
    }
    
}

function CreateMainRegistryDirectory {
    if (!(Test-Path "$($global:Settings."Registry Settings"."Registry Directory")")) {
        New-Item "$($global:Settings."Registry Settings"."Registry Directory")" -Force | Out-Null
    }
}

function UpgradeApp {
    param (
        [string]$AppId
    )
    writeLog "UpgradeApp - Starting on $AppId"
    $PackageType = $null
    $PackageMetaData = & $global:WingetLocation show "$AppId" --exact --accept-source-agreements --accept-package-agreements
    foreach ($Line in $PackageMetaData) {
        if ($Line -match "Installer Type:") { 
            $PackageType = $Line.Split(":")[1].Trim()
            break
        }
    }
    WriteLog "UpgradeApp - $AppId Package Installer Type: $PackageType"

    if ($global:Settings."Powershell Modules"."Microsoft.WinGet.Client".Enabled) {
        WriteLog "UpgradeApp - Using Winget Module"
        #ImportOrInstallModule "Microsoft.WinGet.Client"
        
        $Arguments = @{
            "Id"          = $AppId
            "MatchOption" = "EqualsCaseInsensitive"
        }
        
        # (Get-Command Install-WinGetPackage).Parameters.Keys
        # TODO: Find list of package default install paramaters. is there a way to inspect how its being installed

        ## Handle Installing arguments
        $CustomWingetArgs = $Global:Settings."Application Installation Arguments"."Custom"."$AppId"."Winget Module Arguments"
        if (![string]::IsNullOrWhiteSpace($CustomWingetArgs)) {
        
            WriteLog "UpgradeApp - Using Custom Winget Args"

            # Check for forced uninstall 
            if ($Global:Settings."Application Installation Arguments"."Custom"."$AppId".ContainsKey("Force Uninstall First")) {
                if ($Global:Settings."Application Installation Arguments"."Custom"."$AppId"."Force Uninstall First" -eq $true) {
                    WriteLog "UpgradeApp - Forcing Uninstall First"

                    $pkg = Find-WingetPackage -Id $AppId -MatchOption "EqualsCaseInsensitive"
                    $UninstallArgs = @{
                        "Name"        = $pkg.Name
                        "Verbose"     = $true
                        "MatchOption" = "EqualsCaseInsensitive"
                        "Mode"        = "Silent"
                    }

                    if ($CustomWingetArgs.ContainsKey("Log")) {
                        writeLog "UpgradeApp - Using Custom Log Path for uninstall: $($CustomWingetArgs."Log")"
                        $UninstallArgs["Log"] = $CustomWingetArgs."Log"
                    }

                    foreach ($key in $UninstallArgs.Keys) {
                        WriteLog "UpgradeApp - Uninstall Argument: $key : $($UninstallArgs[$key])"
                    }
                    
                    try {
                        WriteLog "UpgradeApp - Running Uninstall-WingetPackage command"
                        $UninstallResponse = Uninstall-WinGetPackage @UninstallArgs
                        foreach ($key in $UninstallResponse.Keys) {
                            WriteLog "UpgradeApp Force Uninstall $AppId - UninstallResponse: $key : $($UpdateResponse[$key])"
                        }
                    } 
                    catch [Exception] {
                        WriteLog "Error in UpgradeApp function while attempting to Update-WingetPackage" 
                        WriteLog "Message       : $($_.Exception.Message)" 
                        WriteLog "StackTrace    : $($_.Exception.StackTrace)" 
                        WriteLog "Line Number   : $($_.InvocationInfo.ScriptLineNumber)" 
                        WriteLog "Line          : $($_.InvocationInfo.Line)" 
                        WriteLog "Script Name   : $($_.InvocationInfo.ScriptName)"
                    }
                }
            }
            $Arguments += $CustomWingetArgs
        }
        else {
            WriteLog "UpgradeApp - Using DEFAULT Winget Args"
            $Arguments += $Global:Settings."Application Installation Arguments"."Default"."Winget Module Arguments"
            
            if ($PackageType -eq "msi") {
                if ("Custom MSI" -in $Arguments.Keys) {
                    WriteLog "UpgradeApp - Using Custom MSI"
                    $Arguments["Custom"] = $Arguments["Custom MSI"]
                }
                if ("Override MSI" -in $Arguments.Keys) {
                    WriteLog "UpgradeApp - Using Override MSI"
                    $Arguments["Override"] = $Arguments["Override MSI"]
                }
            }
            elseif ($PackageType -eq "exe") {
                if ("Custom EXE" -in $Arguments.Keys) {
                    WriteLog "UpgradeApp - Using Custom EXE"
                    $Arguments["Custom"] = $Arguments["Custom EXE"]
                }
                if ("Override EXE" -in $Arguments.Keys) {
                    WriteLog "UpgradeApp - Using Override MSI"
                    $Arguments["Override"] = $Arguments["Override MSI"]
                }

            }
        }
        
        $RemoveKeysList = @("Custom MSI", "Override MSI", "Custom EXE", "Override EXE", "Skip Custom Args On Failure")
        $RemoveKeysFound = @()
        foreach ($key in $Arguments.Keys) {
            if ($key -in $RemoveKeysList) {
                WriteLog "UpgradeApp - Removing key: $key from Arguments"
                $RemoveKeysFound += @($key)
            }
        }
        foreach ($key in $RemoveKeysFound) {
            $Arguments.Remove($key)
        }
        foreach ($key in $Arguments.Keys) {
            WriteLog "UpgradeApp - Update Argument: $key : $($Arguments[$key])"
        }

        # Execute winget module command
        try {
            $ForceUninstallFirst = $Global:Settings."Application Installation Arguments"."Custom"."$AppId"."Force Uninstall First"
            $SkipCustomArgsOnFailure = $global:Settings."Application Installation Arguments"."Custom"."$AppId"."Skip Custom Args On Failure"
            $SkipDefaultCustomArgsOnFailure = $global:Settings."Application Installation Arguments"."Winget Module Arguments"."Skip Custom Args On Failure"
            
            if ($ForceUninstallFirst -eq $true) {
                # Since it was uninstalled we need to use the install command instead of update
                WriteLog "UpgradeApp - Running Install-WingetPackage command"
                $InstallResponse = Install-WingetPackage @Arguments -ErrorAction SilentlyContinue
                foreach ($key in $InstallResponse.PSObject.Properties.Name) {
                    WriteLog "UpgradeApp - $AppId - InstallResponse: $key : $($InstallResponse."$key")"
                }

                
                # if ($InstallResponse.Status -eq "InstallError" -and $SkipCustomArgsOnFailure -eq $true -and ($Arguments.ContainsKey("Custom") -or $Arguments.ContainsKey("Override")) ) {
                #     WriteLog "UpgradeApp - $AppId - trying again without custom args"
                #     if ($Arguments.ContainsKey("Custom")) {
                #         WriteLog "UpgradeApp - Removing key: 'Custom' = $($Arguments.Custom) from Arguments"
                #         $Arguments.Remove("Custom")
                #     }
                #     if ($Arguments.ContainsKey("Override")) {
                #         WriteLog "UpgradeApp - Removing key: 'Override' = $($Arguments.Override) from Arguments"
                #         $Arguments.Remove("Override")
                #     }
                #     $InstallResponse = Install-WingetPackage @Arguments -ErrorAction SilentlyContinue
                #     foreach ($key in $InstallResponse.PSObject.Properties.Name) {
                #         WriteLog "UpgradeApp - $AppId - InstallResponse: $key : $($InstallResponse."$key")"
                #     }
                # }

            }
            else {
                # Update winget app
                WriteLog "UpgradeApp - Running Update-WingetPackage command"
                $UpdateResponse = Update-WingetPackage @Arguments -ErrorAction SilentlyContinue
                foreach ($key in $UpdateResponse.PSObject.Properties.Name) {
                    WriteLog "UpgradeApp - $AppId - UpdateResponse: $key : $($UpdateResponse."$key")"
                }

                # if ($UpdateResponse.Status -eq "InstallError" -and 
                # ($SkipCustomArgsOnFailure -eq $true -or (-not $global:Settings."Application Installation Arguments"."Custom".ContainsKey($AppId) -and
                # $SkipDefaultCustomArgsOnFailure -eq $true)) -and 
                #         ($Arguments.ContainsKey("Custom") -or $Arguments.ContainsKey("Override") ) ) {
                #     WriteLog "UpgradeApp - $AppId - trying again without custom args"
                #     if ($Arguments.ContainsKey("Custom")) {
                #         WriteLog "UpgradeApp - Removing key: 'Custom' = $($Arguments.Custom) from Arguments"
                #         $Arguments.Remove("Custom")
                #     }
                #     if ($Arguments.ContainsKey("Override")) {
                #         WriteLog "UpgradeApp - Removing key: 'Override' = $($Arguments.Override) from Arguments"
                #         $Arguments.Remove("Override")
                #     }

                #     $UpdateResponse = Update-WingetPackage @Arguments -ErrorAction SilentlyContinue
                #     foreach ($key in $UpdateResponse.PSObject.Properties.Name) {
                #         WriteLog "UpgradeApp - $AppId - UpdateResponse: $key : $($UpdateResponse."$key")"
                #     }
                # }
            }
        } 
        catch [Exception] {
            WriteLog "Error in UpgradeApp function while attempting to Update-WingetPackage" 
            WriteLog "Message       : $($_.Exception.Message)" 
            WriteLog "StackTrace    : $($_.Exception.StackTrace)" 
            WriteLog "Line Number   : $($_.InvocationInfo.ScriptLineNumber)" 
            WriteLog "Line          : $($_.InvocationInfo.Line)" 
            WriteLog "Script Name   : $($_.InvocationInfo.ScriptName)"
        }

    }
    else {
        # Use WinGet CLI
        WriteLog "UpgradeApp - Using Winget CLI"
        $Arguments = [System.Collections.ArrayList]@("upgrade", "--id", $AppId, "--exact", "--accept-package-agreements", "--accept-source-agreements")

        ## Handle Installing arguments
        $CustomWingetArgs = $Global:Settings."Application Installation Arguments"."Custom"."$AppId"."Winget Arguments"
        if (![string]::IsNullOrWhiteSpace($CustomWingetArgs)) {
            WriteLog "UpgradeApp - Using Custom Winget Args"

            # Check for forced uninstall 
            if ($Global:Settings."Application Installation Arguments"."Custom"."$AppId".ContainsKey("Force Uninstall First") -and 
                ($Global:Settings."Application Installation Arguments"."Custom"."$AppId"."Force Uninstall First" -eq $true)) {

                WriteLog "UpgradeApp - Forcing Uninstall First"
                
                # Chnage the upgrade command to install command since we are uninstalling first
                for ($index_count = 0; $index_count -lt $Arguments.Count; $index_count++) {
                    if ($Arguments[$index_count] -eq "upgrade") {
                        WriteLog  "UpgradeApp - Found $($Arguments[$index_count]) in arguments Replaced with install"
                        $Arguments[$index_count] = "install"
                    }
                }

                $UninstallArgs = @("uninstall", "--id", $AppId, "--exact", "--silent", "--accept-source-agreements", "--accept-package-agreements")

                foreach ($key in $UninstallArgs) {
                    WriteLog "UpgradeApp - Uninstall Argument: $key"
                }
                
                try {
                    WriteLog "UpgradeApp - Running Uninstall CLI command"
                    # Define paths for output and error logs

                    $output = & $global:WingetLocation @UninstallArgs 2>&1
                    writeLog "UpgradeApp - CLI command output: $($output.replace("$([char]915)$([char]199)$([char]170)", " "))"

                } 
                catch [Exception] {
                    WriteLog "Error in UpgradeApp function while attempting to uninstall the package $appId" 
                    WriteLog "Message       : $($_.Exception.Message)" 
                    WriteLog "StackTrace    : $($_.Exception.StackTrace)" 
                    WriteLog "Line Number   : $($_.InvocationInfo.ScriptLineNumber)" 
                    WriteLog "Line          : $($_.InvocationInfo.Line)" 
                    WriteLog "Script Name   : $($_.InvocationInfo.ScriptName)"
                }
            }

            foreach ($arg in $CustomWingetArgs) {
                if ($arg -notin $Arguments) {
                    WriteLog "UpgradeApp - Adding Custom Winget Argument: $arg"
                    $Arguments.Add($arg)
                }
                else {
                    WriteLog "UpgradeApp - Skipping Custom Winget Argument: $arg, already exists in Arguments"
                }
            }
            #$Arguments.AddRange($CustomWingetArgs)
        }
        else {
            # Use default Winget CLI arguments if missing
            WriteLog "UpgradeApp - Using DEFAULT Winget Args"
            foreach ($arg in $Global:Settings."Application Installation Arguments"."Default"."Winget Arguments") {
                if ($arg -notin $Arguments) {
                    WriteLog "UpgradeApp - Adding Custom Winget Argument: $arg"
                    $Arguments.Add($arg)
                }
                else {
                    WriteLog "UpgradeApp - Skipping Custom Winget Argument: $arg, already exists in Arguments"
                }
            }
            #$Arguments.AddRange($Global:Settings."Application Installation Arguments"."Default"."Winget Arguments")

            $index_count = 0
            if ($PackageType -eq "msi") {
                for ($index_count = 0; $index_count -lt $Arguments.Count; $index_count++) {
                    if ($Arguments[$index_count] -eq "--custom-msi") {
                        WriteLog "UpgradeApp - Found --custom-msi in arguments"
                        $Arguments[$index_count] = "--custom"
                    }
                    if ($Arguments[$index_count] -eq "--override-msi") {
                        WriteLog "UpgradeApp - Found --override-msi in arguments"
                        $Arguments[$index_count] = "--override"
                    }
                }
            }
            elseif ($PackageType -eq "exe") {
                for ($index_count = 0; $index_count -lt $Arguments.Count; $index_count++) {
                    if ($Arguments[$index_count] -eq "--custom-exe") {
                        WriteLog  "UpgradeApp - Found $($Arguments[$index_count]) in arguments -- Replaced with --custom"
                        $Arguments[$index_count] = "--custom"
                    }
                    if ($Arguments[$index_count] -eq "--override-exe") {
                        WriteLog  "UpgradeApp - Found $($Arguments[$index_count]) in arguments -- Replaced with --override"
                        $Arguments[$index_count] = "--override"
                    }
                }
            }
        }

        # Iterate through the $Arguments list in reverse to safely remove items
        $RemoveKeysList = [System.Collections.ArrayList]@("--override-exe", "--override-msi", "--custom-exe", "--custom-msi", "--skip-custom-args-on-failure")
        for ($index = $Arguments.Count - 1; $index -ge 0; $index--) {
            if ($Arguments[$index] -in $RemoveKeysList) {
                WriteLog "Removing key: $($Arguments[$index]) from Arguments"
                $Arguments.RemoveAt($index)
            }

        }
        foreach ($Key in $Arguments) {
            WriteLog "UpgradeApp - Upgrade Argument: $Key"
        }

        try {
            $SkipCustomArgsOnFailure = $global:Settings."Application Installation Arguments"."Custom"."$AppId"."Skip Custom Args On Failure"
            $SkipDefaultCustomArgsOnFailure = $global:Settings."Application Installation Arguments"."Winget Module Arguments"."Skip Custom Args On Failure"

            $output = & $global:WingetLocation @Arguments 2>&1
            writeLog "UpgradeApp - CLI command output:  $($output.replace("$([char]915)$([char]199)$([char]170)", " "))"

        } 
        catch [Exception] {
            WriteLog "Error in UpgradeApp function while attempting to Upgrade the package $appId" 
            WriteLog "Message       : $($_.Exception.Message)" 
            WriteLog "StackTrace    : $($_.Exception.StackTrace)" 
            WriteLog "Line Number   : $($_.InvocationInfo.ScriptLineNumber)" 
            WriteLog "Line          : $($_.InvocationInfo.Line)" 
            WriteLog "Script Name   : $($_.InvocationInfo.ScriptName)"
        }
    }
}

function SetPowershellExecutionToBypass {
    if ((Get-ExecutionPolicy) -ne "Bypass") {
        try {
            Set-ExecutionPolicy Bypass -Scope Process -Force
            WriteLog "SetPowershellExecutionToBypass - Execution Policy set to Bypass. Required for installation of modules"
        }
        catch {
            WriteLog "Failed to change Execution Policy. Try running as Administrator."
            WriteLog "Error in SetPowershellExecutionToBypass function" 
            WriteLog "Message       : $($_.Exception.Message)" 
            WriteLog "StackTrace    : $($_.Exception.StackTrace)" 
            WriteLog "Line Number   : $($_.InvocationInfo.ScriptLineNumber)" 
            WriteLog "Line          : $($_.InvocationInfo.Line)" 
            WriteLog "Script Name   : $($_.InvocationInfo.ScriptName)"
        }
    }
}


function SetupNotificationCenter {
    try {
        $DisplayName = $Global:Settings."Application Name"
        $LnkName = "$DisplayName.lnk"
        $AppId = ($Global:Settings."Powershell Modules"."BurntToast"."Notification Registry Data"."App Id").Replace(" ", "").Replace("-", "_")
        $IconPath = $Global:Settings."Graphics"."Notification Icon"."$($Global:Settings."Powershell Modules"."BurntToast"."Icon Theme")"."Path"
        $RegistryPath = "HKCU:\Software\Classes\AppUserModelId\$AppId"
        $Current_user = GetLastLoggedInUser

        # Create shortcut for BurntToast custom app
        $Shell = New-Object -ComObject WScript.Shell
        $Shortcut = $Shell.CreateShortcut("$env:systemdrive\Users\$Current_user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\$LnkName")
        $Shortcut.TargetPath = "$env:WINDIR\System32\whoami.exe"
        if ($Global:Settings."Graphics"."Notification Icon"."Use Image") {
            if (test-path $IconPath) {
                $Shortcut.IconLocation = $IconPath
            }
        }
        
        $Shortcut.Description = "Used for notifications from the Winget Deferred Patching app"
        $Shortcut.WorkingDirectory = "$env:systemdrive\Users\$Current_user"
        $Shortcut.Save()

        if (!(Test-Path $registryPath)) {
            New-Item -Path $RegistryPath -Force | Out-Null
        } 

        Set-ItemProperty -Path $RegistryPath -Name "DisplayName" -Value $DisplayName
        Set-ItemProperty -Path $RegistryPath -Name "IconUri" -Value $IconPath
        Set-ItemProperty -Path $RegistryPath -Name "Shortcut" -Value $LnkName

        
        # set priority for the app
        $RegPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\$AppId"
        if (!(Test-Path $RegPath)) {
            # Create registry key if it doesn't exist
            New-Item -Path $RegPath -Force | Out-Null
        } 
        

        # Set values to mark the app as priority and allow notifications
        Set-ItemProperty -Path $RegPath -Name "ShowInActionCenter" -Value 1
        Set-ItemProperty -Path $RegPath -Name "Enabled" -Value 1
        Set-ItemProperty -Path $RegPath -Name "Priority" -Value $Global:Settings."Powershell Modules"."BurntToast"."Notification Registry Data"."priority"  # 1 = Priority, 2 = Normal, 3 = Quiet
    }
    catch {
        WriteLog "Failed SetupNotificationCenter function"
        WriteLog "Message       : $($_.Exception.Message)" 
        WriteLog "StackTrace    : $($_.Exception.StackTrace)" 
        WriteLog "Line Number   : $($_.InvocationInfo.ScriptLineNumber)" 
        WriteLog "Line          : $($_.InvocationInfo.Line)" 
        WriteLog "Script Name   : $($_.InvocationInfo.ScriptName)"
    }
}

function CreateNotification {
    param ($Title, $Text)
    writeLog "CreateNotification - Title: $Title | Text: $Text"
    if ($Global:Settings."User Experience"."Notifications".Enabled) {
        if ($Global:Settings."Powershell Modules"."BurntToast".Enabled) {
            CreateBurntToastNotification -Text $Text -Title $Title
        }
        else {
            CreateToastNotification -title $Title -text $Text
        }
    }
}

function CreateBurntToastNotification {
    param ($Title, $Text)

    $currentTheme = $Global:Settings."User Experience"."Current Theme".Value

    # Create the notification arguments skip title
    $notificationArgs = $Global:Settings."Powershell Modules"."BurntToast"."BurntToast Arguments"
    $notificationArgs["Text"] = "$Text"
    $notificationArgs["AppId"] = $Global:Settings."Powershell Modules"."BurntToast"."Notification Registry Data"."App Id" -replace " ", ""

    # Change icon if icon provided
    if ($Global:Settings."Graphics"."Notification Icon"."Use Image") {
        if (test-path $Global:Settings."Graphics"."Notification Icon"."$currentTheme"."Path") {
            $notificationArgs["AppLogo"] = $Global:Settings."Graphics"."Notification Icon"."$currentTheme"."Path"
        }
    }

    #ImportOrInstallModule "BurntToast"

    # Create a new toast notification
    try {
        New-BurntToastNotification @notificationArgs
    }
    catch {
        WriteLog "Failed to create notification: $($_.Exception.Message)"
        WriteLog "Error in CreateBurntToastNotification function" 
        WriteLog "Message       : $($_.Exception.Message)" 
        WriteLog "StackTrace    : $($_.Exception.StackTrace)" 
        WriteLog "Line Number   : $($_.InvocationInfo.ScriptLineNumber)" 
        WriteLog "Line          : $($_.InvocationInfo.Line)" 
        WriteLog "Script Name   : $($_.InvocationInfo.ScriptName)"
    }
     
}


function CreateToastNotification {
    # Going to use forms to create a baloontip
    param ($title, $text)
    LoadAssembly "System.Windows.Forms"
    $currentTheme = $Global:Settings."User Experience"."Current Theme".Value

    try {
        $notify = New-Object System.Windows.Forms.NotifyIcon

        # Change icon if icon provided a path
        if ( $Global:Settings."Graphics"."Notification Icon"."Use Image" -eq $true -and (Test-Path $Global:Settings."Graphics"."Notification Icon"."$currentTheme"."Path") ) {
            try {
                $notify.Icon = New-Object System.Drawing.Icon($Global:Settings."Graphics"."Notification Icon"."$currentTheme"."Path")
            }
            catch {
                writeLog "CreateToastNotification - Failed to load icon from path: $($_.Exception.Message)"
                $notify.Icon = [System.Drawing.SystemIcons]::Information
            }
        }
        else {
            # Set Default icon
            $notify.Icon = [System.Drawing.SystemIcons]::Information
        }
    
        # Set the title and message for the notification
        $notify.BalloonTipTitle = "$title"
        $notify.BalloonTipText = "$text"
        $notify.Visible = $true
    
        # Show the notification, the number doesnt matter
        $notify.ShowBalloonTip(1000)
        Start-Sleep -Seconds 5
        $notify.Dispose()
    }
    catch {
        WriteLog "Failed to CreateToastNotification Error: $_"
        WriteLog "Error in CreateToastNotification function" 
        WriteLog "Message       : $($_.Exception.Message)" 
        WriteLog "StackTrace    : $($_.Exception.StackTrace)" 
        WriteLog "Line Number   : $($_.InvocationInfo.ScriptLineNumber)" 
        WriteLog "Line          : $($_.InvocationInfo.Line)" 
        WriteLog "Script Name   : $($_.InvocationInfo.ScriptName)"
    }


}

function WingetAppCompletedUpdate {
    param (
        [String]$AppId,
        [String]$AppCurrentVersion
    )
    $AppId = $AppId.replace(".", "_")
    $currentDateTime = Get-Date
    $formattedDateTime = $currentDateTime.ToString("yyyy-MM-dd HH:mm:ss")
    New-ItemProperty -Path "$($Global:Settings."Registry Settings"."Registry Directory")\$AppId" -Name "AppCurrentVersion" -Value "$AppCurrentVersion" -PropertyType String -Force | Out-Null
    New-ItemProperty -Path "$($Global:Settings."Registry Settings"."Registry Directory")\$AppId" -Name "AppNewVersion" -Value "$AppCurrentVersion" -PropertyType String -Force | Out-Null
    New-ItemProperty -Path "$($Global:Settings."Registry Settings"."Registry Directory")\$AppId" -Name "AppDeferral" -Value "0" -PropertyType String -Force | Out-Null
    New-ItemProperty -Path "$($Global:Settings."Registry Settings"."Registry Directory")\$AppId" -Name "DaysSinceLastUpdate" -Value "0" -PropertyType String -Force | Out-Null
    New-ItemProperty -Path "$($Global:Settings."Registry Settings"."Registry Directory")\$AppId" -Name "DeferUntilICant" -Value "False" -PropertyType String -Force | Out-Null
    New-ItemProperty -Path "$($Global:Settings."Registry Settings"."Registry Directory")\$AppId" -Name "RecordUpdated" -Value "$formattedDateTime" -PropertyType String -Force | Out-Null
    New-ItemProperty -Path "$($Global:Settings."Registry Settings"."Registry Directory")\$AppId" -Name "UpdateFailedCount" -Value "0" -PropertyType String -Force | Out-Null
}


function UpdateRegistryFailedAppUpdate {
    param (
        [String]$AppId
    )
    $CurrentRegistryData = GetRegistryAppData -AppId $AppId
    $FailedCount = [int]$CurrentRegistryData."UpdateFailedCount" + 1
    $AppId = $AppId.replace(".", "_")
    $currentDateTime = Get-Date
    $formattedDateTime = $currentDateTime.ToString("yyyy-MM-dd HH:mm:ss")
    # Update count of failed updates
    writeLog "UpdateRegistryFailedAppUpdate - $AppId - FailedCount: $FailedCount"
    New-ItemProperty -Path "$($Global:Settings."Registry Settings"."Registry Directory")\$AppId" -Name "UpdateFailedCount" -Value "$FailedCount" -PropertyType String -Force | Out-Null
    # Update Failed date time if its the first failure
    if ($FailedCount -eq 1) {
        writeLog "UpdateRegistryFailedAppUpdate - $AppId - formattedDateTime: $formattedDateTime"
        New-ItemProperty -Path "$($Global:Settings."Registry Settings"."Registry Directory")\$AppId" -Name "UpdateFailedDate" -Value "$formattedDateTime" -PropertyType String -Force | Out-Null
    }
}

function ResetRegistryFailedAppUpdate {
    param (
        [String]$AppId
    )
    WriteLog "ResetRegistryFailedAppUpdate - Reseting Failed App Update count and date for $AppId"
    $AppId = $AppId.replace(".", "_")
    $currentDateTime = Get-Date
    $formattedDateTime = $currentDateTime.ToString("yyyy-MM-dd HH:mm:ss")
    New-ItemProperty -Path "$($Global:Settings."Registry Settings"."Registry Directory")\$AppId" -Name "UpdateFailedDate" -Value "$formattedDateTime" -PropertyType String -Force | Out-Null
    New-ItemProperty -Path "$($Global:Settings."Registry Settings"."Registry Directory")\$AppId" -Name "UpdateFailedCount" -Value "0" -PropertyType String -Force | Out-Null
}
function CheckSuccessfulUpdate {
    param ($app, $silent=$false)
    #TODO: Might need to check registry for versions for UNKNOWN version issues
    WriteLog "CheckSuccessfulUpdate - Checking if app exists after updating"
    Start-Sleep -Seconds 3
    $InstalledApps = GetInstalledWingetApps 
    $newapp = $null
    foreach ($installedApp in $InstalledApps) {
        if ($installedApp.Id -eq $app.id) {
            $newapp = $installedApp
            break
        }
    }

    if ($null -eq $newapp) {
        WriteLog "CheckSuccessfulUpdate - AppId $($app.id) not found in GetInstalledwingetApps after update"
        UpdateRegistryFailedAppUpdate -AppId $app.id
        
        if ($silent -eq $false) {
            CreateNotification -title "FAILED Updating $($app.name)" -Text "Failed Updating $($app.name) to $(NormalizeVersion $app.Available)"
        }

        return
    }
    
    WriteLog "CheckSuccessfulUpdate - AppId $($app.id) -AppCurrentVersion $(NormalizeVersion $newApp.version)"

    if ( (NormalizeVersion $newApp.Version) -ge (NormalizeVersion $app.Available) ) {
        WriteLog "CheckSuccessfulUpdate - Finished Updating $($app.name) to $(NormalizeVersion $newApp.Version) Successfully"
        WingetAppCompletedUpdate -AppId $app.id -AppCurrentVersion $newApp.version 
        if ($silent -eq $false) {
            CreateNotification -title "Finished Updating $($app.name)" -Text "Finished Updating $($app.name) to $(NormalizeVersion $newApp.Version) Successfully"
        }
    }
    else {
        WriteLog "CheckSuccessfulUpdate - $($app.id) The new version 'newApp' $(NormalizeVersion $newApp.Version) does not match the expected version 'app.available' $(NormalizeVersion $app.Available)"
        UpdateRegistryFailedAppUpdate -AppId $app.id
        if ($silent -eq $false) {
            CreateNotification -title "FAILED Updating $($app.name)" -Text "Failed Updating $($app.name) Current version: $($newApp.Version) -> Expected version $(NormalizeVersion $app.Available)"
        }
    }
}

function KillAppIfFound {
    param (
        [string]$AppId
    )
    if (($global:Settings."Application Process Names"."Process Names").ContainsKey($AppId)) {
        $processName = $global:Settings."Application Process Names"."Process Names"."$AppId"
        if (Get-Process | Where-Object { $_.ProcessName -eq $processName }) {
            WriteLog "KillAppIfFound - Killing $($processName) before updating."
            Stop-Process -Name $processName -Force
        }
        else {
            WriteLog "KillAppIfFound - $AppId does not exist in the AppProcessNames table."
        }
    }
}

function installSilentUpdates {
    WriteLog "installSilentUpdates - Installing silent updates"
    $UpdatedAnApp = $False
    RemoveFailedAppsFromUpgradableApps
    foreach ( $app in $Global:UpgradableApps ) {
        # Check if the key exists so we can install sliently if its not open
        if (($global:Settings."Application Process Names"."Process Names").ContainsKey($app.ID)) {
            # Found silent update process name
            if (Get-Process | Where-Object { $_.ProcessName -eq $global:Settings."Application Process Names"."Process Names"."$($app.id)" }) {
                WriteLog "installSilentUpdates - $($global:Settings."Application Process Names"."Process Names"."$($app.id)") is currently running. unable to silently install"
            } 
            else {
                WriteLog "installSilentUpdates - $($app.name) installing silently."
                if ($Global:Settings."User Experience"."Notifications"."Show Silent Notifications") {
                    CreateNotification -title "Updating $($app.name)" -text "Updating $($app.name) in the background"
                }

                $UpdatedAnApp = $True

                # Update the app
                UpgradeApp -AppId $app.ID 
                
                # Check if the app exists after updating
                if ($Global:Settings."User Experience"."Notifications"."Show Silent Notifications") {
                    CheckSuccessfulUpdate -app $app -silent $false
                }
                else {
                    CheckSuccessfulUpdate -app $app -silent $true
                }
                
            }
        } 
        else {
            WriteLog "installSilentUpdates - $($app.id) doesnt have a process to check for in Settings[Application Process Names][Process Names]"
        }
    }
    if ($UpdatedAnApp -eq $True) {
        WriteLog "installSilentUpdates - Silent Updates found. Refreshing upgradable apps."
        $Global:UpgradableApps = GetUpgradableApps
        
    }
       
}
function LoadAssembly {
    param (
        [string]$AssemblyName
    )

    $assembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq $AssemblyName }
    if ( $null -eq $assembly ) {
        # Assembly is not loaded, so load it
        Add-Type -AssemblyName $AssemblyName
        WriteLog "LoadAssembly - Loaded $AssemblyName assembly."
    }
}

function UpdateRegistryDeferralAmount {
    param (
        [String]$AppId,
        [int]$DeferralAmount
    )
    $AppId = $AppId.replace(".", "_")
    New-ItemProperty -Path "$($Global:Settings."Registry Settings"."Registry Directory")\$AppId" -Name "AppDeferral" -Value "$DeferralAmount" -PropertyType String -Force | Out-Null
}

function UpdateRegistryDefferUntilICantToTrue {
    param (
        [String]$AppId
    )
    $AppId = $AppId.replace(".", "_")
    New-ItemProperty -Path "$($Global:Settings."Registry Settings"."Registry Directory")\$AppId" -Name "DeferUntilICant" -Value "True" -PropertyType String -Force | Out-Null
}

function CreateMainRegistryDirectory {
    if (!(Test-Path "$($Global:Settings."Registry Settings"."Registry Directory")")) {
        New-Item "$($Global:Settings."Registry Settings"."Registry Directory")" -Force | Out-Null
    }
}

function CreateAppRegistryKeys {
    param (
        [System.Array]$App,
        [String]$AppDeferral = "0",
        [String]$DaysSinceLastUpdate = "0", 
        [String]$DeferUntilICant = "False"
    )
    $AppId = ($App.Id).replace(".", "_")
    $AppNewVersion = $App.Available
    $AppCurrentVersion = $App.Version
    $currentDateTime = Get-Date
    $formattedDateTime = $currentDateTime.ToString("yyyy-MM-dd HH:mm:ss")
    
    if (!(Test-Path "$($Global:Settings."Registry Settings"."Registry Directory")\$AppId")) {
        New-Item "$($Global:Settings."Registry Settings"."Registry Directory")\$AppId" -Force | Out-Null
        New-ItemProperty -Path "$($Global:Settings."Registry Settings"."Registry Directory")\$AppId" -Name "AppCurrentVersion" -Value "$AppCurrentVersion" -PropertyType String -Force | Out-Null
        New-ItemProperty -Path "$($Global:Settings."Registry Settings"."Registry Directory")\$AppId" -Name "AppNewVersion" -Value "$AppNewVersion" -PropertyType String -Force | Out-Null
        New-ItemProperty -Path "$($Global:Settings."Registry Settings"."Registry Directory")\$AppId" -Name "AppDeferral" -Value "$AppDeferral" -PropertyType String -Force | Out-Null
        New-ItemProperty -Path "$($Global:Settings."Registry Settings"."Registry Directory")\$AppId" -Name "DaysSinceLastUpdate" -Value "$DaysSinceLastUpdate" -PropertyType String -Force | Out-Null
        New-ItemProperty -Path "$($Global:Settings."Registry Settings"."Registry Directory")\$AppId" -Name "DeferUntilICant" -Value "$DeferUntilICant" -PropertyType String -Force | Out-Null
        New-ItemProperty -Path "$($Global:Settings."Registry Settings"."Registry Directory")\$AppId" -Name "RecordUpdated" -Value "$formattedDateTime" -PropertyType String -Force | Out-Null
        New-ItemProperty -Path "$($Global:Settings."Registry Settings"."Registry Directory")\$AppId" -Name "UpdateAvailableDate" -Value "$formattedDateTime" -PropertyType String -Force | Out-Null
        New-ItemProperty -Path "$($Global:Settings."Registry Settings"."Registry Directory")\$AppId" -Name "UpdateFailedCount" -Value "0" -PropertyType String -Force | Out-Null
        New-ItemProperty -Path "$($Global:Settings."Registry Settings"."Registry Directory")\$AppId" -Name "UpdateFailedDate" -Value "$formattedDateTime" -PropertyType String -Force | Out-Null
    }
}

function GetRegistryAppData {
    param (
        [String]$AppId
    )
    $AppId = $AppId.replace(".", "_")
    return get-itemproperty -path "$($Global:Settings."Registry Settings"."Registry Directory")\$AppId"
}

function SetRegistryAppUpdateAvailableDate {
    param (
        [String]$AppId
    )
    WriteLog "SetRegistryAppUpdateAvailableDate - Setting UpdateAvailableDate for $AppId"
    $AppId = $AppId.replace(".", "_")
    $currentDateTime = Get-Date
    $formattedDateTime = $currentDateTime.ToString("yyyy-MM-dd HH:mm:ss")
    New-ItemProperty -Path "$($Global:Settings."Registry Settings"."Registry Directory")\$AppId" -Name "UpdateAvailableDate" -Value "$formattedDateTime" -PropertyType String -Force | Out-Null
}

function SetRegistryAppNewVersion {
    param (
        [String]$AppId,
        [String]$AppNewVersion
    )
    WriteLog "SetRegistryAppNewVersion - Setting AppNewVersion for $AppId"
    $AppId = $AppId.replace(".", "_")
    New-ItemProperty -Path "$($Global:Settings."Registry Settings"."Registry Directory")\$AppId" -Name "AppNewVersion" -Value "$AppNewVersion" -PropertyType String -Force | Out-Null
}

function SetRegistryAppCurrentVersion {
    param (
        [String]$AppId,
        [String]$AppCurrentVersion
    )
    writeLog "SetRegistryAppCurrentVersion - Setting AppCurrentVersion for $AppId"
    $AppId = $AppId.replace(".", "_")
    New-ItemProperty -Path "$($Global:Settings."Registry Settings"."Registry Directory")\$AppId" -Name "AppCurrentVersion" -Value "$AppCurrentVersion" -PropertyType String -Force | Out-Null
}

function SetRegistryAppDaysSinceLastUpdate {
    param (
        [String]$AppId,
        [String]$DaysSinceLastUpdate
    )
    WriteLog "SetRegistryAppDaysSinceLastUpdate - Setting DaysSinceLastUpdate for $AppId to $DaysSinceLastUpdate"
    $AppId = $AppId.replace(".", "_")
    New-ItemProperty -Path "$($Global:Settings."Registry Settings"."Registry Directory")\$AppId" -Name "DaysSinceLastUpdate" -Value "$DaysSinceLastUpdate" -PropertyType String -Force | Out-Null
}

function UpdateAppRegistryForDisplay {
    foreach ( $app in $Global:UpgradableApps ) {
        $registryAppData = GetRegistryAppData -AppId $app.id

        # Update current version of app into reg because it updated from another source
        if ((NormalizeVersion $registryAppData.AppCurrentVersion) -ne (NormalizeVersion $app.version)) {
            WriteLog "UpdateAppRegistryForDisplay - Updating Registry current version of $($app.name) to $(NormalizeVersion $app.version) because it was updated from another source"
            SetRegistryAppCurrentVersion -AppId $app.id -AppCurrentVersion (NormalizeVersion $app.version)
            # Refresh the data 
            $registryAppData = GetRegistryAppData -AppId $app.id
        }

        # Is this a new update or was there a new release on top of the current pending release?
        if ( (NormalizeVersion $app.Available) -ne (NormalizeVersion $registryAppData.appNewVersion) ) {
            WriteLog "UpdateAppRegistryForDisplay - $($app.name) Update Available $(NormalizeVersion $app.Available) -NE Registry Available $(NormalizeVersion $registryAppData.appNewVersion)"

            # Does the registry current version and new version match?
            # The versions only match after app gets updated
            if ( (NormalizeVersion $registryAppData.AppCurrentVersion) -ne (NormalizeVersion $registryAppData.AppNewVersion)) {
                WriteLog "UpdateAppRegistryForDisplay - $($app.name) new version came through but the user hasnt updated the previous new version"
                # new version came through but the user hasnt updated the previous new version
                # If these are not equal to eachother it means a new update came through
                # but the user is now 2 or more versions behind
                # Make sure days since last update DOES NOT update
                # We shouldnt care to take note of when this specific update was available
                # TODO: For fun we can make a new registry to keep track of this specific update finding

                # set the date when an update was available
                SetRegistryAppUpdateAvailableDate -AppId $app.id
            }

            # Now set the app new version 
            SetRegistryAppNewVersion -AppId $app.id -AppNewVersion $app.Available
        }

        # Refresh the data 
        $registryAppData = GetRegistryAppData -AppId $app.id

        # Calculate days since last update
        $RegistryUpdateAvailableDate = [datetime]::ParseExact($registryAppData.UpdateAvailableDate, "yyyy-MM-dd HH:mm:ss", $null)
        $CurrentDate = Get-Date
        $DaysSinceLastUpdate = ($CurrentDate - $RegistryUpdateAvailableDate).Days
        SetRegistryAppDaysSinceLastUpdate -AppId $app.id -DaysSinceLastUpdate $DaysSinceLastUpdate
    }
}

function DownloadFile {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Url,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    try {
        writeLog "DownloadFile - Downloading image from $Url to $OutputPath"
        Invoke-WebRequest -Uri $Url -OutFile $OutputPath -UseBasicParsing
        WriteLog "DownloadFile - Image downloaded successfully to $OutputPath"
    }
    catch {
        WriteLog "Failed to download image. Error: $_"
        WriteLog "Error in DownloadFile function" 
        WriteLog "Message       : $($_.Exception.Message)" 
        WriteLog "StackTrace    : $($_.Exception.StackTrace)" 
        WriteLog "Line Number   : $($_.InvocationInfo.ScriptLineNumber)" 
        WriteLog "Line          : $($_.InvocationInfo.Line)" 
        WriteLog "Script Name   : $($_.InvocationInfo.ScriptName)"
    }
}


function Convert-PngToIco {
    param (
        [Parameter(Mandatory=$true)]
        [string]$PngPath,

        [Parameter(Mandatory=$true)]
        [string]$IcoOutputPath,

        [int]$IconSize = 64
    )

    LoadAssembly "System.Drawing"

    if (-not (Test-Path $PngPath)) {
        writelog "Convert-PngToIco - PNG file not found: $PngPath"
        return
    }
    try {
        $bmp = New-Object System.Drawing.Bitmap $PngPath

        # Resize the image if necessary
        if ($bmp.Width -ne $IconSize -or $bmp.Height -ne $IconSize) {
            $bmp = New-Object System.Drawing.Bitmap $bmp, $IconSize, $IconSize
        }

        # Convert to icon in memory
        $stream = New-Object System.IO.MemoryStream
        $iconWriter = New-Object System.IO.BinaryWriter $stream

        # Write ICO header
        $iconWriter.Write([UInt16]0)      # Reserved
        $iconWriter.Write([UInt16]1)      # ICO type
        $iconWriter.Write([UInt16]1)      # Number of images

        # Icon directory entry
        $iconWriter.Write([Byte]$bmp.Width)   # Width
        $iconWriter.Write([Byte]$bmp.Height)  # Height
        $iconWriter.Write([Byte]0)            # Color palette
        $iconWriter.Write([Byte]0)            # Reserved
        $iconWriter.Write([UInt16]1)          # Color planes
        $iconWriter.Write([UInt16]32)         # Bits per pixel

        # Reserve space for image size and offset
        $imageDataStream = New-Object System.IO.MemoryStream
        $bmp.Save($imageDataStream, [System.Drawing.Imaging.ImageFormat]::Png)
        $imageData = $imageDataStream.ToArray()

        $iconWriter.Write([UInt32]$imageData.Length)
        $iconWriter.Write([UInt32]22) # offset after header (6 bytes) + entry (16 bytes)

        # Append PNG image data
        $iconWriter.Write($imageData)

        # Write stream to file
        [System.IO.File]::WriteAllBytes("$($IcoOutputPath.split(".")[0])_temp.ico", $stream.ToArray())
        copy-item "$($IcoOutputPath.split(".")[0])_temp.ico" $IcoOutputPath -Force
        remote-item "$($IcoOutputPath.split(".")[0])_temp.ico" -Force

        WriteLog "Convert-PngToIco - ICO saved to: $IcoOutputPath"
        
    }
    catch {
        WriteLog "Error in Convert-PngToIco function" 
        WriteLog "Message       : $($_.Exception.Message)" 
        WriteLog "StackTrace    : $($_.Exception.StackTrace)" 
        WriteLog "Line Number   : $($_.InvocationInfo.ScriptLineNumber)" 
        WriteLog "Line          : $($_.InvocationInfo.Line)" 
        WriteLog "Script Name   : $($_.InvocationInfo.ScriptName)"
    }
}


function ProcessImages {
    LoadAssembly 'System.Drawing'

    WriteLog "ProcessImages - Processing Images"
    foreach ($Graphic in $Global:Settings.Graphics.Keys) {
        # Check if we need this image
        if (!($Global:Settings.Graphics."$Graphic"."Use Image")) {
            WriteLog "ProcessImages - SKIPPING $Graphic image"
            Continue
        }
        WriteLog "ProcessImages - Processing $Graphic image"

        # Check if the image is already downloaded and if we need to redownload it
        if (Test-Path $Global:Settings.Graphics."$Graphic".Dark.Path) {
            # Check date modified to see if we need to redownload
            $lastModified = (Get-Item $Global:Settings.Graphics."$Graphic".Dark.Path).LastWriteTime
            # Check if date is less then settings date
            if ($lastModified -lt [datetime]$Global:Settings.Graphics."Image Reset Date".Value) {
                WriteLog "ProcessImages - $Graphic image downloaded $lastModified is less then $([datetime]$Global:Settings.Graphics."Image Reset Date".Value). Redownloading"
                DownloadFile -Url "$($Global:Settings.Graphics."$Graphic".Dark.Url)" -OutputPath "$($Global:Settings.Graphics."$Graphic".Dark.Path)"
            }
        }
        if (Test-Path $Global:Settings.Graphics."$Graphic".Light.Path) {
            # Check date modified to see if we need to redownload
            $lastModified = (Get-Item $Global:Settings.Graphics."$Graphic".Light.Path).LastWriteTime
            # Check if date is less then settings date
            if ($lastModified -lt [datetime]$Global:Settings.Graphics."Image Reset Date".Value) {
                WriteLog "ProcessImages - $Graphic image downloaded $lastModified is less then $([datetime]$Global:Settings.Graphics."Image Reset Date".Value). Redownloading"
                DownloadFile -Url "$($Global:Settings.Graphics."$Graphic".Light.Url)" -OutputPath "$($Global:Settings.Graphics."$Graphic".Light.Path)"
            }
        }
        
        # Check path and download if missing
        if (!(Test-Path $Global:Settings.Graphics."$Graphic".Dark.Path)) {
            WriteLog "ProcessImages - downloading $Graphic image from $($Global:Settings.Graphics."$Graphic".Dark.Url)"
            DownloadFile -Url "$($Global:Settings.Graphics."$Graphic".Dark.Url)" -OutputPath "$($Global:Settings.Graphics."$Graphic".Dark.Path)"
            if (!(Test-Path $($Global:Settings.Graphics."$Graphic".Dark.Path))) { $Global:Settings.Graphics."$Graphic"."Use Image" = $False }
        }
        if (!(Test-Path $Global:Settings.Graphics."$Graphic".Light.Path)) {
            WriteLog "ProcessImages - downloading $($Graphic) image from $($Global:Settings.Graphics."$Graphic".Light.Url)"
            DownloadFile -Url "$($Global:Settings.Graphics."$Graphic".Light.Url)" -OutputPath "$($Global:Settings.Graphics."$Graphic".Light.Path)"
            if (!(Test-Path $($Global:Settings.Graphics."$Graphic".Light.Path))) { $Global:Settings.Graphics."$Graphic"."Use Image" = $False }
        }
    }

    # convert png to Icon
    if ($Global:Settings.Graphics."Notification Icon"."Use Image") {
        if ($Global:Settings.Graphics."Notification Icon".Dark.Path.split(".")[-1] -ne "ico") {
            $newPath = [System.IO.Path]::ChangeExtension($Global:Settings.Graphics."Notification Icon".Dark.Path, ".ico")
            if (!(test-path $newPath)) {
                # Resize the image to 64x64 before converting to ICO
                Convert-PngToIco -PngPath $Global:Settings.Graphics."Notification Icon".Dark.Path -IcoOutputPath $newPath -IconSize 64
            }
            
            $Global:Settings.Graphics."Notification Icon".Dark.Path = $newPath
        }
        if ($Global:Settings.Graphics."Notification Icon".Light.Path.split(".")[-1] -ne "ico") {
            $newPath = [System.IO.Path]::ChangeExtension($Global:Settings.Graphics."Notification Icon".Light.Path, ".ico")
            if (!(test-path $newPath)) {
                # Resize the image to 64x64 before converting to ICO
                Convert-PngToIco -PngPath $Global:Settings.Graphics."Notification Icon".Light.Path -IcoOutputPath $newPath -IconSize 64
            }
            
            $Global:Settings.Graphics."Notification Icon".Light.Path = $newPath
        }
    }

}

function CheckForMainWindowExit {
    # Used to figure out if there is any other actions required
    $ShouldExit = $True
    WriteLog "CheckForMainWindowExit - checking if we should exit main window"

    # Check if there are any default button states
    foreach ($i in 0..($Global:UpgradableApps.Length - 1)) {
        if ($Global:UpgradableApps[$i]["ButtonState"] -eq "Default" ) {
            $ShouldExit = $False
            break
        }
    }

    if ($ShouldExit) { 
        if ($Global:MainWindow.IsVisible) {
            WriteLog "CheckForMainWindowExit - No Default button states, Closing main window"
            $Global:MainWindow.close()
            
        }
        else {
            WriteLog "CheckForMainWindowExit - Main window is hasnt Opened yet and no Default button states"
        }
    }
    else {
        WriteLog "CheckForMainWindowExit - Main window is still open and has default button states"
    }
}

function ButtonFunction_UpdateApp {
    param ($sender_obj, $e, $delayed = $false)

    WriteLog "ButtonFunction_UpdateApp - $($sender_obj.name)"
    $rowid = [int]("$($sender_obj.name)".Trim("rowid_"))

    # Set the theme
    $currentTheme = $Global:Settings."User Experience"."Current Theme".Value
    
    # Only change how the button Looks and works if its not coming in as a delay. because its already changed from delay logic
    # Delay logic changes the button if it passes the maximum Deferral amount
    if (!($delayed)) { 
        # Add to this so we know the state of the button. Actioned means the button was clicked
        $Global:UpgradableApps[$rowid]["ButtonState"] = "Actioned"

        WriteLog "ButtonFunction_UpdateApp - hiding old buttons"
        # Hide old buttons
        foreach ($ChildButton in $Global:ButtonPanel[$rowid].children) {
            $ChildButton.Visibility = [System.Windows.Visibility]::Collapsed
        }

        WriteLog "ButtonFunction_UpdateApp - hiding old buttons finished"

        # Tag is used for color choices in the theme
        $buttonParams = @{
            ButtonText   = ""
            ButtonAction = { write-host "ButtonFunction_UpdateApp Blank" }
            Tag          = 'Update Clicked'
            Name         = "rowid_$($rowid)"
        }
        
        # Update the button to green checkmark with no text and no action
        if ($Global:Settings.Graphics."$($ButtonParams.Tag)"."Use Image") {
            $buttonParams.ButtonImagePath = $Global:Settings.Graphics."$($ButtonParams.Tag)"."$currentTheme".Path
            $Global:ButtonDictionairy[$rowid]["$($ButtonParams.Tag)"] = CreateImageButton @buttonParams
        }
        else {
            $buttonParams.ButtonColors = $Global:Settings.Themes."$currentTheme"."App Buttons"."$($ButtonParams.Tag)"
            #$buttonParams.ButtonText = "Updating...$([char]0x2705)"
            $buttonParams.ButtonText = "Queued $([char]0x2705)"
            $Global:ButtonDictionairy[$rowid]["$($ButtonParams.Tag)"] = CreateButton @buttonParams
        }
        $Global:ButtonPanel[$rowid].Children.Add($Global:ButtonDictionairy[$rowid]["$($ButtonParams.Tag)"]) | Out-Null
    }
    
    # update the app that was clicked
    WriteLog "ButtonFunctionUpdateApp - updating app $($Global:UpgradableApps[$rowid].Id)"
    try {
        WriteLog "ButtonFunctionUpdateApp - creating script block"

        # Create the script block that handles upgrading app
        $ScriptBlockUpgradeApp = {
            param ($App, $delayed)

            WriteLog "ButtonFunctionUpdateApp - Starting Upgrade for AppId: $($App.id) | AppAvailable: $($App.Available) | currentAppVersion: $($App.Version)"

            if ($delayed) {
                WriteLog "ButtonFunctionUpdateApp - starting delayed update app $($App.name) - sleeping $($Global:Settings.'User Experience'.'Count Down Seconds Force Update'.Value) seconds"
                CreateNotification -title "Save your work $($App.name)" -text "$($App.name) Update will start in $($Global:Settings.'User Experience'.'Count Down Seconds Force Update'.Value) seconds"
                Start-Sleep -Seconds $Global:Settings.'User Experience'.'Count Down Seconds Force Update'.Value
            }

            try {
                KillAppIfFound -AppId $App.id
                UpgradeApp $App.id
                WriteLog "ButtonFunctionUpdateApp - Finished app update $($App.id)"
                
                CheckSuccessfulUpdate -app $App
            } 
            catch {
                WriteLog "Error during update for app $($App.id): $_"
            }
        }

        # Add the job to the UpgradeJobs list
        $UpgradeJob = [PSCustomObject]@{
            ScriptBlock = $ScriptBlockUpgradeApp
            App         = $Global:UpgradableApps[$rowid]
            Delayed     = $delayed
        }

        $global:Settings.UpdateJobs.Add($UpgradeJob)
    
    }

    catch [Exception] {
        WriteLog "Error in ButtonFunction_UpdateApp function" 
        WriteLog "Message       : $($_.Exception.Message)" 
        WriteLog "StackTrace    : $($_.Exception.StackTrace)" 
        WriteLog "Line Number   : $($_.InvocationInfo.ScriptLineNumber)" 
        WriteLog "Line          : $($_.InvocationInfo.Line)" 
        WriteLog "Script Name   : $($_.InvocationInfo.ScriptName)"
    }

    CheckForMainWindowExit
}


function ButtonFunction_DeferApp {
    param ($sender_obj, $e, $SkipMainWindowCheck = $false)

    # Convert row id to int
    $rowid = [int]("$($sender_obj.name)".Trim("rowid_"))
    WriteLog "ButtonFunction_DeferApp - Deferring app with ID: $rowid"

    # Adjust button state to actioned so we know it was clicked
    $Global:upgradableApps[$rowid]["ButtonState"] = "Actioned"

    # Set the theme
    $currentTheme = $Global:Settings."User Experience"."Current Theme".Value

    # Hide old buttons
    WriteLog "ButtonFunction_DeferApp - Hiding old buttons"
    foreach ($ChildButton in $Global:ButtonPanel[$rowid].children) {
        $ChildButton.Visibility = [System.Windows.Visibility]::Collapsed
    }

    # Get current Deferral amount from registry
    $registryAppData = GetRegistryAppData -AppId $Global:UpgradableApps[$rowid].Id
    $MaxDeferralAmount = $Global:Settings."User Experience"."Max Deferral Amount".Value
    $CurrentDeferralAmount = [int]$registryAppData.AppDeferral + 1

    # Tag is used for color choices in the theme
    $buttonParams = @{
        ButtonText   = "Deferred $CurrentDeferralAmount/$MaxDeferralAmount"
        ButtonAction = { WriteLog "Defer Clicked Blank" }
        Tag          = "Defer Clicked"
        Name         = "rowid_$($rowid)"
    }
    
    # Create the new Deffer button
    if ($Global:Settings.Graphics."$($ButtonParams.Tag)"."Use Image") {
        $buttonParams.ButtonImagePath = $Global:Settings.Graphics."$($ButtonParams.Tag)"."$currentTheme".Path
        $Global:ButtonDictionairy[$rowid]["$($ButtonParams.Tag)"] = CreateImageButton @buttonParams
    }
    else {
        $buttonParams.ButtonColors = $Global:Settings.Themes."$currentTheme"."App Buttons"."$($ButtonParams.Tag)"
        $Global:ButtonDictionairy[$rowid]["$($ButtonParams.Tag)"] = CreateButton @buttonParams
    }

    # add to button panel
    $Global:ButtonPanel[$rowid].Children.Add($Global:ButtonDictionairy[$rowid]["$($ButtonParams.Tag)"]) | Out-Null

    # Set the Deferral registry
    UpdateRegistryDeferralAmount -AppId $Global:UpgradableApps[$rowid].Id -DeferralAmount $CurrentDeferralAmount

    # update the app
    WriteLog "ButtonFunction_DeferApp - Deffering app $($Global:UpgradableApps[$rowid].Id)"
    
    if ($SkipMainWindowCheck -eq $true) {
        WriteLog "ButtonFunction_DeferApp - Skipping CheckForMainWindowExit check"
    }
    else {
        # Check if we should close the main window
        CheckForMainWindowExit
    }
}

function ButtonFunction_DeferUntilICant {
    param ($sender_obj, $e)

    # Convert row id to int
    $rowid = [int]("$($sender_obj.name)".Trim("rowid_"))
    WriteLog "ButtonFunction_DeferUntilICant - Deferring until i cant app with ID: $rowid"

    # Adjust button state to actioned so we know it was clicked
    $Global:UpgradableApps[$rowid]["ButtonState"] = "Actioned"

    # Set the theme
    $currentTheme = $Global:Settings."User Experience"."Current Theme".Value

    # Hide old buttons
    foreach ($ChildButton in $Global:ButtonPanel[$rowid].children) {
        $ChildButton.Visibility = [System.Windows.Visibility]::Collapsed
    }


    $buttonParams = @{
        ButtonText   = "$($Global:Settings."User Experience"."Max Deferral Days".Value - [int]$registryAppData.DaysSinceLastUpdate) Days Left"
        ButtonAction = { WriteLog "Deferred Until Date Clicked Blank" }
        Tag          = "Deferred Until Date"
        Name         = "rowid_$($rowid)"
    }

    # Create a new Defer until i cant button
    if ($Global:Settings.Graphics."$($ButtonParams.Tag)"."Use Image") {
        $buttonParams.ButtonImagePath = $Global:Settings.Graphics."$($ButtonParams.Tag)"."$currentTheme"."Path"
        $Global:ButtonDictionairy[$rowid]["$($ButtonParams.Tag)"] = CreateImageButton @buttonParams
    }
    else {
        $buttonParams."ButtonColors" = $Global:Settings.Themes."$currentTheme"."App Buttons"."$($ButtonParams.Tag)"
        $Global:ButtonDictionairy[$rowid]["$($ButtonParams.Tag)"] = CreateButton @buttonParams
    }

    # add to button panel
    $Global:ButtonPanel[$rowid].Children.Add($Global:ButtonDictionairy[$rowid]["$($ButtonParams.Tag)"]) | Out-Null
    
    # set to defer true in registry
    UpdateRegistryDefferUntilICantToTrue -AppId $Global:upgradableApps[$rowid].Id

    # update the app
    WriteLog "ButtonFunction_DeferUntilICant - Deffering app $($upgradableApps[$rowid].Id)"

    CheckForMainWindowExit
}

function ButtonFunction_UpdateAllApps {
    param ($sender_obj, $e)
    WriteLog "ButtonFunction_UpdateAllApps - Upgrading All applications"

    $Global:BottomButtonPanel.Visibility = [System.Windows.Visibility]::Collapsed
    
    foreach ($i in 0..($Global:UpgradableApps.Length - 1)) {
        # Only action on apps if the buttons are in a default state
        if ($Global:UpgradableApps[$i]["ButtonState"] -eq "Default" ) {
            WriteLog "ButtonFunction_UpdateAllApps - Updating - $($Global:UpgradableApps[$i].id) "
            ButtonFunction_UpdateApp -sender_obj @{"name" = "rowid_$I" }
        }
        else {
            WriteLog "ButtonFunction_UpdateAllApps - Skipping $($Global:upgradableApps[$i].id) Button State is $($Global:upgradableApps[$i]["ButtonState"])"
        }
    }
    CheckForMainWindowExit
}


function ButtonFunction_DeferAllApps {
    param ($sender_obj, $e, $SkipMainWindowCheck = $false)
    WriteLog "ButtonFunction_DeferAllApps - Defer All Apps"

    $Global:BottomButtonPanel.Visibility = [System.Windows.Visibility]::Collapsed

    foreach ($i in 0..($Global:upgradableApps.Length - 1)) {

        if ($Global:upgradableApps[$i]["ButtonState"] -eq "Default" ) {
            WriteLog "ButtonFunction_DeferAllApps - Defering - $($Global:upgradableApps[$i].id) "
            if ($SkipMainWindowCheck -eq $true) {
                ButtonFunction_DeferApp -sender_obj @{"name" = "rowid_$I" } -SkipMainWindowCheck $true
            }
            else {
                ButtonFunction_DeferApp -sender_obj @{"name" = "rowid_$I" }
            }
        }
        else {
            WriteLog "ButtonFunction_DeferAllApps - Skipping $($Global:upgradableApps[$i].id) Button State is $($Global:upgradableApps[$i]["ButtonState"])"
        }

    }

    if ($SkipMainWindowCheck -eq $true) {
        WriteLog "ButtonFunction_DeferAllApps - Skipping CheckForMainWindowExit check"
    }
    else {
        # Check if we should close the main window
        CheckForMainWindowExit
    }
}

function ButtonFunction_DeferAllAppsUntilICant {
    param ($sender_obj, $e)
    WriteLog "ButtonFunction_DeferUntilICantAllApps - Defering until i cant All applications"

    foreach ($i in 0..($Global:upgradableApps.Length - 1)) {
        if ($Global:upgradableApps[$i]["ButtonState"] -eq "Default" ) {
            WriteLog "ButtonFunction_DeferUntilICantAllApps - Defering until i cant - $($Global:upgradableApps[$i].id) "
            ButtonFunction_DeferUntilICant -sender_obj @{"name" = "rowid_$I" }
        }
        else {
            WriteLog "ButtonFunction_DeferUntilICantAllApps - Skipping $($Global:upgradableApps[$i].id) Button State is $($Global:upgradableApps[$i]["ButtonState"])"
        }
    }

    $Global:BottomButtonPanel.Visibility = [System.Windows.Visibility]::Collapsed
    CheckForMainWindowExit
}

function HideAppRowButtons {
    param ([int]$rowIndex)
    WriteLog "HideAppRowButtons - Hiding buttons for row $rowIndex"
    $ButtonPanelcounter = 0  # keeps track of how many buttonpanels we found so we know what row to change
    $ContentGriditemCounter = 0  # Keeps track of which grid item we want to change
    foreach ($item in $Global:ContentGrid.children) {
        #WriteLog "$($item.name)"
        if ( "$($item.tag)" -eq "ButtonPanel") {
            #WriteLog $ButtonPanelcounter
            if ( $rowIndex -eq $ButtonPanelcounter ) {
                #WriteLog "$rowIndex -eq $ButtonPanelcounter"
                if ($item.ContainsKey("Visibility")) {
                    $item.Visibility = [System.Windows.Visibility]::Collapsed
                }
                if ($Global:ContentGrid.children[$ContentGriditemCounter].ContainsKey("Visibility")) {
                    $Global:ContentGrid.children[$ContentGriditemCounter].Visibility = [System.Windows.Visibility]::Collapsed
                }
                break
            } 
            # Only goes up if you find a button panel but i think its not creating the dummy header button panel
            # In the main i did a i++ but should probably fix this at some point
            $ButtonPanelcounter++
        }
        $ContentGriditemCounter++
    }
}

function ButtonFunction_UpdateTheme {
    WriteLog "ButtonFunction_UpdateTheme - Changing Theme"

    if ($Global:Settings."User Experience"."Current Theme".Value -eq "Dark") {
        WriteLog "Theme is currently Dark, changing to Light"
        $Global:Settings."User Experience"."Current Theme".Value = "Light"
        New-ItemProperty -Path $Global:Settings."Registry Settings"."Registry Directory" -Name "IsDarkMode" -Value "false" -PropertyType String -Force | Out-Null
        $currentTheme = "Light"
    } 
    else {
        WriteLog "Theme is currently Light, changing to Dark"
        $Global:Settings."User Experience"."Current Theme".Value = "Dark"
        New-ItemProperty -Path $Global:Settings."Registry Settings"."Registry Directory" -Name "IsDarkMode" -Value "true" -PropertyType String -Force | Out-Null
        $currentTheme = "Dark"
    }

    # Change the text color for Bottom dock and Scroll viewer content
    WriteLog "ButtonFunction_UpdateTheme - Changing App Buttons background colors - $currentTheme"
    ChangeTextColors -wpfObejct $Global:ContentGrid -currentTheme $currentTheme -type "App Buttons"
    WriteLog "ButtonFunction_UpdateTheme - Changing Dock Buttons background colors - $currentTheme"
    ChangeTextColors -wpfObejct $Global:BottomButtonPanel -currentTheme $currentTheme -type "Dock Buttons"

    try {
        $brushConverter = New-Object System.Windows.Media.BrushConverter

        WriteLog "ButtonFunction_UpdateTheme - Changing Header Text background colors - $currentTheme"
        $Global:TitleText.Foreground = $brushConverter.ConvertFromString($Global:Settings.Themes."$currentTheme"."Header Text")
        
        
        
        WriteLog "ButtonFunction_UpdateTheme - Changing Content panel background colors - $currentTheme"
        $Global:ScrollViewer.background = $brushConverter.ConvertFromString($Global:Settings.Themes."$currentTheme"."Content Background")
        
        WriteLog "ButtonFunction_UpdateTheme - Changing Dock panel background colors - $currentTheme"
        $Global:DockPanel.Background = $brushConverter.ConvertFromString($Global:Settings.Themes."$currentTheme"."Dock Background")

        WriteLog "ButtonFunction_UpdateTheme - Changing Progress Bar colors - $currentTheme"
        $Global:ProgressBar.BorderBrush = $Global:Settings."Themes"."$currentTheme"."Dock Buttons"."Window Countdown Timer"."Border"
        $Global:ProgressBar.Background = $Global:Settings."Themes"."$currentTheme"."Dock Buttons"."Window Countdown Timer"."ProgressBarBackground"
        $Global:ProgressBarProgressBar.Foreground = $Global:Settings."Themes"."$currentTheme"."Dock Buttons"."Window Countdown Timer"."ProgressBarFill"
        $Global:ProgressBarProgressBar.Background = $Global:Settings."Themes"."$currentTheme"."Dock Buttons"."Window Countdown Timer"."ProgressBarBackground"
        $Global:ProgressBarClock.Foreground = $Global:Settings."Themes"."$currentTheme"."Text"
        $Global:ProgressBarGrid.Background = $Global:Settings."Themes"."$currentTheme"."Dock Buttons"."Window Countdown Timer"."ProgressBarBackground"

        # Change theme button text
        WriteLog "ButtonFunction_UpdateTheme - Changing Theme Button Text - $currentTheme"
        foreach ($ChildButton in $Global:BottomButtonPanel.Children) {
            if ($ChildButton.Name -eq "Theme") {
                if ($currentTheme -eq "Dark") {$ChildButton.Content = "Light Mode"}
                else {$ChildButton.Content = "Dark Mode"}
            }
        }

        # Company logo changes
        if ($Global:Settings.Graphics."Company Logo"."Use Image") {
            WriteLog "ButtonFunction_UpdateTheme - Changing Company Logo background colors - $currentTheme"
            if (Test-Path "$($Global:Settings.Graphics."Company Logo"."$currentTheme"."Path")") {
                $Global:CompanyLogoImage.source = [System.Windows.Media.Imaging.BitmapImage]::new(
                    [System.Uri]::new("$($Global:Settings.Graphics."Company Logo"."$currentTheme"."Path")")
                )
            }
            else {
                WriteLog "ButtonFunction_UpdateTheme - Error: $($Global:Settings.Graphics."Company Logo"."$currentTheme"."Path") does not exist"
            }
        }

        # Header logo changes
        if ($Global:Settings.Graphics."Header Background"."Use Image") {
            WriteLog "CreateGui - Loading Header Background Image $($Global:Settings.Graphics."Header Background"."$currentTheme"."Path")"
            $backgroundImageBrush = New-Object System.Windows.Media.ImageBrush
            $backgroundImageBrush.ImageSource = [System.Windows.Media.Imaging.BitmapImage]::new(
                [System.Uri]::new("$($Global:Settings.Graphics."Header Background"."$currentTheme"."Path")")
            )
            $Global:HeaderDockPanel.Background = $backgroundImageBrush
        }
        else {
            $brushConverter = New-Object System.Windows.Media.BrushConverter
            WriteLog "CreateGui - Settings Header panel background colors - $currentTheme" 
            $Global:HeaderDockPanel.background = $brushConverter.ConvertFromString($Global:Settings."Themes"."$currentTheme"."Header Background")
        }
    }
    catch {
        WriteLog "Error: Changing outer button colors"
        WriteLog "Error in ButtonFunction_UpdateTheme function" 
        WriteLog "Message       : $($_.Exception.Message)" 
        WriteLog "StackTrace    : $($_.Exception.StackTrace)" 
        WriteLog "Line Number   : $($_.InvocationInfo.ScriptLineNumber)" 
        WriteLog "Line          : $($_.InvocationInfo.Line)" 
        WriteLog "Script Name   : $($_.InvocationInfo.ScriptName)"
    }
}

function ChangeTextColors {
    param ($wpfObejct, $currentTheme, $type, $counter = 0)
    
    $outputdata = ""
    
    #  Capture current object data for logging
    try {
        if ($type) { $outputdata += " Type: $($type)" }
        if ($wpfObejct.Name) { $outputdata += " NAME: $($wpfObejct.Name)" }
        if ($wpfObejct.Tag) { $outputdata += " Tag: $($wpfObejct.Tag)" }
        if ($wpfObejct.Foreground) { $outputdata += " TextColor: $($wpfObejct.Foreground) TextType: $($wpfObejct.Foreground.gettype())" }
        if ($wpfObejct.Background) { $outputdata += " BackgroundColor: $($wpfObejct.Background) BackgroundType: $($wpfObejct.Background.gettype())" }
        WriteLog "ChangeTextColors - OBJECT: $($wpfObejct.gettype()) $outputdata"
    }
    catch [Exception] {
        WriteLog "Error: adding outputdata $($type) - $($wpfObejct.name) - $($wpfObejct.tag)"
        WriteLog "Error in ChangeTextColors function" 
        WriteLog "Message       : $($_.Exception.Message)" 
        WriteLog "StackTrace    : $($_.Exception.StackTrace)" 
        WriteLog "Line Number   : $($_.InvocationInfo.ScriptLineNumber)" 
        WriteLog "Line          : $($_.InvocationInfo.Line)" 
        WriteLog "Script Name   : $($_.InvocationInfo.ScriptName)"
    }

    # Change text color
    $brushConverter = New-Object System.Windows.Media.BrushConverter
    try {
        if ($wpfObejct.gettype() -is [System.Windows.Controls.StackPanel] -or $wpfObejct.gettype() -is [System.Windows.Controls.DockPanel]) {
            #WriteLog "ChangeTextColors - SKIPPING $($wpfObejct.gettype()) $outputdata"
            WriteLog "ChangeTextColors - SKIPPING $($wpfObejct.gettype())"
        } 
        elseif ($wpfObejct.Foreground) {
            WriteLog "ChangeTextColors - CHANGING $($wpfObejct.Tag) foreground color from $($wpfObejct.Foreground) to $($Global:Settings.Themes."$currentTheme"."Text")"
            $wpfObejct.Foreground = $brushConverter.ConvertFromString($Global:Settings.Themes."$currentTheme"."Text")
            #WriteLog "ChangeTextColors - Complete"
        }
    }
    catch [Exception] {
        WriteLog "Error: changing text $($type) - $($wpfObejct.name) - $($wpfObejct.tag)"
        WriteLog "Error in ChangeTextColors function" 
        WriteLog "Message       : $($_.Exception.Message)" 
        WriteLog "StackTrace    : $($_.Exception.StackTrace)" 
        WriteLog "Line Number   : $($_.InvocationInfo.ScriptLineNumber)" 
        WriteLog "Line          : $($_.InvocationInfo.Line)" 
        WriteLog "Script Name   : $($_.InvocationInfo.ScriptName)"
    }

    # Change background color or image depending on what it is
    try {
        if ($wpfObejct.gettype() -is [System.Windows.Controls.StackPanel] -or $wpfObejct.gettype() -is [System.Windows.Controls.DockPanel]) {
            WriteLog "ChangeTextColors - SKIPPING $($wpfObejct.gettype())"
        } 
        elseif ($wpfObejct.Background -and $wpfObejct.Tag -and ($wpfObejct.Background -is [System.Windows.Media.ImageBrush])) {
            # Change image
            if (Test-Path $Global:Settings.Graphics."$($wpfObejct.Tag)"."$currentTheme"."Path") {
                WriteLog "ChangeTextColors - CHANGING $($wpfObejct.Tag) background image from $($wpfObejct.Background) to $($Global:Settings.Graphics."$($wpfObejct.Tag)"."$currentTheme"."Path"))"
                $Image = New-Object System.Windows.Media.ImageBrush
                $Image.ImageSource = [System.Windows.Media.Imaging.BitmapImage]::new([System.Uri]::new($Global:Settings.Graphics."$($wpfObejct.Tag)"."$currentTheme"."Path"))
                $Image.Stretch = [System.Windows.Media.Stretch]::Fill
                $wpfObejct.Background = $Image
                WriteLog "ChangeTextColors - Complete Background change"
            }
            else {
                #TODO auto convert to regular button? since we cant find the image?
                WriteLog "Error: $($type) - $($wpfObejct.Tag) Path $($Global:Settings.Graphics."$($wpfObejct.Tag)"."$currentTheme"."Path") does not exist"
            }
            
        }
        elseif ($wpfObejct.Background -and $wpfObejct.Tag -and ($wpfObejct.Background -is [System.Windows.Media.SolidColorBrush])) {
            # Change brush by sending theme hash over
            WriteLog "ChangeTextColors - CHANGING $($wpfObejct.Tag) background color from $($wpfObejct.Background) to $($Global:Settings.Themes."$currentTheme"."$type"."$($wpfObejct.Tag)".Background)"
            UpdateButtonColors -Button $wpfObejct -NewColors $Global:Settings.Themes."$currentTheme"."$type"."$($wpfObejct.Tag)" -UserInterface $Global:Settings."User Interface"."$type"
        }
    }
    catch [Exception] {
        WriteLog "Error: changing background $($wpfObejct.name) - $($wpfObejct.tag)"
        WriteLog "Error in ChangeTextColors function" 
        WriteLog "Message       : $($_.Exception.Message)" 
        WriteLog "StackTrace    : $($_.Exception.StackTrace)" 
        WriteLog "Line Number   : $($_.InvocationInfo.ScriptLineNumber)" 
        WriteLog "Line          : $($_.InvocationInfo.Line)" 
        WriteLog "Script Name   : $($_.InvocationInfo.ScriptName)"
    }
    
    # recursivly change sub objects
    foreach ($object in $wpfObejct.children) {
        try {
            WriteLog "ChangeTextColors - Rerun Children sub objects children from $($type) - $($wpfObejct.name) - $($wpfObejct.tag)"
            ChangeTextColors -wpfObejct $object -currentTheme $currentTheme -type $type -counter ($counter + 4)
        }
        catch [Exception] {
            WriteLog "Error: Rerun sub objects children"
            WriteLog "Error in ChangeTextColors function" 
            WriteLog "Message       : $($_.Exception.Message)" 
            WriteLog "StackTrace    : $($_.Exception.StackTrace)" 
            WriteLog "Line Number   : $($_.InvocationInfo.ScriptLineNumber)" 
            WriteLog "Line          : $($_.InvocationInfo.Line)" 
            WriteLog "Script Name   : $($_.InvocationInfo.ScriptName)"
        }
    }
    foreach ($object in $wpfObejct.content) {
        try {
            WriteLog "ChangeTextColors - Rerun Content sub objects children from $($wpfObejct.name) - $($wpfObejct.tag)"
            ChangeTextColors -wpfObejct $object -currentTheme $currentTheme -type $type -counter ($counter + 4)
        }
        catch [Exception] {
            WriteLog "Error: Rerun sub objects content"
            WriteLog "Error in ChangeTextColors function" 
            WriteLog "Message       : $($_.Exception.Message)" 
            WriteLog "StackTrace    : $($_.Exception.StackTrace)" 
            WriteLog "Line Number   : $($_.InvocationInfo.ScriptLineNumber)" 
            WriteLog "Line          : $($_.InvocationInfo.Line)" 
            WriteLog "Script Name   : $($_.InvocationInfo.ScriptName)"
        }
    }
}

function UpdateButtonColors {
    param (
        [System.Windows.Controls.Button]$Button,
        [hashtable]$NewColors,
        [hashtable]$UserInterface
    )

    # Recreate the ControlTemplate with the new colors
    $xaml = @"
<ControlTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" 
                 xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
                 TargetType="Button">
    <ControlTemplate.Resources>
        <SolidColorBrush x:Key="NormalBackgroundBrush" Color="$($NewColors["Background"])" />
        <SolidColorBrush x:Key="HoverBackgroundBrush" Color="$($NewColors["Hover"])" />
        <SolidColorBrush x:Key="PressedBackgroundBrush" Color="$($NewColors["Pressed"])" />
        <SolidColorBrush x:Key="BorderBrushColor" Color="$($NewColors["Border"])" />
    </ControlTemplate.Resources>
    <Border x:Name="border" 
            CornerRadius="$($UserInterface."Corner Radius")"
            Background="{StaticResource NormalBackgroundBrush}" 
            BorderBrush="{StaticResource BorderBrushColor}" 
            BorderThickness="{TemplateBinding BorderThickness}">
        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center" />
    </Border>
    <ControlTemplate.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
            <Setter TargetName="border" Property="Background" Value="{StaticResource HoverBackgroundBrush}" />
        </Trigger>
        <Trigger Property="IsPressed" Value="True">
            <Setter TargetName="border" Property="Background" Value="{StaticResource PressedBackgroundBrush}" />
        </Trigger>
        <Trigger Property="IsEnabled" Value="False">
            <Setter TargetName="border" Property="Opacity" Value="0.5" />
        </Trigger>
    </ControlTemplate.Triggers>
</ControlTemplate>
"@

    # Apply the new ControlTemplate to the button
    $Button.Template = [Windows.Markup.XamlReader]::Parse($xaml)
}

function CreateButton {
    param (
        [string]$ButtonText,
        [ScriptBlock]$ButtonAction,
        [string]$Tag,
        [string]$Name,
        $ButtonColors = @{
            "Background" = "#2b2b2b"
            "Border"     = "#1760b0"
            "Hover"      = "#15599e"  # Slightly darker blue
            "Pressed"    = "#1760b0"
        },
        $TextSettings = @{
            "Width"            = $Global:Settings."User Interface"."App Buttons"."Width"
            "Height"           = $Global:Settings."User Interface"."App Buttons"."Height"
            "Margin"           = $Global:Settings."User Interface"."App Buttons"."Margin"
            "Font Family"      = $Global:Settings."User Interface"."App Buttons"."Font Family"
            "Font Size"        = $Global:Settings."User Interface"."App Buttons"."Font Size"
            "Font Weight"      = $Global:Settings."User Interface"."App Buttons"."Font Weight"
            "Font Style"       = $Global:Settings."User Interface"."App Buttons"."Font Style"
            "Font Stretch"     = $Global:Settings."User Interface"."App Buttons"."Font Stretch"
            "Corner Radius"    = $Global:Settings."User Interface"."App Buttons"."Corner Radius"
            "Border Thickness" = $Global:Settings."User Interface"."App Buttons"."Border Thickness"
        }
    )

    $currentTheme = $Global:Settings."User Experience"."Current Theme"."Value"

    # Create the button
    WriteLog "CreateButton - Creating button $currentTheme $Name : $Tag : $ButtonText"
    $Button = New-Object System.Windows.Controls.Button
    $Button.Width = $TextSettings['Width']
    $Button.Height = $TextSettings['Height']
    $Button.Tag = $Tag
    $Button.Name = "$(ReplaceSpecialCharacters $Name)"
    $Button.Content = $ButtonText
    $Button.BorderThickness = [System.Windows.Thickness]::new($TextSettings["Border Thickness"])
    $Button.Margin = $TextSettings['Margin']

    # Example of applying different font styles
    $Button.FontFamily = $TextSettings['Font Family']
    $Button.FontSize = $TextSettings['Font Size']
    $Button.FontWeight = $TextSettings['Font Weight']
    $Button.FontStyle = $TextSettings['Font Style']
    $Button.FontStretch = $TextSettings['Font Stretch']
    $Button.Foreground = $Global:Settings."Themes"."$currentTheme"."Text"

    
    # Define a ControlTemplate for the button to give it rounded corners
    # Define a ControlTemplate for the button with inline resources for background and border colors
    $xaml = @"
<ControlTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" 
                 xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
                 TargetType="Button">
    <ControlTemplate.Resources>
        <SolidColorBrush x:Key="NormalBackgroundBrush" Color="$($ButtonColors["Background"])" />
        <SolidColorBrush x:Key="HoverBackgroundBrush" Color="$($ButtonColors["Hover"])" />
        <SolidColorBrush x:Key="PressedBackgroundBrush" Color="$($ButtonColors["Pressed"])" />
        <SolidColorBrush x:Key="BorderBrushColor" Color="$($ButtonColors["Border"])" />
    </ControlTemplate.Resources>
    <Border x:Name="border" 
            CornerRadius="$($TextSettings["Corner Radius"])" 
            Background="{StaticResource NormalBackgroundBrush}" 
            BorderBrush="{StaticResource BorderBrushColor}" 
            BorderThickness="{TemplateBinding BorderThickness}">
        <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center" />
    </Border>
    <ControlTemplate.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
            <Setter TargetName="border" Property="Background" Value="{StaticResource HoverBackgroundBrush}" />
        </Trigger>
        <Trigger Property="IsPressed" Value="True">
            <Setter TargetName="border" Property="Background" Value="{StaticResource PressedBackgroundBrush}" />
        </Trigger>
        <Trigger Property="IsEnabled" Value="False">
            <Setter TargetName="border" Property="Opacity" Value="0.5" />
        </Trigger>
    </ControlTemplate.Triggers>
</ControlTemplate>
"@

    # Parse xaml
    $Button.Template = [Windows.Markup.XamlReader]::Parse($xaml)
    
    # Add click event handler
    $Button.Add_Click($ButtonAction)

    return $Button
}

function CreateImageButton {
    param (
        [string]$ButtonText,
        [string]$ButtonImagePath,
        [ScriptBlock]$ButtonAction,
        [string]$Tag,
        [string]$Name,
        $TextSettings = @{
            "Width"            = $Global:Settings."User Interface"."App Buttons"."Width"
            "Height"           = $Global:Settings."User Interface"."App Buttons"."Height"
            "Margin"           = $Global:Settings."User Interface"."App Buttons"."Margin"
            "Font Family"      = $Global:Settings."User Interface"."App Buttons"."Font Family"
            "Font Size"        = $Global:Settings."User Interface"."App Buttons"."Font Size"
            "Font Weight"      = $Global:Settings."User Interface"."App Buttons"."Font Weight"
            "Font Style"       = $Global:Settings."User Interface"."App Buttons"."Font Style"
            "Font Stretch"     = $Global:Settings."User Interface"."App Buttons"."Font Stretch"
            "Corner Radius"    = $Global:Settings."User Interface"."App Buttons"."Corner Radius"
            "Border Thickness" = $Global:Settings."User Interface"."App Buttons"."Border Thickness"
        }
    )

    $currentTheme = $Global:Settings."User Experience"."Current Theme".Value

    # Create the button
    WriteLog "CreateImageButton - Creating button $Name : $Tag : $ButtonText : $ButtonImagePath"
    $Button = New-Object System.Windows.Controls.Button
    $Button.Width = $TextSettings['Width']
    $Button.Height = $TextSettings['Height']
    $Button.Tag = $Tag
    $Button.Name = "$(ReplaceSpecialCharacters $Name)"
    $Button.BorderThickness = [System.Windows.Thickness]::new(0) # Remove the border
    $Button.Background = [System.Windows.Media.Brushes]::Transparent # Make the background transparent
    $Button.Margin = $TextSettings['Margin']
    
    # Create a Grid to hold the image and text
    $ButtonGrid = New-Object System.Windows.Controls.Grid

    # Load the background image
    $Image = New-Object System.Windows.Media.ImageBrush
    $Image.ImageSource = [System.Windows.Media.Imaging.BitmapImage]::new([System.Uri]::new("$ButtonImagePath"))
    $Image.Stretch = [System.Windows.Media.Stretch]::Fill
    $Button.Background = $Image

    # Create a TextBlock for the button text
    $TextBlock = New-Object System.Windows.Controls.TextBlock
    $TextBlock.FontFamily = $TextSettings['Font Family']
    $TextBlock.FontSize = $TextSettings['Font Size']
    $TextBlock.FontWeight = $TextSettings['Font Weight']
    $TextBlock.FontStyle = $TextSettings['Font Style']
    $TextBlock.FontStretch = $TextSettings['Font Stretch']
    $TextBlock.Foreground = $Global:Settings."Themes"."$currentTheme"."Text"
    $TextBlock.Text = $ButtonText
    $TextBlock.HorizontalAlignment = 'Center'
    $TextBlock.VerticalAlignment = 'Center'

    # Place the text block on top of the image
    $ButtonGrid.Children.Add($TextBlock) | Out-Null

    # Set the ButtonGrid as the button content
    $Button.Content = $ButtonGrid

    # Add click event handler
    $Button.Add_Click($ButtonAction) | Out-Null

    return $Button
}

function CreateTimerLabelAndProgressBar {
    writelog "CreateTimerLabelAndProgressBar - Creating Timer Label and ProgressBar"
    $currentTheme = $Global:Settings."User Experience"."Current Theme".Value
    $Textcolor = $Global:Settings."Themes"."$currentTheme"."Text"
    $ProgressBarFill = $Global:Settings."Themes"."$currentTheme"."Dock Buttons"."Window Countdown Timer"."ProgressBarFill"
    $ProgressBarBackground = $Global:Settings."Themes"."$currentTheme"."Dock Buttons"."Window Countdown Timer"."ProgressBarBackground"
    $BorderColor = $Global:Settings."Themes"."$currentTheme"."Dock Buttons"."Window Countdown Timer"."Border"
    $TextSettings = $Global:Settings."User Interface"."Window Countdown Timer"

    # Create XAML for the Label and ProgressBar
    $xaml = @"
<Border xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        BorderThickness="$($TextSettings["Border Thickness"])" BorderBrush="$BorderColor" 
        CornerRadius="$($TextSettings["Corner Radius"])" Margin="$($TextSettings["Margin"])" 
        Width="$($TextSettings["Width"])" Height="$($TextSettings["Height"])" Background="$ProgressBarBackground">
    <Grid x:Name="Grid" Background="$ProgressBarBackground">
        <!-- ProgressBar -->
        <ProgressBar x:Name="ProgressBar" Height="$($TextSettings["Height"])" 
        Minimum="0" Maximum="100" Value="100" 
        Foreground="$ProgressBarFill" Background="$ProgressBarBackground"/>
        <!-- Label (Clock) -->
        <Label x:Name="Clock" Content="00:00" HorizontalAlignment="Center" VerticalAlignment="Center" 
        Foreground="$Textcolor" FontSize="$($TextSettings["Font Size"])" FontFamily="$($TextSettings["Font Family"])" 
        FontWeight="$($TextSettings["Font Weight"])" FontStyle="$($TextSettings["Font Style"])" FontStretch="$($TextSettings["Font Stretch"])"
         />
    </Grid>
</Border>
"@

    # Load the Grid from XAML
    $xmlReader = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
    $Global:ProgressBar = [Windows.Markup.XamlReader]::Load($xmlReader)

    # Find the Label and ProgressBar in the Grid
    $Global:ProgressBarGrid = $Global:ProgressBar.FindName("Grid")
    $Global:ProgressBarClock = $Global:ProgressBar.FindName("Clock")
    $Global:ProgressBarProgressBar = $Global:ProgressBar.FindName("ProgressBar")

    # Set up the timer
    writelog "CreateTimerLabelAndProgressBar - Settings end time with $($Global:Settings."User Experience"."Window Countdown Timer"."Value") minutes"
    $Global:ProgressBarEndTime = (Get-Date).AddMinutes($Global:Settings."User Experience"."Window Countdown Timer"."Value")  # Set the end time for the countdown
    $Global:ProgressBarTotalDuration = ($Global:ProgressBarEndTime - (Get-Date)).TotalSeconds  # Total countdown duration in seconds

    # Create a DispatcherTimer to update the Label and ProgressBar
    $Global:ProgressBarDispatcher = New-Object System.Windows.Threading.DispatcherTimer
    $Global:ProgressBarDispatcher.Interval = [TimeSpan]"0:0:1"  # Update every second

    $Global:ProgressBarDispatcher.Add_Tick({
        # Calculate the remaining time
        $RemainingTime = $Global:ProgressBarEndTime - (Get-Date)

        if ($RemainingTime.TotalSeconds -le 0) {
            # Stop the timer when the countdown reaches zero
            writelog "CreateTimerLabelAndProgressBar - Timer ended"
            $Global:ProgressBarDispatcher.Stop()
            $Global:ProgressBarClock.Content = "Time's up!"
            $Global:ProgressBarProgressBar.Value = $Global:ProgressBarProgressBar.Minimum
            ButtonFunction_DeferAllApps
        } else {
            # Update the label with the remaining time
            $Global:ProgressBarClock.Content = "{0:D2}:{1:D2}" -f $RemainingTime.Minutes, $RemainingTime.Seconds

            # Update the progress bar to deplete
            $ElapsedSeconds = $Global:ProgressBarTotalDuration - $RemainingTime.TotalSeconds
            $Global:ProgressBarProgressBar.Value = 100 - (($ElapsedSeconds / $Global:ProgressBarTotalDuration) * 100)
        }
    })
    $Global:ProgressBarDispatcher.Start()
}

function CreateGuiScrollBarContentHeader {
    param (
        $Text,
        $Tag,
        $Name,
        $column,
        $TextSettings = @{
            "Font Family"  = $Global:Settings."User Interface"."App Header"."Font Family"
            "Font Size"    = $Global:Settings."User Interface"."App Header"."Font Size"
            "Font Weight"  = $Global:Settings."User Interface"."App Header"."Font Weight"
            "Font Style"   = $Global:Settings."User Interface"."App Header"."Font Style"
            "Font Stretch" = $Global:Settings."User Interface"."App Header"."Font Stretch"
            "Margin"       = $Global:Settings."User Interface"."App Header"."Margin"
        }
    )
    $currentTheme = $Global:Settings."User Experience"."Current Theme".Value
    # Create a TextBlock for Header AppName
    $NewHeader = New-Object System.Windows.Controls.TextBlock
    $NewHeader.Text = "$Text"
    $NewHeader.Tag = "$Tag"
    $NewHeader.Name = "$(ReplaceSpecialCharacters $Name)"
    $NewHeader.Margin = $TextSettings['Margin']
    $NewHeader.FontFamily = $TextSettings['Font Family']
    $NewHeader.FontSize = $TextSettings['Font Size']
    $NewHeader.FontWeight = $TextSettings['Font Weight']
    $NewHeader.FontStyle = $TextSettings['Font Style']
    $NewHeader.FontStretch = $TextSettings['Font Stretch']
    $NewHeader.Foreground = $Global:Settings.Themes."$currentTheme"."Text"
    $NewHeader.HorizontalAlignment = 'Left'
    $NewHeader.VerticalAlignment = 'Center'
    [System.Windows.Controls.Grid]::SetRow($NewHeader, 0)
    [System.Windows.Controls.Grid]::SetColumn($NewHeader, $column)
    $Global:ContentGrid.Children.Add($NewHeader) | Out-Null
}

function CreateAppTextBlock {
    param (
        $Text,
        $Tag,
        $Name,
        $row,
        $column,
        $TextSettings = @{
            "Font Family"  = $Global:Settings."User Interface"."App Text"."Font Family"
            "Font Size"    = $Global:Settings."User Interface"."App Text"."Font Size"
            "Font Weight"  = $Global:Settings."User Interface"."App Text"."Font Weight"
            "Font Style"   = $Global:Settings."User Interface"."App Text"."Font Style"
            "Font Stretch" = $Global:Settings."User Interface"."App Text"."Font Stretch"
            "Margin"       = $Global:Settings."User Interface"."App Text"."Margin"
        }
    )
    $currentTheme = $Global:Settings."User Experience"."Current Theme".Value
    # Create a TextBlock for app name
    $AppTextBlock = New-Object System.Windows.Controls.TextBlock
    $AppTextBlock.Text = "$Text"
    $AppTextBlock.Tag = "$Tag"
    $AppTextBlock.Name = "$(ReplaceSpecialCharacters $Name)"
    $AppTextBlock.Margin = $TextSettings.Margin = $TextSettings['Margin']
    $AppTextBlock.FontFamily = $TextSettings['Font Family']
    $AppTextBlock.FontSize = $TextSettings['Font Size']
    $AppTextBlock.FontWeight = $TextSettings['Font Weight']
    $AppTextBlock.FontStyle = $TextSettings['Font Style']
    $AppTextBlock.FontStretch = $TextSettings['Font Stretch']
    $AppTextBlock.Foreground = $Global:Settings."Themes"."$currentTheme"."Text"
    $AppTextBlock.HorizontalAlignment = 'Left'
    $AppTextBlock.VerticalAlignment = 'Center'
    [System.Windows.Controls.Grid]::SetRow($AppTextBlock, $row + 1) # Skip header row
    [System.Windows.Controls.Grid]::SetColumn($AppTextBlock, $column)
    $Global:ContentGrid.Children.Add($AppTextBlock) | Out-Null
}

# Function to handle the closing event
function OnWindowClosing {
    param($sender, $eventArgs)

    $ShouldPrompt = $false

    # Check if there is something that requires the gui
    foreach ($app in 0..($Global:upgradableApps.Length - 1)) {
        if ($Global:upgradableApps[$app]["ButtonState"] -eq "Default" -or $Global:upgradableApps[$app]["ButtonState"] -eq "1DayLeft" ) {
            $ShouldPrompt = $true
            break
        }
    }

    if ($ShouldPrompt) {
        # Show a confirmation dialog
        $result = [System.Windows.MessageBox]::Show(
            "Are you sure you want to Defer All Apps?",
            "Confirm Defer All Apps",
            "YesNo",
            "Warning"
        )

        if ($result -eq "No") {
            # Cancel the close event
            $eventArgs.Cancel = $true
        }
        elseif ($result -eq "Yes") {
            ButtonFunction_DeferAllApps -SkipMainWindowCheck $true

        }
    }
}

function CreateGui {
    WriteLog "CreateGui - Creating GUI"
    # Load necessary assemblies
    LoadAssembly "PresentationFramework"
    LoadAssembly "PresentationCore"
    LoadAssembly "WindowsBase"

    # set initial theme
    $currentTheme = $Global:Settings."User Experience"."Current Theme".Value
    $wingetappsettings = get-itemproperty -path "$($Global:Settings."Registry Settings"."Registry Directory")"
    if ($wingetappsettings.IsDarkMode) {
        WriteLog "CreateGui - Registry IsDarkMode is $($wingetappsettings.IsDarkMode)"
        if ($wingetappsettings.IsDarkMode -eq "true") {
            $currentTheme = "Dark"
            $Global:Settings."User Experience"."Current Theme".Value = "Dark"
        }
        else {
            $currentTheme = "Light"
            $Global:Settings."User Experience"."Current Theme".Value = "Light"
        }
    }
    WriteLog "CreateGui - Current Theme is $currentTheme"

    # Create the main window
    $Global:MainWindow = New-Object System.Windows.Window
    $Global:MainWindow.Title = $Global:Settings."User Interface".Header.Title
    $Global:MainWindow.Width = $Global:Settings."User Interface"."Window Width".Value
    $Global:MainWindow.Height = $Global:Settings."User Interface"."Window Height".Value

    $Global:MainWindow.WindowStartupLocation = $Global:Settings."User Interface"."Window Startup Location".Value
    if ($Global:Settings."User Interface"."Window Startup Location".Value -eq "Manual") {
        # Get the usable screen area (excluding the taskbar)
        $workArea = [System.Windows.SystemParameters]::WorkArea
        $usableWidth = $workArea.Width
        $usableHeight = $workArea.Height
        $usableLeft = $workArea.X
        $usableTop = $workArea.Y
    
        $windowWidth = $Global:MainWindow.Width
        $windowHeight = $Global:MainWindow.Height
    
        if ($Global:Settings."User Interface"."Window Startup Location"."Bottom Right" -eq $True) {
            $Global:MainWindow.Left = $usableLeft + ($usableWidth - $windowWidth)
            $Global:MainWindow.Top = $usableTop + ($usableHeight - $windowHeight)
        }
        elseif ($Global:Settings."User Interface"."Window Startup Location"."Top Right" -eq $True) {
            $Global:MainWindow.Left = $usableLeft + ($usableWidth - $windowWidth)
            $Global:MainWindow.Top = $usableTop
        }
        elseif ($Global:Settings."User Interface"."Window Startup Location"."Top Left" -eq $True) {
            $Global:MainWindow.Left = $usableLeft
            $Global:MainWindow.Top = $usableTop
        }
        elseif ($Global:Settings."User Interface"."Window Startup Location"."Bottom Left" -eq $True) {
            $Global:MainWindow.Left = $usableLeft
            $Global:MainWindow.Top = $usableTop + ($usableHeight - $windowHeight)
        }
        else {
            # in case of no match, default to center screen
            $Global:MainWindow.WindowStartupLocation = "CenterScreen"
        }
    }
    
    if (!($Global:Settings."User Interface"."Show Title Bar".Value)) { $Global:MainWindow.WindowStyle = 'None' }  # Title bar so you cant exit out
    $Global:MainWindow.ShowInTaskbar = $Global:Settings."User Interface"."Show In Taskbar".Value
    $Global:MainWindow.Topmost = $Global:Settings."User Interface"."Always On Top".Value    # Set the window to always be on top
    if (!($Global:Settings."User Interface".Resizeable.Value)) { $Global:MainWindow.ResizeMode = 'NoResize' }     # Make the window non-resizable

    ########## Main Grid #############
    #                                #
    #    ##### Row1_Header #######   #
    #    #                       #   #
    #    #########################   #
    #                                #
    #    ### Row2_ScrollViewer ###   #
    #    #                       #   #
    #    #########################   #
    #                                #
    ##################################

    # Create main grid to house header and scroll bar
    $Global:MainGrid = New-Object System.Windows.Controls.Grid

    $Row1_Header = New-Object System.Windows.Controls.RowDefinition
    $Row1_Header.Height = [System.Windows.GridLength]::new($Global:Settings."User Interface"."Window Header"."Height", [System.Windows.GridUnitType]::Pixel)
    $Global:MainGrid.RowDefinitions.Add($Row1_Header)
    # Create a RowDefinition for the scrollable content
    $Row2_ScrollViewer = New-Object System.Windows.Controls.RowDefinition
    $Row2_ScrollViewer.Height = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
    $Global:MainGrid.RowDefinitions.Add($Row2_ScrollViewer)

    ######## Header ####################
    #                                  #
    #  ####### DockPanel ############  #
    #  #                            #  #
    #  #  ##### Grid  ############  #  #
    #  #  #                      #  #  #
    #  #  #  ########            #  #  #
    #  #  #  # Icon #            #  #  #
    #  #  #  ######## Title      #  #  #
    #  #  #                      #  #  #
    #  #  ########################  #  #
    #  #                            #  #
    #  ##############################  #
    #                                  #
    ####################################

    # Create a grid to hold the background and the image
    $Global:HeaderDockPanel = New-Object System.Windows.Controls.DockPanel
    
    # Load the background image
    if ($Global:Settings.Graphics."Header Background"."Use Image") {
        WriteLog "CreateGui - Loading Header Background Image $($Global:Settings.Graphics."Header Background"."$currentTheme"."Path")"
        $backgroundImageBrush = New-Object System.Windows.Media.ImageBrush
        $backgroundImageBrush.ImageSource = [System.Windows.Media.Imaging.BitmapImage]::new(
            [System.Uri]::new("$($Global:Settings.Graphics."Header Background"."$currentTheme"."Path")")
        )
        $Global:HeaderDockPanel.Background = $backgroundImageBrush
    }
    else {
        $brushConverter = New-Object System.Windows.Media.BrushConverter
        WriteLog "CreateGui - Settings Header panel background colors - $currentTheme" 
        $Global:HeaderDockPanel.background = $brushConverter.ConvertFromString($Global:Settings."Themes"."$currentTheme"."Header Background")
    }

    $Global:HeaderGrid = New-Object System.Windows.Controls.Grid
    $Global:HeaderGrid.HorizontalAlignment = $Global:Settings."User Interface"."Window Header"."Horizontal Alignment"
    $Global:HeaderGrid.VerticalAlignment = $Global:Settings."User Interface"."Window Header"."Vertical Alignment"
    $Global:HeaderGrid.Background = [System.Windows.Media.Brushes]::Transparent

    # Define columns for the ContentGrid
    $CompanyLogoColumn = New-Object System.Windows.Controls.ColumnDefinition
    $CompanyLogoColumn.Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Auto)
    $Global:HeaderGrid.ColumnDefinitions.Add($CompanyLogoColumn)

    $TextColumn = New-Object System.Windows.Controls.ColumnDefinition
    $TextColumn.Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Auto)
    $Global:HeaderGrid.ColumnDefinitions.Add($TextColumn)

    # Load the image
    if ($Global:Settings.Graphics.'Company Logo'.'Use Image') {
        WriteLog "CreateGui - Loading Company Logo Image $($Global:Settings.Graphics."Company Logo"."$currentTheme"."Path")"
        $Global:CompanyLogoImage = New-Object System.Windows.Controls.Image
        $Global:CompanyLogoImage.Source = [System.Windows.Media.Imaging.BitmapImage]::new([System.Uri]::new("$($Global:Settings.Graphics."Company Logo"."$currentTheme"."Path")"))
        $Global:CompanyLogoImage.Width = $Global:Settings."User Interface"."Company Logo Size"."Width"
        $Global:CompanyLogoImage.Height = $Global:Settings."User Interface"."Company Logo Size"."Height"
        $Global:CompanyLogoImage.HorizontalAlignment = $Global:Settings."User Interface"."Company Logo Size"."Horizontal Alignment"
        $Global:CompanyLogoImage.VerticalAlignment = $Global:Settings."User Interface"."Company Logo Size"."Vertical Alignment"
        #$Global:CompanyLogoImage.Stretch = [System.Windows.Media.Stretch]::Uniform
        $Global:CompanyLogoImage.Margin = $Global:Settings."User Interface"."Company Logo Size"."Margin"
        $Global:CompanyLogoImage.Tag = "Company Logo"

        # Add the transparent image to the grid
        [System.Windows.Controls.Grid]::SetColumn($Global:CompanyLogoImage, 0)
        [System.Windows.Controls.Grid]::SetRow($Global:CompanyLogoImage, 0)
        $Global:HeaderGrid.Children.Add($Global:CompanyLogoImage) | Out-Null
    }
    
    WriteLog "CreateGui - Loading Header Title $($Global:Settings."User Interface"."Header Title"."Text")"
    $brushConverter = New-Object System.Windows.Media.BrushConverter
    $Global:TitleText = New-Object System.Windows.Controls.TextBlock
    $Global:TitleText.Text = "$($Global:Settings.'User Interface'."Header Title"."Text")"
    $Global:TitleText.Tag = "Header Title"
    $Global:TitleText.FontSize = $Global:Settings."User Interface"."Header Title"."Font Size"
    $Global:TitleText.FontFamily = $Global:Settings."User Interface"."Header Title"."Font Family" 
    $Global:TitleText.FontWeight = $Global:Settings."User Interface"."Header Title"."Font Weight" 
    $Global:TitleText.FontStyle = $Global:Settings."User Interface"."Header Title"."Font Style" 
    $Global:TitleText.FontStretch = $Global:Settings."User Interface"."Header Title"."Font Stretch"
    WriteLog "CreateGui - Loading Header Text Color - $($Global:Settings."Themes"."$currentTheme"."Header Text")"
    $Global:TitleText.Foreground = $brushConverter.ConvertFromString($Global:Settings."Themes"."$currentTheme"."Header Text")
    $Global:TitleText.HorizontalAlignment = $Global:Settings."User Interface"."Header Title"."Horizontal Alignment"
    $Global:TitleText.VerticalAlignment = $Global:Settings."User Interface"."Header Title"."Vertical Alignment"
    $Global:TitleText.Margin = $Global:Settings."User Interface"."Header Title"."Margin"

    [System.Windows.Controls.Grid]::SetColumn($Global:TitleText, 1)
    [System.Windows.Controls.Grid]::SetRow($Global:TitleText, 0)
    $Global:HeaderGrid.Children.Add($Global:TitleText) | Out-Null

    $Global:HeaderDockPanel.Children.Add($Global:HeaderGrid) | Out-Null

    [System.Windows.Controls.Grid]::SetRow($Global:HeaderDockPanel, 0)
    $Global:MainGrid.children.Add($Global:HeaderDockPanel) | Out-Null

    ########### Scroll Viewer ##############################
    #                                                      #
    # ######### Content Grid  ############################ #
    # #                                                  # #
    # #  AppName AppVersion AppNewVersion ActionButtons  # #
    # #      #       #           #          # # #        # #
    # #      #       #           #          # # #        # #
    # #      #       #           #          # # #        # #
    # #                                                  # #
    # #################################################### #
    #                                                      # 
    ########################################################

    # Create a ScrollViewer
    $Global:ScrollViewer = New-Object System.Windows.Controls.ScrollViewer
    #$Global:ScrollViewer.HorizontalAlignment = 'Stretch'
    $Global:ScrollViewer.VerticalScrollBarVisibility = 'Auto'
    $Global:ScrollViewer.background = $brushConverter.ConvertFromString($Global:Settings.Themes."$currentTheme"."Content Background")

    # Create a Grid to hold the scrollable content like a spreadsheet
    $Global:ContentGrid = New-Object System.Windows.Controls.Grid

    # Define columns for the ContentGrid
    $NameColumn = New-Object System.Windows.Controls.ColumnDefinition
    # $NameColumn.Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
    # $NameColumn.Width = [System.Windows.GridLength]::new(2, [System.Windows.GridUnitType]::Star) # Set to Auto
    # $NameColumn.MaxWidth = 200
    $NameColumn.Width = [System.Windows.GridLength]::new(
        $Global:Settings."User Interface"."App Header"."Column Name Width",
        [System.Windows.GridUnitType]::Pixel)
    $NameColumn.MaxWidth = $Global:Settings."User Interface"."App Header"."Column Name Width"
    $Global:ContentGrid.ColumnDefinitions.Add($NameColumn)

    $VersionColumn = New-Object System.Windows.Controls.ColumnDefinition
    # $VersionColumn.Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
    # $VersionColumn.MaxWidth = 100
    $VersionColumn.Width = [System.Windows.GridLength]::new(
        $Global:Settings."User Interface"."App Header"."Column Version Width",
        [System.Windows.GridUnitType]::Pixel)
    $VersionColumn.MaxWidth = $Global:Settings."User Interface"."App Header"."Column Version Width"
    $Global:ContentGrid.ColumnDefinitions.Add($VersionColumn)

    $AvailableColumn = New-Object System.Windows.Controls.ColumnDefinition
    # $AvailableColumn.Width = [System.Windows.GridLength]::new(1, [System.Windows.GridUnitType]::Star)
    # $AvailableColumn.MaxWidth = 100
    $AvailableColumn.Width = [System.Windows.GridLength]::new(
        $Global:Settings."User Interface"."App Header"."Column Available Width",
        [System.Windows.GridUnitType]::Pixel)
    $AvailableColumn.MaxWidth = $Global:Settings."User Interface"."App Header"."Column Available Width"
    $Global:ContentGrid.ColumnDefinitions.Add($AvailableColumn)

    $ButtonColumn = New-Object System.Windows.Controls.ColumnDefinition
    # $ButtonColumn.Width = [System.Windows.GridLength]::new(3, [System.Windows.GridUnitType]::Star)
    $ButtonColumn.Width = [System.Windows.GridLength]::new(
        $Global:Settings."User Interface"."App Header"."Column Button Width",
        [System.Windows.GridUnitType]::Pixel)
    $ButtonColumn.MaxWidth = $Global:Settings."User Interface"."App Header"."Column Button Width"
    $Global:ContentGrid.ColumnDefinitions.Add($ButtonColumn)

    # Create Rows for each app, +1 for header
    for ($row_number = 0; $row_number -lt $Global:upgradableApps.count + 1; $row_number++) {
        $RowDefinition = New-Object System.Windows.Controls.RowDefinition
        $RowDefinition.Height = [System.Windows.GridLength]::Auto
        $ContentGrid.RowDefinitions.Add($RowDefinition)
    }

    # Create a hash array of buttons, this button panel gets placed in 4th column so they stick together
    $Global:ButtonPanel = @{}
    $Global:ButtonDictionairy = @{}

    CreateGuiScrollbarContentHeader -Text "Name" -Tag "HeaderAppName" -Name "HeaderAppName" -column 0 -TextSettings $Global:Settings."User Interface"."App Header"
    CreateGuiScrollbarContentHeader -Text "Current" -Tag "HeaderAppVersion" -Name "HeaderAppVersion" -column 1 -TextSettings $Global:Settings."User Interface"."App Header"
    CreateGuiScrollbarContentHeader -Text "New" -Tag "HeaderAppAvailable" -Name "HeaderAppAvailable" -column 2 -TextSettings $Global:Settings."User Interface"."App Header"

    # Add app details and buttons to the ContentGrid rows
    foreach ($row_number in 0..($Global:upgradableApps.Length - 1)) {
        WriteLog "CreateGui - Adding App: $($Global:upgradableApps[$row_number].Name) to the GUI"
        # Track button State
        $Global:upgradableApps[$row_number]["ButtonState"] = "Default"
        $app = $Global:upgradableApps[$row_number]

        # Fill in first 3 columns
        CreateAppTextBlock -Text $app.Name -Tag "AppName" -Name "$($app.id)".replace(".", "_") -row $row_number -column 0 -TextSettings $Global:Settings."User Interface"."App Text"
        CreateAppTextBlock -Text $app.Version -Tag "AppVersion" -Name "$($app.id)".replace(".", "_") -row $row_number -column 1 -TextSettings $Global:Settings."User Interface"."App Text"
        CreateAppTextBlock -Text $app.Available -Tag "AppAvailable" -Name "$($app.id)".replace(".", "_") -row $row_number -column 2 -TextSettings $Global:Settings."User Interface"."App Text"

        # Create a StackPanel to hold the buttons in the last column
        $Global:ButtonPanel[$row_number] = New-Object System.Windows.Controls.StackPanel
        $Global:ButtonPanel[$row_number].Orientation = 'Horizontal'
        $Global:ButtonPanel[$row_number].Tag = 'ButtonPanel'
        $Global:ButtonPanel[$row_number].Name = 'ButtonPanel'
        $Global:ButtonPanel[$row_number].Margin = [System.Windows.Thickness]::new(5)
        [System.Windows.Controls.Grid]::SetRow($Global:ButtonPanel[$row_number], $row_number + 1) # Skip header row
        [System.Windows.Controls.Grid]::SetColumn($Global:ButtonPanel[$row_number], 3)
        $Global:ContentGrid.Children.Add($Global:ButtonPanel[$row_number]) | Out-Null

        # Create buttons
        $Global:ButtonDictionairy[$row_number] = @{}

        # Check if registry for this app has deferuntilicant to true
        $registryAppData = GetRegistryAppData -AppId $app.id
        $MaxDeferralDays = $Global:Settings."User Experience"."Max Deferral Days".Value
        $MaxDeferralAmount = $Global:Settings."User Experience"."Max Deferral Amount".Value
        $CountdownSecondsForcedUpdate = $Global:Settings."User Experience"."Count Down Seconds Force Update".Value

        if ($registryAppData.DeferUntilICant -eq "True") {
            # If the date is more then max Deferral days display countdown
            if ([int]$registryAppData.DaysSinceLastUpdate -gt $MaxDeferralDays) {
                #TODO make the countdown show on the UI
                WriteLog "CreateGui - Updating $($app.id) because time ran out on Max Deferral Days"
                $Global:upgradableApps[$row_number]["ButtonState"] = "MaxTimeRanOut"
                
                # Define tag as the paramater found in json settings and reuse for code var
                $ButtonParams = @{
                    "ButtonText"   = "$CountdownSecondsForcedUpdate seconds left"
                    "Tag"          = "Update Countdown"
                    "ButtonAction" = { WriteLog "updating in $CountdownSecondsForcedUpdate seconds" }
                    "Name"         = "rowid_$($row_number)"
                }

                if ($Global:Settings."User Interface"."App Buttons"."Override Button".ContainsKey("$($ButtonParams.Tag)")) {
                    $ButtonParams.TextSettings = $Global:Settings."User Interface"."App Buttons"."Override Button"."$($ButtonParams.Tag)"
                }
                else {
                    $ButtonParams.TextSettings = $Global:Settings."User Interface"."App Buttons"
                }

                if ($Global:Settings.Graphics."$($ButtonParams.Tag)"."Use Image") {
                    $ButtonParams.ButtonImagePath = $Global:Settings.Graphics."$($ButtonParams.Tag)"."$currentTheme"."Path"
                    $Global:ButtonDictionairy[$row_number]["$($ButtonParams.Tag)"] = CreateImageButton @ButtonParams
                }
                else {
                    $ButtonParams.ButtonColors = $Global:Settings.Themes."$currentTheme"."App Buttons"."$($ButtonParams.Tag)"
                    $Global:ButtonDictionairy[$row_number]["$($ButtonParams.Tag)"] = CreateButton @ButtonParams
                }
                
                $Global:ButtonPanel[$row_number].Children.Add($Global:ButtonDictionairy[$row_number]["$($ButtonParams.Tag)"]) | Out-Null
                ButtonFunction_UpdateApp -sender_obj @{"name" = "rowid_$row_number" } -delayed $true
            }
            else {
                # If the date is less then show days Left
                WriteLog "CreateGui - $($app.id) DeferUntilICant is True but Less then DaysSinceLastUpdate. Days $($registryAppData.DaysSinceLastUpdate) / Max Days $($MaxDeferralDays)" 
                
                $Global:upgradableApps[$row_number]["ButtonState"] = "InTimeDeferralState"
                if ($MaxDeferralDays - [int]$registryAppData.DaysSinceLastUpdate -eq 1) {
                    $Global:upgradableApps[$row_number]["ButtonState"] = "1DayLeft"
                } # used for displaying gui if needed
                
                $ButtonParams = @{
                    "ButtonText"   = "$($MaxDeferralDays - [int]$registryAppData.DaysSinceLastUpdate) Days Left"
                    "Tag"          = "Deferred Until Date"
                    "ButtonAction" = { WriteLog "updating in $($MaxTimeDeferralDays - [int]$registryAppData.DaysSinceLastUpdate) days" } 
                    "Name"         = "rowid_$($row_number)"
                }

                if ($Global:Settings."User Interface"."App Buttons"."Override Button".ContainsKey("$($ButtonParams.Tag)")) {
                    $ButtonParams.TextSettings = $Global:Settings."User Interface"."App Buttons"."Override Button"."$($ButtonParams.Tag)"
                }
                else {
                    $ButtonParams.TextSettings = $Global:Settings."User Interface"."App Buttons"
                }

                if ($Global:Settings.Graphics."$($ButtonParams.Tag)"."Use Image") {
                    $ButtonParams.ButtonImagePath = $Global:Settings.Graphics."$($ButtonParams.Tag)".$currentTheme."Path"
                    $Global:ButtonDictionairy[$row_number]["$($ButtonParams.Tag)"] = CreateImageButton @ButtonParams
                }
                else {
                    $ButtonParams.ButtonColors = $Global:Settings.Themes."$currentTheme"."App Buttons"."$($ButtonParams.Tag)"
                    $Global:ButtonDictionairy[$row_number]["$($ButtonParams.Tag)"] = CreateButton @ButtonParams
                }
                
                $Global:ButtonPanel[$row_number].Children.Add($Global:ButtonDictionairy[$row_number]["$($ButtonParams.Tag)"]) | Out-Null
            }
        }
        elseif ([int]$registryAppData.AppDeferral -ge $MaxDeferralAmount) {
            #TODO make the countdown show on the UI
            WriteLog "CreateGui - Updating $($app.id) because no more Deferrals Registry: $($registryAppData.AppDeferral) Settings: $($MaxDeferralAmount)"
            $Global:upgradableApps[$row_number]["ButtonState"] = "DeferralMaxed"

            $ButtonParams = @{
                "ButtonText"   = "$CountdownSecondsForcedUpdate seconds left"
                "Tag"          = 'Defer Maxed'
                "ButtonAction" = { WriteLog "updating in $CountdownSecondsForcedUpdate seconds" } 
                "Name"         = "rowid_$($row_number)"
            }

            if ($Global:Settings."User Interface"."App Buttons"."Override Button".ContainsKey("$($ButtonParams.Tag)")) {
                $ButtonParams.TextSettings = $Global:Settings."User Interface"."App Buttons"."Override Button"."$($ButtonParams.Tag)"
            }
            else {
                $ButtonParams.TextSettings = $Global:Settings."User Interface"."App Buttons"
            }

            # Create the new Deffer button
            if ($Global:Settings.Graphics."$($ButtonParams.Tag)"."Use Image") {
                $ButtonParams.ButtonImagePath = $Global:Settings.Graphics."$($ButtonParams.Tag)".$currentTheme."Path"
                $Global:ButtonDictionairy[$row_number]["$($ButtonParams.Tag)"] = CreateImageButton @ButtonParams
            }
            else {
                $ButtonParams.ButtonColors = $Global:Settings.Themes."$currentTheme"."App Buttons"."$($ButtonParams.Tag)"
                $Global:ButtonDictionairy[$row_number]["$($ButtonParams.Tag)"] = CreateButton @ButtonParams
            }
            
            $Global:ButtonPanel[$row_number].Children.Add($Global:ButtonDictionairy[$row_number]["$($ButtonParams.Tag)"]) | Out-Null
            ButtonFunction_UpdateApp -sender_obj @{"name" = "rowid_$row_number" } -delayed $true
            
        }
        else {
            # Create all 3 buttons since this is in a default state
            # Update
            $ButtonParams = @{
                "ButtonText"   = "Update"
                "Tag"          = 'Update'
                "ButtonAction" = { ButtonFunction_UpdateApp $this }
                "Name"         = "rowid_$($row_number)"
            }

            if ($Global:Settings."User Interface"."App Buttons"."Override Button".ContainsKey("$($ButtonParams.Tag)")) {
                $ButtonParams.TextSettings = $Global:Settings."User Interface"."App Buttons"."Override Button"."$($ButtonParams.Tag)"
            }
            else {
                $ButtonParams.TextSettings = $Global:Settings."User Interface"."App Buttons"
            }

            if ($Global:Settings.Graphics."$($ButtonParams.Tag)"."Use Image") {
                $ButtonParams.ButtonImagePath = $Global:Settings.Graphics."$($ButtonParams.Tag)"."$currentTheme"."Path"
                $Global:ButtonDictionairy[$row_number]["$($ButtonParams.Tag)"] = CreateImageButton @ButtonParams
            }
            else {
                $ButtonParams.ButtonColors = $Global:Settings.Themes."$currentTheme"."App Buttons"."$($ButtonParams.Tag)"
                $Global:ButtonDictionairy[$row_number]["$($ButtonParams.Tag)"] = CreateButton @ButtonParams 
            }
            
            $Global:ButtonPanel[$row_number].Children.Add($Global:ButtonDictionairy[$row_number]["$($ButtonParams.Tag)"]) | Out-Null

            # Defer
            $ButtonParams = @{
                "ButtonText"   = "Defer"
                "Tag"          = "Defer"
                "ButtonAction" = { ButtonFunction_DeferApp $this }
                "Name"         = "rowid_$($row_number)"
            }

            if ($Global:Settings."User Interface"."App Buttons"."Override Button".ContainsKey("$($ButtonParams.Tag)")) {
                $ButtonParams.TextSettings = $Global:Settings."User Interface"."App Buttons"."Override Button"."$($ButtonParams.Tag)"
            }
            else {
                $ButtonParams.TextSettings = $Global:Settings."User Interface"."App Buttons"
            }

            if ($Global:Settings.Graphics."$($ButtonParams.Tag)"."Use Image") {
                $ButtonParams.ButtonImagePath = $Global:Settings.Graphics."$($ButtonParams.Tag)"."$currentTheme"."Path"
                $Global:ButtonDictionairy[$row_number]["$($ButtonParams.Tag)"] = CreateImageButton @ButtonParams
            }
            else {
                $ButtonParams.ButtonColors = $Global:Settings.Themes."$currentTheme"."App Buttons"."$($ButtonParams.Tag)"
                $Global:ButtonDictionairy[$row_number]["$($ButtonParams.Tag)"] = CreateButton @ButtonParams 
            }
            $Global:ButtonPanel[$row_number].Children.Add($Global:ButtonDictionairy[$row_number]["$($ButtonParams.Tag)"]) | Out-Null

            # Defer until i cant
            $ButtonParams = @{
                "ButtonText"   = "Defer Until I Can't"
                "Tag"          = "Defer Until I Cant"
                "ButtonAction" = { ButtonFunction_DeferUntilICant $this }
                "Name"         = "rowid_$($row_number)"
            }

            if ($Global:Settings."User Interface"."App Buttons"."Override Button".ContainsKey("$($ButtonParams.Tag)")) {
                $ButtonParams.TextSettings = $Global:Settings."User Interface"."App Buttons"."Override Button"."$($ButtonParams.Tag)"
            }
            else {
                $ButtonParams.TextSettings = $Global:Settings."User Interface"."App Buttons"
            }

            if ($Global:Settings.Graphics."$($ButtonParams.Tag)"."Use Image") {
                $ButtonParams.ButtonImagePath = $Global:Settings.Graphics."$($ButtonParams.Tag)".$currentTheme."Path"
                $Global:ButtonDictionairy[$row_number]["$($ButtonParams.Tag)"] = CreateImageButton @ButtonParams
            }
            else {
                $ButtonParams.ButtonColors = $Global:Settings.Themes."$currentTheme"."App Buttons"."$($ButtonParams.Tag)"
                $Global:ButtonDictionairy[$row_number]["$($ButtonParams.Tag)"] = CreateButton  @ButtonParams
            }
            $Global:ButtonPanel[$row_number].Children.Add($Global:ButtonDictionairy[$row_number]["$($ButtonParams.Tag)"]) | Out-Null

        }
        
    }

    # Add the ContentGrid to the ScrollViewer
    $Global:ScrollViewer.Content = $ContentGrid

    # Add the ScrollViewer to the MainGrid
    [System.Windows.Controls.Grid]::SetRow($Global:ScrollViewer, 1)
    $Global:MainGrid.Children.Add($Global:ScrollViewer) | Out-Null

    ########## Dock Panel ############
    #                                #
    #    #### Button Panel #####     #
    #    #                     #     #
    #    #######################     #
    #                                #
    ##################################

    # Create the dock
    $brushConverter = New-Object System.Windows.Media.BrushConverter
    $Global:DockPanel = New-Object System.Windows.Controls.DockPanel
    

    $Global:BottomButtonPanel = New-Object System.Windows.Controls.StackPanel
    $Global:BottomButtonPanel.Orientation = $Global:Settings."User Interface"."Dock"."Orientation"
    $Global:BottomButtonPanel.HorizontalAlignment = $Global:Settings."User Interface"."Dock"."Horizontal Alignment"
    $Global:BottomButtonPanel.VerticalAlignment = $Global:Settings."User Interface"."Dock"."Vertical Alignment"
    $Global:BottomButtonPanel.Margin = $Global:Settings."User Interface"."Dock"."Margin"
    $Global:BottomButtonPanel.Background = [System.Windows.Media.Brushes]::Transparent
    $Global:BottomButtonPanel.MinHeight = $Global:Settings."User Interface"."Dock"."Dock Minimum Height"

    # Theme button
    $ButtonParams = @{
        "ButtonText"   = "$currentTheme Mode"
        "ButtonAction" = { ButtonFunction_UpdateTheme }
        "Tag"          = "Theme"
        "Name"         = "Theme"
    }

    if ($currentTheme -eq "Dark") {
        $ButtonParams.ButtonText = "Light Mode"
    }
    else {
        $ButtonParams.ButtonText = "Dark Mode"
    }
    
    if ($Global:Settings."User Interface"."Dock Buttons"."Override Button".ContainsKey("$($ButtonParams.Tag)")) {
        $ButtonParams.TextSettings = $Global:Settings."User Interface"."Dock Buttons"."Override Button"."$($ButtonParams.Tag)"
    }
    else {
        $ButtonParams.TextSettings = $Global:Settings."User Interface"."Dock Buttons"
    }

    if ($Global:Settings.Graphics."$($ButtonParams.Tag)"."Use Image") {
        $ButtonParams.ButtonImagePath = $Global:Settings.Graphics."$($ButtonParams.Tag)".$currentTheme."Path"
        $ThemeButton = CreateImageButton @ButtonParams
    }
    else {
        $ButtonParams.ButtonColors = $Global:Settings.Themes."$currentTheme"."Dock Buttons"."$($ButtonParams.Tag)"
        $ThemeButton = CreateButton @ButtonParams
    }
    $Global:BottomButtonPanel.Children.Add($ThemeButton) | Out-Null

    # Update All button
    $ButtonParams = @{
        "ButtonText"   = "Update All"
        "ButtonAction" = { ButtonFunction_UpdateAllApps }
        "Tag"          = "Update All"
        "Name"         = "UpdateAll" # Not allowed to have spaces
    }

    if ($Global:Settings."User Interface"."Dock Buttons"."Override Button".ContainsKey("$($ButtonParams.Tag)")) {
        $ButtonParams.TextSettings = $Global:Settings."User Interface"."Dock Buttons"."Override Button"."$($ButtonParams.Tag)"
    }
    else {
        $ButtonParams.TextSettings = $Global:Settings."User Interface"."Dock Buttons"
    }

    if ($Global:Settings.Graphics."$($ButtonParams.Tag)"."Use Image") {
        $ButtonParams.ButtonImagePath = $Global:Settings.Graphics."$($ButtonParams.Tag)".$currentTheme."Path"
        $UpgradeAllButton = CreateImageButton @ButtonParams
    }
    else {
        $ButtonParams.ButtonColors = $Global:Settings.Themes."$currentTheme"."Dock Buttons"."$($ButtonParams.Tag)"
        $UpgradeAllButton = CreateButton @ButtonParams
    }
    $Global:BottomButtonPanel.Children.Add($UpgradeAllButton) | Out-Null

    # Defer All button
    $ButtonParams = @{
        "ButtonText"   = "Defer All"
        "ButtonAction" = { ButtonFunction_DeferAllApps }
        "Tag"          = "Defer All"
        "Name"         = "DeferAll" # Not allowed to have spaces
    }
    
    if ($Global:Settings."User Interface"."Dock Buttons"."Override Button".ContainsKey("$($ButtonParams.Tag)")) {
        $ButtonParams.TextSettings = $Global:Settings."User Interface"."Dock Buttons"."Override Button"."$($ButtonParams.Tag)"
    }
    else {
        $ButtonParams.TextSettings = $Global:Settings."User Interface"."Dock Buttons"
    }

    if ($Global:Settings.Graphics."$($ButtonParams.Tag)"."Use Image") {
        $ButtonParams.ButtonImagePath = $Global:Settings.Graphics."$($ButtonParams.Tag)".$currentTheme."Path"
        $DeferAllButton = CreateImageButton  @ButtonParams
    }
    else {
        $ButtonParams.ButtonColors = $Global:Settings.Themes."$currentTheme"."Dock Buttons"."$($ButtonParams.Tag)"
        $DeferAllButton = CreateButton @ButtonParams
    }
    $Global:BottomButtonPanel.Children.Add($DeferAllButton) | Out-Null

    # Defer All Until I Cant button
    $ButtonParams = @{
        "ButtonText"   = "Defer All Until I Can't"
        "ButtonAction" = { ButtonFunction_DeferAllAppsUntilICant }
        "Tag"          = "Defer All Until I Cant"
        "Name"         = "DeferAllUntilICant" # Not allowed to have spaces
    }

    if ($Global:Settings."User Interface"."Dock Buttons"."Override Button".ContainsKey("$($ButtonParams.Tag)")) {
        $ButtonParams.TextSettings = $Global:Settings."User Interface"."Dock Buttons"."Override Button"."$($ButtonParams.Tag)"
    }
    else {
        $ButtonParams.TextSettings = $Global:Settings."User Interface"."Dock Buttons"
    }

    if ($Global:Settings.Graphics."$($ButtonParams.Tag)"."Use Image") {
        $ButtonParams.ButtonImagePath = $Global:Settings.Graphics."$($ButtonParams.Tag)".$currentTheme."Path"
        $DeferAllUntilCantButton = CreateImageButton @ButtonParams
    }
    else {
        $ButtonParams.ButtonColors = $Global:Settings.Themes."$currentTheme"."Dock Buttons"."$($ButtonParams.Tag)"
        $DeferAllUntilCantButton = CreateButton @ButtonParams
    }
    $Global:BottomButtonPanel.Children.Add($DeferAllUntilCantButton) | Out-Null

    # Create the Label and ProgressBar
    CreateTimerLabelAndProgressBar 
    $Global:DockPanel.Background = $brushConverter.ConvertFromString($Global:Settings.Themes."$currentTheme"."Dock Background")
    $Global:BottomButtonPanel.Children.Add($Global:ProgressBar) | Out-Null

    # Add the BottomButtonPanel to the DockPanel at the bottom
    [System.Windows.Controls.DockPanel]::SetDock($Global:BottomButtonPanel, $Global:Settings."User Interface"."Dock"."Dock Position")
    $Global:DockPanel.Children.Add($Global:BottomButtonPanel) | Out-Null

    ################################
    # Connect Main grid over to Dock
    # Connect Dock to main window
    # Display GUI
    ################################

    ########## Main Grid ############
    #    ######################     #
    #    #  Row1_Header       #     #
    #    ######################     #
    #    #  Row2_ScrollViewer #     #
    #    ######################     #
    #                               #
    ########## Dock Panel ###########
    #    ######################     #
    #    #    Button Panel    #     #
    #    ######################     #
    #################################

    # Add the MainGrid to the DockPanel
    $Global:DockPanel.Children.Add($Global:MainGrid) | Out-Null

    # Set the content of the window to the grid
    $Global:MainWindow.Content = $Global:DockPanel
    $Global:MainWindow.Add_Closing({ OnWindowClosing @args })

    # Check if there is something that requires the gui
    foreach ($app in 0..($upgradableApps.Length - 1)) {
        if ($Global:upgradableApps[$app]["ButtonState"] -eq "Default" -or $Global:upgradableApps[$app]["ButtonState"] -eq "1DayLeft" ) {
            # Show the window
            WriteLog "CreateGui - Showing the Main Window"
            $Global:MainWindow.ShowDialog()
            break
        }
    }
}

function CheckEnforcedUpdates {
    $UpdatedAnApp = $false
    WriteLog "CheckEnforcedUpdates - Starting to check for enforced updates."
    foreach ($app in $Global:UpgradableApps) {
        # Check if app is in the enforced update list
        if ($Global:Settings."Enforced Application Versions"."Applications".ContainsKey($app.id) -and 
            ((NormalizeVersion $Global:Settings."Enforced Application Versions"."Applications"[$app.id]) -gt (NormalizeVersion $app.Version)) ) {
            WriteLog "CheckEnforcedUpdates - Enforced update found for $($app.Name). Enforced Version: $($Global:Settings."Enforced Application Versions"."Applications"[$app.id]) Current Version: $($app.Version)"
            $UpdatedAnApp = $true
            # Update the app
            UpgradeApp -AppId $app.ID
                                        
            # Check if the app exists after updating
            CheckSuccessfulUpdate -app $App
        }
    }
    if ($UpdatedAnApp -eq $True) {
        WriteLog "CheckEnforcedUpdates - Enforced updates found. Refreshing upgradable apps."
        $Global:UpgradableApps = GetUpgradableApps
        RemoveFailedAppsFromUpgradableApps
    }
}

function RemoveFailedAppsFromUpgradableApps {
    WriteLog "RemoveFailedAppsFromUpgradableApps - Starting to remove failed apps from the upgradable apps list."
    $failedApps = @()
    foreach ($app in $Global:UpgradableApps) {
        $registryAppData = GetRegistryAppData -AppId $app.id
        $AppUpdateFailedDate = [datetime]$registryAppData.UpdateFailedDate

        # Check if the app has failed past allowed count
        if ([int]$registryAppData.UpdateFailedCount -ge $Global:Settings."User Experience"."Max Failed Update Count".Value) {
            # Check if the App is in the skip failed list
            $AppSkipFailedDate = $Global:Settings."Reset Failed Applications Before Date"."Applications"."$($App.Id)"
            $AllAppsSkipFailedDate = $Global:Settings."Reset Failed Applications Before Date"."Applications"."All"
            if (![string]::IsNullOrWhiteSpace($AppSkipFailedDate) -and ( $AppUpdateFailedDate -le [datetime]$AppSkipFailedDate ) ) {
                # The app is in the skip failed list and the failed date is before the settings skip date
                WriteLog "RemoveFailedAppsFromUpgradableApps - Resetting failed app: $($app.Name) The app is in the skip failed list and the failed date is before the settings skip date"
                ResetRegistryFailedAppUpdate -AppId $app.id
                continue
            }
            elseif (![string]::IsNullOrWhiteSpace($AllAppsSkipFailedDate) -and ( $AppUpdateFailedDate -le [datetime]$AllAppsSkipFailedDate) ) {
                # The app failed date is before the settings ALL skip date
                WriteLog "RemoveFailedAppsFromUpgradableApps - Resetting failed app: $($app.Name) The app failed date is before the settings ALL skip date"
                ResetRegistryFailedAppUpdate -AppId $app.id
                continue
            }
            else {
                WriteLog "RemoveFailedAppsFromUpgradableApps - adding to Failed Remove list: $($app.Name) with count of $($registryAppData.UpdateFailedCount)"
                $failedApps += $app
            }
            
        }
    }

    foreach ($failedApp in $failedApps) {
        WriteLog "RemoveFailedAppsFromUpgradableApps - Removing failed app: $($failedApp.Name)"
        $Global:UpgradableApps = $Global:UpgradableApps | Where-Object { $_.Id -ne $failedApp.id }
    }
    if ( $Global:UpgradableApps.length -eq 1 ) {
        #force return of a list
        $Global:UpgradableApps = @($Global:UpgradableApps)
    }
}

function Main {
    try {
        if (!(CheckElevation)) {
            write-output "User is not elevated, exiting" | out-file -FilePath "$ENV:LocalAppData\GuiGet error.log" -Append
            Exit 1
        }

        Force64Bit

        # Get configuration settings
        ConfigureSettings

        #HidePowershellWindow

        # Install package manager
        InstallPackageManager
        
        # Process images for use with GUI and Notificaitons
        ProcessImages

        # Check for additional sources
        CheckAddtionalSources

        # Check registry if the main directory has been added yet
        CreateMainRegistryDirectory

        # Get all upgradable apps, checks for $AppSkipList and removes
        $Global:UpgradableApps = GetUpgradableApps
        
        # Create registry files for each app if it doesnt exist
        foreach ( $App in $Global:UpgradableApps ) {
            CreateAppRegistryKeys -App $App
        }

        # Check if apps need enforced updates, if so update and return new upgradableApps
        CheckEnforcedUpdates
        
        # Check to see if upgradeable app is closed then update and returns new upgradableApps
        installSilentUpdates

        # Calculates update available date, new version, date since last update for displaying to user
        UpdateAppRegistryForDisplay

        # Remove failed apps from the list
        RemoveFailedAppsFromUpgradableApps
        
        if ( $Global:UpgradableApps.Length -eq 0 ) { 
            WriteLog "Main - skipping UI, no apps to update"
        }
        elseif (CheckGuiActivation) {
            # Create the GUI
            WriteLog "Main - Creating GUI"
            CreateGui

        }
        else {
            WriteLog "Main - skipping UI, but checking if apps passed the deadline for updates"
            foreach ( $App in $Global:UpgradableApps ) {
                $registryAppData = GetRegistryAppData -AppId $app.id
                $MaxDeferralDays = $Global:Settings."User Experience"."Max Deferral Days".Value
                $MaxDeferralAmount = $Global:Settings."User Experience"."Max Deferral Amount".Value
                $NewDeferralAmount = [int]$registryAppData.AppDeferral + 1
                if ($registryAppData.DeferUntilICant -eq "True") {
                    # If the date is more then max Deferral days display countdown
                    if ([int]$registryAppData.DaysSinceLastUpdate -gt $MaxDeferralDays) {
                        # Update the app
                        UpgradeApp -AppId $app.ID
                        
                        # Check if the app exists after updating
                        CheckSuccessfulUpdate -app $App
                    }
                }
                elseif ($registryAppData.AppDeferral -ge $MaxDeferralAmount) {
                    # Update the app
                    UpgradeApp -AppId $app.ID
                    
                    # Check if the app exists after updating
                    CheckSuccessfulUpdate -app $App
                }
                else {
                    WriteLog "Main - Updating registry for $($app.Name) with new Deferral amount of $NewDeferralAmount"
                    UpdateRegistryDeferralAmount -AppId $app.id -DeferAmount $NewDeferralAmount
                }
            }
        }

        WriteLog "Main - Starting Jobs"
        foreach ($Job in $global:Settings.UpdateJobs) {
            WriteLog "Main - Starting job: $($Job.App.Id)"
            CreateNotification -Title "Updating" -Text "$($Job.App.Name) in progress..."
            $Job.ScriptBlock.Invoke($Job.App, $Job.Delayed)
        }
        WriteLog "Main - Install Jobs finished"
        CreateNotification -Title "Patching Complete" -Text "Patching Complete All tasks are finished."
        
        
    } 
    catch [Exception] {
        WriteLog "Error in main function" 
        WriteLog "Message       : $($_.Exception.Message)" 
        WriteLog "StackTrace    : $($_.Exception.StackTrace)" 
        WriteLog "Line Number   : $($_.InvocationInfo.ScriptLineNumber)" 
        WriteLog "Line          : $($_.InvocationInfo.Line)" 
        WriteLog "Script Name   : $($_.InvocationInfo.ScriptName)"
    }

}

# Run app
Main

