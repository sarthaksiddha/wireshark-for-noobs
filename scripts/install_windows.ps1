# Wireshark MCP Windows Installation Script
# Execute as Administrator in PowerShell

# Check for administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator. Please restart PowerShell as Administrator and try again."
    exit 1
}

Write-Host "Wireshark MCP Installation Script for Windows" -ForegroundColor Cyan
Write-Host "-------------------------------------------" -ForegroundColor Cyan

# Installation paths
$programFiles = $env:ProgramFiles
$installDir = "$programFiles\Wireshark-MCP"
$configDir = "$env:ProgramData\Wireshark-MCP"
$captureDir = "$env:ProgramData\Wireshark-MCP\captures"
$logsDir = "$env:ProgramData\Wireshark-MCP\logs"

# Check if WinPcap/Npcap is installed
$npcapInstalled = Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Npcap" -ErrorAction SilentlyContinue
$winpcapInstalled = Get-ItemProperty -Path "HKLM:\SOFTWARE\WinPcap" -ErrorAction SilentlyContinue

if ((-not $npcapInstalled) -and (-not $winpcapInstalled)) {
    Write-Host "WinPcap or Npcap is required but not installed." -ForegroundColor Yellow
    $installNpcap = Read-Host "Would you like to download and install Npcap now? (y/n)"
    
    if ($installNpcap -eq "y") {
        $npcapUrl = "https://npcap.com/dist/npcap-1.55.exe"
        $npcapInstaller = "$env:TEMP\npcap-installer.exe"
        
        Write-Host "Downloading Npcap installer..."
        Invoke-WebRequest -Uri $npcapUrl -OutFile $npcapInstaller
        
        Write-Host "Installing Npcap..."
        Start-Process -FilePath $npcapInstaller -ArgumentList "/S" -Wait
        
        Remove-Item $npcapInstaller -Force
    } else {
        Write-Host "Please install WinPcap or Npcap manually before proceeding." -ForegroundColor Yellow
        Write-Host "You can download Npcap from: https://npcap.com/" -ForegroundColor Yellow
        exit 1
    }
}

# Create installation directories
Write-Host "Creating installation directories..."
New-Item -Path $installDir -ItemType Directory -Force | Out-Null
New-Item -Path $configDir -ItemType Directory -Force | Out-Null
New-Item -Path $captureDir -ItemType Directory -Force | Out-Null
New-Item -Path $logsDir -ItemType Directory -Force | Out-Null

# Copy program files (assuming the script is run from the distribution directory)
Write-Host "Copying program files..."
Copy-Item -Path "bin\*" -Destination $installDir -Recurse -Force

# Copy configuration template
Write-Host "Copying configuration files..."
Copy-Item -Path "config\wireshark_mcp.conf.template" -Destination "$configDir\wireshark_mcp.conf" -Force

# Set file permissions
Write-Host "Setting file permissions..."
$acl = Get-Acl $captureDir
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Users", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.SetAccessRule($rule)
Set-Acl $captureDir $acl

# Create shortcut
Write-Host "Creating start menu shortcut..."
$startMenuPath = [Environment]::GetFolderPath('CommonPrograms')
$shortcutPath = "$startMenuPath\Wireshark MCP.lnk"
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = "$installDir\wireshark_mcp.exe"
$shortcut.WorkingDirectory = $installDir
$shortcut.IconLocation = "$installDir\wireshark_mcp.exe,0"
$shortcut.Description = "Wireshark MCP - Corporate Network Protocol Analyzer"
$shortcut.Save()

# Add to PATH environment variable
Write-Host "Adding installation directory to PATH..."
$currentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if (-not $currentPath.Contains($installDir)) {
    [Environment]::SetEnvironmentVariable("PATH", "$currentPath;$installDir", "Machine")
}

# Register file associations
Write-Host "Registering file associations..."
$fileExtension = ".wcap"
$progId = "Wireshark-MCP.CaptureFile"

# Create file type
New-Item -Path "HKLM:\SOFTWARE\Classes\$fileExtension" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Classes\$fileExtension" -Name "(Default)" -Value $progId

# Create program ID
New-Item -Path "HKLM:\SOFTWARE\Classes\$progId" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Classes\$progId" -Name "(Default)" -Value "Wireshark MCP Capture File"

# Add icon
New-Item -Path "HKLM:\SOFTWARE\Classes\$progId\DefaultIcon" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Classes\$progId\DefaultIcon" -Name "(Default)" -Value "$installDir\wireshark_mcp.exe,1"

# Add open command
New-Item -Path "HKLM:\SOFTWARE\Classes\$progId\shell\open\command" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Classes\$progId\shell\open\command" -Name "(Default)" -Value "`"$installDir\wireshark_mcp.exe`" `"%1`""

Write-Host "Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Wireshark MCP has been installed to: $installDir"
Write-Host "Configuration files are stored in: $configDir"
Write-Host "Capture files will be saved to: $captureDir"
Write-Host ""
Write-Host "To start Wireshark MCP, use the Start menu shortcut or run:"
Write-Host "   wireshark_mcp.exe"
