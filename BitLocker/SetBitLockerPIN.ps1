param(
    # New PIN
    [Parameter(Position = 1)]
    [String]
    $PIN,
    # SilentMode
    [Parameter(Position = 2)]
    [switch]
    $SilentMode = $false,
    # Overwrite current PIN
    [Parameter(Position = 3)]
    [switch]
    $OverwritePIN = $false,
    # Help parameter
    [Parameter()]
    [switch]
    $help = $false
)

if ($help) {
    Write-Output "This script allows deploying a PIN for BitLocker encrypted drives."
    Write-Output "Usage: .\SetBitLockerPIN [-PIN <NEWPIN>] [-Silentmode] [-Overwritepin]"
    Write-Output "-PIN: Sets new PIN"
    Write-Output "-Silentmode: Does not produce any outputs, suppresses errors"
    Write-Output "-OverwritePIN: Sets new PIN even if there is already a PIN present"
    Write-Output "Warning: If setting a new PIN fails, a TPM protector will be deployed. If no PIN is specified, the PIN is removed."
    exit
}

$NewPIN = $PIN
$RunAsAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")

if (-Not $RunAsAdmin) {
    if (-Not $SilentMode) {
        Write-Host "The script needs to run with administrative privileges."
    }
    exit;
}

$BitlockerStateC = Get-BitLockerVolume | Select-Object -Property "MountPoint", "ProtectionStatus", "KeyProtector" | Where-Object -Property MountPoint -EQ $env:SystemDrive

if ($BitlockerStateC.ProtectionStatus -ne "On") {
    if (-NOT $SilentMode) {
        Write-Host "The system drive $env:SystemDrive protection is not fully active. Try resuming/activating BitLocker."
    }
    exit
}

$correctKeyProtectors = $true
foreach ($Keyprotector in $BitlockerStateC.KeyProtector) {
    if (-NOT (($Keyprotector.KeyProtectorType -eq "RecoveryPassword") -or ($Keyprotector.KeyProtectorType -eq "Tpm") -or ($Keyprotector.KeyProtectorType -eq "TpmPin"))) {
        $correctKeyProtectors = $false
    }
    else {
        if (-NOT ($Keyprotector.KeyProtectorType.toString() -eq "RecoveryPassword")) {
            $TPMKeyProtector = $Keyprotector
            $KeyProtectorType = $Keyprotector.KeyProtectorType.toString()
        }
    }
}


if (-NOT $correctKeyProtectors) {
    if (-NOT $SilentMode) {
        Write-Host "BitLocker is active but running with not supported authentication methods. Only TPM or TPM+PIN is supported."
    }
    exit
}

function CheckPIN {
    param (
        $PIN
    )
    if (($NewPIN.length -gt 20) -or ($NewPIN.length -lt 8)) {
        if (-NOT $SilentMode) {
            Write-Host "PIN has to be numeric and has to consist of between 8 to 20 digits."
        }
        exit
    }
}

$removePIN = $false

if ($(([string]::IsNullOrEmpty($NewPIN)))) {
    if (-NOT $SilentMode) {
        $NewPIN = Read-Host -Prompt "Enter new PIN (numeric and between 8 and 20 characters)" -AsSecureString
        if ($NewPIN.Length -gt 0) {
            CheckPIN($NewPIN)
        }
        else {
            $removePIN = $true
        }
    }
    else {
        $removePIN = $true
    }
}
else {
    CheckPIN($NewPIN)
}


if ($NewPIN.GetType().Name -eq "String") {
    $NewPIN = ConvertTo-SecureString -String $NewPIN -AsPlainText;
}

if ($KeyProtectorType -eq "Tpm") {
    if ($removePIN -eq $false) {
        Add-BitLockerKeyProtector $env:SystemDrive -TpmAndPinProtector -Pin $NewPIN | Out-Null
    }
    else {
        exit
    }
}
elseif ($KeyprotectorType -eq "TpmPin") {
    if ($OverwritePIN -eq $true) {
        if ($removePIN -eq $false) {
            Remove-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $TPMKeyProtector.KeyProtectorId | Out-Null
            $Error.clear()
            Add-BitLockerKeyProtector $env:SystemDrive -TpmAndPinProtector -Pin $NewPIN | Out-Null
            if ($Error[0] -match "0x803100CC") {
                Add-BitLockerKeyProtector $env:SystemDrive -TpmProtector | Out-Null
            }
        }
        else {
            Remove-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $TPMKeyProtector.KeyProtectorId | Out-Null
            Add-BitLockerKeyProtector $env:SystemDrive -TpmProtector | Out-Null
        }
    }
    else {
        if ($SilentMode -ne $true) {
            Write-Host "A PIN has already been set. The overwrite flag was not used so no changes to the PIN have been made."
        }
    }
}