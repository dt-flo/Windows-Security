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
    $OverwritePIN = $false
)
$NewPIN = $PIN
$RunAsAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")

if (-Not $RunAsAdmin) {
    if (-Not $SilentMode) {
        Write-Host "The script needs to run with administrative privileges."
    }
    exit;
}

$MountPoint = $env:SystemDrive

$BitlockerStateC = Get-BitLockerVolume | Select-Object -Property "MountPoint", "ProtectionStatus", "KeyProtector" | Where-Object -Property MountPoint -EQ $MountPoint

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


if ($(([string]::IsNullOrEmpty($NewPIN)))) {
    if (-NOT $SilentMode) {
        $NewPIN = Read-Host -Prompt "Enter new PIN (numeric and between 8 and 20 characters)" -AsSecureString
        CheckPIN($NewPIN)
    }
    else {
        exit;
    }
}
else {
    CheckPIN($NewPIN)
}


if ($NewPIN.GetType().Name -eq "String") {
    $NewPIN = ConvertTo-SecureString -String $NewPIN -AsPlainText;
}

if ($KeyProtectorType -eq "Tpm") {
    Add-BitLockerKeyProtector $env:SystemDrive -TpmAndPinProtector -Pin $NewPIN
}
elseif ($KeyprotectorType -eq "TpmPin") {
    if ($OverwritePIN -eq $true) {
        Remove-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $TPMKeyProtector.KeyProtectorId
        Add-BitLockerKeyProtector $env:SystemDrive -TpmAndPinProtector -Pin $NewPIN
    }
    else {
        if ($SilentMode -ne $true) {
            Write-Host "A PIN has already been set. The overwrite flag was not used so no changes to the PIN have been made."
        }
    }
}
