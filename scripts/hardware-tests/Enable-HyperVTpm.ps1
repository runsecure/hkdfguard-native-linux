<#
.SYNOPSIS
    Enables a virtual TPM on Hyper-V Linux test VMs, starts each one, takes a
    checkpoint to roll back to after testing, and prints the address to
    reach it at with run-remote.sh.

.DESCRIPTION
    Run on the Hyper-V host, elevated. A vTPM needs a Generation 2 VM; others
    are skipped. Safe to rerun: a VM that already has a key protector or a
    vTPM keeps it - replacing a key protector would make the VM's current TPM
    state unreadable. A running VM is shut down (a guest shutdown) to enable
    its vTPM.

    A Linux guest with Secure Boot on needs the "Microsoft UEFI Certificate
    Authority" template; one still on the Windows template is reported, not
    changed.

    In each guest, scripts/hardware-tests/tpm-probe.sh should then find
    /dev/tpmrm0 with manufacturer MSFT.

.PARAMETER VMName
    The VMs to set up.

.PARAMETER CheckpointName
    The checkpoint taken once each VM is running. Default: pre-hkdfguard.
#>
#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory)][string[]]$VMName,
    [string]$CheckpointName = "pre-hkdfguard"
)
$ErrorActionPreference = "Stop"

foreach ($name in $VMName) {
    Write-Host "== $name"
    $vm = Get-VM -Name $name
    if ($vm.Generation -ne 2) {
        Write-Host "  Generation $($vm.Generation) VM: a vTPM needs Generation 2. Skipped."
        continue
    }

    $fw = Get-VMFirmware -VMName $name
    if ($fw.SecureBoot -eq "On" -and $fw.SecureBootTemplate -ne "MicrosoftUEFICertificateAuthority") {
        Write-Warning "  Secure Boot uses the '$($fw.SecureBootTemplate)' template, which most Linux guests cannot boot under. With the VM off: Set-VMFirmware -VMName $name -SecureBootTemplate MicrosoftUEFICertificateAuthority"
    }

    if ((Get-VMSecurity -VMName $name).TpmEnabled) {
        Write-Host "  vTPM already enabled"
    } else {
        if ($vm.State -ne "Off") {
            Write-Host "  shutting down"
            Stop-VM -Name $name    # guest shutdown; add -Force to answer its prompts, -TurnOff to pull the plug
        }
        $kp = Get-VMKeyProtector -VMName $name
        if (-not $kp -or $kp.Length -le 4) {
            Write-Host "  adding a local key protector"
            Set-VMKeyProtector -VMName $name -NewLocalKeyProtector
        } else {
            Write-Host "  key protector already present"
        }
        Write-Host "  enabling vTPM"
        Enable-VMTPM -VMName $name
    }

    if ((Get-VM -Name $name).State -ne "Running") {
        Write-Host "  starting"
        Start-VM -Name $name
    }
    Write-Host "  checkpoint $CheckpointName"
    Checkpoint-VM -Name $name -SnapshotName $CheckpointName
    Get-VMSecurity -VMName $name | Format-List TpmEnabled, KsdEnabled, Shielded | Out-Host

    # The guest reports its addresses through the Hyper-V KVP daemon
    # (hv_kvp_daemon: hyperv-daemons / linux-cloud-tools), once it has booted.
    $ip = $null
    for ($i = 0; $i -lt 24 -and -not $ip; $i++) {
        $ip = (Get-VMNetworkAdapter -VMName $name).IPAddresses | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1
        if (-not $ip) { Start-Sleep -Seconds 5 }
    }
    if ($ip) {
        Write-Host "  address $ip  ->  scripts/hardware-tests/run-remote.sh <user>@$ip"
    } else {
        Write-Host "  no address reported yet (is the KVP daemon installed in the guest?)"
    }
}
