# Proxmox + Windows Server 2022 (Cloudbase‑Init) – README

This guide explains how to stand up a **Windows Server 2022 Domain Controller (static IP)** and **two member servers** in **Proxmox VE** using **Cloudbase‑Init + Cloud‑Init** and **Terraform**. It assumes you are **not** using Packer (yet). You’ll customize a vanilla Win2022 image, sysprep it into a Proxmox template, and then let Terraform clone and configure everything.

> **Goal**
>
> - DC hostname: `lab-dc01`, IP `192.168.86.201/24`, GW `192.168.86.1`, DNS → itself
> - Members: DHCP IPs, DNS → `192.168.86.201`
> - Automatic forest creation, deterministic Administrator password post‑promotion, reliable domain join for members

---

## 1) Prepare a vanilla Windows Server 2022 image

1. **Create a Proxmox VM** for Windows Server 2022 (from ISO):
   - Machine type: `q35`
   - BIOS: `OVMF (UEFI)`
   - Disk: VirtIO SCSI (or SCSI on ZFS)
   - NIC model: **VirtIO** (install Red Hat VirtIO drivers during/after install)
   - Add the VirtIO ISO (for network/storage drivers) to Proxmox if needed.

2. **Install Cloudbase‑Init** (latest MSI) inside Windows:
   - During setup, choose **ConfigDrive** as metadata source.
   - Allow the service to be installed but we’ll adjust config files next.

3. **Replace Cloudbase‑Init configuration files** (exact content below):
   - `C:\Program Files\Cloudbase Solutions\Cloudbase-Init\conf\cloudbase-init.conf`
   - `C:\Program Files\Cloudbase Solutions\Cloudbase-Init\conf\cloudbase-init-unattend.conf`

> **Important:** Keep each `plugins=` value on **one single line**. We explicitly **exclude** `WindowsLicensingPlugin` which can break first boot on some images.

#### `cloudbase-init.conf` (main service)
```ini
[DEFAULT]
metadata_services=cloudbaseinit.metadata.services.configdrive.ConfigDriveService
plugins=cloudbaseinit.plugins.common.mtu.MTUPlugin,cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin,cloudbaseinit.plugins.windows.networkconfig.NetworkConfigPlugin,cloudbaseinit.plugins.windows.createuser.CreateUserPlugin,cloudbaseinit.plugins.common.userdata.UserDataPlugin,cloudbaseinit.plugins.common.localscripts.LocalScriptsPlugin,cloudbaseinit.plugins.windows.ntp.NTPClientPlugin
first_logon_behaviour=no
allow_reboot=true
stop_service_on_exit=true
inject_user_password=true
mtu_use_dhcp_config=true
ntp_use_dhcp_config=true
bsdtar_path=C:\Program Files\Cloudbase Solutions\Cloudbase-Init\bin\bsdtar.exe
mtools_path=C:\Program Files\Cloudbase Solutions\Cloudbase-Init\bin\
verbose=true
debug=true
log_dir=C:\Program Files\Cloudbase Solutions\Cloudbase-Init\log\
log_file=cloudbase-init.log
default_log_levels=comtypes=INFO,suds=INFO,iso8601=WARN,requests=WARN
logging_serial_port_settings=
local_scripts_path=C:\Program Files\Cloudbase Solutions\Cloudbase-Init\LocalScripts\
check_latest_version=true
config_drive_raw_hhd=true
config_drive_cdrom=true
config_drive_vfat=true
```

#### `cloudbase-init-unattend.conf` (sysprep pass)
```ini
[DEFAULT]
metadata_services=cloudbaseinit.metadata.services.configdrive.ConfigDriveService
plugins=cloudbaseinit.plugins.common.mtu.MTUPlugin,cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin,cloudbaseinit.plugins.windows.networkconfig.NetworkConfigPlugin,cloudbaseinit.plugins.windows.extendvolumes.ExtendVolumesPlugin,cloudbaseinit.plugins.common.userdata.UserDataPlugin
allow_reboot=false
stop_service_on_exit=false
username=Administrator
groups=Administrators
inject_user_password=true
mtu_use_dhcp_config=true
ntp_use_dhcp_config=true
bsdtar_path=C:\Program Files\Cloudbase Solutions\Cloudbase-Init\bin\bsdtar.exe
mtools_path=C:\Program Files\Cloudbase Solutions\Cloudbase-Init\bin\
verbose=true
debug=true
log_dir=C:\Program Files\Cloudbase Solutions\Cloudbase-Init\log\
log_file=cloudbase-init-unattend.log
default_log_levels=comtypes=INFO,suds=INFO,iso8601=WARN,requests=WARN
logging_serial_port_settings=
local_scripts_path=C:\Program Files\Cloudbase Solutions\Cloudbase-Init\LocalScripts\
check_latest_version=false
config_drive_raw_hhd=true
config_drive_cdrom=true
config_drive_vfat=true
```

4. **(Optional) Install VirtIO drivers** inside Windows if you used VirtIO NIC/disk.

5. **Generalize with Sysprep**:
   - Open elevated cmd:
     ```cmd
     %WINDIR%\System32\Sysprep\Sysprep.exe /oobe /generalize /shutdown
     ```
   - When the VM powers off, **convert it to a Proxmox template**.

---

## 2) Terraform project layout

Create a working directory containing at least:

```
./main.tf
./variables.tf
./terraform.tfvars         # your values
```

### `variables.tf`
```hcl
variable "node_name" {}
variable "datastore" {}          # e.g., "local-zfs"
variable "bridge" { default = "vmbr0" }
variable "template_vm_id" {}

variable "vm_cpu"   { default = 2 }
variable "vm_memory_mb" { default = 4096 }
variable "disk_size_gb" { default = 64 }
variable "vm_tags"  { default = ["win","lab"] }

variable "domain_fqdn" {}
variable "domain_netbios" {}
variable "dsrm_password" {}
variable "local_admin_password" {}

variable "domain_join_user" {}    # e.g., "LAB\\Administrator"
variable "domain_join_pass" {}
```

### `main.tf`
```hcl
terraform {
  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = ">= 0.48.0"
    }
  }
}

provider "proxmox" {
  endpoint = var.proxmox_api_url      # export this or add to tfvars
  insecure = true
  api_token = var.proxmox_api_token   # same
}

locals {
  # Define the three VMs and their role
  vms = {
    win2022-dc   = { role = "dc" }
    win2022-app1 = { role = "member" }
    win2022-app2 = { role = "member" }
  }

  # --- Post‑promotion fixer (runs on DC after reboot) ---
  dc_post_promo = <<-PS1
    [CmdletBinding()] param()
    # Wait for AD DS to be up
    for ($i=0; $i -lt 60; $i++) { try { if ((Get-Service NTDS).Status -eq 'Running') { break } } catch {}; Start-Sleep 5 }
    # Ensure DC uses itself for DNS
    $nic = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric,IfMetric | Select-Object -First 1).InterfaceAlias
    if ($nic) { Set-DnsClientServerAddress -InterfaceAlias $nic -ServerAddresses 127.0.0.1,'192.168.86.201' }
    # Set DOMAIN Administrator password deterministically (after promotion)
    cmd /c "net user Administrator '${var.local_admin_password}' /domain"
    # Enable RDP
    Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0
    Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' | Out-Null
    # Remove self
    schtasks /Delete /TN "ZN-PostPromo" /F
  PS1

  # --- DC promotion script ---
  dc_promote = <<-PS1
    [CmdletBinding()] param()
    # Ensure hostname first
    if ((hostname) -ne 'lab-dc01') { Rename-Computer -NewName 'lab-dc01' -Force }
    # Ensure local Admin known before promotion
    net user Administrator '${var.local_admin_password}' /active:yes
    wmic useraccount where "name='Administrator'" set PasswordExpires=False | Out-Null

    # Register startup task for post‑promotion actions (runs as SYSTEM)
    $post = "C:\\Windows\\Temp\\post_promo.ps1"
    Set-Content -Path $post -Value @'${replace(local.dc_post_promo, "'", "''")}' -Encoding UTF8
    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$post`""
    $trigger   = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName 'ZN-PostPromo' -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null

    # Promote without auto‑reboot so we control timing
    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
    $forestParams = @{
      DomainName                    = '${var.domain_fqdn}'
      DomainNetbiosName             = '${var.domain_netbios}'
      SafeModeAdministratorPassword = (ConvertTo-SecureString '${var.dsrm_password}' -AsPlainText -Force)
      ForestMode                    = 'WinThreshold'
      DomainMode                    = 'WinThreshold'
      Force                         = $true
      NoRebootOnCompletion          = $true
    }
    Install-ADDSForest @forestParams
    Restart-Computer -Force
  PS1

  # --- Member DNS + Join script ---
  member_join = <<-PS1
    [CmdletBinding()] param()
    $dcDns   = '192.168.86.201'
    $domain  = '${var.domain_fqdn}'
    $joinUsr = '${var.domain_join_user}'
    $joinPwd = ConvertTo-SecureString '${var.domain_join_pass}' -AsPlainText -Force
    $cred    = New-Object System.Management.Automation.PSCredential($joinUsr,$joinPwd)

    function Get-PrimaryInterfaceIndex {
      $r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
           Sort-Object RouteMetric,IfMetric | Select-Object -First 1
      if ($null -ne $r) { return $r.InterfaceIndex }
      return (Get-NetAdapter | ? Status -eq 'Up' | Select-Object -First 1 -Expand ifIndex)
    }
    $ifIndex = Get-PrimaryInterfaceIndex; if (-not $ifIndex) { Start-Sleep 10; $ifIndex = Get-PrimaryInterfaceIndex }

    try { Set-DnsClientServerAddress -InterfaceIndex $ifIndex -ResetServerAddresses; Set-DnsClientServerAddress -InterfaceIndex $ifIndex -ServerAddresses $dcDns } catch {}

    # Wait for DC DNS to answer
    for ($i=0; $i -lt 40; $i++) { try { Resolve-DnsName -Server $dcDns -Name $domain -ErrorAction Stop | Out-Null; break } catch { Start-Sleep 5 } }

    # Install a startup fixer that keeps DNS until joined
    $fix = @"
    \$dcDns='$dcDns'
    function Get-PrimaryInterfaceIndex { \$r=Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue|Sort-Object RouteMetric,IfMetric|Select-Object -First 1; if(\$r){return \$r.InterfaceIndex}; return (Get-NetAdapter|? Status -eq 'Up'|Select-Object -First 1 -Expand ifIndex) }
    try { if ((Get-WmiObject Win32_ComputerSystem).PartOfDomain) { schtasks /Delete /TN 'ZN-FixDNS' /F | Out-Null; exit 0 } } catch {}
    \$ifIndex=Get-PrimaryInterfaceIndex; if(-not \$ifIndex){exit 0}
    try { Set-DnsClientServerAddress -InterfaceIndex \$ifIndex -ResetServerAddresses; Set-DnsClientServerAddress -InterfaceIndex \$ifIndex -ServerAddresses \$dcDns } catch {}
"@
    $fixFile = 'C:\\Windows\\Temp\\fix_dns_startup.ps1'
    Set-Content -Path $fixFile -Value $fix -Encoding UTF8
    $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$fixFile`""
    $trg = New-ScheduledTaskTrigger -AtStartup
    $pri = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName 'ZN-FixDNS' -Action $act -Trigger $trg -Principal $pri -Force | Out-Null

    # Join
    try { Add-Computer -DomainName $domain -Credential $cred -Force -Restart } catch { Write-Host "Join failed: $($_.Exception.Message)" }
  PS1

  # --- Cloud-Init YAML for DC ---
  dc_cloudconfig = <<-CLOUD
    #cloud-config
    hostname: lab-dc01
    fqdn: lab-dc01.${var.domain_fqdn}
    write_files:
      - path: C:\\Windows\\Temp\\promote_dc.ps1
        permissions: "0644"
        content: |
          ${indent(10, local.dc_promote)}
    runcmd:
      - powershell -NoLogo -NonInteractive -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\promote_dc.ps1
  CLOUD

  # --- Cloud-Init YAML for members ---
  member_cloudconfig = <<-CLOUD
    #cloud-config
    write_files:
      - path: C:\\Windows\\Temp\\set_dns_and_join.ps1
        permissions: "0644"
        content: |
          ${indent(10, local.member_join)}
    runcmd:
      - powershell -NoLogo -NonInteractive -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\set_dns_and_join.ps1
  CLOUD
}

# Upload user-data snippets (ensure they exist before VMs boot)
resource "proxmox_virtual_environment_file" "userdata_dc" {
  node_name    = var.node_name
  datastore_id = "local"
  content_type = "snippets"
  source_raw { data = local.dc_cloudconfig, file_name = "userdata-dc-${var.domain_netbios}.yaml" }
}

resource "proxmox_virtual_environment_file" "userdata_member" {
  node_name    = var.node_name
  datastore_id = "local"
  content_type = "snippets"
  source_raw { data = local.member_cloudconfig, file_name = "userdata-member-${var.domain_netbios}.yaml" }
}

resource "proxmox_virtual_environment_vm" "win" {
  for_each  = local.vms

  depends_on = [
    proxmox_virtual_environment_file.userdata_dc,
    proxmox_virtual_environment_file.userdata_member,
  ]

  name      = each.key
  node_name = var.node_name
  tags      = var.vm_tags

  clone {
    vm_id = var.template_vm_id
    full  = true
  }

  cpu { cores = var.vm_cpu, type = "host" }
  memory { dedicated = var.vm_memory_mb }

  disk {
    interface    = "scsi0"
    datastore_id = var.datastore
    size         = var.disk_size_gb * 1024 # MiB
  }

  network_device { bridge = var.bridge, model = "virtio" }

  agent { enabled = false }

  initialization {
    datastore_id = var.datastore
    interface    = "scsi1"           # Cloud-Init drive

    hostname = each.value.role == "dc" ? "lab-dc01" : each.key

    user_account { username = "Administrator", password = var.local_admin_password }

    ip_config {
      ipv4 {
        address = each.value.role == "dc" ? "192.168.86.201/24" : "dhcp"
        gateway = each.value.role == "dc" ? "192.168.86.1" : null
      }
    }

    dns { servers = ["192.168.86.201"], domain = var.domain_fqdn }

    user_data_file_id = each.value.role == "dc"
      ? proxmox_virtual_environment_file.userdata_dc.id
      : proxmox_virtual_environment_file.userdata_member.id
  }

  boot_order = ["scsi0"]
  on_boot    = true
  started    = true
}
```

### `terraform.tfvars` (example)
```hcl
proxmox_api_url   = "https://pve.example.local:8006/api2/json"
proxmox_api_token = "root@pam!tf=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

node_name = "pve"
datastore = "local-zfs"
bridge    = "vmbr0"

template_vm_id = 900         # your Win2022 template ID

vm_cpu        = 2
vm_memory_mb  = 4096
disk_size_gb  = 64
vm_tags       = ["win","lab"]

domain_fqdn       = "lab.local"
domain_netbios    = "LAB"
local_admin_password = "Set.Adm1n.P@ssw0rd!"
dsrm_password        = "Strong.Dsrm.P@ssw0rd!"

domain_join_user = "LAB\\Administrator"
domain_join_pass = "Set.Adm1n.P@ssw0rd!"
```

---

## 3) Apply with Terraform

```bash
terraform init
terraform plan
terraform apply -auto-approve
```

What happens:
- Proxmox clones the Win2022 **template** into three VMs.
- **DC** boots with static IP (201), Cloudbase‑Init runs the promotion script, reboots, then the **post‑promo task** sets the **domain** Administrator password, DNS, enables RDP, and self‑deletes.
- **Members** boot, **force DNS → 201**, confirm resolution, join the domain, and install a startup fixer that persists DNS until they’re joined.

> **Logon after build**: Use `LAB\Administrator` with `local_admin_password` on the DC and (after join) on members.

---

## 4) Smoke tests

On **DC** (console, elevated PowerShell):
```powershell
ipconfig /all
Get-Service NTDS,DNS
Resolve-DnsName $env:COMPUTERNAME
Resolve-DnsName ${env:USERDNSDOMAIN}
schtasks /Query /TN "ZN-PostPromo"
```

On a **member**:
```powershell
$if=(Get-NetRoute -DestinationPrefix 0.0.0.0/0|Sort-Object RouteMetric,IfMetric|Select-Object -First 1).InterfaceIndex
Get-DnsClientServerAddress -InterfaceIndex $if
Resolve-DnsName -Server 192.168.86.201 ${env:USERDNSDOMAIN}
(Get-WmiObject Win32_ComputerSystem).PartOfDomain
```

---

## 5) Troubleshooting

- **Cloudbase‑Init service won’t start** → likely bad INI formatting. Ensure `plugins=` is **one line**; files saved as **UTF‑8** (not UTF‑16). Check `C:\Program Files\Cloudbase Solutions\Cloudbase-Init\log\cloudbase-init.log`.
- **UserData not executed on members** → verify the **template** has the updated config files, the VM **has a Cloud‑Init drive** (SCSI1), and Terraform has `depends_on` the uploaded snippet resources.
- **Licensing plugin crash** (`wmi.x_wmi: Class not registered`) → confirm it’s **not** in the plugin list.
- **Kerberos time skew** → run `w32tm /resync` on DC and members.
- **VirtIO NIC shows no network** → install VirtIO drivers inside the template.

---

## 6) Next steps / Nice‑to‑haves

- Bake all of this into a **Packer** template for reproducible images.
- Add Terraform output for VM IPs and RDP details.
- Parameterize the DC static IP and gateway.
- Add DNS forwarders on the DC (e.g., `8.8.8.8`, `1.1.1.1`).

---

**That’s it.** With these configs, you can clone from a vanilla Win2022 image, reliably promote a DC, and join members—no manual steps after `terraform apply`. Enjoy! 🚀