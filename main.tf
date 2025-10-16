locals {
  vms = {
    win2022-dc   = { role = "dc" }
    win2022-app1 = { role = "member" }
    win2022-app2 = { role = "member" }
  }

  # --- Cloud-config for DC: write PS1 and execute it ---
  dc_cloudconfig = <<-CLOUD
    #cloud-config
    hostname: lab-dc01
    fqdn: lab-dc01.${var.domain_fqdn}

    write_files:
      - path: C:\\Windows\\Temp\\post_promo.ps1
        permissions: "0644"
        content: |
          [CmdletBinding()]
          param()
          # Wait for AD DS to be up
          $max = 60
          for ($i=0; $i -lt $max; $i++) {
            try {
              $ntds = Get-Service NTDS -ErrorAction Stop
              if ($ntds.Status -eq 'Running') { break }
            } catch {}
            Start-Sleep -Seconds 5
          }

          # Set the DOMAIN Administrator password (on a DC, /domain targets AD)
          net user Administrator "${var.local_admin_password}" /domain

          # Optional: enable RDP for convenience
          Set-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 0
          Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' | Out-Null

          # Self-cleanup: remove this scheduled task
          schtasks /Delete /TN "ZN-PostPromo" /F

      - path: C:\\Windows\\Temp\\promote_dc.ps1
        permissions: "0644"
        content: |
          [CmdletBinding()]
          param()

          # Ensure hostname before promotion (safety)
          try {
            if ((hostname) -ne "lab-dc01") {
              Rename-Computer -NewName "lab-dc01" -Force
            }
          } catch {}

          # Make sure local Administrator is enabled with the expected password pre-promo
          net user Administrator "${var.local_admin_password}" /active:yes
          wmic useraccount where "name='Administrator'" set PasswordExpires=False | Out-Null

          # Register a startup task that will set the DOMAIN Administrator password AFTER promotion
          $action    = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\post_promo.ps1"
          $trigger   = New-ScheduledTaskTrigger -AtStartup
          $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
          Register-ScheduledTask -TaskName "ZN-PostPromo" -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null

          # Promote to first forest DC without auto-reboot
          Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
          $forestParams = @{
            DomainName                    = "${var.domain_fqdn}"
            DomainNetbiosName             = "${var.domain_netbios}"
            SafeModeAdministratorPassword = (ConvertTo-SecureString "${var.dsrm_password}" -AsPlainText -Force)
            ForestMode                    = "WinThreshold"
            DomainMode                    = "WinThreshold"
            Force                         = $true
            NoRebootOnCompletion          = $true
          }
          Install-ADDSForest @forestParams

          # Now we control the reboot; the startup task will finalize the password in the DOMAIN context
          Restart-Computer -Force

    runcmd:
      - powershell -NoLogo -NonInteractive -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\promote_dc.ps1
  CLOUD

  # --- Cloud-config for member servers ---
  member_cloudconfig = <<-CLOUD
    #cloud-config
    write_files:
      - path: C:\\Windows\\Temp\\set_dns_and_join.ps1
        permissions: "0644"
        content: |
          [CmdletBinding()]
          param()

          $dcDns = "192.168.86.201"
          $domain = "${var.domain_fqdn}"
          $joinUser = "${var.domain_join_user}"
          $joinPass = ConvertTo-SecureString "${var.domain_join_pass}" -AsPlainText -Force
          $cred     = New-Object System.Management.Automation.PSCredential($joinUser, $joinPass)

          function Get-PrimaryInterfaceIndex {
            # Pick NIC tied to the default IPv4 route
            $route = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
                     Sort-Object -Property RouteMetric, ifMetric -Descending:$false |
                     Select-Object -First 1
            if ($null -ne $route) { return $route.InterfaceIndex }
            # Fallback: first "Up" NIC
            return (Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1 -ExpandProperty ifIndex)
          }

          $ifIndex = Get-PrimaryInterfaceIndex
          if (-not $ifIndex) { Start-Sleep -Seconds 10; $ifIndex = Get-PrimaryInterfaceIndex }

          # Force DNS to the DC (clear DHCP-provided DNS first)
          try {
            Set-DnsClientServerAddress -InterfaceIndex $ifIndex -ResetServerAddresses -ErrorAction Stop
            Set-DnsClientServerAddress -InterfaceIndex $ifIndex -ServerAddresses $dcDns -ErrorAction Stop
          } catch {
            Write-Host "Failed to set DNS on ifIndex $ifIndex: $($_.Exception.Message)"
          }

          # Verify we can query the domain against the DC's DNS specifically
          $max = 40
          for ($i=0; $i -lt $max; $i++) {
            try {
              Resolve-DnsName -Server $dcDns -Name $domain -ErrorAction Stop | Out-Null
              break
            } catch {
              Start-Sleep -Seconds 5
            }
          }

          # Optional: install a startup task that re-applies DNS on reboot (removed after the box is domain-joined)
          $fixScript = @"
          \$dcDns = "$dcDns"
          function Get-PrimaryInterfaceIndex {
            \$route = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
                     Sort-Object -Property RouteMetric, ifMetric -Descending:\$false |
                     Select-Object -First 1
            if (\$null -ne \$route) { return \$route.InterfaceIndex }
            return (Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1 -ExpandProperty ifIndex)
          }
          try {
            # If already domain-joined, remove task and quit
            if ((Get-WmiObject Win32_ComputerSystem).PartOfDomain) {
              schtasks /Delete /TN "ZN-FixDNS" /F | Out-Null
              exit 0
            }
          } catch {}

          \$ifIndex = Get-PrimaryInterfaceIndex
          if (-not \$ifIndex) { exit 0 }
          try {
            Set-DnsClientServerAddress -InterfaceIndex \$ifIndex -ResetServerAddresses
            Set-DnsClientServerAddress -InterfaceIndex \$ifIndex -ServerAddresses \$dcDns
          } catch {}
"@

          $fixFile = "C:\\Windows\\Temp\\fix_dns_startup.ps1"
          $fixScript | Out-File -FilePath $fixFile -Encoding UTF8 -Force

          $action    = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$fixFile`""
          $trigger   = New-ScheduledTaskTrigger -AtStartup
          $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
          Register-ScheduledTask -TaskName "ZN-FixDNS" -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null

          # Attempt the join now that DNS is correct
          try {
            Add-Computer -DomainName $domain -Credential $cred -Force -Restart
          } catch {
            Write-Host "Join failed: $($_.Exception.Message)"
            # Leave the startup task so DNS sticks across reboots; admin can retry the join.
          }

    runcmd:
      - powershell -NoLogo -NonInteractive -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\set_dns_and_join.ps1
  CLOUD
}

# --- Upload cloud-config snippets to a datastore with Snippets enabled (use 'local') ---
resource "proxmox_virtual_environment_file" "userdata_dc" {
  node_name    = var.node_name
  datastore_id = "local"
  content_type = "snippets"

  source_raw {
    data      = local.dc_cloudconfig
    file_name = "userdata-dc-${var.domain_netbios}.yaml"
  }
}

resource "proxmox_virtual_environment_file" "userdata_member" {
  node_name    = var.node_name
  datastore_id = "local"
  content_type = "snippets"

  source_raw {
    data      = local.member_cloudconfig
    file_name = "userdata-member-${var.domain_netbios}.yaml"
  }
}

# --- Create the 3 VMs by cloning the template ---
resource "proxmox_virtual_environment_vm" "win" {
  for_each = local.vms

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

  cpu {
    cores = var.vm_cpu
    type  = "host"
  }

  memory {
    dedicated = var.vm_memory_mb
  }

  # Disk (ensure size >= template) on local-zfs
  disk {
    interface    = "scsi0"
    datastore_id = var.datastore
    size         = var.disk_size_gb * 1024 # MiB
  }

  # NIC on vmbr0 (DHCP)
  network_device {
    bridge = var.bridge
    model  = "virtio"
  }

  agent {
    enabled = false
  }

  # --- Cloud-Init disk + reference to uploaded snippet ---
  initialization {
    datastore_id = var.datastore
    interface    = "scsi1"

    user_account {
      username = "Administrator"
      password = var.local_admin_password
    }

    # --- Network config ---
    ip_config {
      ipv4 {
        # DC = static; members = DHCP
        address = each.value.role == "dc" ? "192.168.86.201/24" : "dhcp"
        gateway = each.value.role == "dc" ? "192.168.86.1"    : null
      }
    }

    # Everyone uses the DC as DNS so members can resolve the domain
    dns {
      servers = ["192.168.86.201"]
      domain  = var.domain_fqdn
    }
    
    # Single-line ternary EXACTLY like this:
    user_data_file_id = each.value.role == "dc" ? proxmox_virtual_environment_file.userdata_dc.id : proxmox_virtual_environment_file.userdata_member.id
  }

  boot_order = ["scsi0"]
  on_boot    = true
  started    = true
}
