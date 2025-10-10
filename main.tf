locals {
  vms = {
    win2022-dc   = { role = "dc" }
    #win2022-app1 = { role = "member" }
    #win2022-app2 = { role = "member" }
  }

  # --- Cloud-config for DC: write PS1 and execute it ---
  dc_cloudconfig = <<-CLOUD
    #cloud-config
    write_files:
      - path: C:\\Windows\\Temp\\promote_dc.ps1
        permissions: "0644"
        content: |
          [CmdletBinding()]
          param()
          Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
          $forestParams = @{
            DomainName                    = "${var.domain_fqdn}"
            DomainNetbiosName             = "${var.domain_netbios}"
            SafeModeAdministratorPassword = (ConvertTo-SecureString "${var.dsrm_password}" -AsPlainText -Force)
            ForestMode                    = "WinThreshold"
            DomainMode                    = "WinThreshold"
            Force                         = $true
          }
          Install-ADDSForest @forestParams
    runcmd:
      - powershell -NoLogo -NonInteractive -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\promote_dc.ps1
  CLOUD

  # --- Cloud-config for member servers ---
  member_cloudconfig = <<-CLOUD
    #cloud-config
    write_files:
      - path: C:\\Windows\\Temp\\join_domain.ps1
        permissions: "0644"
        content: |
          [CmdletBinding()]
          param()
          $joinUser = "${var.domain_join_user}"
          $joinPass = ConvertTo-SecureString "${var.domain_join_pass}" -AsPlainText -Force
          $cred     = New-Object System.Management.Automation.PSCredential($joinUser, $joinPass)
          $domain   = "${var.domain_fqdn}"
          $maxTries = 40
          for ($i=0; $i -lt $maxTries; $i++) {
            try { Resolve-DnsName -Name $domain -ErrorAction Stop | Out-Null; break } catch { Start-Sleep -Seconds 15 }
          }
          Add-Computer -DomainName $domain -Credential $cred -Force -Restart
    runcmd:
      - powershell -NoLogo -NonInteractive -ExecutionPolicy Bypass -File C:\\Windows\\Temp\\join_domain.ps1
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
    enabled = true
  }

  # --- Cloud-Init disk + reference to uploaded snippet ---
  initialization {
    datastore_id = var.datastore

    user_account {
      username = "Administrator"
      password = var.local_admin_password
    }

    ip_config {
      ipv4 {
        address = "dhcp"
      }
    }

    # Single-line ternary EXACTLY like this:
    user_data_file_id = each.value.role == "dc" ? proxmox_virtual_environment_file.userdata_dc.id : proxmox_virtual_environment_file.userdata_member.id
  }

  boot_order = ["scsi0"]
  on_boot    = true
  started    = true
}
