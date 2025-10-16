# -------- Provider/Auth --------
variable "proxmox_api_url" {
  type        = string
  description = "Proxmox VE API endpoint, e.g. https://pve:8006/"
}

variable "proxmox_api_token_id" {
  type        = string
  description = "Token ID, e.g. terraform@pve!provider"
  sensitive   = true
}

variable "proxmox_api_token_secret" {
  type        = string
  description = "API token secret"
  sensitive   = true
}

# -------- Infra Defaults --------
variable "node_name" {
  type        = string
  default     = "pve"
  description = "Target Proxmox node"
}

variable "datastore" {
  type        = string
  default     = "local-zfs"
  description = "Datastore for disks/cloud-init"
}

variable "bridge" {
  type        = string
  default     = "vmbr0"
  description = "Bridge for NIC (DHCP)"
}

variable "template_vm_id" {
  type        = number
  default     = 9007
  
  description = "VMID of the Windows 2022 template to clone"
}
variable "template_name" {
  type        = string
  default     = "win2022-base-v2"
  description = "Existing Proxmox template name (Windows 2022 + Cloudbase-Init)"
}

# -------- Domain Config --------
variable "domain_fqdn" {
  type        = string
  default     = "lab.local"
  description = "AD domain FQDN for new forest"
}

variable "domain_netbios" {
  type        = string
  default     = "LAB"
  description = "NETBIOS short name"
}

variable "dsrm_password" {
  type        = string
  sensitive   = true
  description = "DSRM password used for DC promotion"
}

variable "domain_join_user" {
  type        = string
  sensitive   = true
  description = "Domain join user (sAMAccountName or UPN)"
}

variable "domain_join_pass" {
  type        = string
  sensitive   = true
  description = "Domain join password"
}

# -------- VM Sizing/Tags --------
variable "vm_cpu" {
  type    = number
  default = 2
}

variable "vm_memory_mb" {
  type    = number
  default = 4096
}

variable "vm_tags" {
  type    = list(string)
  default = ["win2022", "terraform", "cloudbase-init"]
}

variable "local_admin_password" {
  type        = string
  sensitive   = true
  description = "Local Administrator password injected via cloud-init"
}
# ensure disk size >= template to avoid shrink error
variable "disk_size_gb" {
  type    = number
  default = 80
}