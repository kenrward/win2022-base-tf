terraform {
  required_version = ">= 1.6.0"
  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "0.84.1"
    }
  }
}

provider "proxmox" {
  # All sensitive values pulled from environment-backed variables
  endpoint  = var.proxmox_api_url
  username  = var.proxmox_api_token_id
  api_token = var.proxmox_api_token_secret
  insecure  = false

  ssh {
    agent    = true
    username = "root" #
    node {
      name    = var.node_name # "pve"
      address = "192.168.86.21"
    }
  }
}
