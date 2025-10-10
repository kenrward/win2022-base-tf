output "vm_names" {
  value = keys(proxmox_virtual_environment_vm.win)
}

output "vm_ids" {
  value = { for n, r in proxmox_virtual_environment_vm.win : n => r.id }
}
