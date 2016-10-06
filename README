# check_vm.sh
[linux] detect the virtual environment (check if we are on VPS/VDS or a dedicated server)

EXAMPLE: qemu/KVM

```
[root@localhost ~]# sh check_vm.sh
-----BEGIN OUTPUT-----
DETECTIONS: 16
kvm: cpuinfo harddisk bus cpuid interrupts ps_aux vda dmesg lscpu lspci lsmod dmidecode
vbox: cpuid 
other: single_core low_ram small_hdd hypervisor 

kvm 12
-----END OUTPUT-----
```

EXAMPLE: VirtualBox

```
[root@localhost ~]# sh check_vm.sh
-----BEGIN OUTPUT-----
DETECTIONS: 6
vbox: harddisk dmesg scsi
other: single_core low_ram small_hdd 

vbox 3
-----END OUTPUT-----

```

EXAMPLE: dedicated server

```
[root@localhost ~]# sh check_vm.sh 
-----BEGIN OUTPUT-----

-----END OUTPUT-----
```

EXAMPLE: local host with libvirt installed (thus xen&vbox detects)
```
[user@localhost ~]$ sh check_vm.sh  
-----BEGIN OUTPUT-----
DETECTIONS: 3
xen: bus 
vbox: dmesg 
other: no_dmidecode 

xen 1
-----END OUTPUT-----
```

