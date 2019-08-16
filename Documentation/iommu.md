I/O MMU
=======
**2019-08-15** Aditya Basu (`mitthu`)

Contents
-------------------------------
+ Acronyms
+ I/O MMU Workings
    - IOTLB shootdowns
+ Running Akaros in QEMU

Acronyms
-------------------------------
+ IEC:  Interrupt Entry Cache
+ RWBF: Required Write-Buffer Flushing
+ IVT:  Invalidate IOTLB

I/O MMU Workings
-------------------------------

### IOTLB Shootdowns / flusing

* If RWBF set in capability, then perform write buffer flushing.
* If IOTLB is present, then we can perform one of the following:
    + global shootdown
    + DID specific shootdown (We perform this!)
    + page-specific shootdown for a specific DID

Running Akaors in QEMU
-------------------------------
* Currently running in QEMU requires a recompilation. This is to allow 4-level
  paging for the IOMMU. Do the following:
    - For qemu version 4.0.50, we need to modify line 52 of
      "include/hw/i386/intel_iommu.h".
    - The macro `VTD_HOST_ADDRESS_WIDTH` will be `VTD_HOST_AW_39BIT`. Change it
      to `VTD_HOST_AW_48BIT` and recompile.

```bash
# Prepare device for passthrough (on Linux host)
# - unbind from existing driver
# - make sure the VFIO module is loaded
# - make sure all virtual functions are released by the driver
# - bind to VFIO driver for passthrough
$ PCIDEVICE_BDF=0000:00:04.*
$ echo $(PCIDEVICE_BDF) | sudo tee /sys/bus/pci/devices/$(PCIDEVICE_BDF)/driver/unbind 
$ sudo modprobe vfio-pci
$ sudo rmmod ioatdma
$ echo $(PCIDEVICE_ID) | sudo tee /sys/bus/pci/drivers/vfio-pci/new_id

# Standard run
$ sudo $(QEMU) \
    -enable-kvm \
    -cpu host \
    -smp 8 \
    -m 4096 \
    -nographic \
    -net nic,model=e1000 \
    -net user,hostfwd=tcp::5555-:22 \
    -machine q35,accel=kvm,kernel-irqchip=split \
    -device intel-iommu,intremap=off,caching-mode=on,device-iotlb=on \
    -device vfio-pci,host=00:04.0 \
    -kernel obj/kern/akaros-kernel

# Trace QEMU calls (for debugging)
$ echo -n '' >/tmp/qemu-trace
$ echo 'vfio_pci_read_config' >>/tmp/qemu-trace
$ echo 'vfio_pci_write_config' >>/tmp/qemu-trace
$ echo 'vfio_region_read' >>/tmp/qemu-trace
$ echo 'vfio_region_write' >>/tmp/qemu-trace
$ echo 'pci_data_read' >>/tmp/qemu-trace

$ sudo $(QEMU) \
    -trace events=/tmp/qemu-trace \
    -enable-kvm \
    -cpu host \
    -smp 8 \
    -m 4096 \
    -nographic \
    -net nic,model=e1000 \
    -net user,hostfwd=tcp::5555-:22 \
    -device vfio-pci,host=00:04.0 \
    -kernel obj/kern/akaros-kernel
```
