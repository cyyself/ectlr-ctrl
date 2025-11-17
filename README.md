# ARM ECTLR Control Driver

This driver provides control over the ECTLR (Enhanced Cache Type Register) for ARM processors. It includes a whitelist mechanism to enable or disable specific features based on the CPU model.

## Note

We haven't successfully tested writing to ECTLR_EL1 on any real hardware yet. Please be cautious when using this driver, as incorrect settings may lead to system instability.

We have tested Radxa Orion O6 and AWS Graviton4 Bare Metal instances. Write IMP_CPUECTLR_EL1 on Radxa Orion O6 at EL2 causes CPU to offline (probably due to trap to EL3). On AWS Graviton4, writing IMP_CPUECTLR_EL1 at EL2 will not change the actual ECTLR_EL1 value, but the write operation itself is successful.

We believe we should modify the EL3 firmware to set `ACTLR_EL3.ECTLREN=1` to allow writes to ECTLR_EL1 from EL2.

## How to use

0. Assume your Kernel is started on EL2. And firmware has set `ACTLR_EL3.ECTLREN=1`.

1. Compile the driver using the provided Makefile. `make` command should suffice.

2. Load the driver into the kernel using `sudo insmod ectlr.ko`.

3. Access the sysfs entries under `/sys/kernel/ectlr/cpuX/` to read or modify the ECTLR registers for each CPU.

For example, to disable Disable Global Spatial Memory Streaming Prefetcher (bit 56 of ECTLR_EL1) on Cortex A720 (CPU 0):

```console
$ make
$ sudo insmod ectlr.ko
$ sudo cat /sys/kernel/ectlr/cpu0/imp_cpuectlr_el1
0x242000720620b014
$ echo 0x252000720620b014 | sudo tee /sys/kernel/ectlr/cpu0/imp_cpuectlr_el1
0x252000720620b014
```

## Whitelist Entries

We have included whitelist entries for the following CPU models:

- Cortex-A520
- Cortex-A720
- Neoverse N2
- Neoverse V2

You can add more entries to the whitelist by modifying the `ectlr.c` file and recompiling the driver. Each entry consists of a MIDR value and a corresponding mask.
