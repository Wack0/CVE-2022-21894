# baton drop (CVE-2022-21894): Secure Boot Security Feature Bypass Vulnerability

Windows Boot Applications allow the `truncatememory` setting to remove blocks of memory containing "persistent" ranges of serialised data from the memory map, leading to Secure Boot bypass.

- The `truncatememory` BCD element will remove all memory above a specified physical address from the memory map.
- This is performed for each boot application during initialisation, before the serialised Secure Boot policy is read from memory.
- Therefore, such an element can be used to remove the serialised Secure Boot policy from the memory map.
- This will allow dangerous settings to be used in a boot application (`bootdebug`, `testsigning`, `nointegritychecks`), thus breaking Secure Boot.

This issue was fixed by two different changes:
- After attempting to load a serialised Secure Boot policy, if no policy was loaded, and Secure Boot is enabled, and the boot application was not loaded directly by UEFI firmware, and the boot application is not `bootmgr`, boot application initialisation fails.
- When loading a boot application, if it has a `VERSIONINFO` resource containing an `OriginalFilename`, if that filename is included in a blocklist (containing `bootmgr.exe` and `hvloader.exe`; in Nickel, `hvloader.efi` was added but this did not get backported), the load fails.
    - In Windows 8 and Windows 8.1, `hvloader.exe` is not included in `winload`'s blocklist - it originally was, which broke Hyper-V loading!
    - Since Windows 10 version 1809, if a certain flags bit is set (used with `flightedbootmgr` element to load `bootmgr` from disk), the `OriginalFilename` is **required** to be `bootmgr.exe`.

## Exploitation

The attacker needs to ensure the serialised Secure Boot Policy is allocated above a known physical address.

- By default, it is allocated at the lowest possible address.
- Originally, the serialised Secure Boot Policy gets allocated after it is loaded, before using any configuration loaded from the BCD.
    - Since RS1, the serialised Secure Boot Policy gets allocated when loading a boot application.
    - Since RS2, any existing serialised Secure Boot Policy gets freed when serialising a Secure Boot Policy.
- The serialised Secure Boot Policy gets reallocated if, when loading a boot application, the BCD entry's `osdevice` is a BitLocker-encrypted partition where the VMK was derived using the TPM.
    - This can be faked by setting bit 0 of the key flags after successful TPM unsealing; this bit can be set manually in the BitLocker metadata, with additional metadata added to specify Secure Boot being used for integrity validation.

The `avoidlowmemory` element can be used to ensure all allocations of physical memory are above a specified physical address:

- Since Windows 10, this element is disallowed if VBS is enabled, but as it is used during boot application initialisation, before the serialised Secure Boot policy is read from memory, loading `bootmgr` and specifying a custom BCD path (using `bcdfilepath` element aka `custom:22000023`) can be used to bypass this.
- If BitLocker is present on the OS volume, or the target system is running TH1 or TH2, then this method will fail; it is therefore also possible to run the attack once with a Windows 8.x `bootmgr` to disable VBS and then swap back to the original bootloader.
    - Windows 10 changed boot application initialisation to cap all TPM PCRs once, so a Windows 8.x `bootmgr` will fail to unseal the VMK on a Windows 10+ system.
    
`hvloader.efi` can be loaded with the `nointegritychecks` element to load a self-signed `mcupdate.dll`, whose entry point will be called before `ExitBootServices`.

Alternatively, on non-AMD64 systems, `winload.efi` before TH2 can be used with the `testsigning` element; this allows self-signed binaries with the `szOID_NT5_CRYPTO` EKU in the certificate.

On ARMv7 systems, loading a patched self-signed `hal.dll` with an import to `mcupdate.dll` will be necessary to get code execution.

On x86 and AMD64 systems, the file loaded as `mcupdate.dll` must be named `mcupdate_*.dll`, where `*` is the CPUID manufacturer string (`GenuineIntel`, `AuthenticAMD` etc).

On ARM64 systems, this technique cannot be used due to the earliest available production signed build being a WinPE of RS2; thus currently only tethered code execution can be performed (using `bootdebug`).

## Included files

This repository includes the following files:
- Source code for a simple payload is provided. This payload just waits for an interrupt infinitely, as without finding interesting functions and variables in the calling boot application, it is impossible to do anything else.
    - Because `mcupdate.dll` runs at a virtual address with paging enabled, it is impossible to call EFI functions directly (paging needs to be disabled to call EFI functions, returning to a virtual address with paging off does not lead to a good time).
    - To call EFI functions, a payload would need to call `BlImgLoadPEImageEx` or `BlImgLoadPEImageFromSourceBuffer` with bit 0 set in the flags to load an additional payload at a 1:1 physical address-virtual address mapping.
        - Alternatively, it can call `BlImgAllocateImageBuffer` with the same bit set to allocate memory at a 1:1 physical address-virtual address mapping; then load a payload itself (or remap itself there).
- An ISO that exploits this issue on AMD64 using the `bootmgfw` from Windows 8 RTM and the `hvloader` from TH1 RTM.
    - The payload used here prints a message to the screen by using a function from `hvloader` obtained by offset and then infinite loops.
- An ISO that exploits this issue on AMD64 using `bootmgr` from RS1 and the `hvloader` from TH1 RTM.
- An ISO that exploits this issue on AMD64 using `bootmgr` version 19041.1081 and the `hvloader` from TH1 RTM.

## Postscript

This issue can be used to dump BitLocker keys (where Secure Boot is used for integrity validation). 
- Although it is possible, the exact method of getting code execution with derived BitLocker keys for an arbitrary volume in memory will not be disclosed.

The fix for this issue also fixed another issue which has no CVE.
- `bootmgr` ignores any BitLocker keytable already in memory and allocates a new one, without wiping the old one.
    - Therefore, an attacker could load RS2+ `bootmgr` from `bootmgr` (specifying an arbitrary `osdevice` where Secure Boot is used for integrity validation), boot to WinPE, load a known vulnerable driver, and use it to search for and dump the existing BitLocker keytable in physical memory.

No known vulnerable boot application has been revoked yet.
- Until revocation happens, an attacker can just bring their own vulnerable bootloader(s).
- Revocation would cause all existing Windows installation/recovery media, and old backups, to fail to boot.
    - Boot failure would occur even with Secure Boot disabled due to `bootmgr` checking its own signature.

## Update (2023-05-10)

An incomplete revocation occured, and another CVE (CVE-2023-24932). There's still vulnerable `bootmgfw`s that were not revoked, as well as additional patches only fixing the case where `bootmgr` loads `bootmgr`. It only took a pasted bootkit to get MS to act ;)  
If you're creative enough you'll find a way to work around the revocation of over 2000 `bootmgfw` files ;)
