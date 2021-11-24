# Apple iDevice Restore/Upgrade/Revive Protocol

# DFU Mode

DFU is a USB standard protocol that Apple uses from `SecureROM` state to bring up the SEP and AP into a `recovery`
state.  This requires a multi-stage process whereby the device is interrogated for it's version, chip, board etc.
(this is done by querying the SerialNumber using an alternate language string property of the USB device, which 
is part of a USB device standard descriptors).  This breaks the device into CPID (chip ID) and BDID (board ID).
Further the device is queried for the value of `APNonce` and `SEPNonce` which are transmitted to TSS (tatsu signing server)
at tss.apple.com to get a "personalized" manifest.  This manifest is a ASN1 signed IMG4 (specifically an IM4M or IMG4 manifest)
that contains the SHA fingerprints of all the later component stages.  Because the APNonce and SEPNonce are unique to each
boot, this means that the values must be submitted to tss on every recovery and cannot be reused (a mistake in NVRAM allowed
reuse of such things in the "FutureRestore" exploit).  SecureROM is very low level assembly that has the responsibility
of interacting with USB, generation of the APNonce, interaction with the SEP for the SEP's SecureROM and associated SEPNonce
and the transfer, and validation of the payloads received over USB.  This means SecureROM has a base USB stack, the SEP
mailbox protocol, SHA implementation, base bring-up of essential controllers such as Hydra/Tristar/ACE/PMP-PMGR,
a hardened ASN1/IMG4 implementation, and a base public/private algorithm implementation as well as compiled (or in the
case of silicon, masked-in) root-of-trust keys.

After personalizing the manifest it is transmitted to the device, which validates it against the nonce set, and then DFU
begins to receive the payloads specified in the BuildManifest.plist file.  Each of these is copied to a volatile memory
region where it is hashed and compared to the manifest.  (Because of the DFU specification this is handled using bulk
transfers to an output endpoint of the interface of 512 byes and completion is signaled by a final 0 byte transfer)
If everything lines up, the payload (iBoot recovery) is handed off too.

Modern versions of DFU / SecureROM include an arbitrary iBoot data payload which per never_released contains DDR4 training
data to bring online LPDDR4 memory early.

# Recovery Mode

Recovery mode is entered either by a failure of the iBoot process (in which case it is the version held in emulated NOR
which is truly NAND backed in any modern iDevice) or by a bring-up from DFU.  In the case of a boot failure, the version
of iBoot / recovery could in fact be out of date, in the case of DFU (excepting AppleInternal access to the sign-anything TSS)
this should always be the most recent version of iBoot.  iBoot is a slightly more sophisticated package as it can be patched
unlike the SecureROM variant, though they come from the exact same codebase.  Because of it's patch-ability all other loading
behaviour happens here.  This stage will bring up additional firmware devices, and bring the SEP out of spin-lock to SEPOS.
The iBoot protocol is also able to handle transports of larger size and to fully access NVRAM and SysCfg which is why
their serial number is available at this stage but not at DFU (ECID is available because its fused or masked in to the AP).
In the final stage, iBoot will receive the DeviceTree and XNU kernel, which should it passes IMG4 verification from personalization
will boot the XNU kernel as the next stage.  (iBoot will set a few flags to alter the XNU behaviour for a recovery boot vs
a normal boot before the jump, for more info use siguza's `dt` to explore the DeviceTree and research OpenFirmware)

## M1 macOS Note Related to Local Security Policy

The M1 macOS restore process leverages the same recovery / restore process as the iDevice, but the iBoot system has
an additional payload as the mac, unlike a iPhone or iPad can boot code not signed by Apple.  This is managed by the
modification of the "local security policy" using the `bptuil` command.  This is a SEP entangled signed policy that
iBoot will verify.  Because this policy must be reset to a secure state, the recovery process will provide a `lpol`
payload, which is the initial secure local security policy.  It should NEVER be the case that this policy is different
than the version in the IPSW in the case of a restore as it could otherwise allow a SecureBoot policy violation