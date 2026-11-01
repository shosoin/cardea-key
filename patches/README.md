# Patches on top of upstream

`scripts/fetch-sources.sh` applies them in order, each one in `third_party/<repo>`
(`NNNN-<repo>-<what>.patch`). Patches marked **upstream** fix bugs that the original
pico-fido / pico-openpgp / pico-keys-sdk also have and could be proposed there. The rest are
specific to Cardea Key (build options, unified firmware) and change nothing when each application
is built on its own without `KEYV2_UNIFIED`. Code comments inside the patches are in Spanish.

| Patch | Repo | What | Type |
|---|---|---|---|
| 0001 | pico-keys-sdk | Build options `HARDEN_HARDWARE` (OFF: no OTP writes, no secure boot) and `ENABLE_VAULT` | Cardea |
| 0002 | pico-fido | `ENABLE_VAULT=OFF` removes the CTAP vault command | Cardea |
| 0003 | pico-openpgp | `ENABLE_VAULT=OFF` removes `INS 0xF2` from OpenPGP and PIV | Cardea |
| 0004 | pico-keys-sdk | Master key encryption key in flash (`EF_MKEK`) when OTP is not used; `SELECT` by longest AID match; configurable USB strings | Cardea (the `SELECT` part is also an upstream fix) |
| 0005 | pico-fido | Unified firmware: external file table, configurable AAGUID, FIDO reset that does not touch other applications' files or vault records | Cardea |
| 0006 | pico-openpgp | Unified firmware: keys in `0xA0-0xA5`, `EF_VAULT_KEY 0xCE05`, TERMINATE and PIV reset only touch their own data, FIDO file table included | Cardea |
| 0007 | pico-fido | The OTP application re-pointed `res_APDU` from the HID callback and CTAP responses were lost (a button timeout arrived as OK) | **upstream** |
| 0008 | pico-fido | `wait_button_pressed()` honours `FORCE_BUTTON_WAIT` (FIDO2 reset, U2F and OTP challenge-response did not require the button); from the USB task (core 0) it denies instead of waiting, which avoided a deadlock that hung the key | **upstream** |
| 0009 | pico-openpgp | TERMINATE resets the OpenPGP PIN counters; the card was blocked after a factory reset | **upstream** |
| 0010 | pico-openpgp | GET DATA per the specification: constructed DOs with their tag (no client guessing with `is_gpg`), key references 01/02/03 in `DE`, and `DE` inside `73`. Makes `ykman openpgp` work | **upstream** |
| 0011 | pico-keys-sdk | Option `KEYV2_LED_PATTERNS`: no fades (on a single-GPIO LED everything ended up as 50 % blinking) and distinguishable patterns: idle = blink every 3 s, busy = fast, waiting for touch = steady on | Cardea (the fade problem on single-GPIO LEDs is upstream's) |
| 0012 | pico-fido | The HID keyboard OTP path (core 0) overwrote the global `apdu` structure without restoring it: CCID hung, and with it `pcscd` and every program using it. Now it is not processed while the card is busy, and `apdu` is saved and restored | **upstream** |
| 0013 | pico-keys-sdk | The card thread (core 1) runs on its own 16 KB stack in RAM. With the default 2 KB stack in SCRATCH_X, an OTP challenge-response over the HID keyboard (4.5 KB of stack on core 0) overflowed into core 1's stack and CCID stopped responding | **upstream** |
| 0014 | pico-fido | OATH `PUT`: the YKOATH property is sent as `78 vv` (no length); upstream parsed it as a TLV and dropped it, so "touch" accounts returned codes without a press. Normalised to TLV | **upstream** |
| 0015 | pico-keys-sdk | `button_wait_start_local()` / `button_local_result()`: asynchronous button wait (steady LED) whose result is polled, for USB-task paths that cannot block | Cardea (feature) |
| 0016 | pico-fido | OTP challenge-response **with touch** over the HID keyboard in **asynchronous mode**, as YubiKeys do: status `0x20` while waiting, the response is computed on the press and expires after 15 s. Before, it was denied (and upstream hung the key) | Cardea (feature; suitable for upstream) |
| 0017 | pico-keys-sdk | Configurable vault root CA (`PICOKEYS_VAULT_CA_INC`); Cardea Key compiles the "Cardea Key Vault CA" from `firmware/certs/cardea-key-vault-ca.crt` (option `KEYV2_VAULT_CA_CERT`; empty = upstream's CA) | Cardea |
| 0018 | pico-keys-sdk | Vault enrollment: verify the certificate with mbedTLS's default profile plus Curve448. The default profile rejects the X448 key of the enrollment certificate (`BADCERT_BAD_KEY`), so no enrollment could ever succeed | **upstream** |
| 0019 | pico-fido | Master-key restore (`CTAP_VENDOR_BACKUP` 0x02): upstream parsed `pinUvAuthParam` but never checked it, so a button press was enough to replace the master key and destroy every credential. With a PIN set it now requires a PIN token with the `acfg` permission and the exact blob size (60 B); without a PIN, the button only, like a reset | **upstream** |
| 0020 | pico-fido | With `FORCE_BUTTON_WAIT`, `getAssertion` waits for the button. Before, with the default button timeout (0), it signed with UP=1 without a press. Only a credential with the button explicitly disabled (authenticatorConfig) skips it | **upstream** |
| 0021 | pico-keys-sdk | Without git history (ZIP download, repository with no commits) the build number was empty and the build failed in `rescue.c`; it now defaults to 0 | **upstream** |
| 0022 | pico-keys-sdk | Phase 1: with `PICOKEYS_SE_HOOKS`, `derive_kbase()` asks the secure-element interface (`firmware/src/se/cardea_se.h`) for the root-key derivation, and `otp_init()` starts the backend. The `soft` backend produces the same bytes as before (no migration). Without the define, the SDK is unchanged | Cardea |
| 0023 | pico-fido | Phase 1 (#3): with a secure-element backend that keeps PINs (`cardea_se_pin_managed()`), the FIDO2 PIN is set, checked and changed there: verifier, retry counter, and the secret that wraps the device key. `EF_PIN` keeps its 35-byte layout with format 2 and no verifier. A v0.1.0 `EF_PIN` moves there on the first correct PIN, in an order that survives a power cut. The 3-mismatches-per-boot rule is unchanged, and the FIDO reset erases the slot. With the `soft` backend nothing changes | Cardea |
| 0024 | pico-openpgp | Phase 1 (#3): the same for OpenPGP and PIV (PW1, PW3, RC, PIV PIN and PUK). Records keep their 34 bytes in format 2, holding the verifier only when the value is a public factory PIN, so the factory-default checks keep working (admin-less mode, KDF-DO, PIV metadata). The `EF_PW_PRIV` counters stay as a mirror for the status DOs. The session key that wraps the DEK is the slot secret. Changes with the current PIN go through `pin_record_change` (`cardea_se_pin_change`: the slot changes in place), unblocks through `cardea_se_pin_reset`; either way the DEK is wrapped again with the returned secret. Migration on the first correct entry of each PIN, through the `pin_txn` journal for PW1/PW3/RC. With the `soft` backend nothing changes | Cardea |
| 0025 | pico-fido | The "3 wrong PINs per power-up" lock could be lifted without a power cycle: every `CTAPHID_INIT` (any client sends it when it opens the key) calls `init_fido()`, which cleared it, and a correct PIN only checked that RAM flag. Now only a power-up, a correct PIN or a reset lift it, and `getPinToken` refuses the PIN while it lasts without spending a retry. Reported privately (GHSA-r8qh-fj4q-7xjp) | **upstream** |
| 0026 | pico-keys-sdk | Phase 1: SE FAULT. If the backend needs the chip and it is not there at boot (or the root key is not in it), and the build does not have `CARDEA_SE_FALLBACK`, the key does not run: `process_apdu` only lets the rescue applet through (anything else: `6F00`), CTAP2 answers `CTAP1_ERR_OTHER`, the button types no OTP, the LED shows three quick red flashes and a pause over any other pattern, and the USB product name (and the interface names) ends in " SE FAULT". Nothing in flash is erased | Cardea |

## Regenerating

Each patch is `git -C third_party/<repo> diff -- <files>`. Some patches touch the same file and
are diffs on top of the previous ones: `0006` and `0009` (`src/openpgp/cmd_terminate_df.c`);
`0007`, `0012` and `0016` (`src/fido/otp.c`); `0008` and `0020` (`src/fido/fido.c`); `0017` and
`0018` (`src/vault.c`). Check: applying all patches to clean clones must reproduce the working tree
and build without warnings.
