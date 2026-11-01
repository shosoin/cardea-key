<p align="center"><img src="assets/cardea-key-logo.svg" alt="Cardea Key logo" width="128"></p>

# Cardea Key

> *Cardea*, Roman goddess of hinges and thresholds: "her power is to open what is shut and to shut
> what is open" (Ovid, *Fasti* VI).

**Cardea Key** is an open-source security key firmware for the **Raspberry Pi Pico 2** (RP2350). It
combines in a single firmware what usually needs several keys:

- **FIDO2 / WebAuthn passkeys** and **U2F** — passwordless login, second factor, SSH `-sk` keys,
  `pam_u2f`, LUKS (`systemd-cryptenroll`).
- **OpenPGP card** — GnuPG signing, encryption and SSH authentication keys on the key.
- **PIV** — X.509 smart card (VPN client certificates, PKCS#11, Windows smart-card login).
- **OATH** (TOTP/HOTP) — authenticator codes, readable with `ykman oath` / Yubico Authenticator.
- **OTP slots** — static password, HOTP and HMAC-SHA1 challenge-response (e.g. KeePassXC), with
  touch support.
- **Vault** — encrypted, restorable backups of your passkeys, signed off by a CA you control.

Website: <https://cardeakey.org>

> **Status: prototype, not audited.** Phase 0 (one unified firmware, tested on a bare Pico 2) is
> complete and released as **v0.1.0**. Do not rely on it as your only key yet. Next phases add an external secure element
> (NXP SE051) for the PIN and root keys, and a fingerprint sensor. See [Roadmap](#roadmap).

## How it is built

Cardea Key is built on the excellent work of **Pol Henarejos**:
[pico-fido](https://github.com/polhenarejos/pico-fido),
[pico-openpgp](https://github.com/polhenarejos/pico-openpgp) and
[pico-keys-sdk](https://github.com/polhenarejos/pico-keys-sdk). It is not affiliated with or
endorsed by the Pico Keys project.

This repository does not fork them. It pins each upstream repository to an exact commit
(`scripts/fetch-sources.sh`) and applies a reviewed set of patches (`patches/`, described in
[patches/README.md](patches/README.md)) to merge both applications into one firmware and to fix
the issues we found while testing, among them:

- **The firmware never writes the RP2350 OTP** unless you explicitly build with
  `HARDEN_HARDWARE=ON`. Upstream writes and locks OTP keys on first boot, which is irreversible.
  With the default build your Pico 2 stays a generic, reusable board.
- **User presence is really required**: the button must be pressed for passkey creation *and*
  sign-in, FIDO reset, U2F, OATH "touch" accounts and OTP challenge-response. Upstream's default
  reports user presence without a press.
- **Master-key restore requires the PIN**, not just a button press.
- **Vault** with a replaceable root CA (see [docs/vault.md](docs/vault.md)).

## Hardware

- Raspberry Pi **Pico 2** (RP2350). The BOOTSEL button is the user-presence button and the
  on-board LED shows the state: short blinks when idle, **steady on when the key is waiting for a
  touch**.
- That's all for now. Phase 1 adds an NXP SE051C2 secure element over I2C.

## Building

Tested on Debian 13 with `arm-none-eabi-gcc` 14.2, CMake 3.31 and Ninja.

```sh
sudo apt install git cmake ninja-build gcc-arm-none-eabi libnewlib-arm-none-eabi \
                 build-essential python3 python3-cryptography
scripts/fetch-sources.sh            # clones upstream at the pinned commits and applies patches/
cmake -G Ninja -S firmware -B build/cardea-key -DPICO_BOARD=pico2 \
      -DPICO_SDK_PATH=$PWD/third_party/pico-sdk
cmake --build build/cardea-key      # -> build/cardea-key/cardea_key.uf2
```

Main build options (`-D<option>=ON|OFF`):

| Option | Default | Meaning |
|---|---|---|
| `HARDEN_HARDWARE` | **OFF** | ON = upstream behaviour: writes and locks OTP keys on first boot. **Irreversible.** |
| `ENABLE_VAULT` | ON | Passkey backups (inactive until each key is enrolled). OFF removes the code. |
| `KEYV2_VAULT_CA_CERT` | Cardea Key Vault CA | Root certificate (PEM) of the vault CA. Point it at your own CA. |
| `FORCE_BUTTON_WAIT` | ON | Require a real button press for user presence. |
| `CARDEA_SE` | `soft` | Secure-element backend. `soft`: no chip, same security and data as v0.1.0. `se05x` (NXP SE051): in progress, phase 1. |
| `ENABLE_OATH_APP`, `ENABLE_OTP_APP` | ON | OATH and OTP-slot applications. |
| `USB_VID`, `USB_PID` | `0x1209`, `0x0001` | USB IDs (see below). |

## Flashing

Download `cardea_key.uf2` from the [latest release](https://github.com/shosoin/cardea-key/releases/latest)
(check its SHA-256) or build it yourself. Hold BOOTSEL while plugging the Pico 2 in, then copy
`cardea_key.uf2` to the `RP2350` drive. Data
on the key (PIN, credentials) survives firmware updates. A key already running Cardea Key can be
rebooted into BOOTSEL with `scripts/cardea-bootsel.sh` (needs a button press).

## USB IDs and host software

The prototype uses the **pid.codes test ID `1209:0001`**. FIDO2 works out of the box (browsers,
`libfido2`, `python-fido2`). The smart-card applications (OpenPGP, PIV, OATH) go through CCID:
`pcscd`'s CCID driver only loads for known IDs, so add the test ID to its list
(`scripts/libccid-reader.py`, needs root) or use GnuPG's internal CCID driver.

This project **never ships with Yubico's vendor ID**. Some Yubico tools (`ykman otp`) only talk to
keys with that ID; changing the ID in your own build is your choice and your responsibility.

## Vault (passkey backups)

Passkeys normally die with the key. The vault lets you export them, encrypted with a vault key you
keep, and import them into another key enrolled in the same vault. Enrolling a key requires its
PIN, a 10-second button press right after plugging it in, and a certificate for that key's serial
number signed by the vault CA, which is compiled into the firmware. You can build with your own
CA. Details and the `scripts/cardea-vault.py` tool: [docs/vault.md](docs/vault.md).

## Documentation

- [docs/applications.md](docs/applications.md) — what each application is for and how to use it.
- [docs/vault.md](docs/vault.md) — vault design, own CA, enrollment, export and import.
- [patches/README.md](patches/README.md) — every change made to upstream, and why.
- [SECURITY.md](SECURITY.md) — threat model of the prototype and how to report a vulnerability.

## Roadmap

| Phase | What | Status |
|---|---|---|
| 0 | Unify pico-fido and pico-openpgp in one firmware; test on a bare Pico 2 without touching OTP | **done** |
| 1 | NXP SE051C2 secure element: PIN and retry counter in the SE, root key out of the flash | planned |
| 2 | Fingerprint sensor as user presence, time-limited biometric unlock | planned |
| 3 | Own PCB | after 0-2 |

## License

[AGPL-3.0](LICENSE), the license of the upstream projects. Patches and tools in this repository
are released under the same license. "Pico Keys" is a trademark of its owner; this project does
not use that name.
