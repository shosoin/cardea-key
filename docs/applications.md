# What each application is for

Cardea Key bundles the applications of pico-fido (FIDO2/U2F, OATH, OTP slots) and pico-openpgp
(OpenPGP, PIV) in one firmware. They all share the button: when the key needs confirmation, the
LED stays **steady on** and you press once.

## FIDO2 / U2F: passwordless login

The modern security-key standard (WebAuthn, passkeys). The key creates a different key pair for
each service; the private key never leaves the key and every use requires presence (button) and,
optionally, the PIN. Phishing-resistant: the key checks the real domain.

- Second factor or passwordless login on websites (Google, GitHub, Microsoft, Cloudflare, Proton…).
- Passkeys: resident credentials stored on the key (login with key + PIN). Back them up with the
  [vault](vault.md).
- `sudo` and Linux login with `pam_u2f`.
- SSH with `-sk` keys (`ssh-keygen -t ed25519-sk`): every connection asks for a touch.
- Unlocking an encrypted disk (LUKS) at boot: `systemd-cryptenroll --fido2-device`.

U2F is the older, second-factor-only version, included for compatibility.

## OATH: one-time codes

Stores the secrets of 6-digit codes: TOTP (change every 30 s) and HOTP (counter-based). For
services that only offer codes (VPNs, admin panels…). Read them with `ykman oath accounts code` or
Yubico Authenticator. Each account can require a touch.

## OTP slots

Two slots, triggered by a short or long press, that make the key type like a keyboard:
- **Static password**: types a long fixed password.
- **HOTP**: counter-based code.
- **HMAC-SHA1 challenge-response**: types nothing; a program sends a challenge and the key
  answers, optionally after a touch. KeePassXC uses it so a database only opens with the key.

`ykman otp` only programs slots on keys with Yubico's vendor ID; see the README.

## OpenPGP: your GnuPG identity on the key

Holds GnuPG keys (signing, encryption, authentication); the key performs the operations.
- Signing git commits and tags (`git commit -S`).
- Encrypting and decrypting files or mail; tools like `pass`.
- SSH with the GnuPG authentication key (through `gpg-agent`).
- The same identity on any computer without copying key files.

With GnuPG's default configuration, add `disable-ccid` to `~/.gnupg/scdaemon.conf` so it uses
`pcscd`.

## PIV: X.509 smart card

The smart-card standard supported out of the box by Windows, macOS, Linux (OpenSC/PKCS#11),
browsers and VPNs. Around 24 key slots with certificates.
- Client certificates: VPN (OpenVPN/IPsec), websites with client certificates, Windows login.
- SSH through PKCS#11 (`ssh -I .../opensc-pkcs11.so`).
- Signing documents or code with a certificate.

OpenPGP is the GnuPG world (git, mail, `pass`); PIV is the X.509 world (VPNs, TLS, Windows).

## Service applications

- **Management**: tells `ykman` which applications are present and lets you enable or disable them.
- **Rescue**: key configuration and reboot into BOOTSEL (`scripts/cardea-bootsel.sh`).
