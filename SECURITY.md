# Security

## Status

Cardea Key is a **prototype**. It has not been audited, it is not FIDO-certified, and phase 0 runs
on a bare Raspberry Pi Pico 2 without a secure element. Use it to experiment, not as your only key.

## What the prototype protects against, and what it does not

- Secrets are stored in the RP2350's external flash, encrypted. In the default build
  (`HARDEN_HARDWARE=OFF`) the key that protects them is also kept in flash, so the board stays
  reusable. **Anyone with physical access can dump the flash**, so assume a lost prototype is a
  compromised one. Phase 1 moves the PIN check, the retry counter and the root key into an
  NXP SE051 secure element.
- User presence is a real button press (see `FORCE_BUTTON_WAIT`), and destructive operations
  (FIDO reset, master-key restore) require it. Master-key restore also requires the PIN.
- Release binaries, when published, will not be signed. Building from source is the way to know
  what runs on your key.
- The vault root CA private key is kept offline by the maintainers. A CA signature alone cannot
  enroll a key in a vault: enrollment also needs the key's PIN and a physical button press
  within a minute of plugging it in. You can build with your own CA (`docs/vault.md`).

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** for this repository
(Security → Report a vulnerability). Do not open a public issue for security problems.

If the issue is in the upstream code (pico-fido, pico-openpgp, pico-keys-sdk), it probably
affects that project too; we will coordinate with its maintainer.
