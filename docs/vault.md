# Vault: passkey backups

A passkey (FIDO2 resident credential) normally lives and dies with the key that created it. The
vault, inherited from pico-fido, lets you **export** a passkey as an encrypted file and **import**
it into another key, so a lost or broken key does not lock you out.

## Design

- A **vault identity** is a random 32-byte vault key plus an X448 key pair. It is created on your
  computer and stored in a passphrase-encrypted file (scrypt + AES-256-GCM). **It is the secret
  that matters**: anyone with it can decrypt every backup exported from keys enrolled in that
  vault. Keep it like you would keep a password-manager export.
- A **vault CA** vouches for vault identities. Its root certificate is compiled into the firmware
  (`firmware/certs/cardea-key-vault-ca.crt` by default, or your own with
  `-DKEYV2_VAULT_CA_CERT=/path/to/ca.crt`). For each physical key, the CA signs an **enrollment
  certificate** that binds the vault's X448 public key to that key's USB serial number.
- **Enrollment** sends the vault key to the device with HPKE in auth mode (RFC 9180:
  DHKEM(X448, HKDF-SHA512), HKDF-SHA512, AES-256-GCM). The device checks that the certificate
  chains to the compiled-in CA and names its own serial, and only then stores the vault key,
  encrypted with its device key.
- **Export** produces a blob encrypted (ChaCha20-Poly1305 by default) with keys derived from the
  vault key. **Import** only accepts blobs of the vault the device is enrolled in.

Enrollment needs, on the device: the **PIN**, and holding the **button for 10 seconds within the
first minute** after plugging the key in. A CA signature alone cannot enroll a key.

Export and import need the PIN. The vault is compiled in by default (`ENABLE_VAULT=ON`) but does
nothing until a key is enrolled; build with `-DENABLE_VAULT=OFF` to remove it.

## Tool: `scripts/cardea-vault.py`

Requires `python3-cryptography` and `python3-fido2`.

```sh
# 1. Create a vault identity (once). Asks for a passphrase.
scripts/cardea-vault.py new --out my-vault.json --label "My vault"

# 2. Have the CA sign an enrollment certificate for a key. Without --serial it reads the serial
#    of the connected key. The CA private key is only accepted as a file.
scripts/cardea-vault.py cert --vault-file my-vault.json --ca-key ca.key --out key1.crt

# 3. Enroll the key: start this, (re)plug the key and hold the button for 10 s.
scripts/cardea-vault.py enroll --vault-file my-vault.json --cert key1.crt

# Back up all passkeys of the key, restore them on another enrolled key, or check a backup.
scripts/cardea-vault.py export --out-dir backups/
scripts/cardea-vault.py import backups/*.pkv
scripts/cardea-vault.py inspect --vault-file my-vault.json backups/*.pkv

scripts/cardea-vault.py status --pin
```

`status` needs the PIN to report the enrollment: the device key is wrapped with the PIN, so until
the PIN has been entered after power-up the device cannot read its vault key and reports "not
enrolled". Nothing is lost.

## Using your own CA

Nothing in the firmware is tied to the Cardea Key CA. To run your own:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 -sha384 -nodes \
  -keyout ca.key -out ca.crt -days 7300 -subj "/CN=My Vault CA" \
  -addext basicConstraints=critical,CA:TRUE,pathlen:0 \
  -addext keyUsage=critical,keyCertSign,cRLSign -addext subjectKeyIdentifier=hash
cmake -S firmware -B build/my-key -DKEYV2_VAULT_CA_CERT=$PWD/ca.crt ...
scripts/cardea-vault.py cert --ca-cert ca.crt --ca-key ca.key ...
```

Keep `ca.key` offline. The build refuses a certificate file that contains a private key.
