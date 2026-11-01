#!/usr/bin/env bash
# Cardea Key — prepara third_party/ con upstream fijado por commit y aplica patches/.
#
# Qué hace:
#   1. Clona pico-fido, pico-openpgp, pico-keys-sdk, pico-sdk, picotool y plug-and-trust (NXP, para
#      el backend se05x del secure element) en los commits anotados
#      en la lista REPOS de abajo.
#   2. Descarga las dependencias del SDK de Pico Keys (mbedtls, tinycbor, libcvc) dentro de
#      pico-keys-sdk/third-party/ con su fichero marcador, para que CMake no vuelva a clonarlas
#      (compilar con -DPICOKEYS_FETCH_DEPS_ON_DEMAND=OFF).
#   3. Sustituye el submódulo pico-keys-sdk de pico-fido y pico-openpgp por un enlace a una única
#      copia (SDK 9.2), que es la que llevará el firmware unificado.
#   4. Aplica los parches de patches/ (sobre todo: sin escrituras en la OTP del RP2350).
#
# Idempotente: si un repo ya existe, solo comprueba que está en el commit esperado.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TP="$ROOT/third_party"
mkdir -p "$TP"

# nombre  url  commit
REPOS=(
  "pico-fido     https://github.com/polhenarejos/pico-fido.git       b1df38dbab49b7365282e1bad12f0c38862cf643"
  "pico-openpgp  https://github.com/polhenarejos/pico-openpgp.git    6834e379aae472a3fd01173a212fff7ee730b870"
  "pico-keys-sdk https://github.com/polhenarejos/pico-keys-sdk.git   a2f0a51588fb523f2d6614e008b4bdbb45e443f1"
  "pico-sdk      https://github.com/raspberrypi/pico-sdk.git         079c6f39023649b154152db30f1d781e884879bc"
  "picotool      https://github.com/raspberrypi/picotool.git         2041936441b48a3cc53ae3da9e805229fe8f4e18"
  "plug-and-trust https://github.com/NXP/plug-and-trust.git          7102413e0457d3dfa4fc4be686ca8ec50bd9f5e2"
)
# Dependencias del SDK de Pico Keys: nombre url ref(tal como la pide cmake/deps.cmake) commit
DEPS=(
  "mbedtls  https://github.com/Mbed-TLS/mbedtls.git      v3.6.7 068ff080b369adfac81509f9b57b2afabaf82dc5"
  "tinycbor https://github.com/intel/tinycbor.git        v0.6.1 c0aad2fb2137a31b9845fbaae3653540c410f215"
  "libcvc   https://github.com/polhenarejos/libcvc.git   main   54562afc4d620c8bdb118183c0db49048baa0b2c"
)

clone_at() { # dir url commit
  local dir="$1" url="$2" commit="$3"
  if [[ ! -d "$dir/.git" ]]; then
    git clone -q "$url" "$dir"
  fi
  if [[ "$(git -C "$dir" rev-parse HEAD)" != "$commit" ]]; then
    git -C "$dir" fetch -q origin
    git -C "$dir" checkout -q "$commit"
  fi
  echo "ok  $(basename "$dir") @ ${commit:0:12}"
}

for r in "${REPOS[@]}"; do
  read -r name url commit <<<"$r"
  clone_at "$TP/$name" "$url" "$commit"
done
git -C "$TP/pico-sdk" submodule update -q --init
git -C "$TP/picotool" submodule update -q --init

for d in "${DEPS[@]}"; do
  read -r name url ref commit <<<"$d"
  dest="$TP/pico-keys-sdk/third-party/$name"
  clone_at "$dest" "$url" "$commit"
  printf 'REPO=%s\nREF=%s\n' "$url" "$ref" > "$dest/.picokeys_dep_source"
done

for app in pico-fido pico-openpgp; do
  link="$TP/$app/pico-keys-sdk"
  if [[ ! -L "$link" ]]; then
    rmdir "$link" 2>/dev/null || { echo "ERROR: $link no es un directorio vacío" >&2; exit 1; }
    ln -s ../pico-keys-sdk "$link"
  fi
done

# Parches: patches/NNNN-<repo>-<descripcion>.patch se aplica en third_party/<repo>
shopt -s nullglob
for p in "$ROOT"/patches/*.patch; do
  base="$(basename "$p")"
  repo=""
  for r in pico-keys-sdk pico-fido pico-openpgp pico-sdk picotool plug-and-trust; do
    [[ "$base" == [0-9][0-9][0-9][0-9]-"$r"-* ]] && repo="$r"
  done
  [[ -n "$repo" ]] || { echo "ERROR: no sé a qué repo va $base" >&2; exit 1; }
  if git -C "$TP/$repo" apply --reverse --check "$p" 2>/dev/null; then
    echo "ya  $base"
  else
    git -C "$TP/$repo" apply "$p"
    echo "ok  $base"
  fi
done
