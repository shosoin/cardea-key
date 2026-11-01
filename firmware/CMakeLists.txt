# Cardea Key — firmware unificado: pico-fido (FIDO2/U2F, OATH, OTP Yubico) + pico-openpgp (OpenPGP, PIV)
# sobre una sola copia de pico-keys-sdk. Las fuentes de upstream se compilan tal cual desde
# third_party/ (con los parches de patches/ ya aplicados por scripts/fetch-sources.sh).
#
#   cmake -G Ninja -S firmware -B build/cardea-key -DPICO_SDK_PATH=$PWD/third_party/pico-sdk -DPICO_BOARD=pico2
#   ninja -C build/cardea-key            (genera cardea_key.uf2)
#
# Opciones propias (además de HARDEN_HARDWARE y ENABLE_VAULT del SDK, ver README.md):
#   USB_VID / USB_PID     identidad USB (pruebas: 1209:0001, Test PID de pid.codes)
#   FORCE_BUTTON_WAIT     exigir pulsar el botón para la presencia de usuario (ON)
#   ENABLE_OATH_APP / ENABLE_OTP_APP   apps OATH y OTP Yubico (ON)

cmake_minimum_required(VERSION 3.13)

set(USB_VID 0x1209 CACHE STRING "USB vendor ID")
set(USB_PID 0x0001 CACHE STRING "USB product ID")
set(KEYV2_USB_MANUFACTURER "Cardea Key" CACHE STRING "USB manufacturer string")
set(KEYV2_USB_PRODUCT "Cardea Key (prototype)" CACHE STRING "USB product string")
set(KEYV2_WEBUSB_URL "cardeakey.org" CACHE STRING "WebUSB landing page (https, sin esquema)")
set(PICOKEYS_FETCH_DEPS_ON_DEMAND OFF CACHE BOOL "deps preparadas por scripts/fetch-sources.sh")
# Vault (copia cifrada de passkeys, export/import): ACTIVADO por defecto en Cardea Key (2026-10-31).
# No hace nada hasta que cada llave se da de alta (PIN + 10 s de boton en el primer minuto +
# certificado de la CA del vault para su serie; scripts/cardea-vault.py). Quien no lo quiera:
# -DENABLE_VAULT=OFF (el codigo no entra en el firmware). Ver docs/vault.md.
set(ENABLE_VAULT ON CACHE BOOL "Enable vault enroll/export/import commands")
# CA raiz del vault: certificado (publico) contra el que el firmware verifica los certificados de
# alta. Por defecto la "Cardea Key Vault CA"; cada cual puede poner la suya. Vacio = la de PicoKeys.
set(KEYV2_VAULT_CA_CERT "${CMAKE_CURRENT_LIST_DIR}/certs/cardea-key-vault-ca.crt" CACHE FILEPATH "Certificado raiz del vault (PEM)")

set(PICO_USE_FASTEST_SUPPORTED_CLOCK 1)
include(pico_sdk_import.cmake)

project(cardea_key C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
add_executable(cardea_key)

set(TP ${CMAKE_CURRENT_LIST_DIR}/../third_party)
set(FIDO_DIR ${TP}/pico-fido/src/fido)
set(PGP_DIR ${TP}/pico-openpgp/src)

include(pico-keys-sdk/cmake/options.cmake)

# --- Opciones ---------------------------------------------------------------------------------
option(ENABLE_POWER_ON_RESET "Enable/disable power cycle on reset" ON)
configure_bool_option(ENABLE_POWER_ON_RESET ENABLE_POWER_ON_RESET "Power cycle on reset: \t enabled" "Power cycle on reset: \t disabled")
option(ENABLE_OATH_APP "Enable/disable OATH application" ON)
configure_bool_option(ENABLE_OATH_APP ENABLE_OATH_APP "OATH Application: \t\t enabled" "OATH Application: \t\t disabled")
option(ENABLE_OTP_APP "Enable/disable OTP (Yubico) application" ON)
configure_bool_option(ENABLE_OTP_APP ENABLE_OTP_APP "OTP Application: \t\t enabled" "OTP Application: \t\t disabled")
option(FORCE_BUTTON_WAIT "Require a button press for user presence" ON)
configure_bool_option(FORCE_BUTTON_WAIT FORCE_BUTTON_WAIT "User presence button: \t required" "User presence button: \t NOT required (upstream default)")
option(KEYV2_LED_PATTERNS "LED: patrones key-v2 sin fundidos (reposo=destello, botón=fijo)" ON)
configure_bool_option(KEYV2_LED_PATTERNS KEYV2_LED_PATTERNS "LED patterns: \t\t key-v2 (button = steady on)" "LED patterns: \t\t upstream")
option(ENABLE_ADMINLESS_MODE "OpenPGP: Gnuk-compatible admin-less PIN mode (upstream default ON)" ON)
# Secure element (fase 1, docs: src/se/cardea_se.h). soft = sin chip, misma seguridad y mismos
# datos que la v0.1.0; se05x = NXP SE051 por I2C (pendiente).
set(CARDEA_SE "soft" CACHE STRING "Secure element backend: soft | se05x")
set_property(CACHE CARDEA_SE PROPERTY STRINGS soft se05x)
if(CARDEA_SE STREQUAL "soft")
    message(STATUS "Secure element: \t\t soft (no chip; root key = MKEK, as v0.1.0)")
elseif(CARDEA_SE STREQUAL "se05x")
    message(FATAL_ERROR "CARDEA_SE=se05x: backend not implemented yet (issues #4, #5, #6)")
else()
    message(FATAL_ERROR "CARDEA_SE must be soft or se05x, not '${CARDEA_SE}'")
endif()
add_compile_definitions(PICOKEYS_SE_HOOKS=1)

# Definiciones extra para builds de diagnóstico (p. ej. -DKEYV2_EXTRA_DEFINITIONS="KEYV2_DEBUG_BUTTON=1")
set(KEYV2_EXTRA_DEFINITIONS "" CACHE STRING "Definiciones de preprocesador extra (lista ;)")
if(KEYV2_EXTRA_DEFINITIONS)
    add_compile_definitions(${KEYV2_EXTRA_DEFINITIONS})
    message(WARNING "Build de diagnóstico: ${KEYV2_EXTRA_DEFINITIONS}")
endif()

if(SECURE_BOOT_PKEY AND NOT HARDEN_HARDWARE)
    message(FATAL_ERROR "SECURE_BOOT_PKEY solo tiene sentido con HARDEN_HARDWARE=ON (firma + secure boot es irreversible)")
endif()

# --- Identidad --------------------------------------------------------------------------------
add_compile_definitions(
    KEYV2_UNIFIED=1
    USB_MANUFACTURER_STR="${KEYV2_USB_MANUFACTURER}"
    USB_PRODUCT_STR="${KEYV2_USB_PRODUCT}"
    USB_WEBUSB_URL="${KEYV2_WEBUSB_URL}"
    # AAGUID = primeros 16 bytes de SHA-256("Cardea Key"), mismo criterio que upstream con "Pico FIDO2"
    FIDO_AAGUID_BYTES=0x73,0x65,0x20,0xd6,0x87,0xb9,0xeb,0x4c,0x7e,0x7b,0x66,0x71,0xfa,0x0d,0xb2,0x0f
)

set(USB_ITF_HID 1)
set(USB_ITF_CCID 1)
set(USB_ITF_WCID 1)
set(ENABLE_LIBCVC 1)
include(pico-keys-sdk/picokeys_sdk_import.cmake)
SET_BUILD_NUMBER("${CMAKE_CURRENT_LIST_DIR}")
SET_VERSION(ver_major ver_minor "${CMAKE_CURRENT_LIST_DIR}/src/keyv2_version.h")
add_compile_definitions(KEYV2_VERSION_MAJOR=${ver_major} KEYV2_VERSION_MINOR=${ver_minor})

# --- Tabla de ficheros de FIDO dentro de la de OpenPGP (generada) -----------------------------
set(GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
file(MAKE_DIRECTORY ${GEN_DIR})
find_package(Python3 REQUIRED COMPONENTS Interpreter)
execute_process(
    COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_LIST_DIR}/tools/gen_fido_file_entries.py
            ${FIDO_DIR} ${GEN_DIR}/fido_file_entries.inc ${GEN_DIR}/fido_static_fids.inc
    RESULT_VARIABLE gen_rc)
if(NOT gen_rc EQUAL 0)
    message(FATAL_ERROR "gen_fido_file_entries.py falló")
endif()
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${FIDO_DIR}/files.c ${FIDO_DIR}/files.h)

if(KEYV2_VAULT_CA_CERT)
    execute_process(
        COMMAND ${Python3_EXECUTABLE} -I ${CMAKE_CURRENT_LIST_DIR}/tools/gen_vault_ca.py
                ${KEYV2_VAULT_CA_CERT} ${GEN_DIR}/vault_ca.inc
        RESULT_VARIABLE ca_rc OUTPUT_VARIABLE ca_out OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(NOT ca_rc EQUAL 0)
        message(FATAL_ERROR "gen_vault_ca.py falló con ${KEYV2_VAULT_CA_CERT}")
    endif()
    message(STATUS "Vault CA: \t\t ${KEYV2_VAULT_CA_CERT} (${ca_out})")
    add_compile_definitions(PICOKEYS_VAULT_CA_INC="vault_ca.inc")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${KEYV2_VAULT_CA_CERT})
else()
    message(STATUS "Vault CA: \t\t PicoKeys (upstream)")
endif()

# --- Fuentes ----------------------------------------------------------------------------------
set(FIDO_SOURCES
    fido.c object_authorization.c object_provider.c resident_container.c files.c cmd_register.c
    cmd_authenticate.c cmd_version.c cbor.c cbor_reset.c cbor_get_info.c cbor_make_credential.c
    event.c known_apps.c cbor_client_pin.c credential.c cbor_get_assertion.c cbor_selection.c
    cbor_cred_mgmt.c cbor_config.c cbor_vendor.c fido_vault.c cbor_large_blobs.c
    management.c   # defs.c no: PICO_PRODUCT y versión están en keyv2_glue.c
)
if(ENABLE_OATH_APP)
    list(APPEND FIDO_SOURCES oath_container.c oath.c)
endif()
if(ENABLE_OTP_APP)
    list(APPEND FIDO_SOURCES otp_container.c otp.c)
endif()
list(TRANSFORM FIDO_SOURCES PREPEND ${FIDO_DIR}/)

# Management: se usa el de pico-fido (ya anuncia OpenPGP/PIV si existen). defs.c de las dos apps
# se sustituye por keyv2_glue.c.
set(PGP_SOURCES
    openpgp/openpgp.c openpgp/object_provider.c openpgp/key_container.c openpgp/openpgp_vault.c
    openpgp/files.c openpgp/piv.c
    piv/cmd_version.c piv/cmd_select.c piv/cmd_get_serial.c piv/cmd_verify.c piv/cmd_get_data.c
    piv/cmd_get_metadata.c piv/cmd_authenticate.c piv/cmd_asym_keygen.c piv/cmd_put_data.c
    piv/cmd_set_mgmkey.c piv/cmd_move_key.c piv/cmd_change_pin.c piv/cmd_reset_retry.c
    piv/cmd_set_retries.c piv/cmd_reset.c piv/cmd_attestation.c piv/cmd_import_asym.c
    openpgp/cmd_select.c openpgp/cmd_get_data.c openpgp/cmd_verify.c openpgp/cmd_put_data.c
    openpgp/cmd_select_data.c openpgp/cmd_import_data.c openpgp/cmd_version.c
    openpgp/cmd_change_pin.c openpgp/cmd_mse.c openpgp/cmd_internal_aut.c openpgp/cmd_challenge.c
    openpgp/cmd_activate_file.c openpgp/cmd_terminate_df.c openpgp/cmd_pso.c
    openpgp/cmd_keypair_gen.c openpgp/cmd_reset_retry.c openpgp/do.c
)
list(TRANSFORM PGP_SOURCES PREPEND ${PGP_DIR}/)

set(GLUE_SOURCES ${CMAKE_CURRENT_LIST_DIR}/src/keyv2_glue.c ${CMAKE_CURRENT_LIST_DIR}/src/se/se_${CARDEA_SE}.c)

# Cada app con sus propias cabeceras: las dos tienen files.h, version.h, management.h,
# object_provider.h... con el mismo nombre y distinto contenido.
set_source_files_properties(${FIDO_SOURCES} PROPERTIES INCLUDE_DIRECTORIES "${FIDO_DIR}")
set_source_files_properties(${PGP_SOURCES} PROPERTIES
    INCLUDE_DIRECTORIES "${PGP_DIR}/openpgp;${PGP_DIR}/piv;${GEN_DIR}"
    # cmd_version existe en FIDO y en PIV
    COMPILE_DEFINITIONS "cmd_version=piv_cmd_version;ENABLE_ADMINLESS_MODE=$<BOOL:${ENABLE_ADMINLESS_MODE}>")
set_source_files_properties(${GLUE_SOURCES} PROPERTIES INCLUDE_DIRECTORIES "${GEN_DIR}")

set(SOURCES ${PICOKEYS_SOURCES} ${FIDO_SOURCES} ${PGP_SOURCES} ${GLUE_SOURCES})
target_sources(cardea_key PUBLIC ${SOURCES})
target_include_directories(cardea_key PUBLIC ${INCLUDES} ${GEN_DIR} ${CMAKE_CURRENT_LIST_DIR}/src/se)
target_compile_options(cardea_key PRIVATE -Wall)

picokeys_apply_strict_flags(
    SOURCES ${SOURCES}
    FILTER_REGEX "/src/fido/|/src/openpgp/|/src/piv/|/pico-keys-sdk/src/|/pico-keys-sdk/config/|/firmware/src/"
)

target_link_libraries(cardea_key PRIVATE
    picokeys_sdk pico_stdlib pico_multicore hardware_flash hardware_sync hardware_adc
    pico_unique_id pico_aon_timer tinyusb_device tinyusb_board)
pico_add_extra_outputs(cardea_key)
