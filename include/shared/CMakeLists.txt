project(headers-shared C)

configure_file(config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)

# ── Paths ────────────────────────────────────────────────────────────────────
set(GEN_HEADER  "${CMAKE_CURRENT_BINARY_DIR}/memcrypt_constants.h")
set(GEN_SCRIPT "${CMAKE_SOURCE_DIR}/cmake/Modules/MemcryptGenerateConstants.cmake")

# ── Custom command: re-runs the cmake script on every build ──────────────────
# cmake -P launches a fresh CMake process whose PRNG is re-seeded from the
# system clock, guaranteeing different constants each time.
# No Python, bash, or od needed whatsoever.
add_custom_command(
        OUTPUT  "${GEN_HEADER}"
        COMMAND ${CMAKE_COMMAND}
        -D "GEN_HEADER=${GEN_HEADER}"
        -P "${GEN_SCRIPT}"
        DEPENDS "${GEN_SCRIPT}"
        COMMENT "Generating build-time LCG constants -> memcrypt_constants.h"
        VERBATIM
)

# ── Custom target so the generation is always part of a normal build ─────────
add_custom_target(generate_constants ALL
        DEPENDS "${GEN_HEADER}"
)

# add_dependencies(headers-shared generate_constants)

