# ==============================================================================
# Doxygen.cmake - Doxygen documentation generation for CMake projects
# ==============================================================================
# Usage in your CMakeLists.txt:
#
#   include(cmake/Doxygen.cmake)
#   enable_doxygen()
#
# Optional: Set variables before calling include() to customize behavior
# (see configurable parameters below).
# ==============================================================================

find_package(Doxygen OPTIONAL_COMPONENTS dot)

function(enable_doxygen)

    # ------------------------------------------------------------------
    # Configurable variables (can be set before calling this function)
    # ------------------------------------------------------------------

    # Directory containing the source files (default: project root)
    if(NOT DEFINED DOXYGEN_INPUT_DIR)
        set(DOXYGEN_INPUT_DIR "${PROJECT_SOURCE_DIR}")
    endif()

    # Output directory for the generated documentation
    if(NOT DEFINED DOXYGEN_OUTPUT_DIR)
        set(DOXYGEN_OUTPUT_DIR "${CMAKE_BINARY_DIR}/docs")
    endif()

    # Path to the Doxyfile.in template
    if(NOT DEFINED DOXYGEN_TEMPLATE)
        set(DOXYGEN_TEMPLATE "${PROJECT_SOURCE_DIR}/Doxyfile.in")
    endif()

    # Project name shown in the documentation
    if(NOT DEFINED DOXYGEN_PROJECT_NAME)
        set(DOXYGEN_PROJECT_NAME "${PROJECT_NAME}")
    endif()

    # Project version shown in the documentation
    if(NOT DEFINED DOXYGEN_PROJECT_VERSION)
        set(DOXYGEN_PROJECT_VERSION "${PROJECT_VERSION}")
    endif()

    # Short project description
    if(NOT DEFINED DOXYGEN_PROJECT_BRIEF)
        set(DOXYGEN_PROJECT_BRIEF "")
    endif()

    # Logo file (empty = no logo)
    if(NOT DEFINED DOXYGEN_PROJECT_LOGO)
        set(DOXYGEN_PROJECT_LOGO "")
    endif()

    # Directories/patterns to exclude from documentation
    if(NOT DEFINED DOXYGEN_EXCLUDE_PATTERNS)
        set(DOXYGEN_EXCLUDE_PATTERNS "*/build/* */test/* */.git/*")
    endif()

    # Enable HTML output
    if(NOT DEFINED DOXYGEN_GENERATE_HTML)
        set(DOXYGEN_GENERATE_HTML "YES")
    endif()

    # Enable LaTeX/PDF output
    if(NOT DEFINED DOXYGEN_GENERATE_LATEX)
        set(DOXYGEN_GENERATE_LATEX "NO")
    endif()

    # Enable XML output (useful for Sphinx/Breathe)
    if(NOT DEFINED DOXYGEN_GENERATE_XML)
        set(DOXYGEN_GENERATE_XML "NO")
    endif()

    # ------------------------------------------------------------------
    # Check whether Doxygen was found
    # ------------------------------------------------------------------
    if(NOT DOXYGEN_FOUND)
        message(WARNING
                "[Doxygen] Doxygen not found - the 'docs' target will not be created. "
                "Please install Doxygen:\n"
                "  Ubuntu/Debian:  sudo apt install doxygen graphviz\n"
                "  macOS:          brew install doxygen graphviz\n"
                "  Windows:        https://www.doxygen.nl/download.html"
        )
        return()
    endif()

    if(NOT Doxygen_dot_FOUND)
        message(STATUS
                "[Doxygen] 'dot' (Graphviz) not found - diagrams will be disabled."
        )
        set(DOXYGEN_HAVE_DOT "NO")
    else()
        set(DOXYGEN_HAVE_DOT "YES")
        message(STATUS "[Doxygen] Graphviz found - diagrams enabled.")
    endif()

    # ------------------------------------------------------------------
    # Configure the Doxyfile from the template
    # ------------------------------------------------------------------
    if(NOT EXISTS "${DOXYGEN_TEMPLATE}")
        message(FATAL_ERROR
                "[Doxygen] Doxyfile.in not found: ${DOXYGEN_TEMPLATE}\n"
                "Please create a 'Doxyfile.in' file in the project root."
        )
    endif()

    set(DOXYFILE_OUT "${CMAKE_CURRENT_BINARY_DIR}/Doxyfile")
    configure_file("${DOXYGEN_TEMPLATE}" "${DOXYFILE_OUT}" @ONLY)

    # ------------------------------------------------------------------
    # Create output directory
    # ------------------------------------------------------------------
    file(MAKE_DIRECTORY "${DOXYGEN_OUTPUT_DIR}")

    # ------------------------------------------------------------------
    # Custom target 'docs'
    # ------------------------------------------------------------------
    add_custom_target(
            docs
            COMMAND ${DOXYGEN_EXECUTABLE} "${DOXYFILE_OUT}"
            WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
            COMMENT "Generating Doxygen documentation..."
            VERBATIM
    )

    # Print the path to the documentation after a successful build
    add_custom_command(
            TARGET docs POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E echo
            "Documentation generated: ${DOXYGEN_OUTPUT_DIR}/html/index.html"
    )

    message(STATUS
            "[Doxygen] Target 'docs' configured."
    )

endfunction()