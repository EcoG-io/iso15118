cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

install(
    DIRECTORY iso15118/secc/
    DESTINATION "${THIRD_PARTY_APP_DST}/josev/iso15118/secc"
)
install(
    DIRECTORY iso15118/shared/
    DESTINATION "${THIRD_PARTY_APP_DST}/josev/iso15118/shared"
)

install(
    FILES iso15118/__init__.py
    DESTINATION "${THIRD_PARTY_APP_DST}/josev/iso15118"
)

install(
    DIRECTORY iso15118/evcc/
    DESTINATION "${THIRD_PARTY_APP_DST}/josev/iso15118/evcc"
)

find_program(
    PYTHON_EXECUTABLE
    python3
    REQUIRED
)

add_custom_target(iso15118_pip_install_dist
    COMMAND
        ${PYTHON_EXECUTABLE} -m pip install --force-reinstall .
    WORKING_DIRECTORY
        ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT
        "Installing iso15118 from distribution"
)

add_custom_target(iso15118_requirements_pip_install_dist
    COMMAND
        ${PYTHON_EXECUTABLE} -m pip install --force-reinstall -r requirements.txt
    WORKING_DIRECTORY
        ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT
        "Installing iso15118 requirements from distribution"
)
