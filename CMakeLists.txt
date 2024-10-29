cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

find_package(everest-cmake 0.3 REQUIRED
    PATHS ../everest-cmake
)

ev_setup_cmake_variables_python_wheel()

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

find_package(Python3 COMPONENTS Interpreter)

ev_create_pip_install_targets(
    PACKAGE_NAME
        "iso15118"
)

ev_create_python_wheel_targets(
    PACKAGE_NAME
        "iso15118"
)

add_custom_target(iso15118_requirements_pip_install_dist
    COMMAND
        ${Python3_EXECUTABLE} -m pip install --force-reinstall -r requirements.txt
    WORKING_DIRECTORY
        ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT
        "Installing iso15118 requirements from distribution"
)

if (ISO15118_2_GENERATE_AND_INSTALL_CERTIFICATES)
    message(STATUS "Generating ISO15118 certificates for ${PROJECT_SOURCE_DIR}")
    set(CREATE_CERTS_WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/iso15118/shared/pki")
    set(CREATE_CERTS_SCRIPT "${CREATE_CERTS_WORKING_DIRECTORY}/create_certs.sh")

    execute_process(
        COMMAND
            ${CREATE_CERTS_SCRIPT} -v iso-2 -i ${PROJECT_SOURCE_DIR}
        WORKING_DIRECTORY
            ${CREATE_CERTS_WORKING_DIRECTORY}
    )
endif()
