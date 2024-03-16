cmake_minimum_required(VERSION 3.10)
project (mtlsgateway)

# prepare python3 venv for generated files in mbedtls
# it creates the venv with the found global interpreter
# then, search again with the virtual env first
if (NOT EXISTS "${CMAKE_BINARY_DIR}/.venv")
    find_package (Python3 COMPONENTS Interpreter)
    execute_process (COMMAND "${Python3_EXECUTABLE}" -m venv "${CMAKE_BINARY_DIR}/.venv")
    execute_process (COMMAND ${CMAKE_BINARY_DIR}/.venv/bin/pip3 install -r ${CMAKE_SOURCE_DIR}/mbedtls/scripts/basic.requirements.txt)
    execute_process (COMMAND ${CMAKE_BINARY_DIR}/.venv/bin/pip3 install -U "jsonschema<4.0")
    
    ## unset Python3_EXECUTABLE because it is also an input variable (see documentation, Artifacts Specification section)
    unset (Python3_EXECUTABLE)
endif ()

# the next line imitates the call to activate
set (ENV{VIRTUAL_ENV} "${CMAKE_BINARY_DIR}/.venv")
set (Python3_FIND_VIRTUALENV ONLY)

find_package (Python3)
set(MBEDTLS_PYTHON_EXECUTABLE Python3_EXECUTABLE)

# Add mbed TLS library subdirectory
# (requires venv already set)
add_subdirectory (./mbedtls)
set (ENABLE_TESTING ON)

# specify the gateway sources
set (SOURCES util.c serial.c main.c)

add_executable(mtlsserialgateway ${SOURCES})

# Link against mbed TLS statically
target_link_libraries(mtlsserialgateway PRIVATE mbedcrypto mbedtls mbedx509)