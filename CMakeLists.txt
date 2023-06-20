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
