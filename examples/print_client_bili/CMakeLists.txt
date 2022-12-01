
file (GLOB SOURCE_FILES *.cpp)
file (GLOB HEADER_FILES *.hpp)

set(CMAKE_CXX_FLAGS "-std=c++14")

link_libraries(z ws2_32)

init_target (print_client_bili)

build_executable (${TARGET_NAME} ${SOURCE_FILES} ${HEADER_FILES})

link_boost ()
final_target ()

set_target_properties(${TARGET_NAME} PROPERTIES FOLDER "examples")
