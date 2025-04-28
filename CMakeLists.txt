cmake_minimum_required(VERSION 3.19)

project(staccato)

find_package(fmt CONFIG REQUIRED)

add_executable(staccato src/staccato.cc)

target_link_libraries(staccato PRIVATE fmt::fmt)