cmake_minimum_required(VERSION 2.8)

project(trend)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DUNICODE -static")

set(SOURCE_EXE src/main.cpp)

add_executable(${PROJECT_NAME} ${SOURCE_EXE})
