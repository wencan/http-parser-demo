cmake_minimum_required(VERSION 2.8)

project(http-parser-demo)
add_executable(${PROJECT_NAME} "main.c")
find_library(LIBRARY_HTTP_PARSER http_parser)
TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${LIBRARY_HTTP_PARSER})
