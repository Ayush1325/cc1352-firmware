# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

include_directories(".")

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(cc1352_firmware)

target_sources(app PRIVATE src/main.c)

add_subdirectory(mdns)
