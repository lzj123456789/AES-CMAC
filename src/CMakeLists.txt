cmake_minimum_required(VERSION 2.8)
project( aes )
add_executable( cmac_aes CMAC.h CMAC.cpp  common.cpp common.h Cipher.cpp Cipher.h InvCipher.cpp InvCipher.h KeyExpansion.cpp KeyExpansion.h Main.cpp)
add_definitions(-std=c++11)
