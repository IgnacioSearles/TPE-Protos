COMPILER=gcc
INCLUDES=-Isrc/shared -Isrc/server -Isrc/server/socks5utils -Isrc/server/pctputils
COMPILERFLAGS=-Wall -Wextra -pedantic -std=c11 -g3 -pthread -D_POSIX_C_SOURCE=200112L -O3 -Wno-unused-parameter $(INCLUDES)
LDFLAGS=
