COMPILER=gcc

COMPILERFLAGS=-Wall -Wextra -pedantic -std=c11 -g3 -fsanitize=address -pthread -D_POSIX_C_SOURCE=200112L -Wno-unused-parameter
LDFLAGS=-fsanitize=address
