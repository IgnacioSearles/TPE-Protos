include ./Makefile.inc

SERVER_SOURCES=$(wildcard src/server/*.c src/server/*/*.c)
CLIENT_SOURCES=$(wildcard src/client/*.c src/client/*/*.c)
SHARED_SOURCES=$(filter-out src/shared/tests/%, $(wildcard src/shared/*.c src/shared/*/*.c))

OBJECTS_FOLDER=./obj
OUTPUT_FOLDER=./bin

SERVER_OBJECTS=$(SERVER_SOURCES:src/%.c=obj/%.o)
CLIENT_OBJECTS=$(CLIENT_SOURCES:src/%.c=obj/%.o)
SHARED_OBJECTS=$(SHARED_SOURCES:src/%.c=obj/%.o)

SERVER_OUTPUT_FILE=$(OUTPUT_FOLDER)/socks5d
CLIENT_OUTPUT_FILE=$(OUTPUT_FOLDER)/client

$(SERVER_OUTPUT_FILE) $(CLIENT_OUTPUT_FILE): | $(OUTPUT_FOLDER)
$(SERVER_OBJECTS) $(CLIENT_OBJECTS) $(SHARED_OBJECTS): | objdirs

all: objdirs server client

server: $(SERVER_OUTPUT_FILE)
client: $(CLIENT_OUTPUT_FILE)

objdirs:
	mkdir -p $(OBJECTS_FOLDER)/server $(OBJECTS_FOLDER)/client $(OBJECTS_FOLDER)/shared
	mkdir -p $(OBJECTS_FOLDER)/server/socks5utils $(OBJECTS_FOLDER)/server/pctputils
	mkdir -p $(OBJECTS_FOLDER)/client/socks5utils

$(OUTPUT_FOLDER):
	mkdir -p $(OUTPUT_FOLDER)

$(SERVER_OUTPUT_FILE): $(SERVER_OBJECTS) $(SHARED_OBJECTS)
	$(COMPILER) $(COMPILERFLAGS) $(LDFLAGS) $^ -o $@

$(CLIENT_OUTPUT_FILE): $(CLIENT_OBJECTS) $(SHARED_OBJECTS)
	$(COMPILER) $(COMPILERFLAGS) $(LDFLAGS) $^ -o $@

clean:
	rm -rf $(OUTPUT_FOLDER) $(OBJECTS_FOLDER)

obj/%.o: src/%.c
	$(COMPILER) $(COMPILERFLAGS) -c $< -o $@

.PHONY: all objdirs server client clean

