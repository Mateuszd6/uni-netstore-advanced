.PHONY: all debug release clean

CC=g++

COMMON_CFLAGS=--std=c++17
DEBUG_FLAGS=-g -O0 -DDEBUG -DTRACE -fno-omit-frame-pointer
RELEASE_FLAGS=-O2 -DNDEBUG
INCLUDE_FLAGS=-I.
LINK_FLAGS=-lpthread -lboost_filesystem -lboost_system
WARN_FLAGS=-Wall -Wextra

# students has completly broken sanitizer dependencies.
SANITIZERS= #-fsanitize=undefined

COMMON_OBJ=cmd.o connection.o logger.o
CLIENT_OBJ=client.o
SERVER_OBJ=server.o

CLIENT_EXE=netstore-client
SERVER_EXE=netstore-server

release: CFLAGS=$(COMMON_CFLAGS) $(WARN_FLAGS) $(RELEASE_FLAGS) $(INCLUDE_FLAGS)
release: all

debug: CFLAGS=$(COMMON_CFLAGS) $(WARN_FLAGS) $(SANITIZERS) $(DEBUG_FLAGS) $(INCLUDE_FLAGS)
debug: all

.cpp.o:
	$(CC) $(CFLAGS) -c $< -o $@

all: clean $(CLIENT_EXE) $(SERVER_EXE)


$(CLIENT_EXE): $(COMMON_OBJ) $(CLIENT_OBJ)
	$(CC) $(SANITIZERS) $(COMMON_OBJ) $(CLIENT_OBJ) -o $(CLIENT_EXE) $(LINK_FLAGS)

$(SERVER_EXE): $(COMMON_OBJ) $(SERVER_OBJ)
	$(CC) $(SANITIZERS) $(COMMON_OBJ) $(SERVER_OBJ) -o $(SERVER_EXE) $(LINK_FLAGS)

clean:
	@rm -f *.o
	@rm -f netstore-server
	@rm -f netstore-client
