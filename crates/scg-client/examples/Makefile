# Build the C and C++ examples against the scg-client shared library.
#
# Prerequisite: build the library so the header and `libscg_client.so` exist:
#   cargo build -p scg-client            # debug   -> target/debug
#   cargo build -p scg-client --release  # release -> target/release
#
# Then, from this directory:
#   make                 # debug build
#   make PROFILE=release # release build
#   make run-c APP=app-telemetry TRANSPORT=uds CLASS=safety
#
# At run time the loader must find libscg_client.so, e.g.:
#   LD_LIBRARY_PATH=../../../target/debug ./c_client ...

PROFILE ?= debug
INCLUDE  := ../include
LIBDIR   := ../../../target/$(PROFILE)

CFLAGS   := -Wall -Wextra -O2 -I$(INCLUDE)
CXXFLAGS := -std=c++17 -Wall -Wextra -O2 -I$(INCLUDE)
LDFLAGS  := -L$(LIBDIR) -lscg_client -lpthread -ldl

.PHONY: all clean run-c run-cpp

all: c_client cpp_client zc_client

c_client: c/client.c $(INCLUDE)/scg_client.h
	$(CC) $(CFLAGS) c/client.c $(LDFLAGS) -o $@

# Zero-copy SHM send: build the message directly in the ring via reserve/commit.
zc_client: c/zero_copy.c $(INCLUDE)/scg_client.h
	$(CC) $(CFLAGS) c/zero_copy.c $(LDFLAGS) -o $@

cpp_client: cpp/client.cpp $(INCLUDE)/scg_client.hpp $(INCLUDE)/scg_client.h
	$(CXX) $(CXXFLAGS) cpp/client.cpp $(LDFLAGS) -o $@

APP       ?= app-telemetry
TRANSPORT ?= uds
CLASS     ?= safety
MGMT      ?=
MESSAGE   ?= hello

run-c: c_client
	LD_LIBRARY_PATH=$(LIBDIR) ./c_client $(APP) $(TRANSPORT) $(CLASS) "$(MGMT)" "$(MESSAGE)"

run-cpp: cpp_client
	LD_LIBRARY_PATH=$(LIBDIR) ./cpp_client $(APP) $(TRANSPORT) $(CLASS) "$(MGMT)" "$(MESSAGE)"

clean:
	rm -f c_client cpp_client
