CURDIR := $(shell pwd)
BASEDIR := $(abspath $(CURDIR)/..)

PROJECT := cryptic_nif

ERTS_INCLUDE_DIR ?= $(shell erl -eval "io:format(\"~s/erts-~s/include/\", [code:root_dir(), erlang:system_info(version)]), halt()." -noshell)

C_SRC_DIR = $(CURDIR)
C_SRC_OUTPUT ?= $(CURDIR)/../priv/$(PROJECT).so

# System specific C compiler/flags.
UNAME_SYS := $(shell uname -s)
UNAME_ARCH := $(shell uname -m)
ifeq ($(UNAME_SYS), Darwin)
	CC ?= cc
	CFLAGS ?= -O3 -std=c99 -arch $(UNAME_ARCH) -finline-functions -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O3 -arch $(UNAME_ARCH) -finline-functions -Wall
	LDFLAGS ?= -arch $(UNAME_ARCH) -bundle -flat_namespace -undefined suppress
else ifeq ($(UNAME_SYS), FreeBSD)
	CC ?= cc
	CFLAGS ?= -O3 -std=c99 -finline-functions -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O3 -finline-functions -Wall
	LDFLAGS ?= -shared
else ifeq ($(UNAME_SYS), Linux)
	CC ?= gcc
	CFLAGS ?= -O3 -std=c99 -finline-functions -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O3 -finline-functions -Wall
	LDFLAGS ?= -shared
endif

CFLAGS += -fPIC -I $(ERTS_INCLUDE_DIR)
CXXFLAGS += -fPIC -I $(ERTS_INCLUDE_DIR)

# Check if libsodium is available via pkg-config
SODIUM_EXISTS := $(shell pkg-config --exists libsodium && echo yes)
ifeq ($(SODIUM_EXISTS), yes)
	CFLAGS += $(shell pkg-config --cflags libsodium)
	LDLIBS += $(shell pkg-config --libs libsodium)
else
	# Fallback to system paths
	CFLAGS += -I/usr/local/include -I/opt/homebrew/include
	LDLIBS += -L/usr/local/lib -L/opt/homebrew/lib -lsodium
endif

# Verbosity.
c_verbose_0 = @echo " C     " $(?F);
c_verbose = $(c_verbose_$(V))
cpp_verbose_0 = @echo " CPP   " $(?F);
cpp_verbose = $(cpp_verbose_$(V))
link_verbose_0 = @echo " LD    " $(@F);
link_verbose = $(link_verbose_$(V))

SOURCES := $(shell find $(C_SRC_DIR) -type f \( -name "*.c" -o -name "*.C" -o -name "*.cc" -o -name "*.cpp" \))
OBJECTS = $(addsuffix .o, $(basename $(SOURCES)))

COMPILE_C = $(c_verbose) $(CC) $(CFLAGS) $(CPPFLAGS) -c
COMPILE_CPP = $(cpp_verbose) $(CXX) $(CXXFLAGS) $(CPPFLAGS) -c

$(C_SRC_OUTPUT): $(OBJECTS)
	@mkdir -p $(BASEDIR)/priv/
	$(link_verbose) $(CC) $(OBJECTS) $(LDFLAGS) $(LDLIBS) -o $(C_SRC_OUTPUT)

%.o: %.c
	$(COMPILE_C) $(OUTPUT_OPTION) $<

%.o: %.cc
	$(COMPILE_CPP) $(OUTPUT_OPTION) $<

%.o: %.C
	$(COMPILE_CPP) $(OUTPUT_OPTION) $<

%.o: %.cpp
	$(COMPILE_CPP) $(OUTPUT_OPTION) $<

clean:
	@rm -f $(C_SRC_OUTPUT) $(OBJECTS)
