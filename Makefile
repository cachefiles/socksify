MODULE := tcpup
THIS_PATH := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

ifneq ($(TARGET),)
CC := $(TARGET)-gcc
LD := $(TARGET)-ld
AR := $(TARGET)-ar
CXX := $(TARGET)-g++
endif

LOCAL_TARGETS := txcat libtx.a
LOCAL_CXXFLAGS := -I$(THIS_PATH)/libtx/include -I$(THIS_PATH)
LOCAL_CFLAGS := $(LOCAL_CXXFLAGS)
LOCAL_LDLIBS := -lstdc++

BIN_FMT_TARGET := $(shell $(THIS_PATH)/getos.sh CC=$(CC))
BUILD_TARGET   ?= $(BIN_FMT_TARGET)

ifeq ($(BUILD_TARGET), mingw)
LOCAL_LDFLAGS += -static
LOCAL_LDLIBS += -lws2_32
endif

ifeq ($(BUILD_TARGET), linux)
LOCAL_LDLIBS += -lrt
endif

LOCAL_CFLAGS += -g -Wall -Wno-sign-compare -I.
LOCAL_CXXFLAGS += -g -Wall -Wno-sign-compare -I.

VPATH := $(THIS_PATH)/libtx:$(THIS_PATH)

TARGETS = reversxy

ifeq ($(BUILD_TARGET), mingw)
LOCAL_LDFLAGS += -static
LOCAL_LDLIBS += -lws2_32
TARGETS += server.srv
endif

ifeq ($(BUILD_TARGET), Linux)
LDLIBS += -lrt -lpthread
endif

all: $(TARGETS)

LOCAL_OBJECTS := libtx.a reversxy.o

$(TARGETS): OBJECTS:=$(LOCAL_OBJECTS)

CFLAGS  := $(LOCAL_CFLAGS) $(CFLAGS)
CXXFLAGS := $(LOCAL_CXXFLAGS) $(CXXFLAGS)

LDLIBS   := $(LOCAL_LDLIBS) $(LDLIBS)
LDFLAGS  := $(LOCAL_LDFLAGS) $(LDFLAGS)

reversxy: $(LOCAL_OBJECTS)

include $(THIS_PATH)/libtx/Makefile
