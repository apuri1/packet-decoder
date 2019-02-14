include ../Make.inc

BUILD_DIR=$(shell pwd)

DEPENDENCIES=$(BUILD_DIR)/../deps

LKSCTP_VERSION=lksctp-tools-1.0.17
LKSCTP_PATH=$(DEPENDENCIES)/lksctp
LKSCTP_SPECIFIC_PATH=$(LKSCTP_PATH)/$(LKSCTP_VERSION)
LKSCTP_LIB= $(LKSCTP_SPECIFIC_PATH)/src/lib/.libs/

JSON=$(DEPENDENCIES)/json

DECODERS=$(BUILD_DIR)/decoders

INCLUDES    = -I. \
              -I/usr/include/ \
              -I$(DEPENDENCIES) \
              -I$(JSON) \
              -I$(LKSCTP_SPECIFIC_PATH)/src/include \
              -isystem $(DEPENDENCIES)/boost

LDFLAGS	    = -L. \
              -L$(LKSCTP_LIB) -lsctp \
              -Llib/ -lpcap \
              -Llib64/ -lcurl \
              -lpthread

OBJS 		= Config.o \
                $(JSON)/json.o \
                MainDecoder.o \
                ContainerMultiIndex.o \
                DecodePacket.o \
                PcapReader.o \
                PacketReceiver.o \
                PacketBuffer.o \
                PacketProcessor.o \
                DecodeDiameter.o \
                DecodeHTTP.o \
                DecodeMQTT.o \
                SctpTx.o \
                Maint.o


CC_FLAGS    = $(CFLAGS) $(WARNINGS) $(INCLUDES)

TARGET_EXECUTABLE = PacketDecoder

#########
# RULES #
#########


$(TARGET_EXECUTABLE): $(OBJS)
	g++ $(CC_FLAGS) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) -c $(CC_FLAGS) $*.c -o $*.o

%.o: %.cpp
	g++ -ggdb -c $(CC_FLAGS) $*.cpp -o $*.o

clean:
	rm -rf $(TARGET_EXECUTABLE) $(OBJS)


