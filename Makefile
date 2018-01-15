COBJS += aes_andlink.o

#CFLAGS += -O2 -Wall -DDEBUG
CFLAGS	+= -I./

LDFLAGS	+= -lssl -lcrypto

CROSS_COMPILE	?=

CC = $(CROSS_COMPILE)gcc

TARGET = aes_andlink

all:$(TARGET)
$(TARGET):$(COBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o:%.c
	$(CC) $(CFLAGS) -c -o $@ $^ $(LDFLAGS)

.PHONY:clean
clean:
	rm -f $(COBJS)
