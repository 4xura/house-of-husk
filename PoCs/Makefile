# Makefile to compile House of Husk PoCs

CC = gcc
CFLAGS = -g -O0 -no-pie -fno-stack-protector

# Get all .c files
SRC = $(wildcard *.c)

# Strip .c from filenames to get binary names
BIN = $(SRC:.c=)

all: $(BIN)

%: %.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(BIN)