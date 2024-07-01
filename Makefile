CC=gcc
CFLAGS=-Wall -Werror -Wextra -g -O0 -std=gnu99

all: block

install:
	install -s block /usr/local/bin/block

block: block.c ipv4_str.c
