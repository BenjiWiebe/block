#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <stdbool.h>
#include "ipv4_str.h"

int ipv4_str(char *buf, size_t buflen, int32_t addr)
{
	int idx = 0;
	uint8_t byte;
	if(buflen < 16)
	{
		errno = ERANGE; // insufficient space in buf for the address
		return -1;
	}
	for(uint8_t bt = 0; bt < 4; bt++) // Which byte to get from addr
	{
		byte = (addr & 0xFF << bt * 8) >> bt * 8;
		if(bt)
			buf[idx++] = '.';
		bool leadingzeroes = true;
		for(int place = 100; place != 0; place /= 10)
		{
			char dgt = byte / place + '0'; // Get the digit in the 100's/10's/1's place
			byte %= place; // Chop that digit off
			if(dgt != '0')
				leadingzeroes = false;
			if(!leadingzeroes || place == 1) // add it if it is not a leading zero, or if it is the one's place
				buf[idx++] = dgt;
		}
	}
	buf[idx] = 0; // Null-terminate the string
	errno = 0;
	return 0;
}
#if 0
int main()
{
	int32_t a = 0;
	a |= 192 << 0;
	a |= 168 << 8;
	a |= 0 << 16;
	a |= 101 << 24;
	char buf[16];
	if(ipv4_str(buf, 16, a) < 0)
	{
		perror("ipv4_str");
		return 1;
	}
	printf("%s\n", buf);
	return 0;
}
#endif
