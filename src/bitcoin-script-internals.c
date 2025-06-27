#include "bitcoin-script-internals.h"
#include <stdio.h>

U8 __is_hex__(const char *str)
{
	if (str == NULL)
	{
		return 0;
	}

	for (U32 i = 0; str[i] != '\0'; i++)
	{
		char c = str[i];
		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
		{
			return 0;
		}
	}
	return 1;
}


void __hexstr_to_bytes(const char *hexString, uint8_t *byteArray, size_t arraySize, size_t *outLength)
{
	size_t len = strlen(hexString);
	if (len % 2 != 0 || len / 2 > arraySize)
	{
		*outLength = 0;
		return;
	}
	*outLength = len / 2;
	for (size_t i = 0; i < *outLength; i++)
	{
		sscanf(hexString + i * 2, "%2hhx", &byteArray[i]);
	}
}

void __modify_bytes__(U8 bytes[], size_t size, int value, U8 isBigEndian)
{
	U8 isSubtracting = value < 0; // Determine if we are subtracting
	unsigned int absValue = (unsigned int)(isSubtracting ? -value : value); // Absolute value of input

	size_t start = isBigEndian ? size - 1 : 0; // Start index based on endianness
	int step = isBigEndian ? -1 : 1;          // Direction of traversal

	unsigned int carry = absValue; // Carry for addition/subtraction
	for (size_t i = start; i < size && i >= 0; i += step) {
		unsigned int current = bytes[i];

		if (isSubtracting) {
			if (current >= carry) {
				bytes[i] = (U8)(current - carry);
				carry = 0;
				break;
			} else {
				bytes[i] = (U8)(0x100 + current - carry);
				carry = 1; // Propagate borrow
			}
		} else {
			unsigned int result = current + carry;
			bytes[i] = (U8)(result & 0xFF); // Store lower 8 bits
			carry = result >> 8;           // Propagate carry
		}
	}

	// If carry is left after the last byte, it means overflow occurred
	if (carry != 0) {
		printf("Warning: Overflow detected!\n");
	}
}
