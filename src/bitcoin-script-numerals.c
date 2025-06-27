#include "bitcoin-script-internals.h"

// https://github.com/bitcoin/bitcoin/blob/1473f69924bc9a68ec1416e30aad5ac068e551b0/src/script/script.h#L245
I32 SCRIPT_DeserializeScriptNum(const U8 *data, U32 len)
{
	if (len > 4)
	{
		return 0;
	}

	U32 result = 0;
	for (U32 i = 0; i < len; ++i)
	{
		result |= ((U32)data[i]) << (8 * i);
	}
	if (len > 0 && (data[len - 1] & 0x80))
	{
		result &= ~(0x80U << (8 * (len - 1)));
		return -(I32)result;
	}
	return (I32)result;
}

U32 SCRIPT_SerializeScriptNum(I32 value, U8 out[4])
{
	if (value == 0) return 0;

	U32 len = 0;
	I8 negative = (value < 0);
	U32 abs = (U32)(negative ? -value : value);

	while (abs)
	{
		out[len++] = abs & 0xff;
		abs >>= 8;
	}
	if (out[len - 1] & 0x80)
	{
		out[len++] = negative ? 0x80 : 0x00;
	}
	else if (negative)
	{
		out[len - 1] |= 0x80;
	}
	return len;
}
