#ifndef BITCOIN_SCRIPT_INTERNALS_H
#define BITCOIN_SCRIPT_INTERNALS_H

#include <stdint.h>						// _BITCOIN_INTERNALS_D_TYPEDEFS_
#include <string.h>						// strcmp

#ifndef _BITCOIN_INTERNALS_D_TYPEDEFS_
#define _BITCOIN_INTERNALS_D_TYPEDEFS_
	typedef uint8_t		U8;
	typedef uint16_t	U16;
	typedef uint32_t	U32;
	typedef uint64_t	U64;
	typedef int8_t		I8;
	typedef int16_t		I16;
	typedef int32_t		I32;
	typedef int64_t		I64;
#endif

#ifndef		SCRIPT_MAX_STACK_SIZE
	#define SCRIPT_MAX_STACK_SIZE			1000
#endif

#ifndef		SCRIPT_MAX_STACK_ITEMS
	#define SCRIPT_MAX_STACK_ITEMS			1500
#endif

#ifndef		SCRIPT_MAX_SCRIPTPUBKEY_SIZE
	#define SCRIPT_MAX_SCRIPTPUBKEY_SIZE	10000
#endif

#ifndef		SCRIPT_MAX_STACK_ELEMENT_SIZE
	#define SCRIPT_MAX_STACK_ELEMENT_SIZE	520
#endif

#ifndef		SCRIPT_MAX_SCRIPT_SIZE
	#define	SCRIPT_MAX_SCRIPT_SIZE			(SCRIPT_MAX_STACK_ELEMENT_SIZE * SCRIPT_MAX_STACK_ITEMS)
#endif

typedef enum SCRIPT_VERSION
{
	LEGACY,
	SEGWIT_V0,
	SEGWIT_V1,
	SEGWIT_V2,
} SCRIPT_VERSION;

#define HAS_FLAG(value, flag) (((value) & (flag)) != 0)
typedef enum SCRIPT_CHECK
{
	SCRIPT_VERIFY_NONE									= 0,
	SCRIPT_VERIFY_STRICT_ENCODING						= 1 << 0,
	SCRIPT_VERIFY_DER_SIG								= 1 << 1,
	SCRIPT_VERIFY_LOW_S_VALUE							= 1 << 2,
	SCRIPT_VERIFY_NULL_DUMMY							= 1 << 3,
	SCRIPT_VERIFY_SIGPUSH_ONLY							= 1 << 4,
	SCRIPT_VERIFY_MINIMALPUSH							= 1 << 5,
	SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS			= 1 << 6,
	SCRIPT_VERIFY_CLEANSTACK							= 1 << 7,
	SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY					= 1 << 8,
	SCRIPT_VERIFY_CHECKSEQUENCEVERIFY					= 1 << 9,
	SCRIPT_VERIFY_WITNESS_V0							= 1 << 10,
	SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM	= 1 << 11,
	SCRIPT_VERIFY_WITNESS_PUBKEY_TYPE					= 1 << 12,
	SCRIPT_VERIFY_WITNESS_V1							= 1 << 13,
	SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_VERSION	= 1 << 14,
	SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS					= 1 << 15,
} SCRIPT_CHECK;

#define SCRIPT_LEGACY_VERIFY_FLAGS	\
	(	SCRIPT_VERIFY_STRICT_ENCODING	|	SCRIPT_VERIFY_DER_SIG				|	SCRIPT_VERIFY_LOW_S_VALUE			|	\
		SCRIPT_VERIFY_NULL_DUMMY		|	SCRIPT_VERIFY_SIGPUSH_ONLY			|	SCRIPT_VERIFY_MINIMALPUSH			|	\
		SCRIPT_VERIFY_CLEANSTACK		|	SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY	|	SCRIPT_VERIFY_CHECKSEQUENCEVERIFY	|	\
		SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS )


/**************************************		Opcodes		*************************************/
typedef enum SCRIPT_OPCODE
{
	OP_0 = 0x00,
	OP_PUSHBYTES_1 = 0x01,
	OP_PUSHBYTES_2 = 0x02,
	OP_PUSHBYTES_3 = 0x03,
	OP_PUSHBYTES_4 = 0x04,
	OP_PUSHBYTES_5 = 0x05,
	OP_PUSHBYTES_6 = 0x06,
	OP_PUSHBYTES_7 = 0x07,
	OP_PUSHBYTES_8 = 0x08,
	OP_PUSHBYTES_9 = 0x09,
	OP_PUSHBYTES_10 = 0x0a,
	OP_PUSHBYTES_11 = 0x0b,
	OP_PUSHBYTES_12 = 0x0c,
	OP_PUSHBYTES_13 = 0x0d,
	OP_PUSHBYTES_14 = 0x0e,
	OP_PUSHBYTES_15 = 0x0f,
	OP_PUSHBYTES_16 = 0x10,
	OP_PUSHBYTES_17 = 0x11,
	OP_PUSHBYTES_18 = 0x12,
	OP_PUSHBYTES_19 = 0x13,
	OP_PUSHBYTES_20 = 0x14,
	OP_PUSHBYTES_21 = 0x15,
	OP_PUSHBYTES_22 = 0x16,
	OP_PUSHBYTES_23 = 0x17,
	OP_PUSHBYTES_24 = 0x18,
	OP_PUSHBYTES_25 = 0x19,
	OP_PUSHBYTES_26 = 0x1a,
	OP_PUSHBYTES_27 = 0x1b,
	OP_PUSHBYTES_28 = 0x1c,
	OP_PUSHBYTES_29 = 0x1d,
	OP_PUSHBYTES_30 = 0x1e,
	OP_PUSHBYTES_31 = 0x1f,
	OP_PUSHBYTES_32 = 0x20,
	OP_PUSHBYTES_33 = 0x21,
	OP_PUSHBYTES_34 = 0x22,
	OP_PUSHBYTES_35 = 0x23,
	OP_PUSHBYTES_36 = 0x24,
	OP_PUSHBYTES_37 = 0x25,
	OP_PUSHBYTES_38 = 0x26,
	OP_PUSHBYTES_39 = 0x27,
	OP_PUSHBYTES_40 = 0x28,
	OP_PUSHBYTES_41 = 0x29,
	OP_PUSHBYTES_42 = 0x2a,
	OP_PUSHBYTES_43 = 0x2b,
	OP_PUSHBYTES_44 = 0x2c,
	OP_PUSHBYTES_45 = 0x2d,
	OP_PUSHBYTES_46 = 0x2e,
	OP_PUSHBYTES_47 = 0x2f,
	OP_PUSHBYTES_48 = 0x30,
	OP_PUSHBYTES_49 = 0x31,
	OP_PUSHBYTES_50 = 0x32,
	OP_PUSHBYTES_51 = 0x33,
	OP_PUSHBYTES_52 = 0x34,
	OP_PUSHBYTES_53 = 0x35,
	OP_PUSHBYTES_54 = 0x36,
	OP_PUSHBYTES_55 = 0x37,
	OP_PUSHBYTES_56 = 0x38,
	OP_PUSHBYTES_57 = 0x39,
	OP_PUSHBYTES_58 = 0x3a,
	OP_PUSHBYTES_59 = 0x3b,
	OP_PUSHBYTES_60 = 0x3c,
	OP_PUSHBYTES_61 = 0x3d,
	OP_PUSHBYTES_62 = 0x3e,
	OP_PUSHBYTES_63 = 0x3f,
	OP_PUSHBYTES_64 = 0x40,
	OP_PUSHBYTES_65 = 0x41,
	OP_PUSHBYTES_66 = 0x42,
	OP_PUSHBYTES_67 = 0x43,
	OP_PUSHBYTES_68 = 0x44,
	OP_PUSHBYTES_69 = 0x45,
	OP_PUSHBYTES_70 = 0x46,
	OP_PUSHBYTES_71 = 0x47,
	OP_PUSHBYTES_72 = 0x48,
	OP_PUSHBYTES_73 = 0x49,
	OP_PUSHBYTES_74 = 0x4a,
	OP_PUSHBYTES_75 = 0x4b,
	OP_PUSHDATA1 = 0x4c,
	OP_PUSHDATA2 = 0x4d,
	OP_PUSHDATA4 = 0x4e,
	OP_1NEGATE = 0x4f,
	OP_RESERVED = 0x50,
	OP_1 = 0x51,
	OP_2 = 0x52,
	OP_3 = 0x53,
	OP_4 = 0x54,
	OP_5 = 0x55,
	OP_6 = 0x56,
	OP_7 = 0x57,
	OP_8 = 0x58,
	OP_9 = 0x59,
	OP_10 = 0x5a,
	OP_11 = 0x5b,
	OP_12 = 0x5c,
	OP_13 = 0x5d,
	OP_14 = 0x5e,
	OP_15 = 0x5f,
	OP_16 = 0x60,

	/* NOTE: Control Flow */
	OP_NOP = 0x61,
	OP_VER = 0x62,
	OP_IF = 0x63,
	OP_NOTIF = 0x64,
	OP_VERIF = 0x65,
	OP_VERNOTIF = 0x66,
	OP_ELSE = 0x67,
	OP_ENDIF = 0x68,
	OP_VERIFY = 0x69,
	OP_RETURN = 0x6a,


	/* NOTE: Stack Operator */
	OP_TOALTSTACK = 0x6b,
	OP_FROMALTSTACK = 0x6c,
	OP_2DROP = 0x6d,
	OP_2DUP = 0x6e,
	OP_3DUP = 0x6f,
	OP_2OVER = 0x70,
	OP_2ROT = 0x71,
	OP_2SWAP = 0x72,
	OP_IFDUP = 0x73,
	OP_DEPTH = 0x74,
	OP_DROP = 0x75,
	OP_DUP = 0x76,
	OP_NIP = 0x77,


	OP_OVER = 0x78,
	OP_PICK = 0x79,
	OP_ROLL = 0x7a,
	OP_ROT = 0x7b,
	OP_SWAP = 0x7c,
	OP_TUCK = 0x7d,


	/* NOTE: Strings */
	OP_CAT = 0x7e,
	OP_SUBSTR = 0x7f,
	OP_LEFT = 0x80,
	OP_RIGHT = 0x81,
	OP_SIZE = 0x82,

	/* NOTE: Bitwise Logic */
	OP_INVERT = 0x83,
	OP_AND = 0x84,
	OP_OR = 0x85,
	OP_XOR = 0x86,
	OP_EQUAL = 0x87,
	OP_EQUALVERIFY = 0x88,
	OP_RESERVED1 = 0x89,
	OP_RESERVED2 = 0x8a,

	/* NOTE: Numeric */
	OP_1ADD						= 0x8b,
	OP_1SUB						= 0x8c,
	OP_2MUL						= 0x8d,
	OP_2DIV						= 0x8e,
	OP_NEGATE					= 0x8f,
	OP_ABS						= 0x90,
	OP_NOT						= 0x91,
	OP_0NOTEQUAL				= 0x92,
	OP_ADD						= 0x93,
	OP_SUB						= 0x94,
	OP_MUL						= 0x95,
	OP_DIV						= 0x96,
	OP_MOD						= 0x97,
	OP_LSHIFT					= 0x98,
	OP_RSHIFT					= 0x99,
	OP_BOOLAND					= 0x9a,
	OP_BOOLOR					= 0x9b,
	OP_NUMEQUAL					= 0x9c,
	OP_NUMEQUALVERIFY			= 0x9d,
	OP_NUMNOTEQUAL				= 0x9e,
	OP_LESSTHAN					= 0x9f,
	OP_GREATERTHAN				= 0xa0,
	OP_LESSTHANOREQUAL			= 0xa1,
	OP_GREATERTHANOREQUAL		= 0xa2,
	OP_MIN						= 0xa3,
	OP_MAX						= 0xa4,
	OP_WITHIN					= 0xa5,


	/* NOTE: Cryptography */
	OP_RIPEMD160				= 0xa6,
	OP_SHA1						= 0xa7,
	OP_SHA256					= 0xa8,
	OP_HASH160					= 0xa9,
	OP_HASH256					= 0xaa,
	OP_CODESEPARATOR			= 0xab,
	OP_CHECKSIG					= 0xac,
	OP_CHECKSIGVERIFY			= 0xad,
	OP_CHECKMULTISIG			= 0xae,
	OP_CHECKMULTISIGVERIFY		= 0xaf,

	/* NOTE: Other */
	OP_NOP1						= 0xb0,
	OP_CHECKLOCKTIMEVERIFY		= 0xb1,
	OP_CHECKSEQUENCEVERIFY		= 0xb2,
	OP_NOP4 = 0xb3,
	OP_NOP5 = 0xb4,
	OP_NOP6 = 0xb5,
	OP_NOP7 = 0xb6,
	OP_NOP8 = 0xb7,
	OP_NOP9 = 0xb8,
	OP_NOP10 = 0xb9,
	OP_CHECKSIGADD = 0xba,
	OP_RETURN_187 = 0xbb,
	OP_RETURN_188 = 0xbc,
	OP_RETURN_189 = 0xbd,
	OP_RETURN_190 = 0xbe,
	OP_RETURN_191 = 0xbf,
	OP_RETURN_192 = 0xc0,
	OP_RETURN_193 = 0xc1,
	OP_RETURN_194 = 0xc2,
	OP_RETURN_195 = 0xc3,
	OP_RETURN_196 = 0xc4,
	OP_RETURN_197 = 0xc5,
	OP_RETURN_198 = 0xc6,
	OP_RETURN_199 = 0xc7,
	OP_RETURN_200 = 0xc8,
	OP_RETURN_201 = 0xc9,
	OP_RETURN_202 = 0xca,
	OP_RETURN_203 = 0xcb,
	OP_RETURN_204 = 0xcc,
	OP_RETURN_205 = 0xcd,
	OP_RETURN_206 = 0xce,
	OP_RETURN_207 = 0xcf,
	OP_RETURN_208 = 0xd0,
	OP_RETURN_209 = 0xd1,
	OP_RETURN_210 = 0xd2,
	OP_RETURN_211 = 0xd3,
	OP_RETURN_212 = 0xd4,
	OP_RETURN_213 = 0xd5,
	OP_RETURN_214 = 0xd6,
	OP_RETURN_215 = 0xd7,
	OP_RETURN_216 = 0xd8, OP_RETURN_217 = 0xd9,
	OP_RETURN_218 = 0xda,
	OP_RETURN_219 = 0xdb,
	OP_RETURN_220 = 0xdc,
	OP_RETURN_221 = 0xdd,
	OP_RETURN_222 = 0xde,
	OP_RETURN_223 = 0xdf,
	OP_RETURN_224 = 0xe0,
	OP_RETURN_225 = 0xe1,
	OP_RETURN_226 = 0xe2,
	OP_RETURN_227 = 0xe3,
	OP_RETURN_228 = 0xe4,
	OP_RETURN_229 = 0xe5,
	OP_RETURN_230 = 0xe6,
	OP_RETURN_231 = 0xe7,
	OP_RETURN_232 = 0xe8,
	OP_RETURN_233 = 0xe9,
	OP_RETURN_234 = 0xea,
	OP_RETURN_235 = 0xeb,
	OP_RETURN_236 = 0xec,
	OP_RETURN_237 = 0xed,
	OP_RETURN_238 = 0xee,
	OP_RETURN_239 = 0xef,
	OP_RETURN_240 = 0xf0,
	OP_RETURN_241 = 0xf1,
	OP_RETURN_242 = 0xf2,
	OP_RETURN_243 = 0xf3,
	OP_RETURN_244 = 0xf4,
	OP_RETURN_245 = 0xf5,
	OP_RETURN_246 = 0xf6,
	OP_RETURN_247 = 0xf7,
	OP_RETURN_248 = 0xf8,
	OP_RETURN_249 = 0xf9,
	OP_RETURN_250 = 0xfa,
	OP_RETURN_251 = 0xfb,
	OP_RETURN_252 = 0xfc,
	OP_RETURN_253 = 0xfd,
	OP_RETURN_254 = 0xfe,
	OP_INVALIDOPCODE = 0xff
} SCRIPT_OPCODE;

static const char *script_opcode_strings[] = {
		"OP_0",                // 0x00
		"OP_PUSHBYTES_1",      // 0x01
		"OP_PUSHBYTES_2",      // 0x02
		"OP_PUSHBYTES_3",      // 0x03
		"OP_PUSHBYTES_4",      // 0x04
		"OP_PUSHBYTES_5",      // 0x05
		"OP_PUSHBYTES_6",      // 0x06
		"OP_PUSHBYTES_7",      // 0x07
		"OP_PUSHBYTES_8",      // 0x08
		"OP_PUSHBYTES_9",      // 0x09
		"OP_PUSHBYTES_10",     // 0x0A
		"OP_PUSHBYTES_11",     // 0x0B
		"OP_PUSHBYTES_12",     // 0x0C
		"OP_PUSHBYTES_13",     // 0x0D
		"OP_PUSHBYTES_14",     // 0x0E
		"OP_PUSHBYTES_15",     // 0x0F
		"OP_PUSHBYTES_16",     // 0x10
		"OP_PUSHBYTES_17",     // 0x11
		"OP_PUSHBYTES_18",     // 0x12
		"OP_PUSHBYTES_19",     // 0x13
		"OP_PUSHBYTES_20",     // 0x14
		"OP_PUSHBYTES_21",     // 0x15
		"OP_PUSHBYTES_22",     // 0x16
		"OP_PUSHBYTES_23",     // 0x17
		"OP_PUSHBYTES_24",     // 0x18
		"OP_PUSHBYTES_25",     // 0x19
		"OP_PUSHBYTES_26",     // 0x1A
		"OP_PUSHBYTES_27",     // 0x1B
		"OP_PUSHBYTES_28",     // 0x1C
		"OP_PUSHBYTES_29",     // 0x1D
		"OP_PUSHBYTES_30",     // 0x1E
		"OP_PUSHBYTES_31",     // 0x1F
		"OP_PUSHBYTES_32",     // 0x20
		"OP_PUSHBYTES_33",     // 0x21
		"OP_PUSHBYTES_34",     // 0x22
		"OP_PUSHBYTES_35",     // 0x23
		"OP_PUSHBYTES_36",     // 0x24
		"OP_PUSHBYTES_37",     // 0x25
		"OP_PUSHBYTES_38",     // 0x26
		"OP_PUSHBYTES_39",     // 0x27
		"OP_PUSHBYTES_40",     // 0x28
		"OP_PUSHBYTES_41",     // 0x29
		"OP_PUSHBYTES_42",     // 0x2A
		"OP_PUSHBYTES_43",     // 0x2B
		"OP_PUSHBYTES_44",     // 0x2C
		"OP_PUSHBYTES_45",     // 0x2D
		"OP_PUSHBYTES_46",     // 0x2E
		"OP_PUSHBYTES_47",     // 0x2F
		"OP_PUSHBYTES_48",     // 0x30
		"OP_PUSHBYTES_49",     // 0x31
		"OP_PUSHBYTES_50",     // 0x32
		"OP_PUSHBYTES_51",     // 0x33
		"OP_PUSHBYTES_52",     // 0x34
		"OP_PUSHBYTES_53",     // 0x35
		"OP_PUSHBYTES_54",     // 0x36
		"OP_PUSHBYTES_55",     // 0x37
		"OP_PUSHBYTES_56",     // 0x38
		"OP_PUSHBYTES_57",     // 0x39
		"OP_PUSHBYTES_58",     // 0x3A
		"OP_PUSHBYTES_59",     // 0x3B
		"OP_PUSHBYTES_60",     // 0x3C
		"OP_PUSHBYTES_61",     // 0x3D
		"OP_PUSHBYTES_62",     // 0x3E
		"OP_PUSHBYTES_63",     // 0x3F
		"OP_PUSHBYTES_64",     // 0x40
		"OP_PUSHBYTES_65",     // 0x41
		"OP_PUSHBYTES_66",     // 0x42
		"OP_PUSHBYTES_67",     // 0x43
		"OP_PUSHBYTES_68",     // 0x44
		"OP_PUSHBYTES_69",     // 0x45
		"OP_PUSHBYTES_70",     // 0x46
		"OP_PUSHBYTES_71",     // 0x47
		"OP_PUSHBYTES_72",     // 0x48
		"OP_PUSHBYTES_73",     // 0x49
		"OP_PUSHBYTES_74",     // 0x4A
		"OP_PUSHBYTES_75",     // 0x4B
		"OP_PUSHDATA1",        // 0x4C
		"OP_PUSHDATA2",        // 0x4D
		"OP_PUSHDATA4",        // 0x4E
		"OP_1NEGATE",          // 0x4F
		"OP_RESERVED",         // 0x50
		"OP_1",                // 0x51
		"OP_2",                // 0x52
		"OP_3",                // 0x53
		"OP_4",                // 0x54
		"OP_5",                // 0x55
		"OP_6",                // 0x56
		"OP_7",                // 0x57
		"OP_8",                // 0x58
		"OP_9",                // 0x59
		"OP_10",               // 0x5A
		"OP_11",               // 0x5B
		"OP_12",               // 0x5C
		"OP_13",               // 0x5D
		"OP_14",               // 0x5E
		"OP_15",               // 0x5F
		"OP_16",               // 0x60
		"OP_NOP",              // 0x61
		"OP_VER",              // 0x62
		"OP_IF",               // 0x63
		"OP_NOTIF",            // 0x64
		"OP_VERIF",            // 0x65
		"OP_VERNOTIF",         // 0x66
		"OP_ELSE",             // 0x67
		"OP_ENDIF",            // 0x68
		"OP_VERIFY",           // 0x69
		"OP_RETURN",           // 0x6A
		"OP_TOALTSTACK",       // 0x6B
		"OP_FROMALTSTACK",     // 0x6C
		"OP_2DROP",            // 0x6D
		"OP_2DUP",             // 0x6E
		"OP_3DUP",             // 0x6F
		"OP_2OVER",            // 0x70
		"OP_2ROT",             // 0x71
		"OP_2SWAP",            // 0x72
		"OP_IFDUP",            // 0x73
		"OP_DEPTH",            // 0x74
		"OP_DROP",             // 0x75
		"OP_DUP",              // 0x76
		"OP_NIP",              // 0x77
		"OP_OVER",             // 0x78
		"OP_PICK",             // 0x79
		"OP_ROLL",             // 0x7A
		"OP_ROT",              // 0x7B
		"OP_SWAP",             // 0x7C
		"OP_TUCK",             // 0x7D
		"OP_CAT",              // 0x7E
		"OP_SUBSTR",           // 0x7F
		"OP_LEFT",             // 0x80
		"OP_RIGHT",            // 0x81
		"OP_SIZE",             // 0x82
		"OP_INVERT",           // 0x83
		"OP_AND",              // 0x84
		"OP_OR",               // 0x85
		"OP_XOR",              // 0x86
		"OP_EQUAL",            // 0x87
		"OP_EQUALVERIFY",      // 0x88
		"OP_RESERVED1",        // 0x89
		"OP_RESERVED2",        // 0x8A
		"OP_1ADD",             // 0x8B
		"OP_1SUB",             // 0x8C
		"OP_2MUL",             // 0x8D
		"OP_2DIV",             // 0x8E
		"OP_NEGATE",           // 0x8F
		"OP_ABS",              // 0x90
		"OP_NOT",              // 0x91
		"OP_0NOTEQUAL",        // 0x92
		"OP_ADD",              // 0x93
		"OP_SUB",              // 0x94
		"OP_MUL",              // 0x95
		"OP_DIV",              // 0x96
		"OP_MOD",              // 0x97
		"OP_LSHIFT",           // 0x98
		"OP_RSHIFT",           // 0x99
		"OP_BOOLAND",          // 0x9A
		"OP_BOOLOR",           // 0x9B
		"OP_NUMEQUAL",         // 0x9C
		"OP_NUMEQUALVERIFY",   // 0x9D
		"OP_NUMNOTEQUAL",      // 0x9E
		"OP_LESSTHAN",         // 0x9F
		"OP_GREATERTHAN",      // 0xA0
		"OP_LESSTHANOREQUAL",  // 0xA1
		"OP_GREATERTHANOREQUAL", // 0xA2
		"OP_MIN",              // 0xA3
		"OP_MAX",              // 0xA4
		"OP_WITHIN",           // 0xA5
		"OP_RIPEMD160",        // 0xA6
		"OP_SHA1",             // 0xA7
		"OP_SHA256",           // 0xA8
		"OP_HASH160",          // 0xA9
		"OP_HASH256",          // 0xAA
		"OP_CODESEPARATOR",    // 0xAB
		"OP_CHECKSIG",         // 0xAC
		"OP_CHECKSIGVERIFY",   // 0xAD
		"OP_CHECKMULTISIG",    // 0xAE
		"OP_CHECKMULTISIGVERIFY", // 0xAF
		"OP_NOP1",             // 0xB0
		"OP_CHECKLOCKTIMEVERIFY", // 0xB1
		"OP_CHECKSEQUENCEVERIFY", // 0xB2
		"OP_NOP4",             // 0xB3
		"OP_NOP5",             // 0xB4
		"OP_NOP6",             // 0xB5
		"OP_NOP7",             // 0xB6
		"OP_NOP8",             // 0xB7
		"OP_NOP9",             // 0xB8
		"OP_NOP10",            // 0xB9
		"OP_CHECKSIGADD",      // 0xBA
		"OP_RETURN_187",       // 0xBB
		"OP_RETURN_188",       // 0xBC
		"OP_RETURN_189",       // 0xBD
		"OP_RETURN_190",       // 0xBE
		"OP_RETURN_191",       // 0xBF
		"OP_RETURN_192",       // 0xC0
		"OP_RETURN_193",       // 0xC1
		"OP_RETURN_194",       // 0xC2
		"OP_RETURN_195",       // 0xC3
		"OP_RETURN_196",       // 0xC4
		"OP_RETURN_197",       // 0xC5
		"OP_RETURN_198",       // 0xC6
		"OP_RETURN_199",       // 0xC7
		"OP_RETURN_200",       // 0xC8
		"OP_RETURN_201",       // 0xC9
		"OP_RETURN_202",       // 0xCA
		"OP_RETURN_203",       // 0xCB
		"OP_RETURN_204",       // 0xCC
		"OP_RETURN_205",       // 0xCD
		"OP_RETURN_206",       // 0xCE
		"OP_RETURN_207",       // 0xCF
		"OP_RETURN_208",       // 0xD0
		"OP_RETURN_209",       // 0xD1
		"OP_RETURN_210",       // 0xD2
		"OP_RETURN_211",       // 0xD3
		"OP_RETURN_212",       // 0xD4
		"OP_RETURN_213",       // 0xD5
		"OP_RETURN_214",       // 0xD6
		"OP_RETURN_215",       // 0xD7
		"OP_RETURN_216",       // 0xD8
		"OP_RETURN_217",       // 0xD9
		"OP_RETURN_218",       // 0xDA
		"OP_RETURN_219",       // 0xDB
		"OP_RETURN_220",       // 0xDC
		"OP_RETURN_221",       // 0xDD
		"OP_RETURN_222",       // 0xDE
		"OP_RETURN_223",       // 0xDF
		"OP_RETURN_224",       // 0xE0
		"OP_RETURN_225",       // 0xE1
		"OP_RETURN_226",       // 0xE2
		"OP_RETURN_227",       // 0xE3
		"OP_RETURN_228",       // 0xE4
		"OP_RETURN_229",       // 0xE5
		"OP_RETURN_230",       // 0xE6
		"OP_RETURN_231",       // 0xE7
		"OP_RETURN_232",       // 0xE8
		"OP_RETURN_233",       // 0xE9
		"OP_RETURN_234",       // 0xEA
		"OP_RETURN_235",       // 0xEB
		"OP_RETURN_236",       // 0xEC
		"OP_RETURN_237",       // 0xED
		"OP_RETURN_238",       // 0xEE
		"OP_RETURN_239",       // 0xEF
		"OP_RETURN_240",       // 0xF0
		"OP_RETURN_241",       // 0xF1
		"OP_RETURN_242",       // 0xF2
		"OP_RETURN_243",       // 0xF3
		"OP_RETURN_244",       // 0xF4
		"OP_RETURN_245",       // 0xF5
		"OP_RETURN_246",       // 0xF6
		"OP_RETURN_247",       // 0xF7
		"OP_RETURN_248",       // 0xF8
		"OP_RETURN_249",       // 0xF9
		"OP_RETURN_250",       // 0xFA
		"OP_RETURN_251",       // 0xFB
		"OP_RETURN_252",       // 0xFC
		"OP_RETURN_253",       // 0xFD
		"OP_RETURN_254",       // 0xFE
		"OP_INVALIDOPCODE",    // 0xFF
		0
	};
SCRIPT_OPCODE	SCRIPT_GetOpcode(const char *opcode);
const char *	SCRIPT_GetOpcodeName(SCRIPT_OPCODE opcode);

/**************************************		Errors		*************************************/
typedef enum SCRIPT_STATUS
{
	SCRIPT_NOSTATUS,
	SCRIPT_SUCCESS,
	SCRIPT_SUCCESS_STACK_NOT_EMPTY,
	SCRIPT_PENDING_EXECUTION,
	SCRIPT_PENDING_VALIDATION,
	SCRIPT_FAILURE,
	SCRIPT_FAILURE_INVALID,
	SCRIPT_FAILURE_NUMBER_OVERFLOW,
	SCRIPT_FAILURE_MISSING_SCRIPT_SEGMENT,
	SCRIPT_FAILURE_DISABLED_OPCODE,
	SCRIPT_FAILURE_STACK_OVERFLOW,
	SCRIPT_FAILURE_STACK_UNDERFLOW,
	SCRIPT_FAILURE_STACK_NOT_EMPTY,
	SCRIPT_FAILURE_CLTV,
} SCRIPT_STATUS;

static const char *script_status_strings[] =
{
	"SCRIPT_NOSTATUS",
	"SCRIPT_SUCCESS",
	"SCRIPT_SUCCESS_STACK_NOT_EMPTY",
	"SCRIPT_PENDING_EXECUTION",
	"SCRIPT_PENDING_VALIDATION",
	"SCRIPT_FAILURE",
	"SCRIPT_FAILURE_INVALID",
	"SCRIPT_FAILURE_NUMBER_OVERFLOW",
	"SCRIPT_FAILURE_MISSING_SCRIPT_SEGMENT",
	"SCRIPT_FAILURE_DISABLED_OPCODE",
	"SCRIPT_FAILURE_STACK_OVERFLOW",
	"SCRIPT_FAILURE_STACK_UNDERFLOW",
	"SCRIPT_FAILURE_STACK_NOT_EMPTY",
	"SCRIPT_FAILURE_CLTV",
	0
};
const char *SCRIPT_GetStatusName(SCRIPT_STATUS status);



/**************************************		Script		*************************************/
typedef struct SCRIPT_StackElement
{
	U8		element[SCRIPT_MAX_STACK_ELEMENT_SIZE];
	U32		elementSize;
} StackElement;

typedef struct SCRIPT_Stack
{
	StackElement	elements[SCRIPT_MAX_STACK_ITEMS];
	U32					stackSize;
} Stack;

void			StackPush(Stack  *stack, StackElement element);
StackElement	StackPop(Stack *stack);
void			PrintStackElement(StackElement *element);
void			PrintStack(Stack *stack);
void			PrintStacks(Stack *mainStack, Stack *altStack);

typedef struct SCRIPT_Script
{
	U8				bytes[SCRIPT_MAX_SCRIPT_SIZE];
	U32				scriptSize;
	char			hex[SCRIPT_MAX_SCRIPT_SIZE * 2];
} Script;
void	InitScript(Script *script, const char *rawScript);
void	PrintScript(Script *script);


/**************************************		numerals		*************************************/
U32 SCRIPT_SerializeScriptNum(I32 value, U8 out[4]);
I32 SCRIPT_DeserializeScriptNum(const U8 *data, U32 len);


/**************************************		utils *************************************/
U8		__is_hex__(const char *str);
void	__hexstr_to_bytes(const char *hexString, uint8_t *byteArray, size_t arraySize, size_t *outLength);
void	__modify_bytes__(U8 bytes[], size_t size, int value, U8 isBigEndian);

#endif
