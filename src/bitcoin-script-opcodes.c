#include "bitcoin-script-internals.h"
#include "bitcoin-script-interpreter.h"
#include "crypto/sha256.h"
#include "crypto/ripemd160.h"
#include "crypto/sha1.h"
#include <stdio.h>

/* ----------------------------------------- OP_PUSH ------------------------------------------------------- */
void OpPushData(ScriptInterpreter *env);

void OpPushBytes(ScriptInterpreter *env, U8 byteCount)
{
	StackElement element = {0}; if ((env->executedByteCount + byteCount + 1) > env->script.scriptSize)
	{
		printf("Error: Missing script segment\n");
		env->scriptExecutionStatus 	= SCRIPT_FAILURE_MISSING_SCRIPT_SEGMENT;
		return;
	}
	env->executedByteCount++;
	memcpy(&element.element, &env->script.bytes[env->executedByteCount], byteCount);
	element.elementSize = byteCount;
	StackPush(&env->mainStack, element);
	env->executedByteCount += byteCount;
	env->stackItemPushedCount++; }

void OpPushNumber(ScriptInterpreter *env, I32 number)
{
    StackElement element = {0};
	U32 len = SCRIPT_SerializeScriptNum(number, element.element);
	element.elementSize = len;
    StackPush(&env->mainStack, element);
    env->executedByteCount++;
	env->stackItemPushedCount++;
}

void ExecutePushDataOpcodes(ScriptInterpreter *env)
{
    if (env->executedByteCount > env->script.scriptSize)
		printf("Error\n");
	U8 opcode = env->script.bytes[env->executedByteCount];
	if (opcode == OP_0)
		OpPushNumber(env, 0);
	if ((OP_1 <= opcode) && (opcode <= OP_16))
		OpPushNumber(env, opcode - 0x50);
	else if ((OP_PUSHBYTES_1 <= opcode) && (opcode <= OP_PUSHBYTES_75))
		OpPushBytes(env, opcode);
	else
		printf("Unsupported Opcode : %02X\n", opcode);
}

/* ----------------------------------------- GENERAL OPCODES ------------------------------------------------------- */
void OpBooleanOperations(ScriptInterpreter *env)
{
	U8 opcode = env->script.bytes[env->executedByteCount];
	StackElement firstElement = StackPop(&env->mainStack);
	StackElement secondElement = StackPop(&env->mainStack);
	if ((firstElement.elementSize > 4) || (secondElement.elementSize > 4))
	{
		env->scriptExecutionStatus = SCRIPT_FAILURE_NUMBER_OVERFLOW;
		return;
	}
	U32 firstItem = SCRIPT_DeserializeScriptNum(firstElement.element, firstElement.elementSize);
	U32 secondItem = SCRIPT_DeserializeScriptNum(secondElement.element, secondElement.elementSize);
	// memcpy(&firstItem, firstElement.element, 4);
	// memcpy(&secondItem, secondElement.element, 4);
	if 	(opcode == OP_BOOLOR)
		OpPushNumber(env, (firstItem || secondItem) ? 1 : 0);
	else if	(opcode == OP_BOOLAND)
		OpPushNumber(env, (firstItem && secondItem) ? 1 : 0);
}

void ExecuteMathopcodes(ScriptInterpreter *env)
{
	if (env->executedByteCount >= env->script.scriptSize)
		printf("Error\n");
	U8 opcode = env->script.bytes[env->executedByteCount];
	if (opcode == OP_1ADD) // WARN: Check Endianness -- Must check for negative numbers.
	{
		StackElement element = StackPop(&env->mainStack);
		__modify_bytes__(element.element, sizeof(element.element), 1, 0);
		StackPush(&env->mainStack, element);
		env->executedByteCount++;
	}
	else if (opcode == OP_1SUB)
	{
		StackElement element = StackPop(&env->mainStack);
		__modify_bytes__(element.element, sizeof(element.element), -1, 0);
		StackPush(&env->mainStack, element);
		env->executedByteCount++;
	}
	else if (opcode == OP_ADD)
	{
		StackElement elementA = StackPop(&env->mainStack);
		StackElement elementB = StackPop(&env->mainStack);
		I32 a = SCRIPT_DeserializeScriptNum(elementA.element, elementA.elementSize);
		I32 b = SCRIPT_DeserializeScriptNum(elementB.element, elementB.elementSize);
		I32 c = a + b;
		OpPushNumber(env, c);
	}
	else if (opcode == OP_SUB)
	{
		StackElement elementA = StackPop(&env->mainStack);
		StackElement elementB = StackPop(&env->mainStack);
		I32 a = SCRIPT_DeserializeScriptNum(elementA.element, elementA.elementSize);
		I32 b = SCRIPT_DeserializeScriptNum(elementB.element, elementB.elementSize);
		I32 c = a - b;
		OpPushNumber(env, c);
	}
	else if (opcode == OP_MUL)
	{
		StackElement elementA = StackPop(&env->mainStack);
		StackElement elementB = StackPop(&env->mainStack);
		I32 a = SCRIPT_DeserializeScriptNum(elementA.element, elementA.elementSize);
		I32 b = SCRIPT_DeserializeScriptNum(elementB.element, elementB.elementSize);
		I32 c = a * b;
		OpPushNumber(env, c);
	}
	else if (opcode == OP_DIV)
	{
		StackElement elementA = StackPop(&env->mainStack);
		StackElement elementB = StackPop(&env->mainStack);
		I32 a = SCRIPT_DeserializeScriptNum(elementA.element, elementA.elementSize);
		I32 b = SCRIPT_DeserializeScriptNum(elementB.element, elementB.elementSize);
		I32 c = a / b;
		OpPushNumber(env, c);
	}
	else if (opcode == OP_NEGATE)
	{
		StackElement element = StackPop(&env->mainStack);
		I32 value = SCRIPT_DeserializeScriptNum(element.element, element.elementSize);
		value *= (-1);
		OpPushNumber(env, value);		// NOTE: Do not increase executedByteCount as OpPushNumber already does it.
	}
	else if (opcode == OP_ABS)
	{
		StackElement element = StackPop(&env->mainStack);
		I32 value = SCRIPT_DeserializeScriptNum(element.element, element.elementSize);
		value = (value > 0) ? value : (value * (-1));
		OpPushNumber(env, value);		// NOTE: Do not increase executedByteCount as OpPushNumber already does it.
	}
	else if ((opcode == OP_BOOLOR) || (opcode == OP_BOOLAND))
		OpBooleanOperations(env);
	else
		printf("Unsupported opcode\n");
}

/* ----------------------------------------- SINGLE OPCODES ------------------------------------------------------- */

void OpToAltStack(ScriptInterpreter *env)
{
	StackElement element = StackPop(&env->mainStack);
	StackPush(&env->altStack, element);
	env->executedByteCount++;
}

void OpFromAltStack(ScriptInterpreter *env)
{
	StackElement element = StackPop(&env->altStack);
	StackPush(&env->mainStack, element);
	env->executedByteCount++;
}


void OpDisabled(ScriptInterpreter *env)
{
	env->scriptExecutionStatus = SCRIPT_FAILURE_DISABLED_OPCODE;
	env->executedByteCount++;
}

void OpReturn(ScriptInterpreter *env)
{
	env->scriptExecutionStatus = SCRIPT_FAILURE_INVALID;
	env->executedByteCount++;
}

void OpNop(ScriptInterpreter *env)
{
	env->executedByteCount++;
}

void OpCheckLocktimeVerify(ScriptInterpreter *env)
{
	StackElement element = env->mainStack.elements[env->mainStack.stackSize];
	I32 value = SCRIPT_DeserializeScriptNum(element.element, element.elementSize);
	if ((env->mainStack.stackSize == 0) || (value > env->nLockTime) || (value < 0) ||	\
		((value >= 500000000)  && (env->nLockTime < 500000000)) || (env->nSequence == 0xffffffff))
	{
		env->scriptExecutionStatus = SCRIPT_FAILURE_CLTV;
		return;
	}
}

void OpEqual(ScriptInterpreter *env)
{
	if (env->mainStack.stackSize < 2)
	{
		env->scriptExecutionStatus = SCRIPT_FAILURE_STACK_UNDERFLOW;
		return;
	}
	StackElement firstElement = StackPop(&env->mainStack);
	StackElement secondElement = StackPop(&env->mainStack);
	if (firstElement.elementSize == secondElement.elementSize)
	{
		if (memcmp(firstElement.element, secondElement.element, firstElement.elementSize) == 0)
		{
			OpPushNumber(env, 1);
			return;
		}
	}
	OpPushNumber(env, 0);
}

void Op0NotEqual(ScriptInterpreter *env)
{
	StackElement element = StackPop(&env->mainStack);
	U32	value = SCRIPT_DeserializeScriptNum(element.element, element.elementSize);
	if (value == 0)
	{
		OpPushNumber(env, 0);
		return;
	}
	OpPushNumber(env, 1);
}

void OpNumEqual(ScriptInterpreter *env)
{
	if (env->mainStack.stackSize  < 2)
	{
		env->scriptExecutionStatus = SCRIPT_FAILURE_STACK_UNDERFLOW;
		return;
	}
	StackElement firstElement = StackPop(&env->mainStack);
	StackElement secondElement = StackPop(&env->mainStack);
	U32 firstNumber = SCRIPT_DeserializeScriptNum(firstElement.element, firstElement.elementSize);
	U32 secondNumber = SCRIPT_DeserializeScriptNum(secondElement.element, secondElement.elementSize);
	if (firstNumber == secondNumber)
	{
		OpPushNumber(env, 1);
		return;
	}
	OpPushNumber(env, 0);
}

void OpNumNotEqual(ScriptInterpreter *env)
{
	if (env->mainStack.stackSize  < 2)
	{
		env->scriptExecutionStatus = SCRIPT_FAILURE_STACK_UNDERFLOW;
		return;
	}
	StackElement firstElement = StackPop(&env->mainStack);
	StackElement secondElement = StackPop(&env->mainStack);
	U32 firstNumber = SCRIPT_DeserializeScriptNum(firstElement.element, firstElement.elementSize);
	U32 secondNumber = SCRIPT_DeserializeScriptNum(secondElement.element, secondElement.elementSize);
	if (firstNumber == secondNumber)
	{
		OpPushNumber(env, 0);
	}
	else
	{
		OpPushNumber(env, 1);
	}
}

void OpLessOrGreaterThan(ScriptInterpreter *env, U8 lessThan)
{
	if (env->mainStack.stackSize  < 2)
	{
		env->scriptExecutionStatus = SCRIPT_FAILURE_STACK_UNDERFLOW;
		return;
	}
	StackElement firstElement = StackPop(&env->mainStack);
	StackElement secondElement = StackPop(&env->mainStack);
	U32 firstNumber = SCRIPT_DeserializeScriptNum(firstElement.element, firstElement.elementSize);
	U32 secondNumber = SCRIPT_DeserializeScriptNum(secondElement.element, secondElement.elementSize);
	if (firstNumber < secondNumber)
	{
		OpPushNumber(env, lessThan);
	}
	else
	{
		OpPushNumber(env, !lessThan);
	}

}

void OpLessOrGreaterOrEqualThan(ScriptInterpreter *env, U8 lessThan)
{
	if (env->mainStack.stackSize  < 2)
	{
		env->scriptExecutionStatus = SCRIPT_FAILURE_STACK_UNDERFLOW;
		return;
	}
	StackElement firstElement = StackPop(&env->mainStack);
	StackElement secondElement = StackPop(&env->mainStack);
	U32 firstNumber = SCRIPT_DeserializeScriptNum(firstElement.element, firstElement.elementSize);
	U32 secondNumber = SCRIPT_DeserializeScriptNum(secondElement.element, secondElement.elementSize);
	if (firstNumber <= secondNumber)
	{
		OpPushNumber(env, lessThan);
	}
	else
	{
		OpPushNumber(env, !lessThan);
	}

}

void OpMinMax(ScriptInterpreter *env, U8 min)
{
	if (env->mainStack.stackSize  < 2)
	{
		env->scriptExecutionStatus = SCRIPT_FAILURE_STACK_UNDERFLOW;
		return;
	}
	StackElement firstElement = StackPop(&env->mainStack);
	StackElement secondElement = StackPop(&env->mainStack);
	U32 firstNumber = SCRIPT_DeserializeScriptNum(firstElement.element, firstElement.elementSize);
	U32 secondNumber = SCRIPT_DeserializeScriptNum(secondElement.element, secondElement.elementSize);
	if (firstNumber <= secondNumber)
	{
		OpPushNumber(env, (min ? firstNumber : secondNumber));
	}
	else
	{
		OpPushNumber(env, (min ? secondNumber : firstNumber));
	}

}

void OpNot(ScriptInterpreter *env)
{
	StackElement element = StackPop(&env->mainStack);
	U32 num = SCRIPT_DeserializeScriptNum(element.element, element.elementSize);
	if (num == 0)
	{
		OpPushNumber(env, 1);
	}
	else
	{
		OpPushNumber(env, 0);
	}
}

void OpVerify(ScriptInterpreter *env)
{
	if (env->mainStack.stackSize == 0)
	{
		env->scriptExecutionStatus = SCRIPT_FAILURE_STACK_UNDERFLOW;
		return;
	}
	StackElement element = StackPop(&env->mainStack);
	U32 num = SCRIPT_DeserializeScriptNum(element.element, element.elementSize);
	env->executedByteCount++;
	if (num == 0)
		env->scriptExecutionStatus = SCRIPT_FAILURE_INVALID;
}

void OpNumEqualVerify(ScriptInterpreter *env)
{
	OpNumEqual(env);
	OpVerify(env);
	env->executedByteCount--;
}

void OpEqualVerify(ScriptInterpreter *env)
{
	OpEqual(env);
	OpVerify(env);
	env->executedByteCount--;
}


void OpDrop(ScriptInterpreter *env)
{
	if (env->mainStack.stackSize == 0)
	{
		env->scriptExecutionStatus = SCRIPT_FAILURE_STACK_OVERFLOW;
		env->executedByteCount++;
		return;
	}
	StackPop(&env->mainStack);
	env->executedByteCount++;
	env->executedOpcodeCount++;
}

void Op2Drop(ScriptInterpreter *env)
{
	OpDrop(env);
	OpDrop(env);
	env->executedByteCount--;
}


void OpDup(ScriptInterpreter *env)
{
	StackElement element = StackPop(&env->mainStack);
	StackPush(&env->mainStack, element);
	StackPush(&env->mainStack, element);
	env->executedByteCount++;
}

void OpIfDup(ScriptInterpreter *env)
{
	StackElement element = StackPop(&env->altStack);
	I32	value = SCRIPT_DeserializeScriptNum(element.element, element.elementSize);
	env->executedByteCount++;
	if (value != 0)
	{
		OpDup(env);
		env->executedByteCount--;
	}
}

void OpDepth(ScriptInterpreter *env)
{
	/*  FIXME: Does not work if stack size is greater than 256 -- (more than one byte) */
	StackElement element;
	memcpy(element.element, &env->mainStack.stackSize, 4);
	// element.elementSize = BytesNeeded(env->mainStack.stackSize);
	StackPush(&env->mainStack, element);
	env->executedByteCount++;
}

void OpSize(ScriptInterpreter *env)
{
	if (env->mainStack.stackSize <= 0)
	{
		env->scriptExecutionStatus = SCRIPT_FAILURE_STACK_UNDERFLOW;
		return;
	}
	StackElement element;
	element.elementSize = SCRIPT_SerializeScriptNum(env->mainStack.elements[0].elementSize, element.element);
	U32 size = SCRIPT_DeserializeScriptNum(element.element, element.elementSize);
	OpPushNumber(env, size);
}


/*------------------------------------------ Crypto ----------------------------------------------*/

void	OpRipemd160(ScriptInterpreter *env)
{
	StackElement newElement = {0};
	StackElement element = StackPop(&env->mainStack);
	ripemd160(element.element, element.elementSize, newElement.element);
	newElement.elementSize = 20;
	StackPush(&env->mainStack, newElement);
	env->executedByteCount++;
}

void	OpSha1(ScriptInterpreter *env)
{
	StackElement newElement = {0};
	StackElement element = StackPop(&env->mainStack);
	SHA1((char*)newElement.element, (char*)element.element, element.elementSize);
	newElement.elementSize = 20;
	StackPush(&env->mainStack, newElement);
	env->executedByteCount++;
}

void	OpSha256(ScriptInterpreter *env)
{
	StackElement newElement = {0};
	StackElement element = StackPop(&env->mainStack);
	sha256(element.element, element.elementSize, newElement.element);
	newElement.elementSize = 32;
	StackPush(&env->mainStack, newElement);
	env->executedByteCount++;
}

void	OpHash256(ScriptInterpreter *env)
{
	StackElement newElement = {0};
	StackElement element = StackPop(&env->mainStack);
	sha256d(element.element, element.elementSize, newElement.element);
	newElement.elementSize = 32;
	StackPush(&env->mainStack, newElement);
	env->executedByteCount++;
}

void	OpHash160(ScriptInterpreter *env)
{
	StackElement newElement = {0};
	StackElement element = StackPop(&env->mainStack);
	sha256(element.element, element.elementSize, newElement.element);
	ripemd160(newElement.element, 32, newElement.element);
	newElement.elementSize = 20;
	StackPush(&env->mainStack, newElement);
	env->executedByteCount++;
}

void	SCRIPT_ExecuteOpcode(ScriptInterpreter	*env)
{
	U8 opcode = env->script.bytes[env->executedByteCount];
	// NOTE:	Yes it's ugly, yes I could do it in a way more elegant manner, yes it's repetitive. 
	// NOTE:	Yet I dont care as for some reason it pleases my brain.
	switch (opcode)
	{
		case	OP_0			:	OpPushNumber(env, 0);			break;
		case 	OP_PUSHBYTES_1	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_2	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_3	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_4	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_5	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_6	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_7	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_8	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_9	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_10	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_11	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_12	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_13	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_14	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_15	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_16	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_17	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_18	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_19	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_20	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_21	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_22	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_23	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_24	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_25	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_26	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_27	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_28	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_29	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_30	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_31	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_32	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_33	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_34	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_35	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_36	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_37	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_38	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_39	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_40	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_41	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_42	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_43	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_44	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_45	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_46	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_47	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_48 :	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_49 :	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_50 :	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_51 :	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_52 :	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_53 :	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_54 :	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_55 :	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_56 :	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_57 :	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_58 :	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_59	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_60	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_61	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_62	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_63	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_64	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_65	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_66	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_67	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_68	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_69	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_70	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_71	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_72	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_73	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_74	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHBYTES_75	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHDATA1	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHDATA2	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_PUSHDATA4	:	ExecutePushDataOpcodes(env);	break;
		case 	OP_1NEGATE		:	OpPushNumber(env, -1);			break;
		case 	OP_RESERVED		:	OpNop(env);						break;
		case 	OP_1			:	OpPushNumber(env, 1);			break;
		case 	OP_2			:	OpPushNumber(env, 2);			break;
		case 	OP_3			:	OpPushNumber(env, 3);			break;
		case 	OP_4			:	OpPushNumber(env, 4);			break;
		case 	OP_5			:	OpPushNumber(env, 5);			break;
		case 	OP_6			:	OpPushNumber(env, 6);			break;
		case 	OP_7			:	OpPushNumber(env, 7);			break;
		case 	OP_8			:	OpPushNumber(env, 8);			break;
		case 	OP_9			:	OpPushNumber(env, 9);			break;
		case 	OP_10			:	OpPushNumber(env, 10);			break;
		case 	OP_11			:	OpPushNumber(env, 11);			break;
		case 	OP_12			:	OpPushNumber(env, 12);			break;
		case 	OP_13			:	OpPushNumber(env, 13);			break;
		case 	OP_14			:	OpPushNumber(env, 14);			break;
		case 	OP_15			:	OpPushNumber(env, 15);			break;
		case 	OP_16			:	OpPushNumber(env, 16);			break;
		case 	OP_NOP			:	OpNop(env);						break;
		case 	OP_VER			:	OpDisabled(env);				break;	// INFO: Disabled opcode
		case 	OP_IF			:	break;
		case 	OP_NOTIF		:	break;
		case 	OP_VERIF		:	OpDisabled(env);				break;	// INFO: Diabled Opcode
		case 	OP_VERNOTIF		:	OpDisabled(env);				break;	// INFO: Disabled Opcode
		case 	OP_ELSE			:	break;
		case 	OP_ENDIF		:	break;
		case 	OP_VERIFY		:	OpVerify(env);					break;
		case 	OP_RETURN		:	OpReturn(env);					break;
		case 	OP_TOALTSTACK	:	OpToAltStack(env);				break;
		case 	OP_FROMALTSTACK	:	OpFromAltStack(env);			break;
		case 	OP_2DROP		:	Op2Drop(env);					break;
		case 	OP_2DUP			:	break;
		case 	OP_3DUP			:	break;
		case 	OP_2OVER		:	break;
		case 	OP_2ROT			:	break;
		case 	OP_2SWAP		:	break;
		case 	OP_IFDUP		:	OpIfDup(env);					break;
		case 	OP_DEPTH		:	OpDepth(env);					break;
		case 	OP_DROP			:	OpDrop(env);					break;
		case 	OP_DUP			:	OpDup(env);						break;
		case 	OP_NIP			:	break;
		case 	OP_OVER						:	break;
		case 	OP_PICK						:	break;
		case 	OP_ROLL						:	break;
		case 	OP_ROT						:	break;
		case 	OP_SWAP						:	break;
		case 	OP_TUCK						:	break;
		case 	OP_CAT						:	OpDisabled(env);			break;
		case 	OP_SUBSTR					:	OpDisabled(env);			break;
		case 	OP_LEFT 					:	OpDisabled(env);			break;
		case 	OP_RIGHT					:	OpDisabled(env);			break;
		case 	OP_SIZE						:	OpSize(env);				break;
		case 	OP_INVERT					:	OpDisabled(env);			break;
		case 	OP_AND						:	OpDisabled(env);			break;
		case 	OP_OR						:	OpDisabled(env);			break;
		case 	OP_XOR						:	OpDisabled(env);			break;
		case 	OP_EQUAL 					:	OpEqual(env);				break;
		case 	OP_EQUALVERIFY 				:	OpEqualVerify(env);			break;
		case 	OP_RESERVED1 				:	OpNop(env);					break;
		case 	OP_RESERVED2 				:	OpNop(env);					break;
		case 	OP_1ADD						:	ExecuteMathopcodes(env);	break;
		case 	OP_1SUB						:	ExecuteMathopcodes(env);	break;
		case 	OP_2MUL						:	OpDisabled(env);			break;
		case 	OP_2DIV						:	OpDisabled(env);			break;
		case 	OP_NEGATE					:	ExecuteMathopcodes(env);	break;
		case 	OP_ABS						:	ExecuteMathopcodes(env);	break;
		case 	OP_NOT						:	OpNot(env);					break;
		case 	OP_0NOTEQUAL				:	Op0NotEqual(env);			break;
		case 	OP_ADD						:	ExecuteMathopcodes(env);	break;
		case 	OP_SUB						:	ExecuteMathopcodes(env);	break;
		case 	OP_MUL						:	OpDisabled(env);			break;
		case 	OP_DIV						:	OpDisabled(env);			break;
		case 	OP_MOD						:	OpDisabled(env);			break;
		case 	OP_LSHIFT					:	OpDisabled(env);			break;
		case 	OP_RSHIFT					:	OpDisabled(env);			break;
		case 	OP_BOOLAND					:	OpBooleanOperations(env);			break;
		case 	OP_BOOLOR					:	OpBooleanOperations(env);			break;
		case 	OP_NUMEQUAL					:	OpNumEqual(env);					break;
		case 	OP_NUMEQUALVERIFY			:	OpNumEqualVerify(env);				break;
		case 	OP_NUMNOTEQUAL				:	OpNumNotEqual(env);					break;
		case 	OP_LESSTHAN					:	OpLessOrGreaterThan(env, 1);		break;
		case 	OP_GREATERTHAN				:	OpLessOrGreaterThan(env, 0);		break;
		case 	OP_LESSTHANOREQUAL			:	OpLessOrGreaterOrEqualThan(env, 1);	break;
		case 	OP_GREATERTHANOREQUAL		:	OpLessOrGreaterOrEqualThan(env, 0);	break;
		case 	OP_MIN						:	OpMinMax(env, 1);					break;
		case 	OP_MAX						:	OpMinMax(env, 0);					break;
		case 	OP_WITHIN					:	break;
		case 	OP_RIPEMD160				:	OpRipemd160(env);					break;
		case 	OP_SHA1						:	OpSha1(env);						break;
		case 	OP_SHA256					:	OpSha256(env);						break;
		case 	OP_HASH160					:	OpHash160(env);						break;
		case 	OP_HASH256					:	OpHash256(env);						break;
		case 	OP_CODESEPARATOR			:	break;
		case 	OP_CHECKSIG					:	break;
		case 	OP_CHECKSIGVERIFY			:	break;
		case 	OP_CHECKMULTISIG			:	break;
		case 	OP_CHECKMULTISIGVERIFY		:	break;
		case 	OP_NOP1						:	OpNop(env);		break;
		case 	OP_CHECKLOCKTIMEVERIFY		:	OpCheckLocktimeVerify(env);			break;
		case 	OP_CHECKSEQUENCEVERIFY		:	break;
		case 	OP_NOP4						:	OpNop(env);		break;
		case 	OP_NOP5						:	OpNop(env);		break;
		case 	OP_NOP6						:	OpNop(env);		break;
		case 	OP_NOP7						:	OpNop(env);		break;
		case 	OP_NOP8						:	OpNop(env);		break;
		case 	OP_NOP9						:	OpNop(env);		break;
		case 	OP_NOP10					:	OpNop(env);		break;
		case 	OP_CHECKSIGADD				:	break;
		case 	OP_RETURN_187				:	OpReturn(env);	break;
		case 	OP_RETURN_188				:	OpReturn(env);	break;
		case 	OP_RETURN_189				:	OpReturn(env);	break;
		case 	OP_RETURN_190				:	OpReturn(env);	break;
		case 	OP_RETURN_191				:	OpReturn(env);	break;
		case 	OP_RETURN_192				:	OpReturn(env);	break;
		case 	OP_RETURN_193				:	OpReturn(env);	break;
		case 	OP_RETURN_194				:	OpReturn(env);	break;
		case 	OP_RETURN_195				:	OpReturn(env);	break;
		case 	OP_RETURN_196				:	OpReturn(env);	break;
		case 	OP_RETURN_197				:	OpReturn(env);	break;
		case 	OP_RETURN_198				:	OpReturn(env);	break;
		case 	OP_RETURN_199				:	OpReturn(env);	break;
		case	OP_RETURN_200				:	OpReturn(env);	break;
		case 	OP_RETURN_201				:	OpReturn(env);	break;
		case 	OP_RETURN_202				:	OpReturn(env);	break;
		case 	OP_RETURN_203				:	OpReturn(env);	break;
		case 	OP_RETURN_204				:	OpReturn(env);	break;
		case 	OP_RETURN_205				:	OpReturn(env);	break;
		case 	OP_RETURN_206				:	OpReturn(env);	break;
		case 	OP_RETURN_207				:	OpReturn(env);	break;
		case 	OP_RETURN_208				:	OpReturn(env);	break;
		case 	OP_RETURN_209				:	OpReturn(env);	break;
		case 	OP_RETURN_210				:	OpReturn(env);	break;
		case 	OP_RETURN_211				:	OpReturn(env);	break;
		case 	OP_RETURN_212				:	OpReturn(env);	break;
		case 	OP_RETURN_213				:	OpReturn(env);	break;
		case 	OP_RETURN_214				:	OpReturn(env);	break;
		case 	OP_RETURN_215				:	OpReturn(env);	break;
		case 	OP_RETURN_216				:	OpReturn(env);	break;
		case 	OP_RETURN_217				:	OpReturn(env);	break;
		case 	OP_RETURN_218				:	OpReturn(env);	break;
		case 	OP_RETURN_219				:	OpReturn(env);	break;
		case 	OP_RETURN_220				:	OpReturn(env);	break;
		case 	OP_RETURN_221				:	OpReturn(env);	break;
		case 	OP_RETURN_222				:	OpReturn(env);	break;
		case 	OP_RETURN_223				:	OpReturn(env);	break;
		case 	OP_RETURN_224				:	OpReturn(env);	break;
		case 	OP_RETURN_225				:	OpReturn(env);	break;
		case 	OP_RETURN_226				:	OpReturn(env);	break;
		case 	OP_RETURN_227				:	OpReturn(env);	break;
		case 	OP_RETURN_228				:	OpReturn(env);	break;
		case 	OP_RETURN_229				:	OpReturn(env);	break;
		case 	OP_RETURN_230				:	OpReturn(env);	break;
		case 	OP_RETURN_231				:	OpReturn(env);	break;
		case 	OP_RETURN_232				:	OpReturn(env);	break;
		case 	OP_RETURN_233				:	OpReturn(env);	break;
		case 	OP_RETURN_234				:	OpReturn(env);	break;
		case 	OP_RETURN_235				:	OpReturn(env);	break;
		case 	OP_RETURN_236				:	OpReturn(env);	break;
		case 	OP_RETURN_237				:	OpReturn(env);	break;
		case 	OP_RETURN_238				:	OpReturn(env);	break;
		case 	OP_RETURN_239				:	OpReturn(env);	break;
		case 	OP_RETURN_240				:	OpReturn(env);	break;
		case 	OP_RETURN_241				:	OpReturn(env);	break;
		case 	OP_RETURN_242				:	OpReturn(env);	break;
		case 	OP_RETURN_243				:	OpReturn(env);	break;
		case 	OP_RETURN_244				:	OpReturn(env);	break;
		case 	OP_RETURN_245				:	OpReturn(env);	break;
		case 	OP_RETURN_246				:	OpReturn(env);	break;
		case 	OP_RETURN_247				:	OpReturn(env);	break;
		case 	OP_RETURN_248				:	OpReturn(env);	break;
		case 	OP_RETURN_249				:	OpReturn(env);	break;
		case 	OP_RETURN_250				:	OpReturn(env);	break;
		case 	OP_RETURN_251				:	OpReturn(env);	break;
		case 	OP_RETURN_252				:	OpReturn(env);	break;
		case 	OP_RETURN_253				:	OpReturn(env);	break;
		case 	OP_RETURN_254				:	OpReturn(env);	break;
		case 	OP_INVALIDOPCODE			:	env->scriptExecutionStatus = SCRIPT_FAILURE_INVALID;	break;
		default								:	env->scriptExecutionStatus = SCRIPT_FAILURE_INVALID;	return;
	}
}

SCRIPT_STATUS ValidateScript(ScriptInterpreter *env)
{
	if (env->scriptExecutionStatus != SCRIPT_PENDING_EXECUTION)
	{
		return env->scriptExecutionStatus;
	}
	if (env->mainStack.stackSize != 1)
	{
		env->scriptExecutionStatus = SCRIPT_FAILURE_STACK_NOT_EMPTY;
		return SCRIPT_FAILURE_STACK_NOT_EMPTY;
	}
	if (env->mainStack.elements[0].element[0] == 0)
	{
		env->scriptExecutionStatus = SCRIPT_FAILURE_INVALID;
		return SCRIPT_FAILURE_INVALID;
	}
	env->scriptExecutionStatus = SCRIPT_SUCCESS;
	return SCRIPT_SUCCESS;
}

SCRIPT_STATUS ExecuteScript(ScriptInterpreter *env)
{
	while (env->scriptExecutionStatus == SCRIPT_PENDING_EXECUTION)
	{
		if (env->executedByteCount >= env->script.scriptSize)
			break;
		printf("executedByteCount : %d\nexecutedOpcodes : %d\n", env->executedByteCount, env->executedOpcodeCount);
		printf("executing Opcode : %s\n", SCRIPT_GetOpcodeName(env->script.bytes[env->executedByteCount]));
		SCRIPT_ExecuteOpcode(env);
		PrintStacks(&env->mainStack, &env->altStack);
		printf("\n\n");
	}
	ValidateScript(env);
	return env->scriptExecutionStatus;
}
