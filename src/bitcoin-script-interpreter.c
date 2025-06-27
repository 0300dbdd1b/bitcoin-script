#include "bitcoin-script-interpreter.h"
#include <stdio.h>

void InitInterpreter(ScriptInterpreter *env)
{
	env->executedByteCount			= 0;
	env->executedOpcodeCount		= 0;
	env->scriptExecutionStatus		= SCRIPT_NOSTATUS;
	env->mainStack.stackSize		= 0;
	env->altStack.stackSize			= 0;
}

void SetInterpreterScript(ScriptInterpreter *env, Script *script)
{
	env->script = *script;
	env->scriptExecutionStatus = SCRIPT_PENDING_EXECUTION;
}

/* -------------------------- STACK --------------------------------- */
void StackPush(Stack *stack, StackElement element)
{
	if (stack->stackSize >= SCRIPT_MAX_STACK_SIZE)
	{
		printf("Error: Stack overflow\n");
		return;
	}
	stack->elements[stack->stackSize] = element;
	stack->stackSize++;
}

StackElement StackPop(Stack *stack)
{
	if (stack->stackSize == 0)
	{
		printf("Error: Stack underflow\n");
		StackElement empty = {0};
		return empty;
	}
	stack->stackSize--;
	return stack->elements[stack->stackSize];
}

void PrintStacks(Stack *mainStack, Stack *altStack) {
	printf("Size | Main Stack            | Size | Alt Stack\n");
	printf("-----|-----------------------|------|----------------------\n");
	size_t maxSize = mainStack->stackSize > altStack->stackSize ? mainStack->stackSize : altStack->stackSize;

	for (size_t i = 0; i < maxSize; i++)
	{
		if (i < mainStack->stackSize)
		{
			printf("%-4u | ", mainStack->elements[i].elementSize);
			for (size_t j = 0; j < mainStack->elements[i].elementSize; j++)
				printf("%02X", mainStack->elements[i].element[j]);
			for (size_t j = mainStack->elements[i].elementSize * 2; j <= 21; j++) // NOTE: Pad remaining space
				printf(" ");
		}
		else
			printf("     |                    ");

		printf("| %-4u | ", i < altStack->stackSize ? altStack->elements[i].elementSize : 0);
		if (i < altStack->stackSize)
		{
			for (size_t j = 0; j < altStack->elements[i].elementSize; j++)
				printf("%02X", altStack->elements[i].element[j]);
			for (size_t j = altStack->elements[i].elementSize * 2; j < 20; j++)
				printf(" ");
		}
		printf("\n");
	}
}

/* -------------------------- SCRIPT --------------------------------- */
void InitScript(Script *script, const char *rawScript)
{
	if (__is_hex__(rawScript))
	{
		strcpy(script->hex, rawScript);
		__hexstr_to_bytes(rawScript, script->bytes, SCRIPT_MAX_SCRIPT_SIZE, (unsigned long *)&script->scriptSize);
	}
}

void InitScriptFromHRF(Script *script, const char *hrf)
{
	script->scriptSize = 0;

	char buffer[2048];
	strncpy(buffer, hrf, sizeof(buffer));
	buffer[sizeof(buffer) - 1] = '\0';

	char *token = strtok(buffer, " ");
	while (token && script->scriptSize < SCRIPT_MAX_SCRIPT_SIZE)
	{
		SCRIPT_OPCODE opcode = SCRIPT_GetOpcode(token);
		if (opcode == OP_INVALIDOPCODE)
		{
			fprintf(stderr, "Unknown opcode: %s\n", token);
			return;
		}

		script->bytes[script->scriptSize++] = (U8)opcode;
		token = strtok(NULL, " ");
	}

	for (U32 i = 0; i < script->scriptSize; ++i)
	{
		sprintf(&script->hex[i * 2], "%02x", script->bytes[i]);
	}
	script->hex[script->scriptSize * 2] = '\0';
}

void PrintScript(Script *script)
{
	printf("script: %s\n", script->hex);
	printf("scriptSize: %u\n", script->scriptSize);

	printf("Bytes: ");
	for (size_t i = 0; i < script->scriptSize; i++)
	{
		printf("%02X", script->bytes[i]);
		if (i < script->scriptSize - 1)
			printf(" ");
	}
	printf("\n");
}

void ScriptToHRF(Script *script)
{
	(void) script;
}

void HRFToBytes(Script *script)
{
	(void) script;
}

