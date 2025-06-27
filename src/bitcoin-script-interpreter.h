#ifndef BITCOIN_SCRIPT_INTERPRETER_H
#define BITCOIN_SCRIPT_INTERPRETER_H

#include "bitcoin-script-internals.h"


typedef struct ScriptInterpreter
{
	SCRIPT_VERSION	version;
	SCRIPT_CHECK	flags;
	Script			script;
	SCRIPT_STATUS	scriptExecutionStatus;
	Stack			mainStack;
	Stack			altStack;

	U32				nLockTime;
	U32				nSequence;

	U32				sigopCount;
	U32				executedOpcodeCount;
	U32				stackItemPushedCount;
	U32				executedByteCount;
} ScriptInterpreter;

void InitInterpreter(ScriptInterpreter *env);
void InitScriptFromHRF(Script *script, const char *hrf);
void SetInterpreterScript(ScriptInterpreter *env, Script *script);
SCRIPT_STATUS ExecuteScript(ScriptInterpreter *env);
#endif
