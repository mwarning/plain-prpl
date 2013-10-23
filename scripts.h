
#ifndef _SCRIPTS_H_
#define _SCRIPTS_H_

#include "account.h"
#include "connection.h"

typedef void CB(const char *line, PurpleConnection *gc, PurpleBuddy *buddy);

int exec_process(
	const char *cmd,
	const char *cmd_arg,
	CB *callback,
	PurpleConnection *gc,
	PurpleBuddy *buddy
);

#endif /* _SCRIPTS_H_ */
