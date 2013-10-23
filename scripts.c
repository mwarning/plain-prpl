
#include <string.h>
#include <fcntl.h>

#include "scripts.h"


typedef struct {
	FILE *pipe;
	CB *callback;
	PurpleConnection *gc;
	PurpleBuddy *buddy;
	const char *cmd;
} job_t;

int exec_process_cb(job_t *job)
{
	char buffer[1024];
	FILE *pipe;

	buffer[0] = '\0';
	pipe = job->pipe;

	if(pipe != NULL && !feof(pipe)) {
		fgets(buffer, sizeof(buffer), pipe);

		if(buffer[0] != '\0') {
			if(job->callback) {
				job->callback(buffer, job->gc, job->buddy);
			}
			/* call this function again later */
			return TRUE;
		}
	}

	pclose(pipe);
	g_free(job);

	/* Stop this job */
	return FALSE;
}

int exec_process(const char *cmd, const char *cmd_arg, CB *callback, PurpleConnection *gc, PurpleBuddy *buddy)
{
	FILE *pipe;
	char cmdline[1024];

	if(cmd == NULL || strlen(cmd) == 0) {
		return 1;
	}

	if(snprintf(cmdline, sizeof(cmdline), cmd, cmd_arg) >= sizeof(cmdline)) {
		fprintf(stderr, "Plainprpl: Command for %s got to big.\n", cmd);
		return 1;
	}

	pipe = popen(cmdline, "r");
	if(pipe == NULL) {
		fprintf(stderr,"Plainprpl: Can't execute %s\n", cmdline);
		return 1;
	}

#ifndef __WIN32__
	int fflags = fcntl(fileno(pipe), F_GETFL, 0);
	fcntl(fileno(pipe), F_SETFL, fflags | O_NONBLOCK);
#else
	//TODO implement FILE_FLAG_OVERLAPPED & FILE_FLAG_NO_BUFFERING for windows
#endif

	job_t *job = (job_t *) malloc(sizeof(job_t));
	job->pipe = pipe;
	job->callback = callback;
	job->gc = gc;
	job->buddy = buddy;
	job->cmd = strdup(cmdline);

	/* Call every 250 msecs until the callback returns FALSE */
	purple_timeout_add(250, (GSourceFunc) exec_process_cb, (gpointer) job);
	return 0;
}
