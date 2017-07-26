#ifndef ASYNC_SERVER_DAEMON_H_
#define ASYNC_SERVER_DAEMON_H_

#ifdef __cplusplus
extern "C" {
#endif

// headers since C89
#include <stdlib.h>
// from libtaomee
#include <libtaomee/atomic.h>

#include "bindconf.h"

extern int max_fd_num;

volatile extern int stop;
volatile extern int restart;
volatile extern int term_signal;

extern char*	prog_name;
extern char*	current_dir;
extern char**	saved_argv;

int  daemon_start(int argc, char** argv);
void daemon_stop(void);
void daemon_set_title(const char* fmt, ...);

static inline void
free_argv(void)
{
	char** argv;
	for ( argv = saved_argv; *argv; ++argv ) {
		free(*argv);
	}
	free(saved_argv);
	saved_argv = NULL;
}

void clean_child_pids();
void killall_children();

extern atomic_t child_pids[max_listen_fds];

#ifdef __cplusplus
}
#endif

#endif // ASYNC_SERVER_DAEMON_H_
