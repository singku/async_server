#ifndef ASYNC_SERVER_BIND_CONF_H_
#define ASYNC_SERVER_BIND_CONF_H_

#ifdef __cplusplus
extern "C" {
#endif

// POSIX
#include <netinet/in.h>
// Self-define
#include "shmq.h"
#include "libtaomee/lua/lua.h"

enum {
	max_listen_fds	= 500
};

typedef struct bind_config_elem {
	uint32_t	online_id;
	char		online_name[16];
	char		bind_ip[16];
	in_port_t	bind_port;
	uint8_t		restart_cnt;
	shm_queue_t	sendq;
	shm_queue_t	recvq;
} bind_config_elem_t;

typedef struct bind_config {
	int					bind_num;
	bind_config_elem_t	configs[max_listen_fds];
} bind_config_t;

extern bind_config_t bindconf;

int load_bind_file(const char* file_name);

static inline bind_config_t*
get_bind_conf()
{
	return &bindconf;
}

static inline int
get_bind_conf_idx(const bind_config_elem_t* bc_elem)
{
	return (bc_elem - &(bindconf.configs[0]));
}

int load_bind_from_lua(lua_State * L );
double getnumber_by_index(lua_State* L , int index   );
const char * getstring_by_index(lua_State* L , int index   );

#ifdef __cplusplus
}
#endif

#endif // ASYNC_SERVER_BIND_CONF_H_
