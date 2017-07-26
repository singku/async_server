// C89
#include <stdlib.h>
#include <string.h>
// POSIX
#include <arpa/inet.h>
#include <sys/mman.h>

#include <libtaomee/log.h>
#include <libtaomee/conf_parser/config.h>

// Self-define
#include "bindconf.h"

// global varibles for bindconf.c
bind_config_t bindconf;

enum {
	bind_conf_max_field_num	= 4
};

/**
 * load_bind_file - parse bind config file @file_name
 * 
 * return: 0 on success, otherwise -1
 */
int load_bind_file(const char* file_name)
{
	int		ret_code = -1;
	char*	buf;

	if ( mmap_config_file(file_name, &buf) > 0 ) {
		char* start = buf;
		char* end;
		char* field[bind_conf_max_field_num];
		bind_config_elem_t* bc;

		size_t len = strlen(buf);
		while (buf + len > start) {
			end = strchr(start, '\n');
			if ( end && *end ) {
				*end = '\0';
			}
			if ( (*start != '#') && (str_split(0, start, field, bind_conf_max_field_num) == bind_conf_max_field_num) ) {
				bc = &(bindconf.configs[bindconf.bind_num]);
				// Online
				bc->online_id = atoi(field[0]); // online id
				strncpy(bc->online_name, field[1], sizeof(bc->online_name) - 1); // online name
				strncpy(bc->bind_ip, field[2], sizeof(bc->bind_ip) - 1); // online ip
				bc->bind_port = atoi(field[3]); // online port
				// increase bind_num
				++(bindconf.bind_num);
			}
			start = end + 1;

			if (bindconf.bind_num > max_listen_fds) {
				goto exit_entry;
			}
		}

		munmap(buf, len);
		ret_code = 0;
	}

exit_entry:
	BOOT_LOG(ret_code, "load bind file:%s", file_name);
}
const char * getstring_by_index(lua_State* L , int index   )
{
    static char buf[4096];
    memset(buf,0,sizeof(buf) );

    lua_pushinteger(L, index);
    lua_gettable(L, -2);

    strncpy(buf ,luaL_checkstring(L, -1),sizeof(buf)-1  );
    lua_pop(L, 1);
    return buf;
}

double getnumber_by_index(lua_State* L , int index   )
{
     double ret;

    lua_pushinteger(L, index);
    lua_gettable(L, -2);

    ret=luaL_checknumber(L, -1);
    lua_pop(L, 1);
    return ret;
}

int load_bind_from_lua(lua_State * L )
{
	int ret_code=-1; 

	bind_config_elem_t* bc;
    lua_getglobal(L,"async_server_bind_map");
    //bind_map
    lua_pushnil(L);
    while (lua_next(L, -2)) {
        const char * p=NULL;
        //int v;
		bc = &(bindconf.configs[bindconf.bind_num]);
        bc->online_id=getnumber_by_index(L,1 );

        p=getstring_by_index(L,2 );
		strncpy(bc->online_name, p, sizeof(bc->online_name) - 1); // online name

        p=getstring_by_index(L,3 );
		strncpy(bc->bind_ip, p, sizeof(bc->bind_ip) - 1); // online ip

        bc->bind_port=getnumber_by_index(L,4 );

		++(bindconf.bind_num);
		if (bindconf.bind_num > max_listen_fds) {
			goto exit_entry;
		}

        lua_pop(L, 1);
    }
    //去掉 - async_server_bind_map
    lua_pop(L, 1);

	ret_code=0;


exit_entry:
	BOOT_LOG(ret_code, "load bind info from lua " );
}
