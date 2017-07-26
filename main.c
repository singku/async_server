#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <signal.h>
#include <libtaomee/log.h>
#include <libtaomee/conf_parser/config.h>
#include <libtaomee/timer.h>

#include "bindconf.h"
#include "daemon.h"
#include "dll.h"
#include "net.h"
#include "service.h"
#include "util.h"
#include "mcast.h"

static const char version[] = "1.6.4.1";

char* prog_name;
char* current_dir;
uint32_t g_child_restart_cnt_limit = 20;

void show_banner()
{
	char feature[256];
	int pos = 0;
	
#ifdef DEBUG	
	pos = sprintf (feature + pos, "-DDEBUG -g ");
#endif
	pos = sprintf (feature + pos, "-DEPOLL_MODE ");

#ifdef USE_TLOG
	BOOT_TLOG("Async Server v%s (C) 2007-2012 TAOMEE.COM", version);
	BOOT_TLOG("Compiled at %s %s, flag: %s", __DATE__, __TIME__, pos ? feature : "");
#else
	printf("Async Server v%s (C) 2007-2012 TAOMEE.COM", version);
	printf("Compiled at %s %s, flag: %s\n", __DATE__, __TIME__, pos ? feature : "");
#endif
}

static inline int
show_usage()
{
#ifdef USE_TLOG
	RT_BOOT_TLOG(-1, "Usage: %s conf", prog_name);
#else
	BOOT_LOG(-1, "Usage: %s conf", prog_name);
#endif
	exit(-1);
}

static inline void
parse_args(int argc, char** argv)
{
	prog_name    = strdup(argv[0]);
	current_dir  = get_current_dir_name();
	show_banner();
	if ( (argc < 2) || !strcmp(argv[1], "--help") || !strcmp(argv[1], "-h") ) {
		show_usage();
	}
}

#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
const char * get_ip (const int ip_type )
{
    #define MAXINTERFACES 16
    register int fd, intrface;
    struct ifreq buf[MAXINTERFACES];
    struct ifconf ifc;
    char * tmp_ip;
    int tmp_type;
    if ((fd = socket (AF_INET, SOCK_DGRAM, 0)) >= 0){
        ifc.ifc_len = sizeof buf;
        ifc.ifc_buf = (caddr_t) buf;
        if (!ioctl (fd, SIOCGIFCONF, (char *) &ifc)){
            intrface = ifc.ifc_len / sizeof (struct ifreq);
            while (intrface-- > 0){
                if (!(ioctl (fd, SIOCGIFADDR, (char *) &buf[intrface]))) {
                    tmp_ip=(char*) inet_ntoa(
                            ((struct sockaddr_in *) ( &( buf[intrface].ifr_addr)))-> sin_addr);
                    if (strncmp(tmp_ip,"192.168",7)==0){
                        tmp_type=0x01;
                    }else if (strncmp(tmp_ip,"10.",3)==0 ){
                        tmp_type=0x01;
                    }else if (strncmp(tmp_ip,"127.",4)==0 ){
                        tmp_type=0x04;
                    }else{//外网
                        tmp_type=0x02;
                    }
                    if ((ip_type & tmp_type)==tmp_type) {
                        close (fd);
                        return tmp_ip;
                    }
                }
            }
        }
    }
    close (fd);
    return "";
}

//得到ip
static int luaT_get_ip(  lua_State* L)
{
    int ip_type=luaL_checkinteger(L,1 );
	const char *ip=  get_ip(ip_type);
    lua_pushstring(L,ip  );
    return 1;
}
char g_progame_name[256];

static int luaT_get_program_name(  lua_State* L)
{
    lua_pushstring(L, g_progame_name );
    return 1;
}
#define REG_LUA_FUNCTION(func_name, p_cfunction) \
    do{\
    lua_pushcfunction(L,p_cfunction );\
    lua_setglobal(L, func_name  );\
    }while(0)

static void out_put_config(lua_State * L )
{
	DEBUG_LOG("--lua config--" );
    lua_pushnil(L);
    while (lua_next(L, LUA_GLOBALSINDEX )) {
        if (lua_type(L, -1) ==LUA_TSTRING || lua_type(L, -1) ==LUA_TNUMBER ){

            const char * p_k=luaL_checkstring(L, -2);
            if ( strcmp(p_k,"_VERSION") ){
                DEBUG_LOG("\t%s\t= %s ",
                        luaL_checkstring(L, -2),
                        luaL_checkstring(L, -1)
                      );
            }
        }
        lua_pop(L, 1);
    }
    DEBUG_LOG("" );

    DEBUG_LOG("=== async_server bind conf ==" );
    lua_getglobal(L,"async_server_bind_map");
	if (! lua_istable(L,-1 )   )  {
    	DEBUG_LOG("=== not find  table: async_server_bind_map   ==" );
		return;
	}

    //bind_map
    lua_pushnil(L);
    while (lua_next(L, -2)) {
        int id,port;
		char servername[255];
		char ip[255];

        id=getnumber_by_index(L,1 );
        strncpy(servername ,getstring_by_index(L,2 ),sizeof(servername)-1 );
		servername[sizeof(servername)-1 ]='\0';

        strncpy(ip ,getstring_by_index(L,3 ),sizeof(ip)-1 );
		ip[sizeof(ip)-1 ]='\0';

        port=getnumber_by_index(L,4 );
        DEBUG_LOG("\t%d  %s  %s  %d",id, servername,ip,port  );

        lua_pop(L, 1);
    }
    //去掉 - async_serve
    lua_pop(L, 1);

}

int main(int argc, char* argv[])
{
 	strncpy(g_progame_name,argv[0],sizeof(g_progame_name)-1  );
	g_progame_name[sizeof(g_progame_name)-1]='\0';

	parse_args(argc, argv);
	char *p_conf_file=argv[1];
	int use_lua_config=0;
	lua_State * L=NULL;

	if (strlen( p_conf_file )>4  )	{
		if(!strcmp(p_conf_file+(strlen(p_conf_file)-4),".lua" ) ){
 			use_lua_config=1;
			L=set_config_use_lua( 1);
			//注册函数
			REG_LUA_FUNCTION("get_ip" , luaT_get_ip );
			REG_LUA_FUNCTION("get_program_name" , luaT_get_program_name );
		}
	}

	if (config_init(p_conf_file ) == -1) {
		BOOT_LOG(-1, "Failed to Parse File '%s'", argv[1]);
	}

	daemon_start(argc, argv);
	renew_now();

	// load bind config file
	if ( use_lua_config && config_get_strval("bind_conf")==NULL ){
		load_bind_from_lua( L );
	}else{
		load_bind_file(config_get_strval("bind_conf"));
	}

#ifdef USE_TLOG
    //init tlog
    INIT_DEFAULT_LOGGER_SYSTEM( config_get_strval("log_dir"),
                                "0",
                                config_get_strval("project_name"),
                                config_get_intval("project_id", 0),
                                config_get_strval("svc_type")
                                );
    int log_time_interval = config_get_intval("tlog_file_interval_sec", 900);
    if (log_time_interval < 0 || log_time_interval > 86400) {
        log_time_interval = 900;
    }
    SET_MAX_ONE_SIZE(100);
    SET_TIME_SLICE_SECS(log_time_interval);
	SET_LOG_LEVEL(config_get_intval("log_level", tlog_lvl_debug));
#endif

	// init log files
	log_init_ex( config_get_strval("log_dir"), 
				config_get_intval("log_level", log_lvl_trace),
				config_get_intval("log_size", 1<<30), 
				config_get_intval("max_log_files", 100), 
				config_get_strval("log_prefix") ,
				config_get_intval("log_save_next_file_interval_min", 0) );

	socket_timeout = config_get_intval("cli_socket_timeout", 0);
	page_size      = config_get_intval("incoming_packet_max_size", -1);
	g_send_buf_limit_size = config_get_intval("send_buf_limit_size", 0);
	if (page_size <= 0) {
		page_size = def_page_size;
	}

	//输出配置文件信息
	if(use_lua_config ){
		out_put_config(L);
	}	

	g_child_restart_cnt_limit = config_get_intval("child_restart_limit", 20);
    
    asynsvr_init_warning_system();
#if 0
    //add start by singku 2011-11-04 for tm_dirty_daemon
    //如果使用脏词检测逻辑，则开启父进程的脏词更新逻辑.
    if (config_get_intval("tm_dirty_use_dirty_logical", 1) == 1) {
        if (tm_dirty_daemon( config_get_strval("tm_dirty_local_dirty_file_path"),
                    config_get_strval("tm_dirty_server_addr"),
                    config_get_intval("tm_dirty_update_cycle", 600),
                    asynsvr_send_warning) == -1) {
            BOOT_LOG(-1, "FAILED TO RUN TM_DIRTY_DAEMON");
        }   
    }
    //add end
#endif
	register_data_plugin(config_get_strval("data_dll_file"));
	register_plugin(config_get_strval("dll_file"), 0);

	net_init(max_fd_num, max_fd_num);
	if (dll.init_service && (dll.init_service(1) != 0)) {
		BOOT_LOG(-1, "FAILED TO INIT PARENT PROCESS");
	}

    clean_child_pids();

	bind_config_t* bc = get_bind_conf();
	int   i;
	pid_t pid;
	for ( i = 0; i != bc->bind_num; ++i ) {
		bind_config_elem_t* bc_elem = &(bc->configs[i]);
		shmq_create(bc_elem);

		if ( (pid = fork ()) < 0 ) {
			BOOT_LOG(-1, "fork child process");
		} else if (pid > 0) { //parent process
			close_shmq_pipe(bc, i, 0);
			do_add_conn(bc_elem->sendq.pipe_handles[0], fd_type_pipe, 0, bc_elem);
			net_start(bc_elem->bind_ip, bc_elem->bind_port, bc_elem);
            atomic_set(&child_pids[i], pid);
		} else { //child process
			g_listen_port = bc_elem->bind_port;
			strncpy(g_listen_ip, bc_elem->bind_ip, sizeof(g_listen_ip) - 1);
			run_worker_process(bc, i, i + 1);
		}
	}

	if (config_get_strval("addr_mcast_ip")) {
		if (create_addr_mcast_socket() != 0) {
			// return -1 if fail to create mcast socket
			BOOT_LOG(-1, "PARENT: FAILED TO CREATE MCAST FOR RELOADING SO");
		}
	} 
    static int stop_count = 0;
	while (1) {
        if (unlikely(stop == 1 && term_signal == 1 && stop_count++ == 0))
            DEBUG_LOG("SIG_TERM from pid=%d", getpid());
        if (unlikely(stop == 1 && dll.fini_service && (dll.fini_service(1) == 0)))
            break;

        net_loop(-1, page_size, 1);
	}

    killall_children();

	net_exit();
	unregister_data_plugin();
	unregister_plugin();
	shmq_destroy(0, bc->bind_num);
	daemon_stop();

	return 0;
}
