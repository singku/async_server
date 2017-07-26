/**
 *============================================================
 *  @file        dll.h
 *  @brief      Define the interfaces that a .so must implement to make use of AsyncServ
 * 
 *  compiler   gcc4.1.2
 *  platform   Linux
 *
 *  copyright:  TaoMee, Inc. ShangHai CN. All rights reserved.
 *
 *============================================================
 */

#ifndef ASYNC_SERVER_DLL_H_
#define ASYNC_SERVER_DLL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

#include "service.h"

/**
 * @struct AsyncServInterface
 * @brief To make use of AsyncServ, a .so must implement the interfaces held by this structure
 *
 */
typedef struct AsyncServInterface {
	void*   data_handle; // Hold the handle returned by dlopen
	void*   handle; // Hold the handle returned by dlopen

	/* The following 5 interfaces are called only by the child process */

	/*!
	  * Called each time before processing packages from clients. Optional interface.
	  * Calling interval of this interface is no much longer than 100ms at maximum.
	  */
	void	(*proc_events)();
	/*!
	  * Called to process packages from clients. Called once for each package. \n
	  * Return non-zero if you want to close the client connection from which the `pkg` is sent,
	  * otherwise returns 0. If non-zero is returned, `on_client_conn_closed` will be called too.
	  */
	int		(*proc_pkg_from_client)(void* pkg, int pkglen, const fdsession_t* fdsess);
	/*! Called to process packages from servers that the child connects to. Called once for each package. */
	void	(*proc_pkg_from_serv)(int fd, void* pkg, int pkglen);
	/*! Called to process multicast packages from the specified `mcast_ip` and `mcast_port`. Called once for each package. */
	void	(*proc_mcast_pkg)(const void* data, int len);
	/*! Called each time when a client close a connection, or when `proc_pkg_from_client` returns -1. */
	void	(*on_client_conn_closed)(int fd);
	/*! Called each time on close of the FDs opened by the child. */
	void	(*on_fd_closed)(int fd);

	/* The following 3 interfaces are called both by the parent and child process */

	/*!
	  * Called only once at server startup by both the parent and child process. Optional interface.\n
	  * `isparent == 1` indicates this interface is called by the parent;
	  * `isparent == 0` indicates this interface is called by the child. \n
	  * You should initialize your service program (allocate memory, create objects, etc) here. \n
	  * You must return 0 on success, -1 otherwise.
	  */
	int 	(*init_service)(int isparent);
	/*!
	  * Called only once at server stop by both the parent and child process. Optional interface.\n
	  * `isparent == 1` indicates this interface is called by the parent;
	  * `isparent == 0` indicates this interface is called by the child. \n
	  * You should finalize your service program (release memory, destroy objects, etc) here. \n
	  * You must return 0 if you have finished finalizing the service, -1 otherwise.
	  */
	int 	(*fini_service)(int isparent);
	/*!
	  * This interface will be called both by the parent and child process.\n
	  * `isparent == 1` indicates this interface is called by the parent;
	  * `isparent == 0` indicates this interface is called by the child. \n
	  * You must return 0 if you cannot yet determine the length of the incoming package,
	  * return -1 if you find that the incoming package is invalid and AsyncServ will close the connection,
	  * otherwise, return the length of the incoming package. Note, the package should be no larger than 8192 bytes.
	  */
	int		(*get_pkg_len)(int fd, const void* avail_data, int avail_len, int isparent);

	int		(*proc_udp_pkg)(int fd, const void* avail_data, int avail_len ,struct sockaddr_in * from, socklen_t fromlen );
	/*!
	 * 为了实现不影响用户在线的更新程序，AsyncServ框架会加载两个so，一个用于保存代码（text.so），一个用于保存全局变量（data.so）。\n
	 * 这个接口用于在子进程重读text.so后，对data.so进行一些必要的重新初始化（如重新调整定时器）。\n
	 * `return 0`表示data.so重新初始化成功；`return -1`表示重新初始化失败，子进程退出运行。
	 */
	int		(*reload_global_data)();
    /*!
        * This interface is used to sync a server's name, ip, and port to business login.\n
        * arg 'svr_id': server id \n
        * arg 'svr_name': '\0' terminated, max length 16 ('\0' included) \n
        * arg 'svr_ip': '\0' terminated, max length 16 ('\0' included) \n
        * arg 'port': port \n
        * arg 'flag': 0 - delete, 1 - add
        */
    void	(*sync_service_info)(uint32_t svr_id, const char* svr_name, const char* svr_ip, in_port_t port, int flag);

	/*!
	 * 为了实现不影响用户在线的更新程序，AsyncServ框架会加载两个so，一个用于保存代码（text.so），一个用于保存全局变量（data.so）。\n
	 * 这个接口用于在重读text.so之前，对全局变量进行一些必要的销毁。\n
	 * 无论父进程还是子进程，都会调用这个函数，所以实现这个函数时，需要根据参数isparent（0表示子进程，1表示父进程）来执行不同的代码。
	 * 建议父进程如果无需特殊处理的话，直接return 0。
	 * `return 0`表示销毁成功；`return -1`表示销毁失败，子进程退出运行。
	 */
	int		(*before_reload)(int isparent);

	/*!
	  * placeholder
	  */
	void	(*placeholder[9])(void);
} async_serv_if_t;

extern async_serv_if_t dll;

/**
  * @brief get id of the server
  * @return id that is specified at the first column of 'bind.conf'
  */
static inline uint32_t get_server_id()
{
	return config_cache.bc_elem->online_id;
}

/**
  * @brief get name of the server
  * @return name that is specified at the second column of 'bind.conf'
  */
static inline const char* get_server_name()
{
	return config_cache.bc_elem->online_name;
}

/**
  * @brief get binding ip of the server
  * @return binding ip of the server
  */
static inline const char* get_server_ip()
{
	return config_cache.bc_elem->bind_ip;
}

/**
  * @brief get binding port of the server
  * @return binding port of the server
  */
static inline in_port_t get_server_port()
{
	return config_cache.bc_elem->bind_port;
}

/**
  * @brief get ip address of a client connection
  * @param fdsess
  * @return ip address of a client
  */
static inline uint32_t
get_cli_ip(const fdsession_t* fdsess)
{
	return fdsess->remote_ip;
}

/**
  * @brief get port of a client connection
  * @param fdsess
  * @return port of a client
  */
static inline uint32_t
get_cli_port(const fdsession_t* fdsess)
{
	return fdsess->remote_port;
}

static inline uint32_t
get_cli_ip2(int fd)
{
	fdsession_t* fdsess = (fdsession_t*)g_hash_table_lookup(fds.cn, &fd);
	return (fdsess ? fdsess->remote_ip : 0);
}

int  register_data_plugin(const char* file_name);
int  register_plugin(const char* file_name, int flag);
void unregister_data_plugin();
void unregister_plugin();

#ifdef __cplusplus
} // end of extern "C"
#endif

#endif // ASYNC_SERVER_DLL_H_
