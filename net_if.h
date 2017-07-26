/**
 *============================================================
 *  @file        net_if.h
 *  @brief      Essential net interface to deal with network
 * 
 *  compiler   gcc4.1.2
 *  platform   Linux
 *
 *  copyright:  TaoMee, Inc. ShangHai CN. All rights reserved.
 *
 *============================================================
 */

#ifndef ASYNC_SERVER_NET_INTERFACE_H_
#define ASYNC_SERVER_NET_INTERFACE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "service.h"

/**
  * @brief hold an ip and a port
  */
typedef struct ip_port {
	/*! ip */
	char		ip[16];
	/*! port */
	in_addr_t	port;
} ip_port_t;

/**
  * @brief Connect to a given server.
  *
  * @param const char* ipaddr,  ip address of the server to connect to.
  * @param in_addr_t port,  port of the server to connect to.
  * @param int bufsz,  size of the buffer to hold the sending data.
  * @param int timeout, interrupt the connecting attempt after timeout secs.
  *
  * @return int, the connected socket fd, -1 on error.
  */
int connect_to_svr(const char* ipaddr, in_addr_t port, int bufsz, int timeout);

/**
  * @brief Connect to a given server whose name is 'service_name'.
  *
  * @param service_name name of the server to connect to.
  * @param svr_id id of the 'service_name' to connect to. If svr_id is assigned with 0, then a random server id is generated.
  * @param int bufsz,  size of the buffer to hold the sending data.
  * @param int timeout, interrupt the connecting attempt after timeout secs.
  *
  * @return int, the connected socket fd, -1 on error.
  */
int connect_to_service(const char* service_name, uint32_t svr_id, int bufsz, int timeout);

/**
  * @brief 异步连接到指定服务器
  *
  * @param ipaddr 服务器IP
  * @param port 服务器端口
  * @param bufsz 发送缓冲区大小（字节）
  * @param callback 回调函数。该回调函数的第一个参数fd由AsyncServer框架本身传递给用户提供的callback函数，fd不等于-1则表示连接成功；
  *                 第二个参数arg由用户提供和维护，用于保存一些标识信息，当callback被调用时，可以根据arg里面的内容执行正确的逻辑。\n
  *                 注意：当fd不等于-1，但是根据arg发现该fd连接已经不符合逻辑，用户需要调用close_svr来关闭该fd。
  * @param arg 由用户提供和维护，用于保存一些标识信息，当callback被调用时，可以根据arg里面的内容执行正确的逻辑
  *
  * @return 成功返回0，失败返回-1。\n
  *         注意：返回-1的话，不会调用callback，用户此时需要释放arg（假设arg是动态分配的话）；
  *         返回0的话，无论最终连接建立成功与否，都会调用callback，用户可以在callback中释放arg（假设arg是动态分配的话）。\n
  *         本函数内部不会调用callback。
  */
int asyn_connect_to_svr(const char* ipaddr, in_addr_t port, int bufsz, void (*callback)(int fd, void* arg), void* arg);

/**
  * @brief 异步连接到名字为'service_name'的服务器
  *
  * @param service_name 服务器名称
  * @param svr_id 'service_name'服务器的ID。如果svr_id为0，则随机连接一个可用的服务器
  * @param bufsz 发送缓冲区大小（字节）
  * @param callback 回调函数。该回调函数的第一个参数fd由AsyncServer框架本身传递给用户提供的callback函数，fd不等于-1则表示连接成功；
  *                 第二个参数arg由用户提供和维护，用于保存一些标识信息，当callback被调用时，可以根据arg里面的内容执行正确的逻辑。\n
  *                 注意：当fd不等于-1，但是根据arg发现该fd连接已经不符合逻辑，用户需要调用close_svr来关闭该fd。
  * @param arg 由用户提供和维护，用于保存一些标识信息，当callback被调用时，可以根据arg里面的内容执行正确的逻辑
  *
  * @return 成功返回0，失败返回-1\n
  *         注意：返回-1的话，不会调用callback，用户此时需要释放arg（假设arg是动态分配的话）；
  *         返回0的话，无论最终连接建立成功与否，都会调用callback，用户可以在callback中释放arg（假设arg是动态分配的话）\n
  *         本函数内部不会调用callback。
  */
int asyn_connect_to_service(const char* service_name, uint32_t svr_id, int bufsz, void (*callback)(int fd, void* arg), void* arg);

/**
  * @brief 主动关闭和服务端（Switch、DBproxy等）的连接。不会调用on_fd_closed。
  * @param svrfd connect_to_svr/connect_to_service返回的fd
  * @see connect_to_svr, connect_to_service
  */
void close_svr(int svrfd);

/**
  * @brief Create a udp socket to the given server.
  *
  * @param struct sockaddr_in* addr,  it will be initialized base on the given ip and port.
  * @param const char* ip,  ip address of the server.
  * @param in_port_t port,  port of the server.
  *
  * @return int, the created udp socket fd, -1 on error.
  */
int create_udp_socket(struct sockaddr_in* addr, const char* ip, in_port_t port);

/**
 * @brief 用于发送报警短信。使用前必须先正确配置好bench.conf的相关选项（warning_ip、warning_port、project_name、phone_numbers），
 *        具体配置方法请参考http://dev.taomee.com/index.php/AsyncServer#bench.conf。
 * @param svr 服务名。比如：online、switch、btlsvr。
 * @param uid 出错的米米号。如果是DBproxy返回出错，那通过这个可以判断是哪一台DBserv出了问题。
 * @param cmdid 出错的协议命令号
 * @param ishex 协议命令号是否使用十六进制显示。0表示十进制显示，1表示十六进制显示。
 * @param ip 出错的IP。比如dbproxy的IP、btlsvr的IP等等。
 */
void asynsvr_send_warning_msg(const char* svr, uint32_t uid, uint32_t cmdid, uint32_t ishex, const char* ip);

/**
  * @brief resolve ip of a given service name and service id
  *
  * @param service_name name of the server ip to resolve
  * @param svr_id id of the 'service_name' to resolve
  *
  * @return the resolved ip or 0
  */
const char* resolve_service_name(const char* service_name, uint32_t svr_id);

/**
  * @brief get ip and port of the service that was most lately try connecting to
  *
  * @return the pointer to ip_port_t or 0
  */
const ip_port_t* get_last_connecting_service();

/**
  * @brief get ip address of a remote server connection
  * @param fd fd of connection to the remote server
  * @return ip address of a client
  */
static inline
uint32_t get_remote_ip(int fd)
{
	if ((fd >= 0) && (fd <= epi.maxfd) && (epi.fds[fd].type != fd_type_unused)) {
		return epi.fds[fd].sk.remote_ip;
	}

	return 0;
}

/**
  * @brief Send data to the given tcp socket fd
  *
  * @param int fd,  socket fd to send data to.
  * @param const void* data,  data to be sent to the given fd.
  * @param uint32_t len,  length of the data to be sent.
  *
  * @return int, 0 on sucess, -1 on failure.
  */
int net_send(int fd, const void* data, uint32_t len);

/**
  * @brief Send a package to a client. For child process only.
  *
  * @param fdsess  fd session of the client to whom the package will be sent.
  * @param pkg  package to be sent.
  * @param pkglen  length of the package to be sent.
  *
  * @return 0 on success, -1 on failure
  */
int send_pkg_to_client(const fdsession_t* fdsess, const void* pkg, const int pkglen);

/**
  * @brief Close a client connection. For child process only. \n
  *           This function will firstly call on_client_conn_closed implemented by the .so lib,
  *           then it'll send a connection-close-request to the parent process.
  *
  * @param fd client socket fd to be closed
  */
void close_client_conn(int fd);

#ifdef __cplusplus
} // end of extern "C"
#endif

#endif // ASYNC_SERVER_NET_INTERFACE_H_

