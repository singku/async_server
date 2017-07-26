#include <stdio.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>

#include <libtaomee/log.h>
#include <libtaomee/conf_parser/config.h>
#include <libtaomee/project/types.h>

#include "net_if.h"
#include "util.h"

#pragma pack(1)

typedef struct {
	/* package length */
	uint32_t	len;
	/* sequence number ((p->fd << 16) | p->waitcmd) */
	uint32_t	seq;
	/* command id */
	uint16_t	cmd;
	/* errno */
	uint32_t	ret;
	/* user id */
	userid_t	id;

	char		svr[120];
	userid_t	uid;
	uint32_t	cmdid;
	uint32_t	hex;
	char		ip[16];
	uint32_t	burst_limit;
	uint32_t	warning_interval;
	char		phone_numbers[256];
} warning_pkg_t ;

#pragma pack()

static int warning_fd = -1;
static struct sockaddr_in warning_sockaddr;

static const char* prj_name;
static const char* phone_nums;

//------------------------------

int pipe_create(int pipe_handles[2])
{
	if (pipe (pipe_handles) == -1)
		return -1;

    int rflag, wflag;
    if (config_get_intval("set_pipe_noatime", 0) == 1) {
        rflag = O_NONBLOCK | O_RDONLY | O_NOATIME;
        wflag = O_NONBLOCK | O_WRONLY | O_NOATIME;
    } else {
        rflag = O_NONBLOCK | O_RDONLY;
        wflag = O_NONBLOCK | O_WRONLY;
    }

	fcntl (pipe_handles[0], F_SETFL, rflag);
	fcntl (pipe_handles[1], F_SETFL, wflag);

	fcntl (pipe_handles[0], F_SETFD, FD_CLOEXEC);
	fcntl (pipe_handles[1], F_SETFD, FD_CLOEXEC);

	return 0;
}

int log_init_ex(const char* dir, log_lvl_t lvl, uint32_t size, int maxfiles, const char* pre_name, uint32_t logtime)
{
	int ret;

	if (logtime == 0) {
		ret = log_init(dir, lvl, size, maxfiles, pre_name);
	} else {
		ret = log_init_t(dir, lvl, pre_name, logtime);
	}

	BOOT_LOG(ret, "Set log dir %s, per file size %g MB", dir, size / 1024.0 / 1024.0);
}

//-----------------------------------
void asynsvr_init_warning_system()
{
	if (config_get_strval("warning_ip") == 0) {
		return;
	}

	warning_fd = create_udp_socket(&warning_sockaddr, config_get_strval("warning_ip"),
									config_get_intval("warning_port", 0));

	if (warning_fd == -1) {
		WARN_LOG("failed to init warning sys: ip=%s port=%d", config_get_strval("warning_ip"),
					config_get_intval("warning_port", 0));
	}

	prj_name   = config_get_strval("project_name");
	if (prj_name == 0) {
		prj_name = "unspecified";
		WARN_LOG("project name unspecified!");
	}

	phone_nums = config_get_strval("phone_numbers");
	if (phone_nums == 0) {
		phone_nums = "13761071357";
		WARN_LOG("no phone numbers inputted!");
	}
}

void asynsvr_send_warning(const char* svr, uint32_t svr_id, const char* ip)
{
	if (warning_fd == -1) {
		return;
	}

	warning_pkg_t pkg;

	if (ip == 0) {
		ip = "";
	}

	pkg.len              = sizeof(pkg);
	pkg.seq              = 0;
	pkg.cmd              = 0xF101;
	pkg.ret              = 0;
	pkg.id               = 0;

	snprintf(pkg.svr, sizeof(pkg.svr), "%s.%s", prj_name, svr);
	pkg.uid              = svr_id;
	pkg.cmdid            = 0;
	pkg.hex              = 0;
	strncpy(pkg.ip, ip, sizeof(pkg.ip));
	pkg.burst_limit      = 1;
	pkg.warning_interval = 5 * 60;
	strncpy(pkg.phone_numbers, phone_nums, sizeof(pkg.phone_numbers));

	sendto(warning_fd, &pkg, sizeof(pkg), 0, (void*)&warning_sockaddr, sizeof(warning_sockaddr));

	DEBUG_LOG("SEND WARNING\t[svr=%s ip=%s]", svr, ip);
}

void asynsvr_send_warning_msg(const char* svr, uint32_t uid, uint32_t cmdid, uint32_t ishex, const char* ip)
{
	if (warning_fd == -1) {
		return;
	}

	warning_pkg_t pkg;

	if (ip == 0) {
		ip = "";
	}

	pkg.len              = sizeof(pkg);
	pkg.seq              = 0;
	pkg.cmd              = 0xF101;
	pkg.ret              = 0;
	pkg.id               = uid;

	snprintf(pkg.svr, sizeof(pkg.svr), "%s.%s", prj_name, svr);
	pkg.uid              = uid;
	pkg.cmdid            = cmdid;
	pkg.hex              = ishex;
	strncpy(pkg.ip, ip, sizeof(pkg.ip));
	pkg.burst_limit      = 10;
	pkg.warning_interval = 10 * 60;
	strncpy(pkg.phone_numbers, phone_nums, sizeof(pkg.phone_numbers));

	sendto(warning_fd, &pkg, sizeof(pkg), 0, (void*)&warning_sockaddr, sizeof(warning_sockaddr));

	DEBUG_LOG("SEND WARNING MSG\t[svr=%s ip=%s]", svr, ip);
}

