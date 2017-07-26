#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libtaomee/conf_parser/config.h>
#include <libtaomee/inet/mcast.h>

#pragma pack(1)

/**
  * @brief for sending a mcast package to notify AsyncServer to reload text.so
  */
typedef struct reload_so_pkg {
	uint16_t	pkg_type;
	uint16_t	proto_type;
	uint8_t		svr_name[16];
	uint32_t	svr_id;
	uint8_t		new_so_name[32];
} reload_so_pkg_t;

#pragma pack()

int main(int argc, char* argv[])
{
	if (argc != 5) {
		fprintf(stderr, "Usage: %s conf_file svr_name svr_id new_so_name\n", argv[0]);
		return -1;
	}

	if (config_init(argv[1]) < 0) {
		fprintf(stderr, "Failed to read conf_file '%s'!\n", argv[1]);
		return -1;
	}

	struct sockaddr_storage mcast_saddr;
	socklen_t mcast_slen;
	int mcast_fd = create_mcast_socket(config_get_strval("reload_mcast_addr"),
										config_get_strval("reload_mcast_port"),
										config_get_strval("reload_mcast_if"),
										mcast_wronly, &mcast_saddr, &mcast_slen);
	if (mcast_fd < 0) {
		fprintf(stderr, "Failed to create multi-cast socket, please check your configuration file!\n");
		return -1;
	}

	reload_so_pkg_t pkg;

	pkg.proto_type = 1;
	pkg.svr_id     = atoi(argv[3]);
	snprintf(pkg.svr_name, sizeof(pkg.svr_name), "%s", argv[2]);
	snprintf(pkg.new_so_name, sizeof(pkg.new_so_name), "%s", argv[4]);

	sendto(mcast_fd, &pkg, sizeof(pkg), 0, (void*)&mcast_saddr, mcast_slen);
	return 0;
}

