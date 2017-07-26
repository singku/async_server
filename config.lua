--程序名称
local program_name=string.match( get_program_name() ,"(%w+)$" );
--内网ip
local ip=get_ip(1) ;
--公网ip
local public_ip=get_ip(2) ;

print (program_name .." "..public_ip.." "..ip  ) ;


log_dir = "./log"
log_level = 8
log_size = 104857600
max_log_files = 100

max_open_fd = 20000
shmq_length = 4194304
run_mode = "background"


mcast_ip = "239.0.0.1"
mcast_port = 5538
mcast_incoming_if = "eth0"
mcast_outgoing_if = "10.1.1.24"

addr_mcast_ip = "239.0.0.1"
addr_mcast_port = "5539"
addr_mcast_incoming_if = "eth0"
addr_mcast_outgoing_if = "10.1.1.24"

warning_ip = "192.168.0.39"
warning_port = 33001
project_name = "mole"
phone_numbers = "13761071357,13808888888"

dll_file = "./sample/test.so"

bind_conf = "./bind.conf"


tm_dirty_use_dirty_logical = 1
tm_dirty_local_dirty_file_path = "./data/dirty.dat"
tm_dirty_server_addr = "10.1.1.155:28000;192.168.4.68:28000;192.168.4.68:28001"
tm_dirty_update_cycle = 600

-- item 格式 { id, "server.name", "ip", port  } 
async_server_bind_map={ }

local bind_i=0;
local online_server_name="online.mole2";
--if ( ip=="192.168.0.1" and program_name=="onlineA" ) then
    for i = 2, 5, 2 do
        async_server_bind_map[ #async_server_bind_map +1]={ i,online_server_name ,public_ip, 6000+i };
    end
--end

