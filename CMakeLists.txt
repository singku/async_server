cmake_minimum_required(VERSION 2.6)

set (CMAKE_INCLUDE_DIRECTORIES_PROJECT_BEFORE  true )
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
set(CMAKE_INSTALL_PREFIX "/usr/local")
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/../ )
set(CMAKE_USE_RELATIVE_PATHS  true )
find_package(glib REQUIRED)
find_package(taomee REQUIRED)
set (SRC_LIST 
	bindconf.c
	daemon.c
	dll.c
	main.c
	mcast.c
	net.c
	net_if.c
	service.c
	shmq.c
	util.c
	)
add_definitions("-Wall -MMD -g  -DDEBUG -DUSE_TLOG -O2 -funroll-loops -D__USE_STRING_INLINES -fhosted -D_REENTRANT -D_GNU_SOURCE  -z defs")
INCLUDE_DIRECTORIES( ${GLIB_INCLUDE_DIR}	${TAOMEE_INCLUDE_DIR} 	)
set (EXTRA_LIBS ${EXTRA_LIBS} glib-2.0 m taomee dl ssl pthread )
add_executable(AsynServ ${SRC_LIST}   )
target_link_libraries (AsynServ ${EXTRA_LIBS})
INSTALL (FILES  net_if.h DESTINATION  include/async_serv    )
INSTALL (FILES  service.h DESTINATION  include/async_serv    )
INSTALL (FILES  net.h DESTINATION  include/async_serv    )
INSTALL (FILES  bindconf.h DESTINATION  include/async_serv    )
INSTALL (FILES  daemon.h DESTINATION  include/async_serv    )
INSTALL (FILES  shmq.h DESTINATION  include/async_serv    )
INSTALL (FILES  mcast.h DESTINATION  include/async_serv    )
INSTALL (FILES  dll.h DESTINATION  include/async_serv    )

