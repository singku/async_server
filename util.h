#ifndef ASYNC_SERVER_UTIL_H_
#define ASYNC_SERVER_UTIL_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef  likely
#undef  likely
#endif
#define likely(x)  __builtin_expect(!!(x), 1)

#ifdef  unlikely
#undef  unlikely
#endif
#define unlikely(x)  __builtin_expect(!!(x), 0)

int log_init_ex(const char* dir, log_lvl_t lvl, uint32_t size, int maxfiles, const char* pre_name, uint32_t logtime);
int pipe_create(int pipe_handles[2]);

void asynsvr_init_warning_system();
void asynsvr_send_warning(const char* svr, uint32_t svr_id, const char* ip);

#ifdef __cplusplus
}
#endif

#endif // ASYNC_SERVER_UTIL_H_
