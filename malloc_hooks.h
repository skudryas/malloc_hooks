#ifndef __MALLOC_HOOKS_H__
#define __MALLOC_HOOKS_H__

#ifdef __cplusplus
extern "C" {
#endif

void my_malloc_init_hooks();
char * my_malloc_dump();
void my_malloc_free_dump(void * p);
extern int global_mem_usage_mhooks;

#ifdef __cplusplus
}
#endif

#endif // #ifndef __MALLOC_HOOKS_H__

