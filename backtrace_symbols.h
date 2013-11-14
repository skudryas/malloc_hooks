#ifndef __BACKTRACE_SYMBOLS_H__
#define __BACKTRACE_SYMBOLS_H__

#ifdef __cplusplus
extern "C"
#endif
char **backtrace_symbols2(void *const *buffer, int size);

#endif
