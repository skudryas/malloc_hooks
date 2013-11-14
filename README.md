Fast and slow implementations of heap proiler using gcc malloc hooks. also applicable and tested for tcmalloc (but requires changes in tcmalloc sources, just add global hooks check in tcmalloc's default_malloc, etc calls).
Call my_malloc_init_hooks() to start profiling, my_malloc_dump() dump non-freed pointers since my_malloc_init_hooks() into stderr.
Note: leaks with same backtrace is grouped, output sorted by total mem usage for one backtrace, memory allocated eventually (less then one second ago) ignored
 (you can change this by modifying code).
Fast version store info about allocation in gap before allocated memory, slow version store it into std::map, it's more safely.
