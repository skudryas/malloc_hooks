/* Prototypes for __malloc_hook, __free_hook */
#include <malloc.h>
#include <unistd.h>
#include <string.h>
#include <set>
#include <map>
#include <string>
#include <sstream>
#include <stdint.h>
#include <execinfo.h>
#include "malloc_hooks.h"
#include "backtrace_symbols.h"

#define TEST_BUILD

static void (*old_free_hook) __MALLOC_PMT ((void *__ptr,
                                       __const __malloc_ptr_t));
static void *(*old_malloc_hook) __MALLOC_PMT ((size_t __size,
                                       __const __malloc_ptr_t));
static void *(*old_memalign_hook) __MALLOC_PMT ((size_t __align, size_t __size,
                                       __const __malloc_ptr_t));
static void *(*old_realloc_hook) __MALLOC_PMT ((void *__ptr, size_t __size,
                                       __const __malloc_ptr_t));

/* Prototypes for our hooks.  */
static void my_init_hook (void);
static void *my_malloc_hook (size_t, const void *);
static void *my_memalign_hook (size_t, size_t, const void *);
static void *my_realloc_hook (void*, size_t, const void *);
static void my_free_hook (void*, const void *);
     
#define my_BT_DEEP 30

#define my_GRAPH_DEEP 50

#define my_PAGESIZE 8192

#define MAGIC_64BIT 0xA110C41EACF18199

struct my_malloc_header
{
  uint32_t size;
  void * bt[my_BT_DEEP];
  uint64_t magic; // == MAGIC_64BIT
  time_t tstamp;
  char unused[512]; // for buggy libraries who corrupting memory (like libpcre)
  void fill(uint32_t size_);
  bool check();
  std::string as_string();
};

#define HOOK_SIZE_GAP sizeof(my_malloc_header)//1

std::string my_malloc_header::as_string()
{
  size_t i = 0;
  for (void ** p = &bt[0]; *p && (p < &bt[my_BT_DEEP]); ++p, ++i);
  return std::string((char*)&bt[0], i*sizeof(void*));
}

void my_malloc_header::fill(uint32_t size_)
{
  int framecnt = backtrace(bt, my_BT_DEEP);
  if (framecnt > my_BT_DEEP)
    fprintf(stderr, "*********************backtraced %d frames\n", framecnt);

  size = size_;
  tstamp = time(NULL);
  magic = MAGIC_64BIT;
/* Сохраняем rbp в переменную. В *rbp 
 * */

/*  void * cur_rbp = NULL;// = __builtin_return_address(0);
  asm ("mov %%rbp, %0" : "=r" (cur_rbp));
  bt[0] = cur_addr;
  fprintf(stderr, "curr_addr = %p\n", cur_addr);
  for (size_t i = 1; i < my_BT_DEEP; ++i)
  {
    
    bt[i] = cur_addr;
    if (!cur_addr)
      break;
  }*/
}

bool my_malloc_header::check()
{
  return magic == MAGIC_64BIT;
}

static std::set<my_malloc_header*> * allocated_pointers = NULL;

struct bt_info
{
  uint64_t cursize_or_cnt;
  std::string bt;
  time_t tstart, tend;
  bt_info(uint64_t cursize_or_cnt_, const std::string& bt_, time_t tstart_, time_t tend_):
          cursize_or_cnt(cursize_or_cnt_), bt(bt_), tstart(tstart_), tend(tend_) {}
};

static char * my_malloc_make_graph()
{
  time_t time_of_start = time(NULL);
  std::multimap<uint64_t, bt_info> result_map;
//  std::set<std::string> consumed_bts;
  std::set<char*> addrs_in_use;
  char * curaddr = NULL;
  std::stringstream ss;
  ss << "leaked_addrs_" << getpid() << ".txt";
  FILE * f = fopen(ss.str().c_str(), "wb");
  for (std::set<my_malloc_header*>::const_iterator it = allocated_pointers->begin(); it != allocated_pointers->end(); ++it)
  {
    uint64_t cursize = (*it)->size, cnt = 1;
    //NOTE START comment this code if you need for eventually allocated memory dump too
    /*
    if ((time_of_start - (*it)->tstamp) != 0)
    {
      fprintf(f, "%p:%d\n", (void*)(*it), (int)cursize);
    }
    else 
      continue;*/
    //NOTE END
    std::string curbt = (*it)->as_string();
//
//    int curaddrdiff = (char*)*it - curaddr;
    curaddr = (char*)*it;
    curaddr -= ((long long unsigned int)curaddr) % my_PAGESIZE;
//    fprintf(stderr, "\taddr %p (diff %d)\n", (void*)curaddr, curaddrdiff);
    while (curaddr < (char*)(*it) + (*it)->size + HOOK_SIZE_GAP)
    {
      addrs_in_use.insert(curaddr);
      curaddr += my_PAGESIZE;
    }
//
//    if (consumed_bts.count(curbt))
//      continue;
//    consumed_bts.insert(curbt);
    std::set<my_malloc_header*>::const_iterator it_next = it;
    ++it_next;
    time_t tstart, tend;
    tstart = tend = (*it)->tstamp;
    for (; it_next != allocated_pointers->end(); ++it_next)
    {
      if ((*it_next)->as_string() == curbt)
      {
        cursize += (*it_next)->size; // неоптимально, не удаляем ноду
        ++cnt;
        if ((*it_next)->tstamp > tend)
        {
          tend = (*it_next)->tstamp;
        }
        if ((*it_next)->tstamp < tstart)
        {
          tstart = (*it_next)->tstamp;
        }
      }
    }
    result_map.insert(std::pair<uint64_t, bt_info> (cursize, bt_info(cnt, curbt, tstart, tend)));
 //                                                  ^---------------^
  }
  fclose(f);
  if (result_map.size() == 0)
  {
    fprintf(stderr, "no results!\n");
    return NULL;
  }
  std::stringstream result_ss;
  std::multimap<uint64_t, bt_info>::const_iterator it = result_map.end();
  --it;
  fprintf(stderr, "\n****** TOTAL MEM USED: %u\n", global_mem_usage_mhooks);
  fprintf(stderr, "****** TOTAL PAGES OF 8192 USED: %u\n", (int)addrs_in_use.size());
  fprintf(stderr, "****** DUMP FOR TIMESTAMP: %lu\n", time_of_start);
  size_t eventually_leaks = 0;
  for (size_t i = my_GRAPH_DEEP; i != 0; --i, --it)
  {
    if (it->second.bt.size() % sizeof(void*))
    {
      fprintf(stderr, "unaligned data in backtrace! sz = %d . exiting..\n", (int)it->second.bt.size());
      return NULL;
    }
    if (it->second.bt.size() > sizeof(void*)*my_BT_DEEP)
    {
      fprintf(stderr, "overflow in backtrace! sz = %d . exiting..\n", (int)it->second.bt.size());
      return NULL;
    }
/*    if (it->second.tend - it->second.tstart <= 1)
    {
      fprintf(stderr, "skipping as ts diff <= 1\n");
      ++it;
      continue;
    }*/
   /* if ((time_of_start - it->second.tend) == 0)
    {
      ++eventually_leaks;
      fprintf(stderr, "skipping eventually leak\n");
      ++i;
      continue;
    }*/
    void * bt[my_BT_DEEP];
    memset(bt, 0, my_BT_DEEP*sizeof(void*));
    memcpy(bt, it->second.bt.data(), it->second.bt.size());
    char ** bt_symb = backtrace_symbols(bt, it->second.bt.size() / sizeof(void*));//*my_BT_DEEP);
    char ** bt_symb2 = backtrace_symbols2(bt, it->second.bt.size() / sizeof(void*));//*my_BT_DEEP);
    if (!bt_symb || !bt_symb2)
    {
      fprintf(stderr, "backtrace_symbols* failed! exiting..\n");
      return NULL;
    }
    result_ss << "\n****** UNFREED MEM SIZE: " << it->first << " count: " << it->second.cursize_or_cnt << " tstamp_start: " << it->second.tstart << " tstamp_end: " 
            << it->second.tend << " diff: " << it->second.tend - it->second.tstart << " (-" << (time_of_start - it->second.tend) << ")" << " bt:\n";
    for (size_t j = 0; j < it->second.bt.size() / sizeof(void*)/**my_BT_DEEP*/; ++j)
    {
      result_ss << "\t" << bt_symb[j] << "\t\t\t" << bt_symb2[j] << "\n";
    }
    free(bt_symb);
    if (it == result_map.begin())
      break;
  }
  fprintf(stderr, "***********EVENTUALLY LEAKS COUNT = %d\n", (int)eventually_leaks);
  std::string result_str = result_ss.str();
  char * result = (char*)malloc(result_str.size() + 1);
  memcpy(result, result_str.c_str(), result_str.size());
  result[result_str.size()] = 0;  
  return result;
}


//void (*__malloc_initialize_hook) (void) = my_init_hook;

extern "C" {
int global_mem_usage_mhooks = 0;
}

  /* Save original hooks */
#define SAVE_OLD_HOOKS  old_malloc_hook = __malloc_hook; \
  old_memalign_hook = __memalign_hook; \
  old_free_hook = __free_hook; \
  old_realloc_hook = __realloc_hook;

  /* Restore all old hooks */
#define RESTORE_OLD_HOOKS __malloc_hook = old_malloc_hook; \
  __memalign_hook = old_memalign_hook; \
  __free_hook = old_free_hook; \
  __realloc_hook = old_realloc_hook;

  /* Restore our own hooks */
#define RESTORE_MY_HOOKS __malloc_hook = my_malloc_hook; \
  __memalign_hook = my_memalign_hook; \
  __free_hook = my_free_hook; \
  __realloc_hook = my_realloc_hook;

extern "C" char * my_malloc_dump()
{
  if (!allocated_pointers)
    return NULL;

  RESTORE_OLD_HOOKS

  fprintf(stderr, "make graph start... allocated_pointers->size() == %d\n", (int)allocated_pointers->size());
  char * retval = my_malloc_make_graph();
  fprintf(stderr, "make graph end...\n");

  RESTORE_MY_HOOKS

  return retval;
}

extern "C" void my_malloc_free_dump(void * p)
{
  RESTORE_OLD_HOOKS

  free(p);

  RESTORE_MY_HOOKS
}

extern "C" void my_malloc_init_hooks()
{
  my_init_hook();
}

/* Override initializing hook from the C library. */
static void
my_init_hook (void)
{
  fprintf(stderr, "my_hooks: init\n");
  if (allocated_pointers)
    delete allocated_pointers;
  allocated_pointers = new std::set<my_malloc_header*>();
  SAVE_OLD_HOOKS
  RESTORE_MY_HOOKS
}


//NOTE: you should never call this fuunction! In 99% cases it will crash your program
static void my_stop_hook (void)
{
  fprintf(stderr, "my_hooks: stop\n");

  RESTORE_OLD_HOOKS

  if (allocated_pointers)
    delete allocated_pointers;
  allocated_pointers = NULL;
}

void my_int_free(void *& ptr)
{
  if (ptr)
  {
    ptr = (my_malloc_header*)ptr - 1;
    if (allocated_pointers->count((my_malloc_header*)ptr) && ((my_malloc_header*)ptr)->check())
    {
      allocated_pointers->erase((my_malloc_header*)ptr);
      global_mem_usage_mhooks -= ((my_malloc_header*)ptr)->size;
    }
    else
    {
      ptr = (my_malloc_header*)ptr + 1;
    }
  }
}

void my_int_alloc(void *& ptr, size_t size)
{
  if (ptr && size)
  {
    allocated_pointers->insert((my_malloc_header*)ptr);
    global_mem_usage_mhooks += size;
    ((my_malloc_header*)ptr)->fill(size);
    ptr = (my_malloc_header*)ptr + 1;
  }
}

#if 1
static void *
my_malloc_hook (size_t size, const void *caller)
{
  void *result;

  RESTORE_OLD_HOOKS
  /* Call recursively */
  result = malloc (size ? (size + HOOK_SIZE_GAP) : size);

  /* Fill & handle internal info */
  my_int_alloc(result, size);

  RESTORE_MY_HOOKS

  return result;
}
#endif

static void *
my_memalign_hook (size_t align, size_t size, const void *caller)
{
  void *result;

  RESTORE_OLD_HOOKS
  /* Call recursively */
  size_t size_new = size + HOOK_SIZE_GAP;
  size_t size_aligned =  (size_new/align + 1) * align;
  result = malloc(size_aligned);//memalign (align, size_aligned);

  /* Fill & handle internal info */
  my_int_alloc(result, size);

  RESTORE_MY_HOOKS

  return result;
}

#if 1
static void *
my_realloc_hook (void *ptr, size_t size, const void *caller)
{
  void *result;
  
  RESTORE_OLD_HOOKS

  if (ptr && !allocated_pointers->count((my_malloc_header*)ptr - 1))
  { /* Hack for previously allocated mem */
    result = malloc(size ? (size + HOOK_SIZE_GAP) : size);
    memcpy((void*)((my_malloc_header*)result + 1), ptr, size);
    free(ptr);
  }
  else
  {
    my_int_free(ptr);
    /* Call recursively */
    result = realloc (ptr, (size ? (size + HOOK_SIZE_GAP) : size));
  }

  /* Fill & handle internal info */
  my_int_alloc(result, size);

  RESTORE_MY_HOOKS

  return result;
}
#endif

#if 1
static void
my_free_hook (void *ptr, const void *caller)
{
  RESTORE_OLD_HOOKS

  /* Fill & handle internal info */
  my_int_free(ptr);

  /* Call recursively */
  free (ptr);

  RESTORE_MY_HOOKS
}
#endif

#ifdef TEST_BUILD
int main(int ac, char **av)
{
        my_malloc_init_hooks();
        int i;
        void *p[1000];

//        fork();
        for ( i = 0 ; i < 1000; ++i)
        {
               p[i] = malloc(100);
        }
        printf("gmum = %d\n", (int)global_mem_usage_mhooks);
        for ( i = 0 ; i < 999; ++i)
        {
               p[i] = realloc(p[i], 200);
        }
        printf("gmum = %d\n", (int)global_mem_usage_mhooks);
        for ( i = 0 ; i < 998; ++i)
        {
               free(p[i]);
        }
        printf("gmum = %d\n", (int)global_mem_usage_mhooks);
        char * d = my_malloc_dump();
        printf("%s", d);
        my_malloc_free_dump(d);
}
#endif

