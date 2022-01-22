#include "config.h"
#include "memlog.h"
#include <sanitizer/asan_interface.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "types.h"

#define XXH_INLINE_ALL
#include "xxhash.h"
#undef XXH_INLINE_ALL

#ifdef _DEBUG
u64 hash64(u8 *key, u32 len, u64 seed) {

#else
static inline u64 hash64(u8 *key, u32 len, u64 seed) {

#endif

  (void)seed;
  return XXH3_64bits(key, len);

}

typedef unsigned __int128 uint128_t;

extern struct mem_map *__afl_mem_map;
// memlog map size not real target mapsize, but this is enough
extern u8 *__afl_area_ptr;
extern u32 __afl_map_size;

// use for cksum calculating
u8 *__memlog_cksum_map;
u32 __memlog_cksum_map_size;
/**
 * Call hook.
 * __memlog_hook1 (unsigned id, void* ptr, size_t size);
 * ex. memset, realloc
 * __memlog_hook2 (unsigned id, void* dst, void* src, size_t size);
 * ex. memcpy
 * __memlog_hook3 (unsigned id, size_t size);
 * ex. malloc
 * __memlog_hook4 (unsigned id, void* ptr);
 * ex. free
 * __memlog_get_element_ptr_hook (unsigned id, void* ptr, unsigned num_of_idx, ...);
 * ex. get_element_ptr inst.
 * 
 */
#ifdef MEMLOG_DEBUG

/**
 * Debug Mode for launching target without AFL++
 * 
 */
void __memlog_debug_output() {

}

__attribute__((constructor(5))) 
void __memlog_debug_init() {
      
  fprintf(stderr, "__memlog_debug_init\n");

  if(!__afl_mem_map) {
      __afl_mem_map = (struct mem_map *)malloc(sizeof(struct mem_map));
    memset(__afl_mem_map, 0, sizeof(struct mem_map));
  }

}

__attribute__((destructor)) 
void __memlog_debug_fini() {

  fprintf(stderr, "__memlog_debug_fini\n");
  if (__afl_mem_map) 
    __memlog_debug_output();
  
  if(__afl_mem_map && !getenv(MEMLOG_SHM_ENV_VAR)) {
    free(__afl_mem_map);
    __afl_mem_map = NULL;
  }

}

void __memlog_hook_debug(u32 id) {
  
}

#endif

/**
 *  Initialize cksum_map used for cksum calculating 
 */
__attribute((constructor(4)))
void __memlog_set_cksum_map() {

  if (unlikely(!__afl_mem_map)) return;

  if (__afl_area_ptr != NULL && __afl_map_size < MEM_MAP_W) {
    // seems the map size is smaller
    // we can use afl bitmap to calculate control flow cksum
    __memlog_cksum_map = __afl_area_ptr;
    __memlog_cksum_map_size = __afl_map_size;

  }
  else {
    // size of afl bitmap is larger than memlog map size
    // let's use memlog map to calculate control flow cksum
    __memlog_cksum_map = __afl_mem_map->hits;
    __memlog_cksum_map_size = MEM_MAP_W;

  }

}

/**
 * ex. memset, realloc
 * 
 */
__attribute__((visibility("default")))
void __memlog_hook1(u32 id, void* ptr, u64 size) {

  if (unlikely(!__afl_mem_map)) return;

  unsigned hits;
  if (!__afl_mem_map->headers[id].type) {
    
    hits = 0;
    __afl_mem_map->headers[id].hits = 1;
    __afl_mem_map->headers[id].type = HT_HOOK1;
  
    // used for hash calculating
    __afl_mem_map->hits[id] = 1;

  }
  else {
    
    hits = __afl_mem_map->headers[id].hits++;

    // used for hash calculating
    __afl_mem_map->hits[id]++;

  }
  
  hits &= MEM_MAP_H - 1;

  // calculate current memlog map header hash
  // can be used to distinguish different path
  __afl_mem_map->cksum[id][hits] = hash64((void *)__memlog_cksum_map, __memlog_cksum_map_size, HASH_CONST);

  __afl_mem_map->log[id][hits].__hook_op.dst = ptr;
  __afl_mem_map->log[id][hits].__hook_op.size = size;

  #ifdef MEMLOG_DEBUG
  fprintf(stderr, "__memlog_hook%d: id: %u ptr: %p size: %llu\n", 
    __afl_mem_map->headers[id].type, id, ptr, size);
  #endif
  
}

/**
 * ex. memcpy
 * 
 */
__attribute__((visibility("default")))
void __memlog_hook2(u32 id, void* dst, void* src, u64 size) {
  
  if (unlikely(!__afl_mem_map)) return;

  unsigned hits;
  if (!__afl_mem_map->headers[id].type) {
    
    hits = 0;
    __afl_mem_map->headers[id].hits = 1;
    __afl_mem_map->headers[id].type = HT_HOOK2;
  
    // used for hash calculating
    __afl_mem_map->hits[id] = 1;
 
  }
  else {
    
    hits = __afl_mem_map->headers[id].hits++;

    // used for hash calculating
    __afl_mem_map->hits[id]++;
    
  }

  hits &= MEM_MAP_H - 1;

  // calculate current memlog map header hash
  // can be used to distinguish different path
  __afl_mem_map->cksum[id][hits] = hash64((void *)__memlog_cksum_map, __memlog_cksum_map_size, HASH_CONST);

  __afl_mem_map->log[id][hits].__hook_op.dst = dst;
  __afl_mem_map->log[id][hits].__hook_op.src = src;
  __afl_mem_map->log[id][hits].__hook_op.size = size;

  #ifdef MEMLOG_DEBUG
  fprintf(stderr, "__memlog_hook%d: id: %u dst: %p src: %p size: %llu\n", 
    __afl_mem_map->headers[id].type, id, dst, src, size);
  #endif
  
}

/**
 * ex. malloc
 * 
 */
__attribute__((visibility("default")))
void __memlog_hook3(u32 id, u64 size) {

  if (unlikely(!__afl_mem_map)) return;

  unsigned hits;
  if (!__afl_mem_map->headers[id].type) {
    
    hits = 0;
    __afl_mem_map->headers[id].hits = 1;
    __afl_mem_map->headers[id].type = HT_HOOK3;
  
    // used for hash calculating
    __afl_mem_map->hits[id] = 1;

  }
  else {
    
    hits = __afl_mem_map->headers[id].hits++;

    // used for hash calculating
    __afl_mem_map->hits[id]++;

  }

  hits &= MEM_MAP_H - 1;

  // calculate current memlog map header hash
  // can be used to distinguish different path
  __afl_mem_map->cksum[id][hits] = hash64((void *)__memlog_cksum_map, __memlog_cksum_map_size, HASH_CONST);

  __afl_mem_map->log[id][hits].__hook_op.size = size;
  
  #ifdef MEMLOG_DEBUG
  fprintf(stderr, "__memlog_hook%d: id: %u size: %llu\n", 
    __afl_mem_map->headers[id].type, id, size);
  #endif

}

/**
 * ex. free
 * 
 */
__attribute__((visibility("default")))
void __memlog_hook4(u32 id, void* ptr) {

  if (unlikely(!__afl_mem_map)) return;

  unsigned hits;
  if(!__afl_mem_map->headers[id].type) {
  
    hits = 0;
    __afl_mem_map->headers[id].hits = 1;
    __afl_mem_map->headers[id].type = HT_HOOK4;

    // used for hash calculating
    __afl_mem_map->hits[id] = 1;
  }
  else {
    
    hits = __afl_mem_map->headers[id].hits++;

    // used for hash calculating
    __afl_mem_map->hits[id]++;
  }

  hits &= MEM_MAP_H - 1;

  // calculate current memlog map header hash
  // can be used to distinguish different path
  __afl_mem_map->cksum[id][hits] = hash64((void *)__memlog_cksum_map, __memlog_cksum_map_size, HASH_CONST);

  __afl_mem_map->log[id][hits].__hook_op.src = ptr;

  #ifdef MEMLOG_DEBUG
  fprintf(stderr, "__memlog_hook%d: id: %u ptr: %p\n", 
    __afl_mem_map->headers[id].type, id, ptr);
  #endif
}

/**
 * ex. get_element_ptr inst.
 * 
 */
__attribute__((visibility("default")))
void __memlog_get_element_ptr_hook(u32 id, void* ptr, u32 num_of_idx, ...) {
  //deal with vararg
  va_list args;
  u32 logged;
  size_t size;
  void *out;
  struct hook_va_arg_operand *__hook_va_arg;

  if (unlikely(!__afl_mem_map)) return;

  unsigned hits;
  if (!__afl_mem_map->headers[id].type) {
    
    hits = 0;
    __afl_mem_map->headers[id].hits = 1;
    __afl_mem_map->headers[id].type = HT_GEP_HOOK;
    // used for hash calculating
    __afl_mem_map->hits[id] = 1;

    // discard idx more than MEM_MAP_MAX_IDX
    if (num_of_idx > MEM_MAP_MAX_IDX)
      logged = MEM_MAP_MAX_IDX;
    else
      logged = num_of_idx;
    
    __afl_mem_map->headers[id].num_of_idx = logged;

  }
  else {
    
    hits = __afl_mem_map->headers[id].hits++;
    // used for hash calculating
    __afl_mem_map->hits[id]++;

    logged = __afl_mem_map->headers[id].num_of_idx;
    
  }
  
  hits &= MEM_MAP_H - 1;
  // calculate current memlog map header hash
  // can be used to distinguish different path
  __afl_mem_map->cksum[id][hits] = hash64((void *)__memlog_cksum_map, __memlog_cksum_map_size, HASH_CONST);

  // dump ptr, size
  __hook_va_arg = &__afl_mem_map->log[id][hits].__hook_va_arg;
  __hook_va_arg->ptr = ptr;
  __asan_locate_address(ptr, NULL, 0, &out, &size);
  __hook_va_arg->size = size;
  
  // dump idx
  va_start(args, num_of_idx);
  for(int i = 0; i < logged; i++) {
    
    __hook_va_arg->idx[i] = va_arg(args, u64);
    
  }
  va_end(args);

  #ifdef MEMLOG_DEBUG

  fprintf(stderr, "__memlog_get_element_ptr_hook: id: %u ptr: %p num: %u size: %lu\n"
    , id, ptr, num_of_idx, size);
  
  for(int i = 0; i < logged; i++) {
    
    fprintf(stderr, "idx: %u", __hook_va_arg->idx[i]);
    
  }fprintf(stderr, "\n");
 
  #endif
  
}
