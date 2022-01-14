#ifndef _MEMLOG_H_
#define _MEMLOG_H_

#define MEM_MAP_W (1 << 16)
#define MEM_MAP_H 32
#define MEM_MAP_MAX_IDX 8

#define MEMLOG_MAXIMUM_INPUT_SIZE (1 << 12)

enum HookType {

  HT_UNKNOWN = 0,
  //  __memlog_hook1 (unsigned id, void* ptr, size_t size);
  //  memset, realloc
  HT_HOOK1 = 1, 
  // __memlog_hook2 (unsigned id, void* dst, void* src, size_t size);
  // ex. memcpy
  HT_HOOK2 = 2,
  // __memlog_hook3 (unsigned id, size_t size);
  // ex. malloc
  HT_HOOK3 = 3,
  // __memlog_hook4 (unsigned id, void* ptr);
  // ex. free
  HT_HOOK4 = 4,
  // __memlog_get_element_ptr_hook (unsigned id, void* ptr, unsigned num_of_idx, ...);
  HT_GEP_HOOK = 5
  
};

struct mem_header {
  
  // instructions executed
  unsigned int hits;
  // unique id
  unsigned int id;
  //type
  unsigned int type : 4;
  
} __attribute__((packed));

enum memlog_type {

  MEMLOG_SRC = 1,
  MEMLOG_DST = 2,
  MEMLOG_SIZE = 3,
  MEMLOG_IDX = 4,
  MEMLOG_VA_SRC = 5

};

struct hook_operand {
  
  void* src;
  void* dst;
  unsigned long long size;

}__attribute__((packed));

struct hook_va_arg_operand {
  
  void* ptr;
  unsigned long long size;
  unsigned int num;
  unsigned int idx[MEM_MAP_MAX_IDX];

} __attribute__((packed));

struct hook_va_arg_idx {
  
  unsigned int type;
  unsigned long long idx;

} __attribute__((packed));

union hook_operands {

  struct hook_operand __hook_op;
  struct hook_va_arg_operand __hook_va_arg;

};

struct mem_map {
  
  /* used for path hash calculation, for speed, just one byte */
  unsigned char hits[MEM_MAP_W];
  struct mem_header headers[MEM_MAP_W];
  union hook_operands log[MEM_MAP_W][MEM_MAP_H]; 
  /**
   * current memlog map hash
   * used to distinguish different path
   * 
   */
  unsigned long long cksum[MEM_MAP_W][MEM_MAP_H];

};

/* Execs the child */

struct afl_forkserver;
void memlog_exec_child(struct afl_forkserver *fsrv, char **argv);
#endif