#include "afl-fuzz.h"
#include "memlog.h"

#define FLIP_BIT(_ar, _b)                   \
  do {                                      \
                                            \
    u8 *_arf = (u8 *)(_ar);                 \
    u32 _bf = (_b);                         \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf)&7)); \
                                            \
  } while (0)

static struct tainted* add_tainted(struct tainted *taint, u32 pos, u32 len) {

  struct tainted *new_taint;
  u32 end;
 
  if (taint == NULL) {
    
    new_taint = ck_alloc_nozero(sizeof(struct tainted));  
    new_taint->pos = pos;
    new_taint->len = len;
    new_taint->prev = NULL;
    new_taint->next = NULL;
    return new_taint;

  }

  end = taint->pos + taint->len - 1;

  if (end + 1 == pos) {
    
    taint->len += 1;
  
  }
  else if (pos > end) {
    
    new_taint = ck_alloc_nozero(sizeof(struct tainted));  
    new_taint->pos = pos;
    new_taint->len = len;
    new_taint->prev = NULL;
    new_taint->next = taint;
    taint->prev = new_taint;
    return new_taint;

  }

  return taint;

}

static u8 get_exec_checksum(afl_state_t *afl, u8 *buf, u32 len, u64 *cksum) {

  if (unlikely(common_fuzz_stuff(afl, buf, len))) { return 1; }

  *cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

  return 0;

}

/* replace everything with different values but stay in the same type */
static void type_replace(afl_state_t *afl, u8 *buf, u32 len) {

  u32 i;
  u8  c;
  for (i = 0; i < len; ++i) {

    // wont help for UTF or non-latin charsets
    do {

      switch (buf[i]) {

        case 'A' ... 'F':
          c = 'A' + rand_below(afl, 1 + 'F' - 'A');
          break;
        case 'a' ... 'f':
          c = 'a' + rand_below(afl, 1 + 'f' - 'a');
          break;
        case '0':
          c = '1';
          break;
        case '1':
          c = '0';
          break;
        case '2' ... '9':
          c = '2' + rand_below(afl, 1 + '9' - '2');
          break;
        case 'G' ... 'Z':
          c = 'G' + rand_below(afl, 1 + 'Z' - 'G');
          break;
        case 'g' ... 'z':
          c = 'g' + rand_below(afl, 1 + 'z' - 'g');
          break;
        case '!' ... '*':
          c = '!' + rand_below(afl, 1 + '*' - '!');
          break;
        case ',' ... '.':
          c = ',' + rand_below(afl, 1 + '.' - ',');
          break;
        case ':' ... '@':
          c = ':' + rand_below(afl, 1 + '@' - ':');
          break;
        case '[' ... '`':
          c = '[' + rand_below(afl, 1 + '`' - '[');
          break;
        case '{' ... '~':
          c = '{' + rand_below(afl, 1 + '~' - '{');
          break;
        case '+':
          c = '/';
          break;
        case '/':
          c = '+';
          break;
        case ' ':
          c = '\t';
          break;
        case '\t':
          c = ' ';
          break;
        case '\r':
          c = '\n';
          break;
        case '\n':
          c = '\r';
          break;
        case 0:
          c = 1;
          break;
        case 1:
          c = 0;
          break;
        case 0xff:
          c = 0;
          break;
        default:
          if (buf[i] < 32) {

            c = (buf[i] ^ 0x1f);

          } else {

            c = (buf[i] ^ 0x7f);  // we keep the highest bit

          }

      }

    } while (c == buf[i]);

    buf[i] = c;

  }

}

void update_state(afl_state_t *afl, u32 mut, u8 type, u8 *tainted, u8 *inst_hit) {
 
  if (!(*tainted)) {
    afl->tainted_len += 1;
    *tainted = 1;
  }
  
  if (*inst_hit) return;
  
  *inst_hit = 1;
  afl->ht_tainted[type][mut] += 1;
  
}

void byte_level_mutator(afl_state_t *afl, u8 *buf, u32 ofs, u32 mutator) {
  u32 _bit;
  // mutator
  switch(mutator) {
  case 0: {
      _bit = (ofs << 3) + rand_below(afl, 8);
      FLIP_BIT(buf, _bit);
      break;
  }
  case 1: {
      *(buf + ofs) += 1;
      break;
  }
  case 2: {
      type_replace(afl, buf + ofs, 1);
      break;
  }
  case 3: {
      *(buf + ofs) -= 1;
      break;
  }
  default:
      break;
  }

}

u8 taint_inference_stage(afl_state_t *afl, u8 *orig_buf, u8 *buf, u32 len) { 
  struct hook_va_arg_operand *va_o = NULL, *orig_va_o = NULL;
  struct hook_operand *o = NULL, *orig_o = NULL;
  u8 input_tainted, inst_hit;
  u32 loggeds;
  u64 cksum, exec_cksum, mem_cksum, mem_exec_cksum;

  afl->stage_name = "taint inference";
  afl->stage_short = "infer";
  afl->stage_max = len * TAINT_INFER_MUTATOR_NUM;
  afl->stage_cur = 0;

  // reset state info
  afl->tainted_len = 0;
  afl->unstable_len = 0;
  memset(afl->ht_tainted, 0, MEMLOG_HOOK_NUM * TAINT_INFER_MUTATOR_NUM * sizeof(u32));
  
  if (unlikely(!afl->orig_mem_map)) {

    afl->orig_mem_map = ck_alloc_nozero(sizeof(struct mem_map));

  }

  if (unlikely(common_fuzz_memlog_stuff(afl, orig_buf, len))) return 1;
  memcpy(afl->orig_mem_map, afl->shm.mem_map, sizeof(struct mem_map));
  
  mem_cksum = hash64(afl->memlog_fsrv.trace_bits, afl->memlog_fsrv.map_size, HASH_CONST);
  get_exec_checksum(afl, orig_buf, len, &cksum);
  
  // check unstable
  /*if (check_unstable()) {

    return 1;

  }*/

  for (u32 i = 0; i < len; i++) {
    
    input_tainted = 0;
    afl->stage_cur_byte = i;
    
    if (i > 0)
        *(buf + i - 1) = *(orig_buf + i - 1);      
    afl->stage_cur += 1;

    // byte-level mutate
    for (u32 j = 0; j < TAINT_INFER_MUTATOR_NUM; j++) { 
      
      byte_level_mutator(afl, buf, i, j); 
      // execute
      if (unlikely(common_fuzz_memlog_stuff(afl, buf, len))) return 1;

      /**
       * execution path check
       * 
       * PATA check
       * loggeds = MIN((u32)(m_map->headers[k].hits), (u32)(afl->orig_mem_map->headers[k].hits));
       * 
       * strict check
       * 
       * common subpath check
       * if (afl->orig_mem_map->cksum[k][l] != afl->shm.mem_map->cksum[k][l]) continue;
       * 
       */
       
      // directly use mem_map afl bitmap
      mem_exec_cksum = hash64(afl->memlog_fsrv.trace_bits, afl->memlog_fsrv.map_size, HASH_CONST);
      get_exec_checksum(afl, buf, len, &exec_cksum);
  
      if (exec_cksum != cksum && mem_cksum != mem_exec_cksum) continue;
      else if (exec_cksum != cksum || mem_cksum != mem_exec_cksum){
          fprintf(stderr, "wierd...\n");
          afl->unstable_len += 1;
      }

      for (u32 k = 0; k < MEM_MAP_W; k++) {
        
        loggeds = MIN((u32)(afl->shm.mem_map->headers[k].hits), (u32)(afl->orig_mem_map->headers[k].hits));
        if (!loggeds) continue;

        if (loggeds > MEM_MAP_H) 
          loggeds = MEM_MAP_H;
        
        inst_hit = 0;
        for (u32 l = 0; l < loggeds; l++) {
        
          if (afl->shm.mem_map->headers[k].type >= HT_GEP_HOOK) {
          
            va_o = &afl->shm.mem_map->log[k][l].__hook_va_arg;
            orig_va_o = &afl->orig_mem_map->log[k][l].__hook_va_arg;

          }
          else {

            o = &afl->shm.mem_map->log[k][l].__hook_op;
            orig_o = &afl->orig_mem_map->log[k][l].__hook_op;
          
          }

          switch (afl->shm.mem_map->headers[k].type) {

            case HT_HOOK1: {

              if (o->dst != orig_o->dst) 
                update_state(afl, j, HT_HOOK1, &input_tainted, &inst_hit);
              if (o->size != orig_o->size) 
                update_state(afl, j, HT_HOOK1, &input_tainted, &inst_hit);
              break;
            
            }
            case HT_HOOK2: {

              /*if (o->dst != orig_o->dst)
                update_state(afl, j, HT_HOOK2, &input_tainted, &inst_hit);
              if (o->src != orig_o->src)
                update_state(afl, j, HT_HOOK2, &input_tainted, &inst_hit);*/
              if (o->size != orig_o->size) 
                update_state(afl, j, HT_HOOK2, &input_tainted, &inst_hit);
              break;

            }
            case HT_HOOK3: {

              if (o->size != orig_o->size) 
                update_state(afl, j, HT_HOOK3, &input_tainted, &inst_hit);
              break;

            }
            case HT_HOOK4: {

              if (o->src != orig_o->src) 
                update_state(afl, j, HT_HOOK4, &input_tainted, &inst_hit);
              break;

            }
            case HT_GEP_HOOK: {
              
              for (u32 idx = 0; idx < va_o->num; idx++) {

                if (va_o->idx[idx] != orig_va_o->idx[idx]) {

                  update_state(afl, j, HT_GEP_HOOK, &input_tainted, &inst_hit);
                
                }

              }

              //if (va_o->ptr != orig_va_o->ptr) 
              break;

            }
            default:
              break;

          }

        }

      }

    }

  }

  return 0;

}

