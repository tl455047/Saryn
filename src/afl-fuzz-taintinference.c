#include "afl-fuzz.h"
#include "cmplog.h"
#include "math.h"
#include "memlog.h"

#define SLIGHT_TAINTED 64
#define MIN_TAINTED_HAVOC 32
#define LINEAR_TIME 0xff
#define PASS_TIME 0x200

#define SWAPA(_x) ((_x & 0xf8) + ((_x & 7) ^ 0x07))

struct taint_operations {

  void (*check_unstable)(afl_state_t *afl);
  void (*inference)(afl_state_t *afl, u32 ofs);
  u8   (*common_fuzz_staff)(afl_state_t *afl, u8 *out_buf, u32 len);
  
};

struct taint_taint_mode {

  void *map;
  void *orig_map;
  u32 map_size;
  afl_forkserver_t *fsrv;
  u32 fsrv_map_size;
  struct taint_operations ops;

};

static struct taint_taint_mode taint_mode;

enum cmplog_type {

  CMP_V0 = 0,
  CMP_V1 = 1,
  CMP_V0_128 = 2,
  CMP_V1_128 = 3,
  RTN_V0 = 4,
  RTN_V1 = 5,

};

// cmp operator type
enum {
  
  IS_NE = 0,
  IS_EQUAL = 1,    // arithemtic equal comparison
  IS_GREATER = 2,  // arithmetic greater comparison
  IS_GE = 3,
  IS_LESSER = 4,   // arithmetic lesser comparison
  IS_LE = 5,
  IS_FP = 8

};

#define FLIP_BIT(_ar, _b)                   \
  do {                                      \
                                            \
    u8 *_arf = (u8 *)(_ar);                 \
    u32 _bf = (_b);                         \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf)&7)); \
                                            \
  } while (0)

#define _ABS(_v0, _v1)                     \
  ({                                       \
                                           \
    u64 _diff = (_v1 >= _v0) ?             \
      (u64)(_v1 - _v0) : (u64)(_v0 - _v1); \
    _diff;                                 \
                                           \
  })                                       \

/* replace everything with different values but stay in the same type */
static void type_replace(afl_state_t *afl, u8 *buf, u32 len) {

  u32 i;
  u8  c;
  for(i = 0; i < len; ++i) {

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
    
    taint->len += len;
  
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

static void add_cmp_tainted_info(afl_state_t *afl, u32 id, u32 hits, u8 type, u32 ofs, u32 len, u8 attr) {
  
  struct tainted_info *new_info;
  struct cmp_map *c_map = afl->shm.cmp_map;

  if ((*afl->tmp_tainted)[id][hits] == NULL) {
  
    new_info = ck_alloc(sizeof(struct tainted_info));
    new_info->id = id;
    new_info->hits = hits;
    new_info->inst_type = c_map->headers[id].type;
    new_info->type = type;
    new_info->attr = attr;
    new_info->ret_addr = c_map->extra.ret_addr[id];

    new_info->taint = add_tainted(new_info->taint, ofs, len);

    (*afl->tmp_tainted)[id][hits] = new_info;

    afl->queue_cur->taint_cur[TAINT_CMP]++;

  }
  else {

    (*afl->tmp_tainted)[id][hits]->taint = 
      add_tainted((*afl->tmp_tainted)[id][hits]->taint, ofs, len);

  }

}

static void add_mem_tainted_info(afl_state_t *afl, u32 id, u32 hits, u8 type, u32 ofs, u8 idx) {
  
  struct tainted_info *new_info;
  struct mem_map *m_map = afl->shm.mem_map;
  if ((*afl->tmp_tainted)[id][hits] == NULL) {
      
    new_info = ck_alloc(sizeof(struct tainted_info));
    new_info->id = id;
    new_info->hits = hits;
    new_info->inst_type = m_map->headers[id].type;
    new_info->type = type;
    
    if (m_map->headers[id].type == HT_GEP_HOOK) {
      
      new_info->gep = ck_alloc(sizeof(struct tainted_gep_info));
      new_info->gep->size = m_map->log[id][hits].__hook_va_arg.size;
      new_info->gep->num_of_idx = m_map->headers[id].num_of_idx;
      new_info->gep->idx_taint = ck_alloc(sizeof(struct tainted *) * new_info->gep->num_of_idx);
      new_info->gep->idx_taint[idx] = add_tainted(new_info->gep->idx_taint[idx], ofs, 1);

    }

    new_info->taint = add_tainted(new_info->taint, ofs, 1);

    (*afl->tmp_tainted)[id][hits] = new_info;
    
    afl->queue_cur->taint_cur[TAINT_MEM]++;

  }
  else {
    
    if (m_map->headers[id].type == HT_GEP_HOOK) {

      (*afl->tmp_tainted)[id][hits]->gep->idx_taint[idx] = 
        add_tainted((*afl->tmp_tainted)[id][hits]->gep->idx_taint[idx], ofs, 1);

    }

    (*afl->tmp_tainted)[id][hits]->taint = 
      add_tainted((*afl->tmp_tainted)[id][hits]->taint, ofs, 1);
    
  }

}

struct tainted* get_constraint(struct tainted *taint, u8 *buf, 
                                u8 *orig_buf, u32 len) {

  for(u32 i = 0; i < len; i++) {

    if (buf[i] != orig_buf[i]) 
      taint = add_tainted(taint, i, 1);

  }

  return taint;

}

void set_constraint(struct tainted *taint, u8 *buf, u8 *orig_buf, 
                      u32 len) {
  
  while(taint != NULL) {

    if (taint->pos >= len || taint->pos + taint->len >= len)
      break;

    memcpy(buf + taint->pos, orig_buf + taint->pos, taint->len);
    taint = taint->next;

  }

}

/**
 * Even the same input, sometimes the results also may be different.
 * Such as the program apply randomness to certain part of progam state 
 * 
 */
void cmp_check_unstable(afl_state_t *afl) {

  for(u32 i = 0; i < CMP_MAP_W; i++) {

    if (!afl->shm.cmp_map->headers[i].hits ||
         afl->pass_stats[TAINT_CMP][i].total >= LINEAR_TIME) continue;

    if (afl->shm.cmp_map->headers[i].hits != afl->orig_cmp_map->headers[i].hits)
      afl->orig_cmp_map->headers[i].hits = 0;

  }

}

void mem_check_unstable(afl_state_t *afl) {

  for(u32 i = 0; i < MEM_MAP_W; i++) {

    if (afl->shm.mem_map->headers[i].hits != afl->orig_mem_map->headers[i].hits)
      afl->orig_mem_map->headers[i].hits = 0;

  }

}

void byte_level_mutate(afl_state_t *afl, u8 *buf, u32 ofs, u32 mutator, u32 val) {
  u32 _bit;
  // mutator
  switch(mutator) {

    case 0: {
      
      type_replace(afl, buf + ofs, 1);
      break;
    
    }
    case 1: {
      
      _bit = (ofs << 3) + rand_below(afl, 8);
      FLIP_BIT(buf, _bit);
      
      break;
    
    }
    case 2: {
      
      *(buf + ofs) += val;
      break;
    
    }
    case 3: {
      
      *(buf + ofs) -= val;
      break;
    
    }
    default:
      break;

  }

}


/* Helper to choose random block len for block operations in fuzz_one().
   Doesn't return zero, provided that max_len is > 0. */

static inline u32 choose_block_len(afl_state_t *afl, u32 limit) {

  u32 min_value, max_value;
  u32 rlim = MIN(afl->queue_cycle, (u32)3);

  if (unlikely(!afl->run_over10m)) { rlim = 1; }

  switch (rand_below(afl, rlim)) {

    case 0:
      min_value = 1;
      max_value = HAVOC_BLK_SMALL;
      break;

    case 1:
      min_value = HAVOC_BLK_SMALL;
      max_value = HAVOC_BLK_MEDIUM;
      break;

    default:

      if (likely(rand_below(afl, 10))) {

        min_value = HAVOC_BLK_MEDIUM;
        max_value = HAVOC_BLK_LARGE;

      } else {

        min_value = HAVOC_BLK_LARGE;
        max_value = HAVOC_BLK_XL;

      }

  }

  if (min_value >= limit) { min_value = 1; }

  return min_value + rand_below(afl, MIN(max_value, limit) - min_value + 1);

}

u8 taint_havoc(afl_state_t *afl, u8* buf, u8* orig_buf, u32 len, 
  u32 stage_max, struct tainted *taint) {
   
  struct tainted *t; 
  s32 r_part;
  u32 use_stacking, r_max, r, temp_len, parts, t_len; 
  u8* out_buf;

  parts = 0;
  t_len = 0;

  t = taint;
  while(t != NULL) {

    parts += 1;  
    t_len += t->len;
    t = t->next;
  
  }
  
  for( ; afl->stage_cur < stage_max; afl->stage_cur++) {
    
    if (parts < 4) {

      use_stacking = 1 << (rand_below(afl, 2));

    }
    else {

      use_stacking = 1 << (1 + rand_below(afl, 4));

    }
   
    afl->stage_cur_val = use_stacking;
      
    for(u32 i = 0; i < use_stacking; i++) {
      
      // random generate tainted part
      r_part = rand_below(afl, parts);
      
      t = taint;
      while(r_part--) {

        t = t->next;

      }  
      
      if (t->pos + t->len > len) continue;

      out_buf = buf + t->pos;
      temp_len = t->len;
  
      if (t->len < 2) {
        
        r_max = 20;

      }
      else if (t->len < 4) {

        r_max = 35;

      }
      else {

        r_max = 53;

      }

      switch ((r = rand_below(afl, r_max))) {
        
        case 0 ... 3: {

          /* Flip a single bit somewhere. Spooky! */

          FLIP_BIT(out_buf, rand_below(afl, temp_len << 3));
          break;

        }
        
        case 4 ... 7: {

        /* Set byte to interesting value. */

        out_buf[rand_below(afl, temp_len)] =
            interesting_8[rand_below(afl, sizeof(interesting_8))];
        break;

        }

        case 8 ... 11: {

          /* Randomly subtract from byte. */

          out_buf[rand_below(afl, temp_len)] -= 1 + rand_below(afl, ARITH_MAX);
          break;

        }

        case 12 ... 15: {

          /* Randomly add to byte. */

          out_buf[rand_below(afl, temp_len)] += 1 + rand_below(afl, ARITH_MAX);
          break;

        }

        case 16 ... 19: {

          /* Just set a random byte to a random value. Because,
             why not. We use XOR with 1-255 to eliminate the
             possibility of a no-op. */

          out_buf[rand_below(afl, temp_len)] ^= 1 + rand_below(afl, 255);
          break;

        }

        case 20 ... 21: {

          /* Set word to interesting value, little endian. */

          if (temp_len < 2) { break; }

          *(u16 *)(out_buf + rand_below(afl, temp_len - 1)) =
              interesting_16[rand_below(afl, sizeof(interesting_16) >> 1)];

          break;

        }

        case 22 ... 23: {

          /* Set word to interesting value, big endian. */

          if (temp_len < 2) { break; }

          *(u16 *)(out_buf + rand_below(afl, temp_len - 1)) = SWAP16(
              interesting_16[rand_below(afl, sizeof(interesting_16) >> 1)]);

          break;

        }

        case 24 ... 25: {

          /* Randomly subtract from word, little endian. */

          if (temp_len < 2) { break; }

          u32 pos = rand_below(afl, temp_len - 1);

          *(u16 *)(out_buf + pos) -= 1 + rand_below(afl, ARITH_MAX);

          break;

        }

        case 26 ... 27: {

          /* Randomly subtract from word, big endian. */

          if (temp_len < 2) { break; }

          u32 pos = rand_below(afl, temp_len - 1);
          u16 num = 1 + rand_below(afl, ARITH_MAX);
          
          *(u16 *)(out_buf + pos) =
              SWAP16(SWAP16(*(u16 *)(out_buf + pos)) - num);

          break;

        }

        case 28 ... 29: {

          /* Randomly add to word, little endian. */

          if (temp_len < 2) { break; }

          u32 pos = rand_below(afl, temp_len - 1);

          *(u16 *)(out_buf + pos) += 1 + rand_below(afl, ARITH_MAX);

          break;

        }

        case 30 ... 31: {

          /* Randomly add to word, big endian. */

          if (temp_len < 2) { break; }

          u32 pos = rand_below(afl, temp_len - 1);
          u16 num = 1 + rand_below(afl, ARITH_MAX);

          *(u16 *)(out_buf + pos) =
              SWAP16(SWAP16(*(u16 *)(out_buf + pos)) + num);

          break;

        }

        case 32 ... 33: {

          /* Overwrite bytes with a randomly selected chunk bytes. */

          if (temp_len < 2) { break; }

          u32 copy_len = choose_block_len(afl, temp_len - 1);
          u32 copy_from = rand_below(afl, temp_len - copy_len + 1);
          u32 copy_to = rand_below(afl, temp_len - copy_len + 1);

          if (likely(copy_from != copy_to)) {

            memmove(out_buf + copy_to, out_buf + copy_from, copy_len);

          }

          break;

        }

        case 34: {

          /* Overwrite bytes with fixed bytes. */

          if (temp_len < 2) { break; }

          u32 copy_len = choose_block_len(afl, temp_len - 1);
          u32 copy_to = rand_below(afl, temp_len - copy_len + 1);

          memset(out_buf + copy_to,
                 rand_below(afl, 2) ? rand_below(afl, 256)
                                    : out_buf[rand_below(afl, temp_len)],
                 copy_len);

          break;

        }

        case 35 ... 36: {

          /* Set dword to interesting value, big endian. */

          if (temp_len < 4) { break; }

          *(u32 *)(out_buf + rand_below(afl, temp_len - 3)) = SWAP32(
              interesting_32[rand_below(afl, sizeof(interesting_32) >> 2)]);

          break;

        }

      

        case 37 ... 38: {

          /* Randomly subtract from dword, little endian. */

          if (temp_len < 4) { break; }

          u32 pos = rand_below(afl, temp_len - 3);

          *(u32 *)(out_buf + pos) -= 1 + rand_below(afl, ARITH_MAX);

          break;

        }

        case 39 ... 40: {

          /* Randomly subtract from dword, big endian. */

          if (temp_len < 4) { break; }

          u32 pos = rand_below(afl, temp_len - 3);
          u32 num = 1 + rand_below(afl, ARITH_MAX);

          *(u32 *)(out_buf + pos) =
              SWAP32(SWAP32(*(u32 *)(out_buf + pos)) - num);

          break;

        }

        case 41 ... 42: {

          /* Randomly add to dword, little endian. */

          if (temp_len < 4) { break; }

          u32 pos = rand_below(afl, temp_len - 3);

          *(u32 *)(out_buf + pos) += 1 + rand_below(afl, ARITH_MAX);

          break;

        }

        case 43 ... 44: {

          /* Randomly add to dword, big endian. */

          if (temp_len < 4) { break; }

          u32 pos = rand_below(afl, temp_len - 3);
          u32 num = 1 + rand_below(afl, ARITH_MAX);

          *(u32 *)(out_buf + pos) =
              SWAP32(SWAP32(*(u32 *)(out_buf + pos)) + num);

          break;

        }
        
        case 45 ... 47: {

          /* Set dword to interesting value, little endian. */

          if (temp_len < 4) { break; }

          *(u32 *)(out_buf + rand_below(afl, temp_len - 3)) =
              interesting_32[rand_below(afl, sizeof(interesting_32) >> 2)];

          break;

        }

        case 48 ... 52: {

          if (afl->extras_cnt) {
            
            u32 use_extra = rand_below(afl, afl->extras_cnt);
            u32 extra_len = afl->extras[use_extra].len;

            if (extra_len > temp_len) { break; }

            u32 insert_at = rand_below(afl, temp_len - extra_len + 1);

            memcpy(out_buf + insert_at, afl->extras[use_extra].data,
                    extra_len);

            break;

          }

          if (afl->a_extras_cnt) {

            u32 use_extra = rand_below(afl, afl->a_extras_cnt);
            u32 extra_len = afl->a_extras[use_extra].len;

            if (extra_len > temp_len) { break; }

            u32 insert_at = rand_below(afl, temp_len - extra_len + 1);

            memcpy(out_buf + insert_at, afl->a_extras[use_extra].data,
                    extra_len);

            break;

          }
         
        }

      }

    } 

    // execute
    if (unlikely(common_fuzz_stuff(afl, buf, len))) { return 1; }
    //restore buf
    memcpy(buf, orig_buf, len);
    
  }

  return 0;

}

u8 exec_path_check(afl_state_t *afl, u64 cksum, u8 mode) {
  
  u64 exec_cksum;

  exec_cksum = hash64(afl->cmplog_fsrv.trace_bits, afl->cmplog_fsrv.map_size, HASH_CONST);

  if (mode == TAINT_CMP) {

    if (exec_cksum == cksum) {

      return 0;
    
    }
  
  }
  else {
      
    return 1;

  }

  return 1;

}

u64 mem_get_val(afl_state_t *afl, u32 cur, u8 idx) {

  struct tainted_info *tmp;
  struct hook_operand *o = NULL;
  struct hook_va_arg_operand *va_o = NULL;
  u64 val = 0;

  tmp = afl->queue_cur->taint[TAINT_MEM][cur];

  if (tmp->inst_type >= HT_GEP_HOOK) {
        
    va_o = &afl->shm.mem_map->log[tmp->id][tmp->hits].__hook_va_arg;
    
  }
  else {

    o = &afl->shm.mem_map->log[tmp->id][tmp->hits].__hook_op;
        
  }

  switch(tmp->type) {

    case MEM_IDX: {

      val = va_o->idx[idx];
      break;

    }
    case MEM_SIZE: {

      val = o->size;
      break;

    }
    default:
      break;

  }

  return val;

}

u8 cmp_is_fulfill(u64 v0, u64 v1, u8 attr) {
  
  // according to cmp type
  switch(attr) {
    
    case IS_NE: {

      if (v0 != v1) {

        return 0;

      }
      else {

        return 1;

      }
      
      break;

    }
    
    case IS_EQUAL: {
      
      if (v0 == v1) {

        return 0;

      }
      else {

        return 1;

      }
      
      break;

    }

    case IS_GREATER: {
      
      if (v0 > v1) {

        return 0;

      }
      else {

        return 1;

      }
      break;

    }

    case IS_GE: {

      if (v0 >= v1) {

        return 0;

      }
      else {

        return 1;

      }
      break;

    }
  
    case IS_LESSER: {

      if (v0 < v1) {

        return 0;

      }
      else {

        return 1;

      }

      break;

    }

    case IS_LE: {
      
      if (v0 <= v1) {

        return 0;

      }
      else {

        return 1;

      }

      break;

    }

    case IS_FP: {

      break;

    }

    default: 
      break;

  }  

  return 1;

}


u8 descend(u64 *orig_v0, u64 *orig_v1, u64 v0, u64 v1, u8 attr) {

  // according to cmp type
  switch(attr) {
    
    case IS_EQUAL: {
      
      // fprintf(f, "gap: %08llu new gap: %08llu\n", 
      //     _ABS(*orig_v0, *orig_v1), _ABS(v0, v1));

      if (_ABS(v0, v1) < _ABS(*orig_v0, *orig_v1)) {

        *orig_v0 = v0;
        *orig_v1 = v1;

        return 0;

      }

      break;
    
    }
    
    case IS_GE:
    case IS_GREATER: {
       
      // fprintf(f, "gap: %08ld new gap: %08ld\n", 
      //     (s64)((s64)*orig_v0 - (s64)*orig_v1), (s64)((s64)v0 - (s64)v1));

      if ((s64)((s64)v0 - (s64)v1) > (s64)((s64)*orig_v0 - (s64)*orig_v1)) {
        
        *orig_v0 = v0;
        *orig_v1 = v1;

        return 0;

      }

      break;

    }

    case IS_LE:
    case IS_LESSER: {

      // fprintf(f, "gap: %08ld new gap: %08ld\n", 
      //     (s64)((s64)*orig_v0 - (s64)*orig_v1), (s64)((s64)v0 - (s64)v1));
     
      if ((s64)((s64)v0 - (s64)v1) < (s64)((s64)*orig_v0 - (s64)*orig_v1)) {
        
        *orig_v0 = v0;
        *orig_v1 = v1;

        return 0;

      }

      break;

    }

    case IS_FP: {

      break;

    }

    default: 
      break;

  }  

  return 1;

}

u8 gradient_fuzz(afl_state_t *afl, u8 *buf, u32 len, u8 *status) {

  u64 orig_hit_cnt, new_hit_cnt;

  orig_hit_cnt = afl->queued_items + afl->saved_crashes;

  if (unlikely(common_fuzz_stuff(afl, buf, len))) { return 1; }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  if (unlikely(new_hit_cnt != orig_hit_cnt)) {

    *status = 1;

  } else {

    *status = 2;

  }

  return 0;

}


/**
 * 
 * f'(x) = [v(x+u) - v(x)] / [u]
 * 
 * if u == 1
 * 
 * f'(x) = [v(x+1) - v(x)]
 * 
 */
u8 cmp_choose_move_ops(afl_state_t *afl, u8* buf, u32 len, u32 ofs, u32 id, 
    u32 hits, u64 *orig_v0, u64 *orig_v1, u8* ops, u8 attr, u64 cksum, FILE *f) {
  
  u64 v0, v1;

  // buf[ofs] + 1 exec  
  *ops = 2;
  byte_level_mutate(afl, buf, ofs, *ops, 1);

  afl->shm.cmp_map->headers[id].type = 0;
  if (unlikely(common_fuzz_cmplog_stuff(afl, buf, len))) goto cmp_choose_move_ops_failed;

  // get new iterate val
  v0 = afl->shm.cmp_map->log[id][hits].v0;
  v1 = afl->shm.cmp_map->log[id][hits].v1;

  //fprintf(f, "v0: %08llu v1: %08llu\n", v0, v1);

  if (hits < afl->shm.cmp_map->headers[id].hits &&
      !cmp_is_fulfill(v0, v1, attr)) {

    return 1;

  }

  // execution path check
  if (hits < afl->shm.cmp_map->headers[id].hits &&
      !exec_path_check(afl, cksum, TAINT_CMP)) {
        
    if (!descend(orig_v0, orig_v1, v0, v1, attr)) {
          
      return 0;

    }
    
  }

  // restore buffer
  byte_level_mutate(afl, buf, ofs, *ops ^ 1, 1);

  // buf[ofs] - 1 exec  
  *ops = 3;
  byte_level_mutate(afl, buf, ofs, *ops, 1);

  afl->shm.cmp_map->headers[id].type = 0;
  if (unlikely(common_fuzz_cmplog_stuff(afl, buf, len))) goto cmp_choose_move_ops_failed;
  
  // get new iterate val
  v0 = afl->shm.cmp_map->log[id][hits].v0;
  v1 = afl->shm.cmp_map->log[id][hits].v1;

  //fprintf(f, "v0: %08llu v1: %08llu\n", v0, v1);
  
  if (hits < afl->shm.cmp_map->headers[id].hits &&
      !cmp_is_fulfill(v0, v1, attr)) {

    return 1;

  }

  // execution path check
  if (hits < afl->shm.cmp_map->headers[id].hits &&
      !exec_path_check(afl, cksum, TAINT_CMP)) {
        
    if (!descend(orig_v0, orig_v1, v0, v1, attr)) {
          
      return 0;

    }
    
  }

cmp_choose_move_ops_failed:

  // restore buffer
  byte_level_mutate(afl, buf, ofs, *ops ^ 1, 1);

  return 2;

}

void reverse_attribute(u8* attr) {
  
  switch(*attr) {
      
    case IS_NE: {
      
      *attr = IS_EQUAL;
      break;

    }

    case IS_GREATER: {

      *attr = IS_LE;
      break;

    }

    case IS_GE: {

      *attr = IS_LESSER;
      break;

    }

    case IS_LESSER: {

      *attr = IS_GE;
      break;

    }

    case IS_LE: {

      *attr = IS_GREATER;
      break;

    }

  }

}

u8 cmp_linear_search(afl_state_t *afl, u8* buf, u32 len, u32 cur, u64 cksum, FILE *f) {

  struct tainted *t; 
  struct tainted_info *tmp;
  u64 orig_v0, orig_v1, v0, v1;
  u8 ops = 2, attr, status = 0, reverse = 0, step = 1;
  
  tmp = afl->queue_cur->taint[TAINT_CMP][cur];
  t = tmp->taint;
  
  // exec
  // afl->shm.cmp_map->headers[tmp->id].type = 0;
  // if (unlikely(common_fuzz_cmplog_stuff(afl, buf, len))) return 0;
  
  // get new iterate val
  orig_v0 = v0 = afl->orig_cmp_map->log[tmp->id][tmp->hits].v0;
  orig_v1 = v1 = afl->orig_cmp_map->log[tmp->id][tmp->hits].v1;

  //fprintf(f, "v0: %08llu v1: %08llu\n", orig_v0, orig_v1);
        
  attr = tmp->attr;

  // not yet handling
  if (attr > IS_LE) 
    return 0; 

  if (!cmp_is_fulfill(v0, v1, attr)) {
    
    if (attr == IS_EQUAL)
      return 1;

    reverse = 1;
    reverse_attribute(&attr);

  }

  if (afl->pass_stats[TAINT_CMP][tmp->id].ls_total[reverse] >= PASS_TIME ||
      afl->pass_stats[TAINT_CMP][tmp->id].ls_faileds[reverse] >= PASS_TIME)
    return 0;

  //fprintf(f, "attr: %u\n", attr);

  while(t != NULL) {
    
    for(u32 i = 0; i < t->len; i++) {
      
      afl->stage_cur_byte = t->pos + i;

      // fprintf(f, "ofs: %u\n", t->pos + i);
      // decide iterate direction, check if this offset is able to affect inst. 
      status = cmp_choose_move_ops(afl, buf, len, t->pos + i, tmp->id, tmp->hits, 
                    &orig_v0, &orig_v1, &ops, attr, cksum, f);

      if (status == 1) {
        
        //fprintf(f, "solved\n");
        afl->pass_stats[TAINT_CMP][tmp->id].ls_total[reverse]++;

        if (exec_path_check(afl, cksum, TAINT_CMP)) {
          
          // try
          gradient_fuzz(afl, buf, len, &status);
        
          // restore buf
          //byte_level_mutate(afl, buf, t->pos + i, ops ^ 1, 1); 

        }

        return 1;

      }
      else if (status == 2) {
        
        continue;

      }

      u32 k = 0xff;
      while (k--) {

        // iterate
        byte_level_mutate(afl, buf, t->pos + i, ops, step);
    
        // exec
        afl->shm.cmp_map->headers[tmp->id].type = 0;
        if (unlikely(common_fuzz_cmplog_stuff(afl, buf, len))) goto linear_ofs_iter_failed;
        
        // get new iterate val
        v0 = afl->shm.cmp_map->log[tmp->id][tmp->hits].v0;
        v1 = afl->shm.cmp_map->log[tmp->id][tmp->hits].v1;

        //fprintf(f, "v0: %08llu v1: %08llu\n", v0, v1);

        if (tmp->hits < afl->shm.cmp_map->headers[tmp->id].hits && 
          !cmp_is_fulfill(v0, v1, attr)) {
          
          //fprintf(f, "solved\n");
          afl->pass_stats[TAINT_CMP][tmp->id].ls_total[reverse]++;
        
          if (exec_path_check(afl, cksum, TAINT_CMP)) { 

            // try
            gradient_fuzz(afl, buf, len, &status);

            // restore buf
            //byte_level_mutate(afl, buf, t->pos + i, ops ^ 1, 1); 

          }

          return 1;

        }

        // execution path check, skip this iterate if execution path changed
        if (tmp->hits >= afl->shm.cmp_map->headers[tmp->id].hits ||
            exec_path_check(afl, cksum, TAINT_CMP)) {
          
          // failed
          goto linear_ofs_iter_failed;

        }
        
        if (!descend(&orig_v0, &orig_v1, v0, v1, attr)) {
          
          continue;
        
        }

        // failed       
      linear_ofs_iter_failed:
        // try
        // gradient_fuzz(afl, buf, len, &status);  
        // restore buf
        byte_level_mutate(afl, buf, t->pos + i, ops ^ 1, 1); 

        break;

      }

    }

    t = t->next;

  }
  

  afl->pass_stats[TAINT_CMP][tmp->id].ls_faileds[reverse]++;

  return 0;

}

void taint_debug(afl_state_t *afl, u8 mode) {
  
  struct tainted *t;
  struct tainted_info *tmp;
  u8 *queue_fn = "";
  FILE *f;

  if (mode == TAINT_CMP) {
  
    queue_fn = alloc_printf("%s/taint/cmp/id:%06u,%06u,debug", 
      afl->out_dir, afl->queue_cur->id, afl->tainted_len);
  
  }
  else {
    
    queue_fn = alloc_printf("%s/taint/mem/id:%06u,%06u,debug", 
      afl->out_dir, afl->queue_cur->id, afl->tainted_len);

  }

  f = create_ffile(queue_fn);

  for(u32 i = 0; i < afl->queue_cur->taint_cur[mode]; i++) {

    tmp = afl->queue_cur->taint[mode][i];

    fprintf(f, "id: %u hits: %u inst type: %u type: %u\n", 
                        tmp->id,
                        tmp->hits,
                        tmp->inst_type,
                        tmp->type);

    t = tmp->taint;

    while(t != NULL) {
      
      fprintf(f, "pos: %u len: %u ", t->pos, t->len);
      t = t->next;

    }
    fprintf(f, "\n");
    
    if (afl->queue_cur->taint[mode][i]->inst_type == HT_GEP_HOOK) {
    
      fprintf(f, "GEP size: %u num_of_idx: %u\n", tmp->gep->size, 
                                                       tmp->gep->num_of_idx);
      
      for(u32 j = 0; j < tmp->gep->num_of_idx; j++) {

        if (tmp->gep->idx_taint[j] != NULL) {
        
          t = tmp->gep->idx_taint[j];

          fprintf(f, "taint idx: %u ", j);
          while(t != NULL) {
      
            fprintf(f, "pos: %u len: %u ", t->pos, t->len);
            t = t->next;

          }
          fprintf(f, "\n");
          
        }

      }

    }
 
  }

  fclose(f);
  ck_free(queue_fn);

}

void taint_free(struct tainted *taint) {
  
  struct tainted *t = taint;
  while(t != NULL) {

    taint = t->next;
    ck_free(t);
    t = taint;

  }
  
}


void taint_info_free(struct tainted_info *info) {

  taint_free(info->taint);
  
  if (info->inst_type == HT_GEP_HOOK) {

    for(u32 j = 0; j < info->gep->num_of_idx; j++) {
      
      taint_free(info->gep->idx_taint[j]);
      
    }

  }

  ck_free(info);

}

void destroy_taint(afl_state_t *afl, struct queue_entry *q) {

  // cmplog mode
  if (afl->shm.cmplog_mode) {
    // free c_bytes
    if (q->taint_cur[TAINT_CMP])
      taint_free(q->c_bytes[TAINT_CMP]);
    // free taint
    for(u32 i = 0; i < q->taint_cur[TAINT_CMP]; i++) {
     
      taint_info_free(q->taint[TAINT_CMP][i]);
      
    }

  }
  // memlog mode
  if (afl->shm.memlog_mode) {
    // free c_bytes
    if (q->taint_cur[TAINT_MEM])
      taint_free(q->c_bytes[TAINT_MEM]);
    // free taint
    for(u32 i = 0; i < q->taint_cur[TAINT_MEM]; i++) {
      
      taint_info_free(q->taint[TAINT_MEM][i]);
    
    }

  }

}

void update_c_bytes_len(afl_state_t *afl, u8 mode) {
  
  struct tainted *t;
  
  afl->tainted_len = 0;
  t = afl->queue_cur->c_bytes[mode];
  while(t != NULL) {

    afl->tainted_len += t->len;
    t = t->next;

  }

}

void update_state(afl_state_t *afl, u8 mode) {
  
  // update tainted input length
  if (!afl->tainted_len)   
    update_c_bytes_len(afl, mode);

  afl->taint_mode = mode;

}

void write_to_taint(afl_state_t *afl, u8 mode) {
  
  struct tainted *t;
  struct tainted_info **tmp;
  u8 *queue_fn = "";
  FILE *f;
  
  // update tainted input length
  update_c_bytes_len(afl, mode);

  // critical bytes 
  if (mode == TAINT_CMP) {

    queue_fn = alloc_printf("%s/taint/cmp/id:%06u,%06u,time:%llu,%s.symranges", 
      afl->out_dir, afl->queue_cur->id, afl->tainted_len, 
      get_cur_time() + afl->prev_run_time - afl->start_time, 
      strrchr(afl->queue_cur->fname, '/') + 1);
  
  }
  else {

    queue_fn = alloc_printf("%s/taint/mem/id:%06u,%06u,time:%llu,%s.symranges", 
      afl->out_dir, afl->queue_cur->id, afl->tainted_len, 
      get_cur_time() + afl->prev_run_time - afl->start_time,
      strrchr(afl->queue_cur->fname, '/') + 1);

  }
 
  f = create_ffile(queue_fn);

  t = afl->queue_cur->c_bytes[mode];
  
  while(t != NULL) {
  
    fprintf(f, "%u-%u\n", t->pos, t->len);
    t = t->next;
  
  }

  fclose(f);
  ck_free(queue_fn);
  
  // GEP size
  if (mode == TAINT_MEM) {

    queue_fn = alloc_printf("%s/taint/mem/size/id:%06u,%06u,time:%llu,%s", 
      afl->out_dir, afl->queue_cur->id, afl->tainted_len,
      get_cur_time() + afl->prev_run_time - afl->start_time, 
      strrchr(afl->queue_cur->fname, '/') + 1);
    
    f = create_ffile(queue_fn);

    tmp = afl->queue_cur->taint[mode];
    
    for(u32 i = 0; i < afl->queue_cur->taint_cur[mode]; i++) {
      // GEP inst.
      if (i > 0 && tmp[i]->id == tmp[i-1]->id) 
        continue;
      
      if (tmp[i]->inst_type == HT_GEP_HOOK) {
        
        fprintf(f, "%u-%u\n", tmp[i]->id, tmp[i]->gep->size);
      
      }

    } 

    fclose(f);
    ck_free(queue_fn);

  }  
  // selected ret
  if (mode == TAINT_CMP) {

    u32 cnt = 0;
    tmp = afl->queue_cur->taint[TAINT_CMP];

    for(u32 i = 0; i < afl->queue_cur->taint_cur[TAINT_CMP]; i++) {
      
      if (i > 0 && tmp[i]->id == tmp[i-1]->id) 
        continue;
      cnt++;

    }
    
    queue_fn = alloc_printf("%s/taint/cmp/id:%06u,ret-addr-%u", afl->out_dir, 
                                                      afl->queue_cur->id, cnt);
    f = create_ffile(queue_fn);

    for(u32 i = 0; i < afl->queue_cur->taint_cur[TAINT_CMP]; i++) {
    
      if (i > 0 && tmp[i]->id == tmp[i-1]->id) 
        continue;

      if (afl->pass_stats[TAINT_CMP][tmp[i]->id].faileds >= 0xff || 
        afl->pass_stats[TAINT_CMP][tmp[i]->id].total >= 0xff)
      continue;

      fprintf(f, "%llx %u\n", tmp[i]->ret_addr, tmp[i]->id);
   
    }

    fclose(f);
    ck_free(queue_fn);

  }
  
}

// cmplog mode instruction inference
u8 ins_inference(afl_state_t *afl, u8* buf, u8 *orig_buf, u32 len, u8 *cbuf, u32 ofs, u32 i, u32 loggeds) {
  
  struct cmp_operands *o = NULL, *orig_o = NULL;
  struct cmp_header   *h = NULL;

#ifdef WORD_SIZE_64
  u32  is_n = 0;
  u128 s128_v0 = 0, s128_v1 = 0, orig_s128_v0 = 0, orig_s128_v1 = 0;
#endif
  u32 hshape;
  u64 s_v0, s_v1;
  u8  s_v0_fixed = 1, s_v1_fixed = 1;
  u8  s_v0_inc = 1, s_v1_inc = 1;
  u8  s_v0_dec = 1, s_v1_dec = 1;

  u8  status = 0, found_one = 0, ret = 0;
  u32 taint_len = 8, sect = MIN((u32)TAINT_SECTION, (u32)(len - ofs));

  h = &afl->shm.cmp_map->headers[i];  
  hshape = SHAPE_BYTES(h->shape);

  #ifdef WORD_SIZE_64
    switch (hshape) {

      case 1:
      case 2:
      case 4:
      case 8:
        break;
      default:
        is_n = 1;

    }
  #endif

  for(u32 j = 0; j < loggeds; j++) {
        
    //common subpath check
    // if (afl->orig_cmp_map->cksum[i][j] != afl->shm.cmp_map->cksum[i][j]) continue;

    o = &afl->shm.cmp_map->log[i][j];
    orig_o = &afl->orig_cmp_map->log[i][j];

    // loop detection code
    if (j == 0) {

      s_v0 = o->v0;
      s_v1 = o->v1;

    } else {

      if (s_v0 != o->v0) { s_v0_fixed = 0; }
      if (s_v1 != o->v1) { s_v1_fixed = 0; }
      if (s_v0 + 1 != o->v0) { s_v0_inc = 0; }
      if (s_v1 + 1 != o->v1) { s_v1_inc = 0; }
      if (s_v0 - 1 != o->v0) { s_v0_dec = 0; }
      if (s_v1 - 1 != o->v1) { s_v1_dec = 0; }
      s_v0 = o->v0;
      s_v1 = o->v1;

    } 

    for (u32 k = 0; k < j; ++k) {

      if (afl->shm.cmp_map->log[i][k].v0 == o->v0 &&
          afl->shm.cmp_map->log[i][k].v1 == o->v1) {

        goto ins_inference_next_iter;

      }

    }

    if (afl->ins_tainted[i] & 1 << j) continue;

#ifdef WORD_SIZE_64
    if (unlikely(is_n)) {

      s128_v0 = ((u128)o->v0) + (((u128)o->v0_128) << 64);
      s128_v1 = ((u128)o->v1) + (((u128)o->v1_128) << 64);
      orig_s128_v0 = ((u128)orig_o->v0) + (((u128)orig_o->v0_128) << 64);
      orig_s128_v1 = ((u128)orig_o->v1) + (((u128)orig_o->v1_128) << 64);

    }

#endif

#ifdef WORD_SIZE_64
    if (is_n) {  // _ExtInt special case including u128

      // not handling yet
      if (s128_v0 != orig_s128_v0 && orig_s128_v0 != orig_s128_v1) {
        
        afl->ins_tainted[i] |= 1 << j;

        ret = 1;

        afl->queue_cur->c_bytes[TAINT_CMP] = 
          add_tainted(afl->queue_cur->c_bytes[TAINT_CMP], ofs, sect);
        add_cmp_tainted_info(afl, i, j, CMP_V0_128, ofs, sect, h->attribute);
  
      }
      else if (s128_v1 != orig_s128_v1 && orig_s128_v1 != orig_s128_v0) {
        
        afl->ins_tainted[i] |= 1 << j;

        ret = 1;

        afl->queue_cur->c_bytes[TAINT_CMP] = 
          add_tainted(afl->queue_cur->c_bytes[TAINT_CMP], ofs, sect);
        add_cmp_tainted_info(afl, i, j, CMP_V1_128, ofs, sect, h->attribute);

      }

    }

#endif
        
    if (o->v0 != orig_o->v0 && orig_o->v0 != orig_o->v1) {
      
      afl->ins_tainted[i] |= 1 << j;

      ret = 1;

      afl->queue_cur->c_bytes[TAINT_CMP] = 
          add_tainted(afl->queue_cur->c_bytes[TAINT_CMP], ofs, sect);
        add_cmp_tainted_info(afl, i, j, CMP_V0, ofs, sect, h->attribute);
      
    }
    else if (o->v1 != orig_o->v1 && orig_o->v0 != orig_o->v1) {
      
      afl->ins_tainted[i] |= 1 << j;

      ret = 1;

      afl->queue_cur->c_bytes[TAINT_CMP] = 
          add_tainted(afl->queue_cur->c_bytes[TAINT_CMP], ofs, sect);
        add_cmp_tainted_info(afl, i, j, CMP_V1, ofs, sect, h->attribute);
      
    }

    if (!afl->taint_alone_mode) {

      for(u32 k = 0; k < sect; k++) {
      
        status = 0;
            
#ifdef WORD_SIZE_64
        if (is_n) {  // _ExtInt special case including u128

          // not handling yet
          if (s128_v0 != orig_s128_v0 && orig_s128_v0 != orig_s128_v1) {

            if (unlikely(cmp_extend_encodingN(
                      afl, h, s128_v0, s128_v1, orig_s128_v0, orig_s128_v1,
                      h->attribute, ofs + k, taint_len, orig_buf, buf, cbuf, len, 1,
                      1, &status))) {

              return ret;

            }

          }
          
          if (status == 1) {

            found_one = 1;
            break;

          }
            
          if (s128_v1 != orig_s128_v1 && orig_s128_v1 != orig_s128_v0) {
            
            if (unlikely(cmp_extend_encodingN(
                      afl, h, s128_v1, s128_v0, orig_s128_v1, orig_s128_v0,
                      SWAPA(h->attribute), ofs + k, taint_len, orig_buf, buf, cbuf, len,
                      1, 1, &status))) {

              return ret;

            }

          }

        }

        if (status == 1) {

          found_one = 1;
          break;

        }

#endif
            
        if (o->v0 != orig_o->v0 && orig_o->v0 != orig_o->v1) {

          if (unlikely(cmp_extend_encoding(
                    afl, h, o->v0, o->v1, orig_o->v0, orig_o->v1, h->attribute, ofs + k,
                    taint_len, orig_buf, buf, cbuf, len, 1, 1, &status))) {
            
            return ret;

          }

        }

        if (status == 1) {

          found_one = 1;
          break;

        }
            
        if (o->v1 != orig_o->v1 && orig_o->v0 != orig_o->v1) {

          if (unlikely(cmp_extend_encoding(afl, h, o->v1, o->v0, orig_o->v1,
                                            orig_o->v0, SWAPA(h->attribute), ofs + k,
                                            taint_len, orig_buf, buf, cbuf, len, 1,
                                            1, &status))) {
            
            return ret;

          }

        }

        if (status == 1) {

          found_one = 1;
          break;

        }

      }

      // we only learn 16 bit +
      if (hshape > 1) {

        if (!found_one || afl->queue_cur->is_ascii) {

#ifdef WORD_SIZE_64
          if (unlikely(is_n)) {

            if (!found_one ||
                check_if_text_buf((u8 *)&s128_v0, SHAPE_BYTES(h->shape)) ==
                    SHAPE_BYTES(h->shape))
              try_to_add_to_dictN(afl, s128_v0, SHAPE_BYTES(h->shape));
            if (!found_one ||
                check_if_text_buf((u8 *)&s128_v1, SHAPE_BYTES(h->shape)) ==
                    SHAPE_BYTES(h->shape))
              try_to_add_to_dictN(afl, s128_v1, SHAPE_BYTES(h->shape));

          } else

#endif
          {

            if (!memcmp((u8 *)&o->v0, (u8 *)&orig_o->v0, SHAPE_BYTES(h->shape)) &&
                (!found_one ||
                check_if_text_buf((u8 *)&o->v0, SHAPE_BYTES(h->shape)) ==
                    SHAPE_BYTES(h->shape)))
              try_to_add_to_dict(afl, o->v0, SHAPE_BYTES(h->shape));
            if (!memcmp((u8 *)&o->v1, (u8 *)&orig_o->v1, SHAPE_BYTES(h->shape)) &&
                (!found_one ||
                check_if_text_buf((u8 *)&o->v1, SHAPE_BYTES(h->shape)) ==
                    SHAPE_BYTES(h->shape)))
              try_to_add_to_dict(afl, o->v1, SHAPE_BYTES(h->shape));

          }

        }

      }

    }

  ins_inference_next_iter:
    continue;

  }

  if (loggeds > 3 && ((s_v0_fixed && s_v1_inc) || (s_v1_fixed && s_v0_inc) ||
                      (s_v0_fixed && s_v1_dec) || (s_v1_fixed && s_v0_dec))) {
    //ignore loop
    afl->pass_stats[TAINT_CMP][i].total = 0xff;

  }
  
  return ret;

}

u8 rtn_inference(afl_state_t *afl, u8* buf, u8 *orig_buf, u32 len, u8 *cbuf, u32 ofs, u32 i, u32 loggeds) {

  struct cmpfn_operands *o = NULL, *orig_o = NULL;
  struct cmp_header *h = NULL;
  u8  status = 0, found_one = 0, ret = 0, is_tainted = 0;
  u32 taint_len = 8, sect = MIN((u32)TAINT_SECTION, (u32)(len - ofs)),
      v0_len = 0, v1_len = 0; 

  h = &afl->shm.cmp_map->headers[i]; 
  

  for(u32 j = 0; j < loggeds; j++) {
        
    //common subpath check
    // if (afl->orig_cmp_map->cksum[i][j] != afl->shm.cmp_map->cksum[i][j]) continue;

    o = &((struct cmpfn_operands *)afl->shm.cmp_map->log[i])[j];
    orig_o = &((struct cmpfn_operands *)afl->orig_cmp_map->log[i])[j];

    for (u32 k = 0; k < j; ++k) {

      if (!memcmp(&((struct cmpfn_operands *)afl->shm.cmp_map->log[i])[k], o,
                  sizeof(struct cmpfn_operands))) {

        goto rtn_inference_next_iter;

      }
    
    }

    is_tainted = 0;

    v0_len = o->v0_len;
    v1_len = o->v1_len;

    if (v0_len > 0x80)
      v0_len -= 0x80;
    
    if (v1_len > 0x80)
      v1_len -= 0x80;

    if (o->v0_len != orig_o->v0_len || (memcmp(o->v0, orig_o->v0, v0_len))) {

      ret = 1;

      is_tainted = 1;

      afl->queue_cur->c_bytes[TAINT_CMP] = 
        add_tainted(afl->queue_cur->c_bytes[TAINT_CMP], ofs, sect);
      add_cmp_tainted_info(afl, i, j, RTN_V0, ofs, sect, h->attribute);
     
    }
    else if (o->v1_len != orig_o->v1_len || (memcmp(o->v1, orig_o->v1, v1_len))) {
      
      ret = 1;
      
      is_tainted = 2;

      afl->queue_cur->c_bytes[TAINT_CMP] = 
        add_tainted(afl->queue_cur->c_bytes[TAINT_CMP], ofs, sect);
      add_cmp_tainted_info(afl, i, j, RTN_V1, ofs, sect, h->attribute);
      
    }

    /*if (!afl->taint_alone_mode) {

      for(u32 k = 0; k < sect; k++) {
        
        status = 0;

        if (is_tainted == 1) {
          
          if (unlikely(rtn_extend_encoding(afl, 0, o, orig_o, ofs + k, taint_len,
                                        orig_buf, buf, cbuf, len, 1,
                                        &status))) {

            return 1;

          }

          if (status == 1) {

            found_one = 1;
            break;

          }
        
        }

        status = 0;

        if (is_tainted == 2) {

          if (unlikely(rtn_extend_encoding(afl, 1, o, orig_o, ofs + k, taint_len,
                                          orig_buf, buf, cbuf, len, 1,
                                          &status))) {

            return 1;

          }

          if (status == 1) {

            found_one = 1;
            break;

          }

        }

      }

      //  if (unlikely(!afl->its_pass_stats[key].total)) {

      if (!found_one || afl->queue_cur->is_ascii) {

        // if (unlikely(!afl->its_pass_stats[key].total)) {

        u32 shape_len = SHAPE_BYTES(h->shape);
        u32 v0_len = shape_len, v1_len = shape_len;
        if (afl->queue_cur->is_ascii ||
            check_if_text_buf((u8 *)&o->v0, shape_len) == shape_len) {

          if (strlen(o->v0)) v0_len = strlen(o->v0);

        }

        if (afl->queue_cur->is_ascii ||
            check_if_text_buf((u8 *)&o->v1, shape_len) == shape_len) {

          if (strlen(o->v1)) v1_len = strlen(o->v1);

        }

        // fprintf(stderr, "SHOULD: found:%u ascii:%u text?%u:%u %u:%s %u:%s \n",
        // found_one, afl->queue_cur->is_ascii, check_if_text_buf((u8 *)&o->v0,
        // shape_len), check_if_text_buf((u8 *)&o->v1, shape_len), v0_len,
        // o->v0, v1_len, o->v1);

        if (!memcmp(o->v0, orig_o->v0, v0_len) ||
            (!found_one || check_if_text_buf((u8 *)&o->v0, v0_len) == v0_len))
          maybe_add_auto(afl, o->v0, v0_len);
        if (!memcmp(o->v1, orig_o->v1, v1_len) ||
            (!found_one || check_if_text_buf((u8 *)&o->v1, v1_len) == v1_len))
          maybe_add_auto(afl, o->v1, v1_len);

        //}

      }

    }*/

    rtn_inference_next_iter:
      continue;

  }

  return ret;

}

void cmp_inference(afl_state_t *afl, u8 *buf, u8 *orig_buf, u32 len, u8 *cbuf, u32 ofs) {
  
  u8 ret = 0;
  u32 loggeds;
  
  for(u32 i = 0; i < CMP_MAP_W; i++) {

    loggeds = MIN((u32)(afl->shm.cmp_map->headers[i].hits), 
      (u32)(afl->orig_cmp_map->headers[i].hits));
    
    // skip inst.
    if (!loggeds ||
        afl->pass_stats[TAINT_CMP][i].total >= LINEAR_TIME)
        continue;

    if (loggeds > CMP_MAP_H) 
      loggeds = CMP_MAP_H;
    
    
    if (afl->shm.cmp_map->headers[i].type == CMP_TYPE_INS) {

      ret = ins_inference(afl, buf, orig_buf, len, cbuf, ofs, i, loggeds);

    }
    else {

      if (afl->taint_alone_mode)
        ret = rtn_inference(afl, buf, orig_buf, len, cbuf, ofs, i, loggeds);
    
    }
    
  }

}

void mem_inference(afl_state_t *afl, u32 ofs) {

  struct hook_va_arg_operand *va_o = NULL, *orig_va_o = NULL;
  struct hook_operand *o = NULL, *orig_o = NULL;
  u32 loggeds;

  for(u32 i = 0; i < MEM_MAP_W; i++) {
    
    // skip inconsistent inst.
    loggeds = MIN((u32)(afl->shm.mem_map->headers[i].hits), 
      (u32)(afl->orig_mem_map->headers[i].hits));
    if (!loggeds) continue;

    // skip inst. which fails too many times
    if (afl->pass_stats[TAINT_MEM][i].faileds >= MEMLOG_FAIL_MAX || 
        afl->pass_stats[TAINT_MEM][i].total >= MEMLOG_FAIL_MAX) 
      continue;

    if (loggeds > MEM_MAP_H) 
      loggeds = MEM_MAP_H;
    
    for(u32 j = 0; j < loggeds; j++) {
      
      // common subpath checks
      // if (afl->orig_mem_map->cksum[i][j] != afl->shm.mem_map->cksum[i][j]) continue;
   
      if (afl->shm.mem_map->headers[i].type >= HT_GEP_HOOK) {
        
        va_o = &afl->shm.mem_map->log[i][j].__hook_va_arg;
        orig_va_o = &afl->orig_mem_map->log[i][j].__hook_va_arg;

      }
      else {

        o = &afl->shm.mem_map->log[i][j].__hook_op;
        orig_o = &afl->orig_mem_map->log[i][j].__hook_op;
        
      }

      switch (afl->shm.mem_map->headers[i].type) {
        
        case HT_HOOK1:
        case HT_HOOK2:
        case HT_HOOK3: {

          for (u32 k = 0; k < j; ++k) {

            if (afl->shm.mem_map->log[i][k].__hook_op.size == o->size) {
              
              goto mem_inference_next_iter;

            }

          }

          // if (o->dst != orig_o->dst) 
          // if (o->src != orig_o->src)
          if (o->size != orig_o->size) {
            
            afl->queue_cur->c_bytes[TAINT_MEM] = 
              add_tainted(afl->queue_cur->c_bytes[TAINT_MEM], ofs, 1);
            add_mem_tainted_info(afl, i, j, MEM_SIZE, ofs, 0);

          }
          break;

        }
    
        case HT_HOOK4: {
          // if (o->src != orig_o->src) 
          break;

        }
        case HT_GEP_HOOK: {  

          for(u32 idx = 0; idx < afl->shm.mem_map->headers[i].num_of_idx; idx++) {
            
            for (u32 k = 0; k < j; ++k) {

              if (afl->shm.mem_map->log[i][k].__hook_va_arg.idx[idx] == va_o->idx[idx]) {
                
                goto gep_idx_next_iter;

              }

            }

            if (va_o->idx[idx] != orig_va_o->idx[idx]) {
  
              afl->queue_cur->c_bytes[TAINT_MEM] = 
                add_tainted(afl->queue_cur->c_bytes[TAINT_MEM], ofs, 1);
              add_mem_tainted_info(afl, i, j, MEM_IDX, ofs, idx);
            
            }

            gep_idx_next_iter:
              continue;

          }
          // if (va_o->ptr != orig_va_o->ptr) 
          break;

        }
        default:
          break;

      }

    mem_inference_next_iter:
      continue;

    }
  
  }

}

u8 taint_fuzz(afl_state_t *afl, u8 *buf, u8 *orig_buf, u32 len, u8 mode) {  
  
  struct tainted_info **tmp;
  u32 idx = 0;

  update_state(afl, mode);

  // tainted part only mutation
  u64 orig_hit_cnt, new_hit_cnt, orig_execs;
  u32 inst_stage_max, j;
  
  afl->stage_name = "taint havoc";
  afl->stage_short = "th";
  afl->stage_cur = 0;
  
  tmp = afl->queue_cur->taint[mode];

  orig_hit_cnt = afl->queued_items + afl->saved_crashes;
  orig_execs = afl->fsrv.total_execs;

  inst_stage_max = afl->stage_max / afl->queue_cur->taint_cur[mode]; 
  
  if (inst_stage_max < MIN_TAINTED_HAVOC) {
    
    inst_stage_max = MIN_TAINTED_HAVOC;
    
    j = 0;
    for(u32 i = 0; i < afl->stage_max / inst_stage_max; i++) {

      idx = rand_below(afl, afl->queue_cur->taint_cur[mode]);
    
      if (taint_havoc(afl, buf, orig_buf, len, 
          (++j) * inst_stage_max, tmp[idx]->taint)) goto taint_fuzz_failed;
    
    }

  }
  else {

    j = 0;
    for(u32 i = 0; i < afl->queue_cur->taint_cur[mode]; i++) {
  
      if (i > 0 && tmp[i]->id == tmp[i-1]->id) 
        continue;

      if (taint_havoc(afl, buf, orig_buf, len, 
            (++j) * inst_stage_max, tmp[i]->taint)) goto taint_fuzz_failed;

    }

  }
  
  // whole tainted part havoc
    
  if (taint_havoc(afl, buf, orig_buf, len, 
        (j + 4) * inst_stage_max, afl->queue_cur->c_bytes[mode])) goto taint_fuzz_failed;

  new_hit_cnt = afl->queued_items + afl->saved_crashes;
  afl->stage_finds[STAGE_TAINT_HAVOC] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_TAINT_HAVOC] += afl->fsrv.total_execs - orig_execs;

  // linear search

  u8 *queue_fn = "";
  FILE *f = NULL;
  u8 ret = 0;
  u64 cksum = 0;

  afl->stage_name = "linear search";
  afl->stage_short = "ls";
  
  orig_hit_cnt = afl->queued_items + afl->saved_crashes;
  orig_execs = afl->fsrv.total_execs;
  
  /*queue_fn = alloc_printf("%s/taint/cmp/id:%06u,ls,debug", 
    afl->out_dir, afl->queue_cur->id);

  f = create_ffile(queue_fn);*/
  
  memset(afl->shm.cmp_map->headers, 0, sizeof(struct cmp_header) * CMP_MAP_W);
  if (common_fuzz_cmplog_stuff(afl, orig_buf, len)) return 1;
  memcpy(afl->orig_cmp_map->log, afl->shm.cmp_map->log, sizeof(struct cmp_operands) * CMP_MAP_W * CMP_MAP_H);
  cksum = hash64(afl->cmplog_fsrv.trace_bits, afl->cmplog_fsrv.map_size, HASH_CONST);
 
  afl->stage_cur = 0;

  afl->stage_max = afl->queue_cur->taint_cur[mode];

  for(; afl->stage_cur < afl->stage_max; afl->stage_cur++) {
  
    idx = afl->stage_cur;

    //fprintf(f, "id: %06u hits: %06u type: %06u inst_type: %06u attr: %06u\n", 
    //    tmp[idx]->id, tmp[idx]->hits, tmp[idx]->type, tmp[idx]->inst_type, tmp[idx]->attr);

    memcpy(buf, orig_buf, len);

    if (tmp[idx]->inst_type == CMP_TYPE_INS && 
      (tmp[idx]->type == CMP_V0 || tmp[idx]->type == CMP_V1)) {
      
      ret = cmp_linear_search(afl, buf, len, idx, cksum, f);
      
    }
    else if (tmp[idx]->inst_type == CMP_TYPE_INS &&
            (tmp[idx]->type == CMP_V0_128 || tmp[idx]->type == CMP_V1_128)) {
      
      // u128 not yet handling
      continue;

    }
    else {

      // rtn not yet handling
      continue;

    }

    show_stats(afl);

  }
    
  new_hit_cnt = afl->queued_items + afl->saved_crashes;
  afl->stage_finds[STAGE_TAINT_LS] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_TAINT_LS] += afl->fsrv.total_execs - orig_execs;

taint_fuzz_failed:

  memcpy(buf, orig_buf, len);

  //ck_free(queue_fn);
  //fclose(f);

  return 0;

}

u8 taint(afl_state_t *afl, u8 *buf, u8 *orig_buf, u32 len, u8 mode) {
  
  u32 sect;
  u64 orig_hit_cnt, new_hit_cnt, orig_execs;
  u8 *cbuf = NULL, *virgin_backup = NULL;
  // u64 cksum = 0, exec_cksum = 0;

  orig_hit_cnt = afl->queued_items + afl->saved_crashes;
  orig_execs = afl->fsrv.total_execs;

  if (!afl->taint_alone_mode) {

#ifdef CMPLOG_COMBINE
  
  cbuf = afl_realloc((void **)&afl->in_scratch_buf, len + 128);
  memcpy(cbuf, orig_buf, len);
  virgin_backup = afl_realloc((void **)&afl->ex_buf, afl->shm.map_size);
  memcpy(virgin_backup, afl->virgin_bits, afl->shm.map_size);
  
#endif

  }

  // Reset bitmap before each execution.
  // memset(taint_mode.map, 0, taint_mode.map_size);
  memset(afl->shm.cmp_map->headers, 0, sizeof(struct cmp_header) * CMP_MAP_W);
  if (unlikely((*taint_mode.ops.common_fuzz_staff)(afl, orig_buf, len))) return 1;
  
  memcpy(taint_mode.orig_map, taint_mode.map, taint_mode.map_size);

  // cksum = hash64(afl->cmplog_fsrv.trace_bits, afl->cmplog_fsrv.map_size, HASH_CONST);
  
  // check unstable
  memset(afl->shm.cmp_map->headers, 0, sizeof(struct cmp_header) * CMP_MAP_W);
  if (unlikely((*taint_mode.ops.common_fuzz_staff)(afl, orig_buf, len))) return 1;
  
  (*taint_mode.ops.check_unstable)(afl);
 
  // taint
  for(u32 i = 0; i < len; i += TAINT_SECTION) {

    if (len - i < TAINT_SECTION)
      sect = len - i;
    else 
      sect = TAINT_SECTION;

    afl->stage_cur_byte = i; 
    
    memset(afl->ins_tainted, 0, CMP_MAP_W * sizeof(u32));

    // for each mutator
    for(u32 j = 0; j < TAINT_INFER_MUTATOR_NUM; j++) { 
      
      afl->stage_cur += sect;
      //update stat
      if (!(afl->stage_cur % afl->stats_update_freq) ||
        afl->stage_cur + 1 == afl->stage_max) {
        
        update_c_bytes_len(afl, mode);
        show_stats(afl);
   
      }

      // byte-level mutate
      for(u32 k = 0; k < sect; k++)
        byte_level_mutate(afl, buf, i + k, TAINT_INFER_MUTATOR_NUM - j - 1, 1); 

      /**
       * execution path check
       * 
       * ### PATA check ###
       * 
       *   loggeds = MIN((u32)(afl->shm.mem_map->headers[k].hits), (u32)(afl->orig_mem_map->headers[k].hits));
       * 
       * ### strict check (AFL Instrumentation) ###
       * 
       *   get_exec_checksum(afl, orig_buf, len, &cksum);
       *   get_exec_checksum(afl, buf, len, &exec_cksum);
       * 
       *   if (cksum != exec_cksum) continue;
       * 
       * ### strict check (memlog AFL Instrumentation) ###
       * 
       *   if (unlikey(common_fuzz_memlog_stuff(afl, orig_buf, len))) return 1;
       *   cksum = hash64(afl->memlog_fsrv.trace_bits, afl->memlog_fsrv.map_size, HASH_CONST);
       * 
       *   if (unlikey(common_fuzz_memlog_stuff(afl, buf, len))) continue;
       *   exec_cksum = hash64(afl->memlog_fsrv.trace_bits, afl->memlog_fsrv.map_size, HASH_CONST);
       * 
       *   if (cksum != exec_cksum) continue;
       * 
       * ### common subpath check ###
       * 
       *   if (afl->orig_mem_map->cksum[k][l] != afl->shm.mem_map->cksum[k][l]) continue;
       * 
       */
      
      // execute
      memset(afl->shm.cmp_map->headers, 0, sizeof(struct cmp_header) * CMP_MAP_W);
      if (unlikely((*taint_mode.ops.common_fuzz_staff)(afl, buf, len))) {

        if (afl->stop_soon) return 1;
        goto taint_next_iterator;

      }
      
      // directly use cmp map or mem map afl bitmap
      
      // exec_cksum = hash64(afl->cmplog_fsrv.trace_bits, afl->cmplog_fsrv.map_size, HASH_CONST);

      // infer result
      // *taint_mode.ops.inference)(afl, i);
      // if (cksum == exec_cksum)
      cmp_inference(afl, buf, orig_buf, len, cbuf, i);

taint_next_iterator:
      // reset buffer
      for(u32 k = 0; k < sect; k++)
        buf[i + k] = orig_buf[i + k];

    }

  }

  if (!afl->taint_alone_mode) {

#ifdef CMPLOG_COMBINE
    
    if (afl->queued_items + afl->saved_crashes > orig_hit_cnt + 1) {

      // copy the current virgin bits so we can recover the information
      u8 *virgin_save = afl_realloc((void **)&afl->eff_buf, afl->shm.map_size);
      memcpy(virgin_save, afl->virgin_bits, afl->shm.map_size);
      // reset virgin bits to the backup previous to redqueen
      memcpy(afl->virgin_bits, virgin_backup, afl->shm.map_size);

      u8 status = 0;
      its_fuzz(afl, cbuf, len, &status);

    // now combine with the saved virgin bits
#ifdef WORD_SIZE_64
      u64 *v = (u64 *)afl->virgin_bits;
      u64 *s = (u64 *)virgin_save;
      u32  i;
      for (i = 0; i < (afl->shm.map_size >> 3); i++) {

        v[i] &= s[i];

      }

#else
      u32 *v = (u32 *)afl->virgin_bits;
      u32 *s = (u32 *)virgin_save;
      u32  i;
      for (i = 0; i < (afl->shm.map_size >> 2); i++) {

        v[i] &= s[i];

      }

#endif

    }

#endif

  new_hit_cnt = afl->queued_items + afl->saved_crashes;
  afl->stage_finds[STAGE_ITS_PLUS] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ITS_PLUS] += afl->fsrv.total_execs - orig_execs;

  }

  return 0;

}

u8 taint_inference_stage(afl_state_t *afl, u8 *buf, u8 *orig_buf, u32 len, u8 mode) {  
  
  u32 map_w, map_h;

  afl->stage_name = "taint inference";
  afl->stage_short = "ti";
  afl->stage_max = len * TAINT_INFER_MUTATOR_NUM;
  afl->stage_cur = 0;
  afl->taint_mode = mode;
  
  show_stats(afl);
  
  // reset state info
  afl->tainted_len = 0;
  afl->cur_tainted_len = len;

  
  if (mode == TAINT_CMP) {
  
    map_w = CMP_MAP_W;
    map_h = CMP_MAP_H;

    taint_mode.ops.check_unstable = cmp_check_unstable;
    taint_mode.ops.common_fuzz_staff = common_fuzz_cmplog_stuff;
    //taint_mode.ops.inference = cmp_inference;
    taint_mode.map = afl->shm.cmp_map;
  

    if (unlikely(!afl->orig_cmp_map)) {

      afl->orig_cmp_map = ck_alloc(sizeof(struct cmp_map));

    }
    taint_mode.orig_map = afl->orig_cmp_map;
    taint_mode.map_size = sizeof(struct cmp_map) - sizeof(struct cmp_extra);
    
    taint_mode.fsrv = &afl->cmplog_fsrv;
    taint_mode.fsrv_map_size = afl->cmplog_fsrv.map_size;

  }
  else {

    map_w = MEM_MAP_W;
    map_h = MEM_MAP_H;

    taint_mode.ops.check_unstable = mem_check_unstable;
    taint_mode.ops.common_fuzz_staff = common_fuzz_memlog_stuff;
    taint_mode.ops.inference = mem_inference;
    taint_mode.map = afl->shm.mem_map;
    
    if (unlikely(!afl->orig_mem_map)) {
      
      afl->orig_mem_map = ck_alloc(sizeof(struct mem_map));

    }
    taint_mode.orig_map = afl->orig_mem_map;
    taint_mode.map_size = sizeof(struct mem_map);

    taint_mode.fsrv = &afl->memlog_fsrv;
    taint_mode.fsrv_map_size = afl->memlog_fsrv.map_size;

  }
    
  // set pass stats
  if (unlikely(!afl->pass_stats[mode])) {

    afl->pass_stats[mode] = ck_alloc(sizeof(struct afl_pass_stat) * map_w);

  }

  if (unlikely(!afl->ins_tainted)) {

    afl->ins_tainted = ck_alloc(CMP_MAP_W * sizeof(u32));

  }

  // tmp tainted map init
  if (unlikely(!afl->tmp_tainted)) {
    
    afl->tmp_tainted = ck_alloc(sizeof(tainted_map));

  }
  memset(afl->tmp_tainted, 0, sizeof(struct taint_info *) * map_w * map_h);
  
  if (afl->queue_cur->taint[mode] == NULL && !afl->queue_cur->taint_failed[mode]) {
    
    // taint inference
    if (taint(afl, buf, orig_buf, len, mode)) {
      
      if (afl->queue_cur->taint_cur[mode]) {
        
        afl->queue_cur->taint_cur[mode] = 0;
        // free c bytes
        taint_free(afl->queue_cur->c_bytes[mode]);
        // free tmp_tainted
        for(u32 i = 0; i < map_w; i++) {
      
          for(u32 j = 0; j < map_h; j++) {  
        
            if ((*afl->tmp_tainted)[i][j] != NULL) {
                    
              // free tmp_tainted tainted_info
              taint_info_free((*afl->tmp_tainted)[i][j]);

            }

          }  
    
        }

      }

      // taint failed
      afl->queue_cur->taint_failed[mode]++;
      
      return 1;
    
    }

    if (!afl->queue_cur->taint_cur[mode]) {
      
      // taint failed
      afl->queue_cur->taint_failed[mode]++;

      return 1;
    
    }
    // Construct tainted_info list
    afl->queue_cur->taint[mode] = ck_alloc(sizeof(struct tainted_info *) * afl->queue_cur->taint_cur[mode]);
    u32 cur = 0;
  
    for(u32 i = 0; i < map_w; i++) {
      
      for(u32 j = 0; j < map_h; j++) {  
        
        if ((*afl->tmp_tainted)[i][j] != NULL) {
          
          // store per tainted inst. 
          afl->queue_cur->taint[mode][cur++] = (*afl->tmp_tainted)[i][j];  
        
        }

      }  
    
    }

    // write c_byte to file
    if (afl->taint_alone_mode)
      write_to_taint(afl, mode);

  }
  else if(afl->queue_cur->taint_failed[mode]) {
    
    // taint failed
    return 1;

  }

  // update_state(afl, mode);

  // taint_debug(afl, mode);

  return 0;

}

