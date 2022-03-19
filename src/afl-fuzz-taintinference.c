#include "afl-fuzz.h"
#include "cmplog.h"
#include "math.h"
#include "memlog.h"

#define SLIGHT_TAINTED 8

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

static void add_cmp_tainted_info(afl_state_t *afl, u32 id, u32 hits, u8 type, u32 ofs) {
  
  struct tainted_info *new_info;
  struct cmp_map *c_map = afl->shm.cmp_map;

  if ((*afl->tmp_tainted)[id][hits] == NULL) {
  
    new_info = ck_alloc(sizeof(struct tainted_info));
    new_info->id = id;
    new_info->hits = hits;
    new_info->inst_type = c_map->headers[id].type;
    new_info->type = type;
    new_info->ret_addr = c_map->ret_addr[id];

    new_info->taint = add_tainted(new_info->taint, ofs, 1);

    (*afl->tmp_tainted)[id][hits] = new_info;

    afl->queue_cur->taint_cur[TAINT_CMP]++;

  }
  else {

    (*afl->tmp_tainted)[id][hits]->taint = 
      add_tainted((*afl->tmp_tainted)[id][hits]->taint, ofs, 1);

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

void byte_level_mutate(afl_state_t *afl, u8 *buf, u32 ofs, u32 mutator) {
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

u8 taint_havoc(afl_state_t *afl, u8* buf, u8* orig_buf, u32 len, u32 stage_max, u32 cur, u8 mode) {
   
  struct tainted *t; 
  struct tainted_info *tmp;
  s32 r_part;
  u32 use_stacking, r_max, r, temp_len, parts, t_len; 
  u8* out_buf;

  tmp = afl->queue_cur->taint[mode][cur];
  afl->log_id = tmp->id;
  afl->log_type = tmp->inst_type;
  afl->log_op_type = tmp->type;

  parts = 0;
  t_len = 0;

  t = tmp->taint;
  while(t != NULL) {

    parts += 1;  
    t_len += t->len;
    t = t->next;
  
  }
  
  for( ; afl->stage_cur < (cur + 1) * stage_max; afl->stage_cur++) {
    
    if (t_len < SLIGHT_TAINTED) {

      use_stacking = 1 + rand_below(afl, MIN((u32)(t_len), (u32)(SLIGHT_TAINTED)));

    }
    else {

      use_stacking = 1 << (1 + rand_below(afl, afl->havoc_stack_pow2));

    }
   
    afl->stage_cur_val = use_stacking;

    for(u32 i = 0; i < use_stacking; i++) {
      
      // random generate tainted part
      r_part = rand_below(afl, parts);
      
      t = tmp->taint;
      while(r_part--) {

        t = t->next;

      }  
      
      out_buf = buf + t->pos;
      temp_len = t->len;

      if (t->len < 2) {
        
        r_max = 19;

      }
      else if (t->len < 4) {

        r_max = 34;

      }
      else {

        r_max = 50;

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

        default: 

          if (afl->extras_cnt) {
            
            /* Use the dictionary. */

            u32 use_extra = rand_below(afl, afl->extras_cnt);
            u32 extra_len = afl->extras[use_extra].len;

            if (extra_len > temp_len) { break; }

            u32 insert_at = rand_below(afl, temp_len - extra_len + 1);

            memcpy(out_buf + insert_at, afl->extras[use_extra].data,
                    extra_len);

            break;

          }

          if (afl->a_extras_cnt) {

            /* Use the dictionary. */

            u32 use_extra = rand_below(afl, afl->a_extras_cnt);
            u32 extra_len = afl->a_extras[use_extra].len;

            if (extra_len > temp_len) { break; }

            u32 insert_at = rand_below(afl, temp_len - extra_len + 1);

            memcpy(out_buf + insert_at, afl->a_extras[use_extra].data,
                    extra_len);

            break;

          }
          break;

      }

    } 

    // execute
    if (unlikely(common_fuzz_stuff(afl, buf, len))) { return 1; }
    //restore buf
    memcpy(buf, orig_buf, len);
    
  }

  return 0;

}

u8 exec_path_check(afl_state_t *afl, u32 cur, u8 mode) {
  
  struct tainted_info *tmp;

  tmp = afl->queue_cur->taint[mode][cur];

  if (mode == TAINT_CMP) {

    if (afl->shm.cmp_map->headers[tmp->id].hits < tmp->hits + 1) {

      return 1;
    
    }
  
  }
  else {

    if (afl->shm.mem_map->headers[tmp->id].hits < tmp->hits + 1) {
      
      return 1;

    }
  
  }

  return 0;

}

u64 cmp_get_val(afl_state_t *afl, u32 cur, u8 type) {

  struct tainted_info *tmp;
  struct cmp_operands *o = NULL;
  u64 val = 87;

  tmp = afl->queue_cur->taint[TAINT_CMP][cur];

  if (tmp->inst_type == CMP_TYPE_INS) {

    o = &afl->shm.cmp_map->log[tmp->id][tmp->hits];

  }
  else {

    // rtn

  }
  
  switch(type) {

    case CMP_V0: {
      
      val = o->v0;
      break;

    }
    case CMP_V1: {
      
      val = o->v1;
      break;
    
    }
    case CMP_V0_128: {
      
      val = ((u128)o->v0) + (((u128)o->v0_128) << 64);
      break;

    }
    case CMP_V1_128: {
      
      val = ((u128)o->v1) + (((u128)o->v1_128) << 64);
      break;

    }
    default:
      break;

  }

  return val;

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

/**
 * 
 * f'(x) = [v(x+u) - v(x)] / [u]
 * 
 * if u == 1
 * 
 * f'(x) = [v(x+1) - v(x)]
 * 
 */
u8 cmp_choose_move_ops(afl_state_t *afl, u8* buf, u32 len, u32 cur, u32 ofs, u64 v0, u64 gap, u8* ops) {

  u32 v1;

  // buf[i + 1] exec  
  *ops = 1;
  byte_level_mutate(afl, buf, ofs, *ops);

  memset(afl->shm.cmp_map, 0, sizeof(struct cmp_map));
  if (unlikely(common_fuzz_cmplog_stuff(afl, buf, len))) return 1;
  // execution path check
  if (!exec_path_check(afl, cur, TAINT_CMP)) {

    v1 = cmp_get_val(afl, cur, 
      afl->queue_cur->taint[TAINT_CMP][cur]->type);
      
    if (_ABS(v0, v1) < gap) {
    
      return 0;

    }
  
  }

  // restore buffer
  byte_level_mutate(afl, buf, ofs, *ops ^ 2);

  // buf[i - 1] exec  
  *ops = 3;
  byte_level_mutate(afl, buf, ofs, *ops);

  memset(afl->shm.cmp_map, 0, sizeof(struct cmp_map));
  if (unlikely(common_fuzz_cmplog_stuff(afl, buf, len))) return 1;
  // execution path check
  if (!exec_path_check(afl, cur, TAINT_CMP)) {

    v1 = cmp_get_val(afl, cur, 
      afl->queue_cur->taint[TAINT_CMP][cur]->type);

    if (_ABS(v0, v1) < gap) {
    
      return 0;

    }
  
  }

  // restore buffer
  byte_level_mutate(afl, buf, ofs, *ops ^ 2);

  return 1;

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
u8 mem_choose_move_ops(afl_state_t *afl, u8* buf, u32 len, u32 cur, u8 idx, u32 ofs, u32 v0, u8* ops) {

  u32 v1;

  // buf[i + 1] exec  
  *ops = 1;
  byte_level_mutate(afl, buf, ofs, *ops);
  
  memset(afl->shm.mem_map, 0, sizeof(struct mem_map));
  if (unlikely(common_fuzz_memlog_stuff(afl, buf, len))) return 1;
  // execution path check
  if (!exec_path_check(afl, cur, TAINT_MEM)) {
      
    v1 = mem_get_val(afl, cur, idx);
      
    if (v1 > v0) {
    
      return 0;

    }

  }
  // restore buffer
  byte_level_mutate(afl, buf, ofs, *ops ^ 2);

  // buf[i - 1] exec  
  *ops = 3;
  byte_level_mutate(afl, buf, ofs, *ops);

  memset(afl->shm.mem_map, 0, sizeof(struct mem_map));
  if (unlikely(common_fuzz_memlog_stuff(afl, buf, len))) return 1;
  // execution path check
  if (!exec_path_check(afl, cur, TAINT_MEM)) {

    v1 = mem_get_val(afl, cur, idx);

    if (v1 > v0) {
    
      return 0;

    }

  }
  // restore buffer
  byte_level_mutate(afl, buf, ofs, *ops ^ 2);

  return 1;

}

u8 linear_search(afl_state_t *afl, u8* buf, u32 len, u32 cur, u8 idx, u8 mode) {

  struct tainted *t; 
  struct tainted_info *tmp;
  u64 v0, v1, gap = 0;
  u8 ops = 1;

  tmp = afl->queue_cur->taint[mode][cur];

  if (tmp->inst_type == HT_GEP_HOOK) {

    t = tmp->gep->idx_taint[idx];

  }
  else 
    t = tmp->taint;
  
  if (mode == TAINT_CMP) {

    v1 = cmp_get_val(afl, cur, tmp->type);
    v0 = cmp_get_val(afl, cur, tmp->type ^ 1);

    gap = _ABS(v0, v1);

  }
  else {
  
    v1 = v0 = mem_get_val(afl, cur, idx);
  
  }

  u8 *queue_fn = "";
  FILE *f;
  
  // critical bytes
  if (mode == TAINT_CMP) { 
    
    queue_fn = alloc_printf("%s/taint/cmp/id:%06u,%06u,ls,debug", 
      afl->out_dir, afl->queue_cur->id, afl->tainted_len);

  }
  else {

    queue_fn = alloc_printf("%s/taint/mem/id:%06u,%06u,ls,debug", 
      afl->out_dir, afl->queue_cur->id, afl->tainted_len);

  }

  f = create_ffile(queue_fn);
  fprintf(f, "mode: %d inst_type: %u cur: %u idx: %u init v0: %llu init v1: %llu\n", 
    mode, tmp->inst_type, cur, idx, v0, v1);

  while(t != NULL) {
    
    for(u32 i = 0; i < t->len; i++) {
      
      afl->stage_cur++;
      afl->log_val = v0;
      
      if (mode == TAINT_CMP) {
        
        fprintf(f, "ofs: %u gap: %llu v0: %llu v1: %llu ops: %u\n", 
          t->pos + i, gap, v0, v1, ops);
        if (cmp_choose_move_ops(afl, buf, len, cur, t->pos + i, v0, gap, &ops)) continue;

      }
      else {
        
        fprintf(f, "ofs: %u v1: %llu ops: %u\n", t->pos + i, v1, ops);
        if (mem_choose_move_ops(afl, buf, len, cur, idx, t->pos + i, v0, &ops)) continue;
        
      }

      while (1) {
        
        byte_level_mutate(afl, buf, t->pos + i, ops);
        
        if (mode == TAINT_CMP) {

          // exec
          memset(afl->shm.cmp_map, 0, sizeof(struct cmp_map));
          if (unlikely(common_fuzz_cmplog_stuff(afl, buf, len))) return 1;
          // execution path check
          if (exec_path_check(afl, cur, TAINT_CMP)) {

            // restore buffer
            byte_level_mutate(afl, buf, t->pos + i, ops ^ 2);
            break;
          
          }
          // get val
          v1 = cmp_get_val(afl, cur, tmp->type);

          fprintf(f, "v0: %llu v1: %llu new_gap: %llu old_gap: %llu ops: %u\n",
            v0, v1, _ABS(v0, v1), gap, ops);
          
          // stop condition
          if (_ABS(v0, v1) == 0) {
            
            break;

          }
          else if (_ABS(v0, v1) >= gap) {

            // restore buffer
            byte_level_mutate(afl, buf, t->pos + i, ops ^ 2);
            break;

          }
          // update gap
          gap = _ABS(v0, v1);

        } 
        else {
          
          memset(afl->shm.mem_map, 0, sizeof(struct mem_map));
          // exec
          if (unlikely(common_fuzz_memlog_stuff(afl, buf, len))) return 1;
          // execution path check
          if (exec_path_check(afl, cur, TAINT_MEM)) {
            
            // restore buffer
            byte_level_mutate(afl, buf, t->pos + i, ops ^ 2);
            break;
          
          }
          // get val
          v1 = mem_get_val(afl, cur, idx);

          if (tmp->inst_type == HT_GEP_HOOK) {
            // GEP 
            if (v1 >= tmp->gep->size - 1) {
              // interesting
              // try 
              if (unlikely(common_fuzz_stuff(afl, buf, len))) return 1;

            }

          }
          fprintf(f, "v0: %llu v1: %llu\n", v0, v1);
          // stop condition 
          if (v1 <= v0) {
            
            // restore buffer
            byte_level_mutate(afl, buf, t->pos + i, ops ^ 2);
            break;
          
          }
          
          // update v0
          v0 = v1;

        }

      }

      // try fuzz once
      if (unlikely(common_fuzz_stuff(afl, buf, len))) return 1;

    }

    show_stats(afl);

    t = t->next;

  }

  fclose(f);

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

    fprintf(f, "id: %u hits: %u inst type: %u type: %u ", 
                        tmp->id,
                        tmp->hits,
                        tmp->inst_type,
                        tmp->type);

    t = tmp->taint;

    fprintf(f, "taint: ");
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
  
  struct tainted_info **tmp;

  // update tainted input length
  if (!afl->tainted_len)   
    update_c_bytes_len(afl, mode);

  // update tainted inst.
  tmp = afl->queue_cur->taint[mode];
  for(u32 i = 0; i < afl->queue_cur->taint_cur[mode]; i++) {
    
    if (i > 0 && tmp[i]->id == tmp[i-1]->id) 
      continue;

    afl->ht_tainted[tmp[i]->inst_type] += 1;

  }

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

      fprintf(f, "%llx\n", tmp[i]->ret_addr);

    }

    fclose(f);
    ck_free(queue_fn);

  } 
  
}

// cmplog mode instruction inference
void ins_inference(afl_state_t *afl, u32 ofs, u32 i, u32 loggeds) {
  
  struct cmp_operands *o = NULL, *orig_o = NULL;
#ifdef WORD_SIZE_64
  u32  is_n = 0;
  u128 s128_v0 = 0, s128_v1 = 0, orig_s128_v0 = 0, orig_s128_v1 = 0;
#endif
  u32 hshape;
  /*u64 s_v0, s_v1;
  u8  s_v0_fixed = 1, s_v1_fixed = 1;
  u8  s_v0_inc = 1, s_v1_inc = 1;
  u8  s_v0_dec = 1, s_v1_dec = 1;*/
  
  hshape = SHAPE_BYTES(afl->shm.cmp_map->headers[i].shape);

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
    /*if (j == 0) {

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

    }*/

    for (u32 k = 0; k < j; ++k) {

      if (afl->shm.cmp_map->log[i][k].v0 == o->v0 &&
          afl->shm.cmp_map->log[i][k].v1 == o->v1) {

        goto ins_inference_next_iter;

      }

    }

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
      if (s128_v0 != orig_s128_v0) {

        afl->queue_cur->c_bytes[TAINT_CMP] = 
          add_tainted(afl->queue_cur->c_bytes[TAINT_CMP], ofs, 1);
        add_cmp_tainted_info(afl, i, j, CMP_V0_128, ofs);
          
      }
      else if (s128_v1 != orig_s128_v1) {
        
        afl->queue_cur->c_bytes[TAINT_CMP] = 
          add_tainted(afl->queue_cur->c_bytes[TAINT_CMP], ofs, 1);
        add_cmp_tainted_info(afl, i, j, CMP_V1_128, ofs);

      }

    }

#endif
    
    if (o->v0 != orig_o->v0) {
      
      afl->queue_cur->c_bytes[TAINT_CMP] = 
          add_tainted(afl->queue_cur->c_bytes[TAINT_CMP], ofs, 1);
        add_cmp_tainted_info(afl, i, j, CMP_V0, ofs);
     
    }
    // only handle one situation
    else if (o->v1 != orig_o->v1) {
      
      afl->queue_cur->c_bytes[TAINT_CMP] = 
          add_tainted(afl->queue_cur->c_bytes[TAINT_CMP], ofs, 1);
        add_cmp_tainted_info(afl, i, j, CMP_V1, ofs);
      
    }
  
  ins_inference_next_iter:
    continue;

  }

  // is this really useful ???
  /*if (((s_v0_fixed && s_v1_inc) || (s_v1_fixed && s_v0_inc) ||
                    (s_v0_fixed && s_v1_dec) || (s_v1_fixed && s_v0_dec))) {
    //ignore loop
    afl->pass_stats[TAINT_CMP][i].total = afl->pass_stats[TAINT_CMP][i].faileds = 0xff;

  }*/

}

void rtn_inference(afl_state_t *afl, u32 ofs, u32 i, u32 loggeds) {

  struct cmpfn_operands *o = NULL, *orig_o = NULL;

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
     
    if (o->v0_len != orig_o->v0_len || memcmp(o->v0, orig_o->v0, sizeof(struct cmpfn_operands))) {

      afl->queue_cur->c_bytes[TAINT_CMP] = 
        add_tainted(afl->queue_cur->c_bytes[TAINT_CMP], ofs, 1);
      add_cmp_tainted_info(afl, i, j, RTN_V0, ofs);
     
    }

    if (o->v1_len != orig_o->v1_len || memcmp(o->v1, orig_o->v1, sizeof(struct cmpfn_operands))) {
      
      afl->queue_cur->c_bytes[TAINT_CMP] = 
        add_tainted(afl->queue_cur->c_bytes[TAINT_CMP], ofs, 1);
      add_cmp_tainted_info(afl, i, j, RTN_V1, ofs);
      
    }

    rtn_inference_next_iter:
      continue;

  }

}

void cmp_inference(afl_state_t *afl, u32 ofs) {
  
  u32 loggeds;

  for(u32 i = 0; i < CMP_MAP_W; i++) {

    loggeds = MIN((u32)(afl->shm.cmp_map->headers[i].hits), 
      (u32)(afl->orig_cmp_map->headers[i].hits));
    if (!loggeds) continue;
    
    // skip inst. which fails too many times
    if (afl->pass_stats[TAINT_CMP][i].faileds >= CMPLOG_FAIL_MAX || 
        afl->pass_stats[TAINT_CMP][i].total >= CMPLOG_FAIL_MAX) 
      continue;

    if (loggeds > CMP_MAP_H) 
      loggeds = CMP_MAP_H;
    
    
    if (afl->shm.cmp_map->headers[i].type == CMP_TYPE_INS) {

      ins_inference(afl, ofs, i, loggeds);

    }
    /*else {

      rtn_inference(afl, ofs, i, loggeds);

    }*/

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
  
  struct tainted *t;
  struct tainted_info *tmp;

  update_state(afl, mode);

  // tainted part only mutation
  u64 orig_hit_cnt, new_hit_cnt, orig_execs;
  u32 inst_stage_max;

  afl->stage_name = "taint havoc";
  afl->stage_short = "th";
  afl->stage_cur = 0;
  
  afl->stage_max = HAVOC_CYCLES_INIT * 2;
  inst_stage_max = afl->stage_max / afl->queue_cur->taint_cur[mode];
  
  orig_hit_cnt = afl->queued_items + afl->saved_crashes;
  orig_execs = afl->fsrv.total_execs;

  for(u32 i = 0; i < afl->queue_cur->taint_cur[mode]; i++) {
    
    if (taint_havoc(afl, buf, orig_buf, len, inst_stage_max, i, mode)) return 1;

  }
  
  new_hit_cnt = afl->queued_items + afl->saved_crashes;
  afl->stage_finds[STAGE_TAINT_HAVOC] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_TAINT_HAVOC] += afl->fsrv.total_execs - orig_execs;

  // linear search
  
  u64 inst_orig_hit_cnt, inst_new_hit_cnt;
  u32 r_max, r;

  afl->stage_name = "linear search";
  afl->stage_short = "ls";
  
  orig_hit_cnt = afl->queued_items + afl->saved_crashes;
  orig_execs = afl->fsrv.total_execs;

  if (afl->queue_cur->taint_cur[mode] < 4) {

    r_max = afl->queue_cur->taint_cur[mode];

  }
  else {

    r_max = MIN((u32)(afl->queue_cur->taint_cur[mode] / 2), 
      (u32)(1 << (1 + rand_below(afl, HAVOC_STACK_POW2))));

  }

  inst_orig_hit_cnt = orig_hit_cnt;
  
  for(u32 i = 0; i < r_max; i++) {
    
    r = rand_below(afl, afl->queue_cur->taint_cur[mode]);

    memcpy(buf, orig_buf, len);
    
    memcpy(taint_mode.map, taint_mode.orig_map, taint_mode.map_size);

    tmp = afl->queue_cur->taint[mode][r];

    if (tmp->inst_type == HT_GEP_HOOK) {

      for(u32 j = 0; j < tmp->gep->num_of_idx; j++) {
        
        t = tmp->gep->idx_taint[j];
        while(t != NULL) {
        
          afl->stage_max += t->len;
          t = t->next; 
        
        }
      
      }

    }
    else {

      t = tmp->taint;
      while(t != NULL) {
        
        afl->stage_max += t->len;
        t = t->next; 
        
      }

    }

    afl->log_id = tmp->id;
    afl->log_type = tmp->inst_type;
    afl->log_op_type = tmp->type;

    if (tmp->inst_type == HT_GEP_HOOK) {

      for(u32 j = 0; j < tmp->gep->num_of_idx; j++) {
        
        if (tmp->gep->idx_taint[j] != NULL) {
          
          if (linear_search(afl, buf, len, i, j, mode)) return 1;
        
        }

      }

    }
    else if (tmp->type == CMP_V0_128 || tmp->type == CMP_V1_128) {
      
      // not yet handling 128 linear search
      continue;

    }
    else {

      if (linear_search(afl, buf, len, i, 0, mode)) return 1;

    }
    
    inst_new_hit_cnt = afl->queued_items + afl->saved_crashes;
    
    if (r == 0 || afl->queue_cur->taint[mode][r]->id 
      != afl->queue_cur->taint[mode][r-1]->id) {
        
      // fail
      if (inst_orig_hit_cnt == inst_new_hit_cnt) {
        
        if (afl->pass_stats[mode][tmp->id].faileds < 0xff) {

          afl->pass_stats[mode][tmp->id].faileds++;

        }

      }
      
      // update total
      if (afl->pass_stats[mode][tmp->id].total < 0xff) {

        afl->pass_stats[mode][tmp->id].total++;

      }

    }
    
    inst_orig_hit_cnt = inst_new_hit_cnt;

  }
  
  new_hit_cnt = afl->queued_items + afl->saved_crashes;
  afl->stage_finds[STAGE_TAINT_LS] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_TAINT_LS] += afl->fsrv.total_execs - orig_execs;

  return 0;

}

u8 taint(afl_state_t *afl, u8 *buf, u8 *orig_buf, u32 len, u8 mode) {
  
  // u64 cksum, exec_cksum;
  // orig exec
 
  // Reset bitmap before each execution.
  memset(taint_mode.map, 0, taint_mode.map_size);
  if (unlikely((*taint_mode.ops.common_fuzz_staff)(afl, orig_buf, len))) return 1;
  
  memcpy(taint_mode.orig_map, taint_mode.map, taint_mode.map_size);

  // orig cksum
  // cksum = hash64(taint_mode.fsrv->trace_bits, taint_mode.fsrv_map_size, HASH_CONST);

  // check unstable
  memset(taint_mode.map, 0, taint_mode.map_size);
  if (unlikely((*taint_mode.ops.common_fuzz_staff)(afl, orig_buf, len))) return 1;
  
  (*taint_mode.ops.check_unstable)(afl);
 
  // taint
  for(u32 i = 0; i < len; i++) {

    afl->stage_cur_byte = i;     
    // for each mutator
    for(u32 j = 0; j < TAINT_INFER_MUTATOR_NUM; j++) { 
      
      afl->stage_cur++;
      //update stat
      if (!(afl->stage_cur % afl->stats_update_freq) ||
        afl->stage_cur + 1 == afl->stage_max) {
        
        update_c_bytes_len(afl, mode);
        show_stats(afl);
   
      }
      // byte-level mutate
      byte_level_mutate(afl, buf, i, j); 
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
      memset(taint_mode.map, 0, taint_mode.map_size);
      if (unlikely((*taint_mode.ops.common_fuzz_staff)(afl, buf, len))) {

        if (afl->stop_soon) return 1;
        // reset buffer
        // buf[i] = orig_buf[i];
        // continue;

      }
      
      // directly use cmp map or mem map afl bitmap
      // exec_cksum = hash64(taint_mode.fsrv->trace_bits, taint_mode.fsrv_map_size, HASH_CONST);
      
      //if (exec_cksum != cksum) goto taint_next_iterator;

      // infer result
      (*taint_mode.ops.inference)(afl, i);
      
      // reset buffer
      buf[i] = orig_buf[i];

    }

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

  memset(afl->ht_tainted, 0, MEMLOG_HOOK_NUM * sizeof(u32));
  
  if (mode == TAINT_CMP) {
  
    map_w = CMP_MAP_W;
    map_h = CMP_MAP_H;

    taint_mode.ops.check_unstable = cmp_check_unstable;
    taint_mode.ops.common_fuzz_staff = common_fuzz_cmplog_stuff;
    taint_mode.ops.inference = cmp_inference;
    taint_mode.map = afl->shm.cmp_map;
    
    // set cmplog fsrv timeout
    // ensure taint inference completed
    afl->cmplog_fsrv.exec_tmout = TAINT_CMP_TIMEOUT;

    if (unlikely(!afl->orig_cmp_map)) {

      afl->orig_cmp_map = ck_alloc(sizeof(struct cmp_map));

    }
    taint_mode.orig_map = afl->orig_cmp_map;
    taint_mode.map_size = sizeof(struct cmp_map);
    
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
  // reset orig map
  memset(taint_mode.orig_map, 0, taint_mode.map_size);
    
  // set pass stats
  if (unlikely(!afl->pass_stats[mode])) {

    afl->pass_stats[mode] = ck_alloc(sizeof(struct afl_pass_stat) * map_w);

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

      return 0;
    
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
    write_to_taint(afl, mode);

  }
  else if(afl->queue_cur->taint_failed[mode]) {
    
    // taint failed
    return 0;

  }

  update_state(afl, mode);

  taint_debug(afl, mode);

  return 0;

}

