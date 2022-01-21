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

static void add_tainted_info(afl_state_t *afl, u32 id, u32 hits, u8 type, u32 ofs) {
  
  struct tainted_info *new_info;
  struct mem_map *m_map = afl->shm.mem_map;

  if ((*afl->tmp_tainted)[id][hits] == NULL) {
    
    new_info = ck_alloc(sizeof(struct tainted_info));
    new_info->id = id;
    new_info->hits = hits;
    new_info->inst_type = m_map->headers[id].type;
    new_info->type = type;
    if (m_map->headers[id].type == HT_GEP_HOOK)
        new_info->size = m_map->log[id][hits].__hook_va_arg.size;
    // idx ?  
    new_info->taint = add_tainted(new_info->taint, ofs, 1);

    (*afl->tmp_tainted)[id][hits] = new_info;
    
    afl->queue_cur->tainted_cur++;

  }
  else {
    
    (*afl->tmp_tainted)[id][hits]->taint = add_tainted((*afl->tmp_tainted)[id][hits]->taint, ofs, 1);
    
  }
  
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

/**
 * Even the same input, sometimes the results also may be different.
 * Such as the program apply randomness to certain part of progam state 
 * 
 */
u8 check_unstable(afl_state_t *afl, u8 *orig_buf, u32 len) {

  if (unlikely(common_fuzz_memlog_stuff(afl, orig_buf, len))) return 1;
  
  for(u32 i = 0; i < MEM_MAP_W; i++) {
    
    if (afl->shm.mem_map->headers[i].hits != afl->orig_mem_map->headers[i].hits) 
      afl->orig_mem_map->headers[i].hits = 0;    
  
  }

  return 0;

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

u8 taint_havoc(afl_state_t *afl, u8* buf, u8* orig_buf, u32 len, u32 stage_max, u32 cur) {
   
  struct tainted *t; 
  u32 use_stacking, r_max, r, r_part, temp_len, parts; 
  u8* out_buf;

  afl->memlog_id = afl->queue_cur->memlog_taint[cur]->id;
  afl->memlog_hits = afl->queue_cur->memlog_taint[cur]->hits;
  afl->memlog_type = afl->queue_cur->memlog_taint[cur]->inst_type;
  afl->memlog_op_type = afl->queue_cur->memlog_taint[cur]->type;

  r_max = 50;
  
  parts = 0;
  t = afl->queue_cur->memlog_taint[cur]->taint;
  while(t != NULL) {

    parts += 1;  
    t = t->next;
  
  }

  for( ; afl->stage_cur < (cur + 1) * stage_max; afl->stage_cur++) {
  
    use_stacking = 1 << (1 + rand_below(afl, afl->havoc_stack_pow2));
    afl->stage_cur_val = use_stacking;

    for(u32 i = 0; i < use_stacking; i++) {
      
      // random generate tainted part
      r_part = rand_below(afl, parts);
      t = afl->queue_cur->memlog_taint[cur]->taint;
      while(r_part--) {

        t = t->next;

      }  

      out_buf = buf + t->pos;
      temp_len = t->len;

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

      
        case 8 ... 9: {

          /* Set word to interesting value, little endian. */

          if (temp_len < 2) { break; }

          *(u16 *)(out_buf + rand_below(afl, temp_len - 1)) =
              interesting_16[rand_below(afl, sizeof(interesting_16) >> 1)];

          break;

        }

        case 10 ... 11: {

          /* Set word to interesting value, big endian. */

          if (temp_len < 2) { break; }

          *(u16 *)(out_buf + rand_below(afl, temp_len - 1)) = SWAP16(
              interesting_16[rand_below(afl, sizeof(interesting_16) >> 1)]);

          break;

        }

        case 12 ... 13: {

          /* Set dword to interesting value, little endian. */

          if (temp_len < 4) { break; }

          *(u32 *)(out_buf + rand_below(afl, temp_len - 3)) =
              interesting_32[rand_below(afl, sizeof(interesting_32) >> 2)];

          break;

        }

        case 14 ... 15: {

          /* Set dword to interesting value, big endian. */

          if (temp_len < 4) { break; }

          *(u32 *)(out_buf + rand_below(afl, temp_len - 3)) = SWAP32(
              interesting_32[rand_below(afl, sizeof(interesting_32) >> 2)]);

          break;

        }

        case 16 ... 19: {

          /* Randomly subtract from byte. */

          out_buf[rand_below(afl, temp_len)] -= 1 + rand_below(afl, ARITH_MAX);
          break;

        }

        case 20 ... 23: {

          /* Randomly add to byte. */

          out_buf[rand_below(afl, temp_len)] += 1 + rand_below(afl, ARITH_MAX);
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

          /* Randomly subtract from dword, little endian. */

          if (temp_len < 4) { break; }

          u32 pos = rand_below(afl, temp_len - 3);

          *(u32 *)(out_buf + pos) -= 1 + rand_below(afl, ARITH_MAX);

          break;

        }

        case 34 ... 35: {

          /* Randomly subtract from dword, big endian. */

          if (temp_len < 4) { break; }

          u32 pos = rand_below(afl, temp_len - 3);
          u32 num = 1 + rand_below(afl, ARITH_MAX);

          *(u32 *)(out_buf + pos) =
              SWAP32(SWAP32(*(u32 *)(out_buf + pos)) - num);

          break;

        }

        case 36 ... 37: {

          /* Randomly add to dword, little endian. */

          if (temp_len < 4) { break; }

          u32 pos = rand_below(afl, temp_len - 3);

          *(u32 *)(out_buf + pos) += 1 + rand_below(afl, ARITH_MAX);

          break;

        }

        case 38 ... 39: {

          /* Randomly add to dword, big endian. */

          if (temp_len < 4) { break; }

          u32 pos = rand_below(afl, temp_len - 3);
          u32 num = 1 + rand_below(afl, ARITH_MAX);

          *(u32 *)(out_buf + pos) =
              SWAP32(SWAP32(*(u32 *)(out_buf + pos)) + num);

          break;

        }
        
        case 40 ... 43: {

          /* Just set a random byte to a random value. Because,
             why not. We use XOR with 1-255 to eliminate the
             possibility of a no-op. */

          out_buf[rand_below(afl, temp_len)] ^= 1 + rand_below(afl, 255);
          break;

        }

        case 44 ... 46: {

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

        case 47: {

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

u8 taint_grad(afl_state_t *afl, u8* buf, u8* orig_buf, u32 len, u32 stage_max, u32 cur) {

  struct tainted *t; 
  s32 grad;

  afl->memlog_id = afl->queue_cur->memlog_taint[cur]->id;
  afl->memlog_hits = afl->queue_cur->memlog_taint[cur]->hits;
  afl->memlog_type = afl->queue_cur->memlog_taint[cur]->inst_type;
  afl->memlog_op_type = afl->queue_cur->memlog_taint[cur]->type;

  while (afl->stage_cur < (cur + 1) * stage_max) {
    
    afl->stage_cur++;
    // calculate gradient
    //if (cal_grad()) continue;
    
    //if (grad != 0) {

      // discend

    //}
  }

  return 0;
}

void taint_debug(afl_state_t *afl) {
  
  struct tainted *t;
  t = afl->queue_cur->c_bytes;
  fprintf(stderr, "c_bytes: ");
  while(t != NULL) {
      
    fprintf(stderr, "pos: %u len: %u ", t->pos, t->len);
    t = t->next;

  }fprintf(stderr, "\n");
  
  for(u32 i = 0; i < afl->queue_cur->tainted_cur; i++) {
    
    fprintf(stderr, "id: %u hits: %u inst type: %u type: %u ", 
                        afl->queue_cur->memlog_taint[i]->id,
                        afl->queue_cur->memlog_taint[i]->hits,
                        afl->queue_cur->memlog_taint[i]->inst_type,
                        afl->queue_cur->memlog_taint[i]->type);

    if (afl->queue_cur->memlog_taint[i]->inst_type == HT_GEP_HOOK)
      fprintf(stderr, "GEP size: %u ", afl->queue_cur->memlog_taint[i]->size);
    
    t = afl->queue_cur->memlog_taint[i]->taint;

    while(t != NULL) {
      
      fprintf(stderr, "pos: %u len: %u ", t->pos, t->len);
      t = t->next;

    }fprintf(stderr, "\n");

  }

}

void taint_failed(afl_state_t *afl) {
  
  struct tainted *t;

  for(u32 i = 0; i < MEM_MAP_W; i++) {

    for(u32 j = 0; j < MEM_MAP_H; j++) {  
      
      if ((*afl->tmp_tainted)[i][j] != NULL) {
        
        t = (*afl->tmp_tainted)[i][j]->taint;
        
        while(t != NULL) {   

          (*afl->tmp_tainted)[i][j]->taint = t->next;
          ck_free(t);
          t = (*afl->tmp_tainted)[i][j]->taint;
        
        }
        
        (*afl->tmp_tainted)[i][j]->taint = NULL;

        ck_free((*afl->tmp_tainted)[i][j]);
        (*afl->tmp_tainted)[i][j] = NULL;

      }
    
    }
  
  }

}

void update_state(afl_state_t *afl) {
  
  struct tainted *t;
  struct tainted_info **tmp;
  // update tainted input length
  if (afl->tainted_len == 0) {
  
    t = afl->queue_cur->c_bytes;
    while(t != NULL) {

        afl->tainted_len += t->len;
        t = t->next;

    }
  
  }
  
  // update tainted inst.
  tmp = afl->queue_cur->memlog_taint;
  for(u32 i = 0; i < afl->queue_cur->tainted_cur; i++) {
    
    if (i > 0 && tmp[i]->id == tmp[i-1]->id) 
      continue;

    afl->ht_tainted[tmp[i]->inst_type] += 1;

  }

}

void write_to_taint(afl_state_t *afl) {
  
  struct tainted *t;
  struct tainted_info **tmp;
  u8 *queue_fn = "", *mem;
  u32 total_len, ofs;
  s32 fd, len;

  // update tainted input length
  t = afl->queue_cur->c_bytes;
  while(t != NULL) {

    afl->tainted_len += t->len;
    t = t->next;

  }  
  // critical bytes 

  // calculate total length of buffer 
  total_len = 0;
  t = afl->queue_cur->c_bytes;
  while(t != NULL) {
  
    len = snprintf(NULL, 0, "%u,%u\n", t->pos, t->len);

    if (len < 0)
      FATAL("Whoa, snprintf() fails?!"); 

    total_len += len;
    t = t->next;
  
  }

  // collect all c_bytes to buffer
  mem = ck_alloc(total_len + 1);
  ofs = 0;
  t = afl->queue_cur->c_bytes;
  while(t != NULL) {
    
    len = snprintf(mem + ofs, total_len, "%u,%u\n", t->pos, t->len);
      
    if (len < 0) 
      FATAL("Whoa, snprintf() fails?!"); 

    ofs += len;
    t = t->next;

  }
  
  // write all critical bytes to file  
  queue_fn = alloc_printf(
    "%s/taint/id:%06u,%06u", afl->out_dir, afl->queue_cur->id,
    afl->tainted_len);

  fd = open(queue_fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
  if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", queue_fn); }
  ck_write(fd, mem, total_len, queue_fn);

  close(fd);
  ck_free(mem);
  ck_free(queue_fn);
  
  // GEP size
  tmp = afl->queue_cur->memlog_taint;
  // calculate total length  
  total_len = 0;
  for(u32 i = 0; i < afl->queue_cur->tainted_cur; i++) {
    // GEP inst.
    if (i > 0 && tmp[i]->id == tmp[i-1]->id) 
      continue;
    
    if (tmp[i]->inst_type == HT_GEP_HOOK) {
      
      len = snprintf(NULL, 0, "%u,%u\n", tmp[i]->id, tmp[i]->size);
    
      if (len < 0)
        FATAL("Whoa, snprintf() fails?!"); 
      
      total_len += len;

    }
  } 

  // collect all c_bytes to buffer
  mem = ck_alloc(total_len + 1);
  ofs = 0;
  for(u32 i = 0; i < afl->queue_cur->tainted_cur; i++) {  
    //GEP inst.
    if (i > 0 && tmp[i]->id == tmp[i-1]->id) 
      continue;
      
    if (tmp[i]->inst_type == HT_GEP_HOOK) {
    
      len = snprintf(mem + ofs, total_len, "%u,%u\n", tmp[i]->id, tmp[i]->size);
        
      if (len < 0) 
        FATAL("Whoa, snprintf() fails?!"); 

      ofs += len;
    
    }
  }
  
  // write all critical bytes to file  
  queue_fn = alloc_printf(
    "%s/taint/size/id:%06u,%06u", afl->out_dir, afl->queue_cur->id,
    afl->tainted_len);
  
  fd = open(queue_fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
  if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", queue_fn); }
  ck_write(fd, mem, total_len, queue_fn);

  close(fd);
  ck_free(mem);
  ck_free(queue_fn);

}

void inference(afl_state_t *afl, u32 ofs) {

  struct hook_va_arg_operand *va_o = NULL, *orig_va_o = NULL;
  struct hook_operand *o = NULL, *orig_o = NULL;
  u32 loggeds;

  for(u32 k = 0; k < MEM_MAP_W; k++) {
    
    // skip inconsistent inst.
    loggeds = MIN((u32)(afl->shm.mem_map->headers[k].hits), (u32)(afl->orig_mem_map->headers[k].hits));
    if (!loggeds) continue;

    if (loggeds > MEM_MAP_H) 
      loggeds = MEM_MAP_H;
    
    for(u32 l = 0; l < loggeds; l++) {
    
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
          //if (o->dst != orig_o->dst) 
          if (o->size != orig_o->size) {
            
            afl->queue_cur->c_bytes = add_tainted(afl->queue_cur->c_bytes, ofs, 1);
            add_tainted_info(afl, k, l, MEMLOG_SIZE, ofs);

          }
          break;
        }
        case HT_HOOK2: {
          /*if (o->dst != orig_o->dst)
          update_state(afl, j, HT_HOOK2, &input_tainted, &inst_hit);
          if (o->src != orig_o->src)
          update_state(afl, j, HT_HOOK2, &input_tainted, &inst_hit);*/
          if (o->size != orig_o->size) {
            
            afl->queue_cur->c_bytes = add_tainted(afl->queue_cur->c_bytes, ofs, 1);
            add_tainted_info(afl, k, l, MEMLOG_SIZE, ofs);

          }
          break;
        }
        case HT_HOOK3: {
          if (o->size != orig_o->size) {

            afl->queue_cur->c_bytes = add_tainted(afl->queue_cur->c_bytes, ofs, 1);
            add_tainted_info(afl, k, l, MEMLOG_SIZE, ofs);

          }
          break;
        }
        case HT_HOOK4: {
          //if (o->src != orig_o->src) 
          break;
        }
        case HT_GEP_HOOK: {  
          for(u32 idx = 0; idx < va_o->num; idx++) {
            if (va_o->idx[idx] != orig_va_o->idx[idx]) {

              afl->queue_cur->c_bytes = add_tainted(afl->queue_cur->c_bytes, ofs, 1);
              add_tainted_info(afl, k, l, MEMLOG_IDX, ofs);
            
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


u8 taint(afl_state_t *afl, u8 *buf, u8 *orig_buf, u32 len) {
  
  u64 cksum, exec_cksum;
  // orig exec
  if (unlikely(common_fuzz_memlog_stuff(afl, orig_buf, len))) return 1;
  memcpy(afl->orig_mem_map, afl->shm.mem_map, sizeof(struct mem_map));
  
  // orig cksum
  cksum = hash64(afl->memlog_fsrv.trace_bits, afl->memlog_fsrv.map_size, HASH_CONST);
  
  // check unstable
  if(check_unstable(afl, orig_buf, len)) return 1;

  // taint
  for(u32 i = 0; i < len; i++) {
    
    afl->stage_cur_byte = i;
    // reset buffer
    if (i > 0)
      *(buf + i - 1) = *(orig_buf + i - 1);      
    afl->stage_cur += 1;

    // for each mutator
    for(u32 j = 0; j < TAINT_INFER_MUTATOR_NUM; j++) { 
      // byte-level mutate
      byte_level_mutate(afl, buf, i, j); 
      // execute
      if (unlikely(common_fuzz_memlog_stuff(afl, buf, len))) continue;

      /**
       * execution path check
       * 
       * PATA check
       * loggeds = MIN((u32)(m_map->headers[k].hits), (u32)(afl->orig_mem_map->headers[k].hits));
       * 
       * strict check
       * get_exec_checksum(afl, orig_buf, len, &cksum);
       * get_exec_checksum(afl, buf, len, &exec_cksum);
       * if (cksum != exec_cksum) continue;
       * 
       * common subpath check
       * if (afl->orig_mem_map->cksum[k][l] != afl->shm.mem_map->cksum[k][l]) continue;
       * 
       */
       
      // directly use mem_map afl bitmap
      exec_cksum = hash64(afl->memlog_fsrv.trace_bits, afl->memlog_fsrv.map_size, HASH_CONST);
      if (exec_cksum != cksum) continue;

      // infer result
      inference(afl, i);

    }

  }
  
  return 0;

}

u8 taint_inference_stage(afl_state_t *afl, u8 *orig_buf, u8 *buf, u32 len) {  
  
  afl->stage_name = "taint inference";
  afl->stage_short = "ti";
  afl->stage_max = len * TAINT_INFER_MUTATOR_NUM;
  afl->stage_cur = 0;

  // reset state info
  afl->tainted_len = 0;
  afl->unstable_len = 0;
  memset(afl->ht_tainted, 0, MEMLOG_HOOK_NUM * sizeof(u32));
  
  // tmp taint_map init
  if (unlikely(!afl->tmp_tainted)) {

    afl->tmp_tainted = ck_alloc(sizeof(tainted_map));

  }
  memset(afl->tmp_tainted, 0, sizeof(struct tainted_info *) * MEM_MAP_W * MEM_MAP_H);

  // orig mem_map
  if (unlikely(!afl->orig_mem_map)) {
    
    afl->orig_mem_map = ck_alloc(sizeof(struct mem_map));
  
  }
  
  if (afl->queue_cur->memlog_taint == NULL) {
    // taint-inference
    if (taint(afl, buf, orig_buf, len)) {
      // free
      taint_failed(afl);
      
      return 1;
    
    }
    
    if (!afl->queue_cur->tainted_cur) return 0;
    
    // Construct taint-info list
    afl->queue_cur->memlog_taint = ck_alloc(sizeof(struct tainted_info *) * afl->queue_cur->tainted_cur);
    u32 cur = 0;
    for(u32 i = 0; i < MEM_MAP_W; i++) {
      
      for(u32 j = 0; j < MEM_MAP_H; j++) {  
      
        if ((*afl->tmp_tainted)[i][j] != NULL) {
            // store per tainted inst. input offset
            afl->queue_cur->memlog_taint[cur++] = (*afl->tmp_tainted)[i][j];  
        }

      }  
    
    }

    // write c_byte to file
    write_to_taint(afl);

  }
  else if(!afl->queue_cur->tainted_cur) {

    return 0;

  }

  update_state(afl);
  
  //taint_debug(afl);
  
  // tainted part only mutation
  u64 orig_hit_cnt, new_hit_cnt, orig_execs;
  u32 inst_stage_max;

  afl->stage_name = "taint havoc";
  afl->stage_short = "th";
  afl->stage_cur = 0;
  
  afl->stage_max = HAVOC_CYCLES_INIT * 4;
  inst_stage_max = afl->stage_max / afl->queue_cur->tainted_cur;
  
  orig_hit_cnt = afl->queued_items + afl->saved_crashes;
  orig_execs = afl->fsrv.total_execs;
  
  afl->stage_cur = 0;
  for(u32 i = 0; i < afl->queue_cur->tainted_cur; i++) {
    
    if (taint_havoc(afl, buf, orig_buf, len, inst_stage_max, i)) return 1;

  }
  
  new_hit_cnt = afl->queued_items + afl->saved_crashes;
  afl->stage_finds[STAGE_TAINT_HAVOC] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_TAINT_HAVOC] += afl->fsrv.total_execs - orig_execs;

  // gradient descent
  /*afl->stage_name = "taint grad";
  afl->stage_short = "tg";
  afl->stage_cur = 0;

  afl->stage_max = HAVOC_CYCLES_INIT * 4;
  inst_stage_max = afl->stage_max / afl->queue_cur->tainted_cur;

  orig_hit_cnt = afl->queued_items + afl->saved_crashes;
  orig_execs = afl->fsrv.total_execs;
  
  afl->stage_cur = 0;
  for(u32 i = 0; i < afl->queue_cur->tainted_cur; i++) {
    
    if (taint_grad(afl, buf, orig_buf, len, inst_stage_max, i)) return 1;

  }*/

  return 0;

}

