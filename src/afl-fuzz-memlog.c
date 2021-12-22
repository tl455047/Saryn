/*
   american fuzzy lop++ - cmplog execution routines
   ------------------------------------------------
   Originally written by Michal Zalewski
   Forkserver design by Jann Horn <jannhorn@googlemail.com>
   Now maintained by by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>
   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:
     http://www.apache.org/licenses/LICENSE-2.0
   Shared code to handle the shared memory. This is used by the fuzzer
   as well the other components like afl-tmin, afl-showmap, etc...
 */

#include <sys/select.h>

#include "afl-fuzz.h"
#include "memlog.h"
#include "cmplog.h"

#define FLIP_BIT(_ar, _b)                   \
  do {                                      \
                                            \
    u8 *_arf = (u8 *)(_ar);                 \
    u32 _bf = (_b);                         \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf)&7)); \
                                            \
  } while (0)

void memlog_exec_child(afl_forkserver_t *fsrv, char **argv) {

  setenv("___AFL_EINS_ZWEI_POLIZEI___", "1", 1);

  if (fsrv->qemu_mode) { setenv("AFL_DISABLE_LLVM_INSTRUMENTATION", "1", 0); }

  if (!fsrv->qemu_mode && !fsrv->frida_mode && argv[0] != fsrv->memlog_binary) {

    argv[0] = fsrv->memlog_binary;

  }

  execv(argv[0], argv);

}

u8 common_fuzz_memlog_stuff(afl_state_t *afl, u8 *out_buf, u32 len) {

  u8 fault;

  write_to_testcase(afl, out_buf, len);

  fault = fuzz_run_target(afl, &afl->memlog_fsrv, afl->fsrv.exec_tmout);

  if (afl->stop_soon) { return 1; }

  if (fault == FSRV_RUN_TMOUT) {

    if (afl->subseq_tmouts++ > TMOUT_LIMIT) {

      ++afl->cur_skipped_items;
      return 1;

    }

  } else {

    afl->subseq_tmouts = 0;

  }

  /* Users can hit us with SIGUSR1 to request the current input
     to be abandoned. */

  if (afl->skip_requested) {

    afl->skip_requested = 0;
    ++afl->cur_skipped_items;
    return 1;

  }

  /* This handles FAULT_ERROR for us: */

  afl->queued_discovered += save_if_interesting(afl, out_buf, len, fault);

  if (!(afl->stage_cur % afl->stats_update_freq) ||
      afl->stage_cur + 1 == afl->stage_max) {

    show_stats(afl);

  }

  return 0;

}


void __memlog_debug_output(afl_state_t *afl) {

  struct hook_va_arg_operand *__hook_va_arg;
  for(int i = 0; i < MEM_MAP_W; i++) {
    
    if (!afl->shm.mem_map->headers[i].hits) continue;

    fprintf(stderr, "header: id: %u hits: %u src_shape: %u rst_shape: %u type: %u\n", 
      afl->shm.mem_map->headers[i].id, 
      afl->shm.mem_map->headers[i].hits,
      afl->shm.mem_map->headers[i].src_shape,
      afl->shm.mem_map->headers[i].rst_shape,
      afl->shm.mem_map->headers[i].type);
    
    switch(afl->shm.mem_map->headers[i].type) {
       case HT_VARARG_HOOK1:
        fprintf(stderr, "hook va arg log: num: %u ptr: %p\n",
          afl->shm.mem_map->log[i][0].__hook_va_arg.num,
          afl->shm.mem_map->log[i][0].__hook_va_arg.ptr);
        __hook_va_arg = &afl->shm.mem_map->log[i][0].__hook_va_arg;
        for(u32 j = 0; j < afl->shm.mem_map->log[i][0].__hook_va_arg.num; j++) {
          fprintf(stderr, "idx: %d ",
          __hook_va_arg->idx[j]);
        }fprintf(stderr, "\n");
        break;
      default:
        /*fprintf(stderr, "hook log: type: %u dst: %p src: %p value: %lld size: %lld\n",
          afl->shm.memlog_map->headers[i].type,
          afl->shm.memlog_map->log[i][0].__hook_op.dst,
          afl->shm.memlog_map->log[i][0].__hook_op.src,
          afl->shm.memlog_map->log[i][0].__hook_op.value,
          afl->shm.memlog_map->log[i][0].__hook_op.size);*/
        break;
    }
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

void update_colorized(afl_state_t *afl, u32 k, u32 mut, u32 id, u32 hits, u8 type, u8 op_type, u8 *k_tainted, u8 *inst_hit) {
 
  //if (afl->is_colored == 1)
  //  (*afl->memlog_tainted_map)[id][hits][op_type] = add_tainted((*afl->memlog_tainted_map)[id][hits][op_type], k, 1);
  
  if (*inst_hit != 0) return;
  *inst_hit = 1;

  if (afl->is_colored == 0)
    afl->color_ht_tainted[type][mut] += 1;
  else if (afl->is_colored == 1)
    afl->ht_tainted[type][mut] += 1;
  else if (afl->is_colored == 2)
    afl->infer_ht_tainted[type][mut] += 1;
  
  if (*k_tainted != 0) return;
  *k_tainted = 1;

  if (afl->is_colored == 1)
    afl->memlog_tainted_len += 1;
  else if (afl->is_colored == 2)
    afl->infer_tainted_len += 1;
  
}

u8 taint_havoc(afl_state_t *afl, u8* buf, u8* orig_buf, u32 len, u32 id, u32 hits, u32 op_type, struct tainted *taint) {
   
  struct tainted *t = taint; 
  u32 use_stacking, r_max, r, temp_len; 
  u8* out_buf;

  afl->memlog_id = id;
  afl->memlog_hits = hits;
  afl->memlog_type = afl->shm.mem_map->headers[id].type;
  afl->memlog_op_type = op_type;
  afl->memlog_ofs = 0;

  // decide fuzz how many times
  afl->stage_max += 64;
  // how many times we should fuzz ?
  r_max = 39 + 1;
  for(u32 i = 0; i < 64; i++) {
    t = taint;
    // tainted part only mutate 
    while(t != NULL) {
    
      out_buf = buf + t->pos;
      temp_len = t->len;
      use_stacking = 1 << (1 + rand_below(afl, afl->havoc_stack_pow2));
      for(u32 j = 0; j < use_stacking; j++) {
      
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
    
          default:
            // ... 
            break;

        }

      } 

      t = t->next;

    }

    // execute
    if (unlikely(common_fuzz_stuff(afl, buf, len))) { return 1; }
    
    //restore buf
    memcpy(buf, orig_buf, len);

    afl->stage_cur++;

  }

  return 0;

}

static u64 screen_update;

struct range {

  u32           start;
  u32           end;
  struct range *next;
  struct range *prev;
  u8            ok;

};

static struct range *add_range(struct range *ranges, u32 start, u32 end) {

  struct range *r = ck_alloc_nozero(sizeof(struct range));
  r->start = start;
  r->end = end;
  r->next = ranges;
  r->ok = 0;
  if (likely(ranges)) ranges->prev = r;
  return r;

}

static struct range *pop_biggest_range(struct range **ranges) {

  struct range *r = *ranges;
  struct range *rmax = NULL;
  u32           max_size = 0;

  while (r) {

    if (!r->ok) {

      u32 s = 1 + r->end - r->start;

      if (s >= max_size) {

        max_size = s;
        rmax = r;

      }

    }

    r = r->next;

  }

  return rmax;

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

static u8 colorization(afl_state_t *afl, u8 *buf, u32 len,
                       struct tainted **taints) {

  struct range *  ranges = add_range(NULL, 0, len - 1), *rng;
  struct tainted *taint = NULL;
  u8 *            backup = ck_alloc_nozero(len);
  u8 *            changed = ck_alloc_nozero(len);

  u64 exec_cksum;
  
  afl->stage_name = "memlog colorization";
  afl->stage_short = "colorization";
  afl->stage_max = (len << 1);
  afl->stage_cur = 0;

  if (likely(afl->queue_cur->exec_us)) {

    if (likely((100000 / 2) >= afl->queue_cur->exec_us)) {

      screen_update = 100000 / afl->queue_cur->exec_us;

    } else {

      screen_update = 1;

    }

  } else {

    screen_update = 100000;

  }

  // in colorization we do not classify counts, hence we have to calculate
  // the original checksum.
  if (unlikely(get_exec_checksum(afl, buf, len, &exec_cksum))) {

    goto checksum_fail;

  }

  memcpy(backup, buf, len);
  memcpy(changed, buf, len);
  type_replace(afl, changed, len);

  while ((rng = pop_biggest_range(&ranges)) != NULL &&
         afl->stage_cur < afl->stage_max) {

    u32 s = 1 + rng->end - rng->start;

    memcpy(buf + rng->start, changed + rng->start, s);

    u64 cksum = 0;
    if (unlikely(get_exec_checksum(afl, buf, len, &cksum))) {

      goto checksum_fail;

    }

    /* Discard if the mutations change the path or if it is too decremental
      in speed - how could the same path have a much different speed
      though ...*/
    if (cksum != exec_cksum) {

      memcpy(buf + rng->start, backup + rng->start, s);

      if (s > 1) {  // to not add 0 size ranges

        ranges = add_range(ranges, rng->start, rng->start - 1 + s / 2);
        ranges = add_range(ranges, rng->start + s / 2, rng->end);

      }

      if (ranges == rng) {

        ranges = rng->next;
        if (ranges) { ranges->prev = NULL; }

      } else if (rng->next) {

        rng->prev->next = rng->next;
        rng->next->prev = rng->prev;

      } else {

        if (rng->prev) { rng->prev->next = NULL; }

      }

      free(rng);

    } else {

      rng->ok = 1;

    }

    if (++afl->stage_cur % screen_update == 0) { show_stats(afl); };

  }

  rng = ranges;
  while (rng) {

    rng = rng->next;

  }

  u32 i = 1;
  u32 positions = 0;
  while (i) {

  restart:
    i = 0;
    struct range *r = NULL;
    u32           pos = (u32)-1;
    rng = ranges;

    while (rng) {

      if (rng->ok == 1 && rng->start < pos) {

        if (taint && taint->pos + taint->len == rng->start) {

          taint->len += (1 + rng->end - rng->start);
          positions += (1 + rng->end - rng->start);
          rng->ok = 2;
          goto restart;

        } else {

          r = rng;
          pos = rng->start;

        }

      }

      rng = rng->next;

    }

    if (r) {

      struct tainted *t = ck_alloc_nozero(sizeof(struct tainted));
      t->pos = r->start;
      t->len = 1 + r->end - r->start;
      positions += (1 + r->end - r->start);
      if (likely(taint)) { taint->prev = t; }
      t->next = taint;
      t->prev = NULL;
      taint = t;
      r->ok = 2;
      i = 1;

    }

  }

  /* temporary: clean ranges */
  while (ranges) {

    rng = ranges;
    ranges = rng->next;
    ck_free(rng);
    rng = NULL;

  }

  if (taint) {
  
    *taints = taint;

  }

  ck_free(backup);
  ck_free(changed);

  return 0;

checksum_fail:
  while (ranges) {

    rng = ranges;
    ranges = rng->next;
    ck_free(rng);
    rng = NULL;

  }

  ck_free(backup);
  ck_free(changed);

  return 1;

}


/**
 * I don't know what's the name of my method yet.
 * Before figuring out, just call it memlog stage. 
 */
u8 memlog_stage(afl_state_t *afl, u8 *orig_buf, u8 *buf, u32 len) { 

  struct mem_map *m_map;           
  struct hook_va_arg_operand *va_o = NULL, *orig_va_o = NULL;
  struct hook_operand *o = NULL, *orig_o = NULL;
  struct tainted *t;
  u8 input_tainted, inst_hit;
  u32 loggeds, _bit;
  u64 cksum, exec_cksum;

  afl->stage_name = "taint inference";
  afl->stage_short = "infer";
  afl->stage_max = len * MEMLOG_MUTATOR_NUM;
  afl->stage_cur = 0;

  // reset state info
  afl->is_colored = 0;
  afl->memlog_tainted_len = 0;
  afl->unstable_len = 0;

  memset(afl->ht_tainted, 0, MEMLOG_HOOK_NUM * MEMLOG_MUTATOR_NUM * sizeof(u32));

  /*if (afl->memlog_tainted_map == NULL) {

    afl->memlog_tainted_map = ck_alloc_nozero(sizeof(TAINTED_MAP));

  }

  memset(afl->memlog_tainted_map, 0, sizeof(TAINTED_MAP));*/

  if (unlikely(!afl->orig_mem_map)) {

    afl->orig_mem_map = ck_alloc_nozero(sizeof(struct mem_map));

  }

  // check unstable
  // disable unstable inst. even if is same input
  memset(afl->shm.mem_map, 0, sizeof(struct mem_map));
  if (unlikely(common_fuzz_memlog_stuff(afl, orig_buf, len))) {

    return 1;

  }
  
  memcpy(afl->orig_mem_map, afl->shm.mem_map, sizeof(struct mem_map));
  
  memset(afl->shm.mem_map, 0, sizeof(struct mem_map));
  if (unlikely(common_fuzz_memlog_stuff(afl, orig_buf, len))) {

    return 1;

  }

  m_map = afl->shm.mem_map;
  for(u32 i = 0; i < MEM_MAP_W; i++) {
    
    if (!m_map->headers[i].hits && !afl->orig_mem_map->headers[i].hits)
      continue;
    
    if (m_map->headers[i].hits != afl->orig_mem_map->headers[i].hits) {
      // unstable
      // control flow is not same
      // skip this inst. in taint inference
      afl->orig_mem_map->headers[i].hits = 0;
      afl->unstable_len += 1;
      continue;

    }
      
    for(u32 j = 0; j < MEM_MAP_H; j++) {

      if (m_map->headers[i].type >= HT_VARARG_HOOK1) {
          
        va_o = &m_map->log[i][j].__hook_va_arg;
        orig_va_o = &afl->orig_mem_map->log[i][j].__hook_va_arg;

      }
      else {

        o = &m_map->log[i][j].__hook_op;
        orig_o = &afl->orig_mem_map->log[i][j].__hook_op;
      
      }

      switch (m_map->headers[i].type) {

        case HT_HOOK3: {

          if (o->dst != orig_o->dst || o->value != orig_o->value || o->size != orig_o->size) {
            
            afl->orig_mem_map->headers[i].hits = 0;
            afl->unstable_len += 1;

          }
          break;
        
        }
        case HT_HOOK4: {

          if (o->dst != orig_o->dst || o->src != orig_o->src || o->size != orig_o->size) {
            
            afl->orig_mem_map->headers[i].hits = 0;
            afl->unstable_len += 1;

          }
          break;

        }
        case HT_HOOK5: {

          if (o->size != orig_o->size) {
            
            afl->orig_mem_map->headers[i].hits = 0;
            afl->unstable_len += 1;

          }
          break;

        }
        case HT_HOOK6: {

          if (o->src != orig_o->src) {
            
            afl->orig_mem_map->headers[i].hits = 0;
            afl->unstable_len += 1;

          }
          break;

        }
        case HT_HOOK7: {

          if (o->src != orig_o->src || o->size != orig_o->size) {
            
            afl->orig_mem_map->headers[i].hits = 0;
            afl->unstable_len += 1;

          }
          break;

        }
        case HT_VARARG_HOOK1: {
          
          if (va_o->ptr != orig_va_o->ptr) {
            
            afl->orig_mem_map->headers[i].hits = 0;
            afl->unstable_len += 1;
            break;

          }

          for (u32 idx = 0; idx < va_o->num; idx++) {

            if (va_o->idx[idx] != orig_va_o->idx[idx]) {

              afl->orig_mem_map->headers[i].hits = 0;
              afl->unstable_len += 1;
              break;
            
            }

          }

          break;

        }
        default:
          break;

      }

    }

  }
  
  /* colorization */

  struct tainted* taints = NULL;
  afl->stage_name = "colorization";
  afl->stage_short = "color";
  afl->stage_max = MEM_MAP_W;
  afl->stage_cur = 0;

  afl->is_colored = 0;
  afl->color_tainted_len = 0;
  memset(afl->color_ht_tainted, 0, MEMLOG_HOOK_NUM * MEMLOG_MUTATOR_NUM * sizeof(u32));
  memcpy(buf, orig_buf, len);
  if (unlikely(colorization(afl, buf, len, &taints))) { return 1; }
  
  // execute
  memset(m_map, 0, sizeof(struct mem_map));
  if (unlikely(common_fuzz_memlog_stuff(afl, buf, len))) {

    return 1;

  }

  t = taints;
  while(t != NULL) {

    afl->color_tainted_len += t->len; 
    t = t->next;

  }

  t = taints;
  if (t != NULL) {
    
    u32 i = 0, j = 0;
    for (u32 k = 0; k < MEM_MAP_W; k++) {
      
      afl->stage_cur = k;
      // check unstable
      // different path
      loggeds = MIN(m_map->headers[k].hits, afl->orig_mem_map->headers[k].hits);
      if (!loggeds) continue;
    
      if (loggeds > MEM_MAP_H) 
        loggeds = MEM_MAP_H;
      
      inst_hit = 0;
      for (u32 l = 0; l < loggeds; l++) {
      
        if (m_map->headers[k].type >= HT_VARARG_HOOK1) {
        
          va_o = &m_map->log[k][l].__hook_va_arg;
          orig_va_o = &afl->orig_mem_map->log[k][l].__hook_va_arg;

        }
        else {

          o = &m_map->log[k][l].__hook_op;
          orig_o = &afl->orig_mem_map->log[k][l].__hook_op;
        
        }

        switch (m_map->headers[k].type) {

          case HT_HOOK3: {

            if (o->dst != orig_o->dst) 
              update_colorized(afl, i, j, k, l, HT_HOOK3, MEMLOG_DST, &input_tainted, &inst_hit);
            if (o->value != orig_o->value)
              update_colorized(afl, i, j, k, l, HT_HOOK3, MEMLOG_VALUE, &input_tainted, &inst_hit);
            if (o->size != orig_o->size) 
              update_colorized(afl, i, j, k, l, HT_HOOK3, MEMLOG_SIZE, &input_tainted, &inst_hit);
            break;
          
          }
          case HT_HOOK4: {

            if (o->dst != orig_o->dst)
              update_colorized(afl, i, j, k, l, HT_HOOK4, MEMLOG_DST, &input_tainted, &inst_hit);
            if (o->src != orig_o->src)
              update_colorized(afl, i, j, k, l, HT_HOOK4, MEMLOG_SRC, &input_tainted, &inst_hit);
            if (o->size != orig_o->size) 
              update_colorized(afl, i, j, k, l, HT_HOOK4, MEMLOG_SIZE, &input_tainted, &inst_hit);        
            break;

          }
          case HT_HOOK5: {

            if (o->size != orig_o->size) 
              update_colorized(afl, i, j, k, l, HT_HOOK5, MEMLOG_SIZE, &input_tainted, &inst_hit);
            break;

          }
          case HT_HOOK6: {

            if (o->src != orig_o->src) 
              update_colorized(afl, i, j, k, l, HT_HOOK6, MEMLOG_SRC, &input_tainted, &inst_hit);
            break;

          }
          case HT_HOOK7: {

            if (o->src != orig_o->src)
              update_colorized(afl, i, j, k, l, HT_HOOK7, MEMLOG_SRC, &input_tainted, &inst_hit);
            if (o->size != orig_o->size) 
              update_colorized(afl, i, j, k, l, HT_HOOK7, MEMLOG_SIZE, &input_tainted, &inst_hit);
            break;

          }
          case HT_VARARG_HOOK1: {
            
            for (u32 idx = 0; idx < va_o->num; idx++) {

              if (va_o->idx[idx] != orig_va_o->idx[idx]) {

                update_colorized(afl, i, j, k, l, HT_VARARG_HOOK1, MEMLOG_IDX, &input_tainted, &inst_hit);
              
              }

            }

            if (va_o->ptr != orig_va_o->ptr) 
              update_colorized(afl, i, j, k, l, HT_VARARG_HOOK1, MEMLOG_VA_SRC, &input_tainted, &inst_hit);
  
            break;
          }
          default:
            break;

        }

      }

    }
       
  }

  /* taint inference with path check */
  afl->stage_name = "taint inference(check)";
  afl->stage_short = "infer";
  afl->stage_max = len * MEMLOG_MUTATOR_NUM;
  afl->stage_cur = 0;

  afl->is_colored = 1;
  afl->memlog_tainted_len = 0;

  cksum = exec_cksum = 0;
  memset(afl->ht_tainted, 0, MEMLOG_HOOK_NUM * MEMLOG_MUTATOR_NUM * sizeof(u32));
  
  //if (get_exec_checksum(afl, orig_buf, len, &cksum)) return 1;

  memcpy(buf, orig_buf, len);
  for (u32 i = 0; i < len; i++) {
    
    input_tainted = 0;
    afl->stage_cur_byte = i;
   
    // byte-level mutate
    for (u32 j = 0; j < MEMLOG_MUTATOR_NUM; j++) { 
      // mutator
      switch(j) {
        case 0: {
          _bit = (i << 3) + rand_below(afl, 8);
          FLIP_BIT(buf, _bit);
          break;
        }
        case 1: {
          *(buf + i) += 1;
          break;
        }
        case 2: {
          type_replace(afl, buf + i, 1);
          break;
        }
        case 3: {
          *(buf + i) -= 1;
          break;
        }
        default:
          break;
      }
      
      // check if is same path
      /*if (get_exec_checksum(afl, buf, len, &exec_cksum)) return 1;
      
      if (cksum != exec_cksum) {
         
        // restore input
        *(buf + i) = *(orig_buf + i);
        // update afl_cur
        afl->stage_cur += 1;
        continue;
      
      }*/

      // execute
      memset(m_map, 0, sizeof(struct mem_map));
      if (unlikely(common_fuzz_memlog_stuff(afl, buf, len))) return 1;

    

      for (u32 k = 0; k < MEM_MAP_W; k++) {
        
        // check unstable
        // different path
        loggeds = MIN(m_map->headers[k].hits, afl->orig_mem_map->headers[k].hits);
        if (!loggeds) continue;
      
        if (loggeds > MEM_MAP_H) 
          loggeds = MEM_MAP_H;
           
        inst_hit = 0;
        for (u32 l = 0; l < loggeds; l++) {
          
          if (m_map->cksum[k][l] != afl->orig_mem_map->cksum[k][l]) continue;

          if (m_map->headers[k].type >= HT_VARARG_HOOK1) {
          
            va_o = &m_map->log[k][l].__hook_va_arg;
            orig_va_o = &afl->orig_mem_map->log[k][l].__hook_va_arg;

          }
          else {

            o = &m_map->log[k][l].__hook_op;
            orig_o = &afl->orig_mem_map->log[k][l].__hook_op;
          
          }

          switch (m_map->headers[k].type) {

            case HT_HOOK3: {

              if (o->dst != orig_o->dst) 
                update_colorized(afl, i, j, k, l, HT_HOOK3, MEMLOG_DST, &input_tainted, &inst_hit);
              if (o->value != orig_o->value)
                update_colorized(afl, i, j, k, l, HT_HOOK3, MEMLOG_VALUE, &input_tainted, &inst_hit);
              if (o->size != orig_o->size) 
                update_colorized(afl, i, j, k, l, HT_HOOK3, MEMLOG_SIZE, &input_tainted, &inst_hit);
              break;
            
            }
            case HT_HOOK4: {

              if (o->dst != orig_o->dst)
                update_colorized(afl, i, j, k, l, HT_HOOK4, MEMLOG_DST, &input_tainted, &inst_hit);
              if (o->src != orig_o->src)
                update_colorized(afl, i, j, k, l, HT_HOOK4, MEMLOG_SRC, &input_tainted, &inst_hit);
              if (o->size != orig_o->size) 
                update_colorized(afl, i, j, k, l, HT_HOOK4, MEMLOG_SIZE, &input_tainted, &inst_hit);        
              break;

            }
            case HT_HOOK5: {

              if (o->size != orig_o->size) 
                update_colorized(afl, i, j, k, l, HT_HOOK5, MEMLOG_SIZE, &input_tainted, &inst_hit);
              break;

            }
            case HT_HOOK6: {

              if (o->src != orig_o->src) 
                update_colorized(afl, i, j, k, l, HT_HOOK6, MEMLOG_SRC, &input_tainted, &inst_hit);
              break;

            }
            case HT_HOOK7: {

              if (o->src != orig_o->src)
                update_colorized(afl, i, j, k, l, HT_HOOK7, MEMLOG_SRC, &input_tainted, &inst_hit);
              if (o->size != orig_o->size) 
                update_colorized(afl, i, j, k, l, HT_HOOK7, MEMLOG_SIZE, &input_tainted, &inst_hit);
              break;

            }
            case HT_VARARG_HOOK1: {
              
              for (u32 idx = 0; idx < va_o->num; idx++) {

                if (va_o->idx[idx] != orig_va_o->idx[idx]) {

                  update_colorized(afl, i, j, k, l, HT_VARARG_HOOK1, MEMLOG_IDX, &input_tainted, &inst_hit);
                
                }

              }

              if (va_o->ptr != orig_va_o->ptr) 
                update_colorized(afl, i, j, k, l, HT_VARARG_HOOK1, MEMLOG_VA_SRC, &input_tainted, &inst_hit);
    
              break;
            }
            default:
              break;

          }

        }

      }
       
      // restore input
      *(buf + i) = *(orig_buf + i);
      // update afl_cur
      afl->stage_cur += 1;

    }

  }

  /* taint inference no check */
  afl->stage_name = "taint inference";
  afl->stage_short = "infer";
  afl->stage_max = len * MEMLOG_MUTATOR_NUM;
  afl->stage_cur = 0;

  afl->is_colored = 2;
  afl->infer_tainted_len = 0;

  memset(afl->infer_ht_tainted, 0, MEMLOG_HOOK_NUM * MEMLOG_MUTATOR_NUM * sizeof(u32));

  memcpy(buf, orig_buf, len);
  for (u32 i = 0; i < len; i++) {
    
    input_tainted = 0;
    afl->stage_cur_byte = i;
   
    // byte-level mutate
    for (u32 j = 0; j < MEMLOG_MUTATOR_NUM; j++) { 
      // mutator
      switch(j) {
        case 0: {
          _bit = (i << 3) + rand_below(afl, 8);
          FLIP_BIT(buf, _bit);
          break;
        }
        case 1: {
          *(buf + i) += 1;
          break;
        }
        case 2: {
          type_replace(afl, buf + i, 1);
          break;
        }
        case 3: {
          *(buf + i) -= 1;
          break;
        }
        default:
          break;
      }
      
      // execute
      memset(m_map, 0, sizeof(struct mem_map));
      if (unlikely(common_fuzz_memlog_stuff(afl, buf, len))) return 1;

      for (u32 k = 0; k < MEM_MAP_W; k++) {
        
        // check unstable
        // different path
        loggeds = MIN(m_map->headers[k].hits, afl->orig_mem_map->headers[k].hits);
        if (!loggeds) continue;
      
        if (loggeds > MEM_MAP_H) 
          loggeds = MEM_MAP_H;
        
        inst_hit = 0;
        for (u32 l = 0; l < loggeds; l++) {
        
          if (m_map->headers[k].type >= HT_VARARG_HOOK1) {
          
            va_o = &m_map->log[k][l].__hook_va_arg;
            orig_va_o = &afl->orig_mem_map->log[k][l].__hook_va_arg;

          }
          else {

            o = &m_map->log[k][l].__hook_op;
            orig_o = &afl->orig_mem_map->log[k][l].__hook_op;
          
          }

          switch (m_map->headers[k].type) {

            case HT_HOOK3: {

              if (o->dst != orig_o->dst) 
                update_colorized(afl, i, j, k, l, HT_HOOK3, MEMLOG_DST, &input_tainted, &inst_hit);
              if (o->value != orig_o->value)
                update_colorized(afl, i, j, k, l, HT_HOOK3, MEMLOG_VALUE, &input_tainted, &inst_hit);
              if (o->size != orig_o->size) 
                update_colorized(afl, i, j, k, l, HT_HOOK3, MEMLOG_SIZE, &input_tainted, &inst_hit);
              break;
            
            }
            case HT_HOOK4: {

              if (o->dst != orig_o->dst)
                update_colorized(afl, i, j, k, l, HT_HOOK4, MEMLOG_DST, &input_tainted, &inst_hit);
              if (o->src != orig_o->src)
                update_colorized(afl, i, j, k, l, HT_HOOK4, MEMLOG_SRC, &input_tainted, &inst_hit);
              if (o->size != orig_o->size) 
                update_colorized(afl, i, j, k, l, HT_HOOK4, MEMLOG_SIZE, &input_tainted, &inst_hit);        
              break;

            }
            case HT_HOOK5: {

              if (o->size != orig_o->size) 
                update_colorized(afl, i, j, k, l, HT_HOOK5, MEMLOG_SIZE, &input_tainted, &inst_hit);
              break;

            }
            case HT_HOOK6: {

              if (o->src != orig_o->src) 
                update_colorized(afl, i, j, k, l, HT_HOOK6, MEMLOG_SRC, &input_tainted, &inst_hit);
              break;

            }
            case HT_HOOK7: {

              if (o->src != orig_o->src)
                update_colorized(afl, i, j, k, l, HT_HOOK7, MEMLOG_SRC, &input_tainted, &inst_hit);
              if (o->size != orig_o->size) 
                update_colorized(afl, i, j, k, l, HT_HOOK7, MEMLOG_SIZE, &input_tainted, &inst_hit);
              break;

            }
            case HT_VARARG_HOOK1: {
              
              for (u32 idx = 0; idx < va_o->num; idx++) {

                if (va_o->idx[idx] != orig_va_o->idx[idx]) {

                  update_colorized(afl, i, j, k, l, HT_VARARG_HOOK1, MEMLOG_IDX, &input_tainted, &inst_hit);
                
                }

              }

              if (va_o->ptr != orig_va_o->ptr) 
                update_colorized(afl, i, j, k, l, HT_VARARG_HOOK1, MEMLOG_VA_SRC, &input_tainted, &inst_hit);
    
              break;
            }
            default:
              break;

          }

        }

      }
       
      // restore input
      *(buf + i) = *(orig_buf + i);
      // update afl_cur
      afl->stage_cur += 1;

    }

  }

  // taint part only mutation
  /*afl->stage_name = "taint havoc";
  afl->stage_short = "taint";
  afl->stage_max = 0;
  afl->stage_cur = 0;
  
  m_map = afl->orig_memlog_map;
  for(u32 i = 0; i < MEMLOG_MAP_W; i++) {
    if (!m_map->headers[i].hits) continue;
    loggeds = m_map->headers[i].hits;
    if (loggeds > MEMLOG_MAP_H) 
        loggeds = MEMLOG_MAP_H;
    
    for(u32 j = 0; j < loggeds; j++) {
    
      for(u32 k = 0; k < MEMLOG_OP_NUM; k++) {
        
        t = (*afl->memlog_tainted_map)[i][j][k];
        if (t == NULL) continue;
        taint_havoc(afl, buf, orig_buf, len, i, j, k, t);
      }
    
    }
  
  }*/
  
  // linear search
  /*afl->stage_name = "linear search";
  afl->stage_short = "linear";
  afl->stage_max = 0;
  afl->stage_cur = 0;
  
  m_map = afl->orig_memlog_map;
  for(u32 i = 0; i < MEMLOG_MAP_W; i++) {
    if (!m_map->headers[i].hits) continue;
    loggeds = m_map->headers[i].hits;
    if (loggeds > MEMLOG_MAP_H) 
        loggeds = MEMLOG_MAP_H;
    
    for(u32 j = 0; j < loggeds; j++) {
    
      for(u32 k = 0; k < MEMLOG_OP_NUM; k++) {
        
        t = (*afl->memlog_tainted_map)[i][j][k];
        if (t == NULL) continue;
        while(t != NULL) {
          
          for(u32 l = 0; l < t->len; l++) {
            
            if (k == MEMLOG_IDX) { 
              
              for(u32 m = 0; m < m_map->log[i][j].__hook_va_arg.num; m++) {
                
                afl->memlog_idx_num = m_map->log[i][j].__hook_va_arg.num;
                gradient_descend(afl, buf, len, t->pos + l, i, j, k, m, 1);
                // restore buf
                memcpy(buf, orig_buf, len);
                gradient_descend(afl, buf, len, t->pos + l, i, j, k, m, -1);
              
              }
            }
            else {
              
              afl->memlog_idx_num = 0;
              gradient_descend(afl, buf, len, t->pos + l, i, j, k, 0, 1);
              // restore buf
              memcpy(buf, orig_buf, len);
              gradient_descend(afl, buf, len, t->pos + l, i, j, k, 0, -1);
            
            }
          }
          t = t->next;
        }
        // restore buf
        memcpy(buf, orig_buf, len);
      }
    
    }
  
  }*/

  // free 
  /*for(u32 i = 0; i < MEM_MAP_W; i++) {

    for(u32 j = 0; j < MEM_MAP_H; j++) {
      
      for(u32 k = 0; k < MEMLOG_OP_NUM; k++) {
        t = (*afl->memlog_tainted_map)[i][j][k];
        while(t != NULL) {
          
          prev = t;
          t = t->next;
          free(prev);

        }
      }

    }

  }*/

  return 0;

}