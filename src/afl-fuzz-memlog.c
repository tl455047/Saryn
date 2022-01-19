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

  // Reset memlog bitmap before each execution.
  memset(afl->shm.mem_map, 0, sizeof(struct mem_map));

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

  //afl->queued_discovered += save_if_interesting(afl, out_buf, len, fault);

  if (!(afl->stage_cur % afl->stats_update_freq) ||
      afl->stage_cur + 1 == afl->stage_max) {

    show_stats(afl);

  }

  return 0;

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
