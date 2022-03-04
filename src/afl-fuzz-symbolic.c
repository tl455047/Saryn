#include "afl-fuzz.h"
#include "list.h"
/**
 * We should check symbolc_path is exist before bump into this function.
 * 
 *
 * Should be called only when fuzzer stucks.
 * We use S2E as our symbolic execution engine, 
 * this function prepares all things needed by
 * symbolic execution. Firstly, we apply 
 * taint inference to current seed, and send 
 * the seed with critical bytes to S2E. Wrapper
 * in S2E reads critical bytes as filename.symranges.
 * here we manually prepare the critical bytes file as
 * filename.symranges.
 * WANT TO DO
 * We try to decide which branch we want S2E to solve for us.
 * we need to find out which branch contains uncovered edge, and
 * this cannot be done in current AFL model. To obtain this 
 * information, we need to modify instrumentation part and do this 
 * in compile time. But now, we just try to construct a hybrid 
 * fuzzing system with only critical bytes maked as symbolic input 
 * in symbolic execution.
 */

static void setup_symbolic_testcase(afl_state_t *afl, u8 *buf, u32 len) {
  
  FILE *f;
  u8 *fn; 
  struct tainted *t; 

  // write current seed to S2E project dir
  fn = alloc_printf("%s/poc", afl->symbolic_path);
  f = create_ffile(fn);
  
  fwrite(buf, len, 1, f);

  fclose(f);
  ck_free(fn);
  
  // write critical bytes file to s2e project dir
  fn = alloc_printf("%s/poc.symranges", afl->symbolic_path);
  f = create_ffile(fn);

  t = afl->queue_cur->c_bytes[TAINT_CMP];

  while(t != NULL) {
  
    fprintf(f, "%u-%u\n", t->pos, t->len);
    t = t->next;
  
  }

  fclose(f);
  ck_free(fn);

}

u8 invoke_symbolic(afl_state_t *afl, u8 *buf, u8 *orig_buf, u32 len) {
  
  u8* fn, *s2e_path;
  // u8 *new_fn;
  // s32 status;
  pid_t pid;

  // we assume fuzzer stucks now, and we will invoke the S2E, a 
  // symbolic execution engine, to do single concolic execution.

  // Before launching the symbolic engine, we want to obtain critical
  // bytes for current seed first, this can be used to reduce the symbolic
  // input size dramatically.
  
  // check sync_id since we want to use this mechanism to sync our 
  // testcases from symbolic
  // this should done when checking the symbolic dir

  // taint inference
  memcpy(buf, orig_buf, len);
  
  if (taint_inference_stage(afl, buf, orig_buf, len, TAINT_CMP)) {

    return 1;

  }

  afl->tainted_seed[TAINT_CMP]++;

  setup_symbolic_testcase(afl, buf, len);
  
  // create output dir
  // we follow the nameing convention in S2E
  u32 i;
  for(i = 0;; i++) {
    
    fn = alloc_printf("%s/s2e-out-%d", afl->sync_dir, i);
    
    if (opendir(fn)) {
      
      closedir(fn);
      ck_free(fn);

    }
    else if (errno == ENOENT) {
      
      if (afl->s2e_out_dir) {
      
        ck_free(afl->s2e_out_dir);
        afl->s2e_out_dir = NULL;

      }
      afl->s2e_out_dir = fn;    
      
      break;
    
    }
    else {

      PFATAL("Open directory failed");

    }

  }

  // S2E launch script
  s2e_path = alloc_printf("%s/launch-s2e.sh", afl->symbolic_path);
  
  afl->ready_for_symbolic = 0;
  // launch S2E
  pid = fork();

  if (pid == 0) {
    
    // set S2E output directory to sync directory
    setenv("S2E_OUTPUT_DIR", afl->s2e_out_dir, 1);
    
    // change directory to s2e directory
    if (chdir(afl->symbolic_path) < 0) {
      
      PFATAL("Chdir failed");
        
    }
    
    // redirect stdout, stderr to /dev/null
    close(1);
    
    if (dup(afl->fsrv.dev_null_fd) < 0) {

      PFATAL("Dup failed");

    }
    
    close(2);
    
    if (dup(afl->fsrv.dev_null_fd) < 0) {

      PFATAL("Dup failed");

    }
    
    char *argv[1];
    argv[0] = NULL;
    
    execv(s2e_path, argv);
    
    FATAL("Execv failed in invoke_symbolic.");

  }
  else if (pid > 0) {
    
    // We are not going to wait S2E terminates, since it's quite slow.
    // We set sigaction for signal SIGCHLD, when symbolic engine terminates,
    // it sends the signal to AFL, and we know the symbolic has finished.
    // we put testcases generated by S2E in sync_dir, and can find a good place 
    // to invoke sync_fuzzers. This should be a better way.
  
  }
  else {
    
    PFATAL("Fork failed");

  }

  ck_free(s2e_path);
  
  // memlog mode is not support yet, since it does not have proper S2E plugin to 
  // cooperate with, and S2E does not handle symbolic pointer well currently.
  return 0;

}