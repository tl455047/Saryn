#include "afl-fuzz.h"
#include "list.h"
/**
 * We should check symbolc_path is exist before bump into this function.
 * 
 *
 * Should be called only when fuzzer stucks.
 * We use s2e as our symbolic execution engine, 
 * this function prepares all things needed by
 * symbolic execution. Firstly, we apply 
 * taint inference to current seed, and send 
 * the seed with critical bytes to s2e. Wrapper
 * in s2e reads critical bytes as filename.symranges.
 * here we manually prepare the critical bytes file as
 * filename.symranges.
 * WANT TO DO
 * We try to decide which branch we want s2e to solve for us.
 * we need to find out which branch contains uncovered edge, and
 * this cannot be done in current AFL model. To obtain this 
 * information, we need to modify instrumentation part and do this 
 * in compile time. But now, we just try to construct a hybrid 
 * fuzzing system with only critical bytes maked as symbolic input 
 * in symbolic execution.
 */

static u8 setup_symbolic_testcase(afl_state_t *afl, u8 *buf, u32 len) {
  
  FILE *f;
  u8 *fn; 
  struct tainted_info **tmp;
  struct tainted *t; 

  afl->selected_inst = 0;
  // write selected inst.'s returne address to s2e project dir
  fn = alloc_printf("%s/ret_addr", afl->symbolic_path);
  f = create_ffile(fn);

  tmp = afl->queue_cur->taint[TAINT_CMP];
  
  for(u32 i = 0; i < afl->queue_cur->taint_cur[TAINT_CMP]; i++) {
  
    if (i > 0 && tmp[i]->id == tmp[i-1]->id) 
      continue;
    
    if (afl->pass_stats[TAINT_CMP][tmp[i]->id].faileds == 0xFF || 
        afl->pass_stats[TAINT_CMP][tmp[i]->id].total == 0xFF)
      continue;

    fprintf(f, "%llx %u\n", tmp[i]->ret_addr, tmp[i]->id);
    afl->selected_inst++;
    
  }

  fclose(f);
  ck_free(fn);

  if (!afl->selected_inst)
    return 1;

  // write current seed to s2e project dir
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

  return 0;

}

void handle_failed_inst(afl_state_t *afl, u8 *dir) {
  
  u8 *fn;
  FILE *f;
  u32 id;
  
  fn = alloc_printf("%s/%s/failed.stats", afl->sync_dir, dir);
  
  f = fopen(fn, "r");
  
  if (f) {
  
    while(!feof(f)) {
      
      s32 len = fscanf(f, "%u", &id);
      if (len < 0) break;
      
      afl->pass_stats[TAINT_CMP][id].faileds += 1;

    }
    
    // remove file
    if (remove(fn) < 0) 
      PFATAL("cannot delete failed.stats");

    fclose(f);
    ck_free(fn);

  }
 
}

void reset_cpu_bind(afl_state_t *afl) {
  
  u8  cpu_used[4096] = {0};
  u8  lockfile[PATH_MAX] = "";
  s32 i;
  cpu_set_t c;

  if (afl->cpu_core_count < 2) { return; }
  
  if (afl->sync_id) {

    s32 lockfd, first = 1;

    snprintf(lockfile, sizeof(lockfile), "%s/.affinity_lock", afl->sync_dir);
    setenv(CPU_AFFINITY_ENV_VAR, lockfile, 1);

    do {

      if ((lockfd = open(lockfile, O_RDWR | O_CREAT | O_EXCL,
                         DEFAULT_PERMISSION)) < 0) {

        if (first) {

          WARNF("CPU affinity lock file present, waiting ...");
          first = 0;

        }

        usleep(1000);

      }

    } while (lockfd < 0);

    close(lockfd);

  }
  
  // only for linux

  DIR *          d;
  struct dirent *de;
  d = opendir("/proc");

  if (!d) {

    if (lockfile[0]) unlink(lockfile);
    WARNF("Unable to access /proc - can't scan for free CPU cores.");
    return;

  }
  /* Scan all /proc/<pid>/status entries, checking for Cpus_allowed_list.
     Flag all processes bound to a specific CPU using cpu_used[]. This will
     fail for some exotic binding setups, but is likely good enough in almost
     all real-world use cases. */

  while ((de = readdir(d))) {

    u8    fn[PATH_MAX];
    FILE *f;
    u8    tmp[MAX_LINE];
    u8    has_vmsize = 0;

    if (!isdigit(de->d_name[0])) { continue; }

    snprintf(fn, PATH_MAX, "/proc/%s/status", de->d_name);

    if (!(f = fopen(fn, "r"))) { continue; }

    while (fgets(tmp, MAX_LINE, f)) {

      u32 hval;

      /* Processes without VmSize are probably kernel tasks. */

      if (!strncmp(tmp, "VmSize:\t", 8)) { has_vmsize = 1; }

      if (!strncmp(tmp, "Cpus_allowed_list:\t", 19) && !strchr(tmp, '-') &&
          !strchr(tmp, ',') && sscanf(tmp + 19, "%u", &hval) == 1 &&
          hval < sizeof(cpu_used) && has_vmsize) {

        cpu_used[hval] = 1;
        break;

      }

    }

    fclose(f);

  }

  closedir(d);

  size_t cpu_start = 0;
  cpu_set_t orig_c;

  if (sched_getaffinity(0, sizeof(orig_c), &orig_c)) {

    PFATAL("getaffinity failed");

  }

  CPU_ZERO(&c);

  for (i = cpu_start; i < afl->cpu_core_count; i++) {

    if (cpu_used[i]) { continue; }

    if (!CPU_ISSET(i, &orig_c)) {

      CPU_SET(i, &c);
    
    }
    
  }

  if (sched_setaffinity(0, sizeof(c), &c)) {
      
    PFATAL("setaffinity failed");

  }

  if (lockfile[0]) unlink(lockfile);

}

u8 invoke_symbolic(afl_state_t *afl, u8 *buf, u8 *orig_buf, u32 len) {
  
  u8* fn, *s2e_path;
  DIR *d;
  // u8 *new_fn;
  // s32 status;
  pid_t pid;

  // we assume fuzzer stucks now, and we will invoke the s2e, a 
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
  
  if (setup_symbolic_testcase(afl, buf, len)) {

    return 1;

  }
  
  // create output dir
  // we follow the nameing convention in s2e
  u32 i;
  for(i = 0;; i++) {
    
    fn = alloc_printf("%s/s2e-out-%d", afl->sync_dir, afl->queue_cur->id);
    
    d = opendir(fn);
    
    if (d) {
      
      closedir(d);
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

  // s2e launch script
  s2e_path = alloc_printf("%s/launch-s2e.sh", afl->symbolic_path);
  
  afl->ready_for_symbolic = 0;
  // launch s2e
  pid = fork();

  if (pid == 0) {
    
    // set s2e output directory to sync directory
    setenv("S2E_OUTPUT_DIR", afl->s2e_out_dir, 1);
    
    // reset cpu affinity
    reset_cpu_bind(afl);
    
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
    
    // We are not going to wait s2e terminates, since it's quite slow.
    // We set sigaction for signal SIGCHLD, when symbolic engine terminates,
    // it sends the signal to AFL, and we know the symbolic has finished.
    // we put testcases generated by s2e in sync_dir, and can find a good place 
    // to invoke sync_fuzzers. This should be a better way.
    fn = alloc_printf("%d", pid);

    setenv(S2E_ENV_VAR, fn, 1);
    
    afl->s2e_usr_time = get_cur_time();

    ck_free(fn);

  }
  else {
    
    PFATAL("Fork failed");

  }

  ck_free(s2e_path);
  
  // memlog mode is not support yet, since it does not have proper s2e plugin to 
  // cooperate with, and s2e does not handle symbolic pointer well currently.
  return 0;

}
