
#include "afl-fuzz.h"
#include "cmplog.h"
#include "memlog.h"
#include <limits.h>
#include <stdlib.h>
#ifndef USEMMAP
  #include <sys/mman.h>
  #include <sys/stat.h>
  #include <fcntl.h>
  #include <sys/ipc.h>
  #include <sys/shm.h>
#endif

static void at_exit() {

  s32   i, pid1 = 0, pid2 = 0, pid3 = 0;
  char *list[5] = {SHM_ENV_VAR, SHM_FUZZ_ENV_VAR, CMPLOG_SHM_ENV_VAR, MEMLOG_SHM_ENV_VAR, NULL};
  char *ptr;

  ptr = getenv(CPU_AFFINITY_ENV_VAR);
  if (ptr && *ptr) unlink(ptr);

  ptr = getenv("__AFL_TARGET_PID1");
  if (ptr && *ptr && (pid1 = atoi(ptr)) > 0) kill(pid1, SIGTERM);

  ptr = getenv("__AFL_TARGET_PID2");
  if (ptr && *ptr && (pid2 = atoi(ptr)) > 0) kill(pid2, SIGTERM);

  ptr = getenv("__AFL_TARGET_PID3");
  if (ptr && *ptr && (pid3 = atoi(ptr)) > 0) kill(pid3, SIGTERM);

  i = 0;
  while (list[i] != NULL) {

    ptr = getenv(list[i]);
    if (ptr && *ptr) {

#ifdef USEMMAP

      shm_unlink(ptr);

#else

      shmctl(atoi(ptr), IPC_RMID, NULL);

#endif

    }

    i++;

  }

  int kill_signal = SIGKILL;
  /* AFL_KILL_SIGNAL should already be a valid int at this point */
  if ((ptr = getenv("AFL_KILL_SIGNAL"))) { kill_signal = atoi(ptr); }

  if (pid1 > 0) { kill(pid1, kill_signal); }
  if (pid2 > 0) { kill(pid2, kill_signal); }
  if (pid3 > 0) { kill(pid3, kill_signal); }

}


/* Display usage hints. */

static void usage(u8 *argv0) {

  SAYF(
      "\n%s [ options ] -- /path/to/fuzzed_app [ ... ]\n\n"

      "Required parameters:\n"
      "  -i dir        - input directory with test cases\n"
      "  -o dir        - output directory for fuzzer findings\n"
      "  -c program    - enable CmpLog by specifying a binary compiled for\n"
      "  -m megs       - memory limit for child process (%u MB, 0 = no limit\n"
      "  -t msec       - timeout for each run (auto-scaled, default %u ms).\n"
      "  -y program    - enable Memlog by specifying a binary compiled for\n",
      argv0, EXEC_TIMEOUT, MEM_LIMIT);
      

}
/* Main entry point */

int main(int argc, char **argv_orig, char **envp) {
  
  u8  mem_limit_given = 0;
  s32 opt;
  u32 show_help = 0, map_size = get_map_size();
  char **argv = argv_cpy_dup(argc, argv_orig);
  char **use_argv;
  
  struct timeval  tv;
  struct timezone tz;

  afl_state_t *afl = calloc(1, sizeof(afl_state_t));
  if (!afl) { FATAL("Could not create afl state"); }

  afl_state_init(afl, map_size);
  afl_fsrv_init(&afl->fsrv);
  read_afl_environment(afl, envp);

  if (afl->shm.map_size) { afl->fsrv.map_size = afl->shm.map_size; }

  doc_path = access(DOC_PATH, F_OK) != 0 ? (u8 *)"docs" : (u8 *)DOC_PATH;
  
  gettimeofday(&tv, &tz);
  rand_set_seed(afl, tv.tv_sec ^ tv.tv_usec ^ getpid());

  afl->shmem_testcase_mode = 1;  // we always try to perform shmem fuzzing

   while ((opt = getopt(
              argc, argv,
              "+c:hi:f:m:o:t:y:")) > 0) {

    switch (opt) {

      // enable memlog mode
      case 'y': {
       
        afl->shm.memlog_mode = 1;
        afl->memlog_binary = ck_strdup(optarg);
        break;

      }

      case 'c': {

        afl->shm.cmplog_mode = 1;
        afl->cmplog_binary = ck_strdup(optarg);
        break;

      }

      case 'i':                                                /* input dir */

        if (afl->in_dir) { FATAL("Multiple -i options not supported"); }
        if (optarg == NULL) { FATAL("Invalid -i option (got NULL)."); }
        afl->in_dir = optarg;

        break;

      case 'o':                                               /* output dir */

        if (afl->out_dir) { FATAL("Multiple -o options not supported"); }
        afl->out_dir = optarg;
        break;

      case 'f':                                              /* target file */

        if (afl->fsrv.out_file) { FATAL("Multiple -f options not supported"); }
        afl->fsrv.out_file = ck_strdup(optarg);
        afl->fsrv.use_stdin = 0;
        break;

      case 't': {                                                /* timeout */

        u8 suffix = 0;

        if (afl->timeout_given) { FATAL("Multiple -t options not supported"); }

        if (!optarg ||
            sscanf(optarg, "%u%c", &afl->fsrv.exec_tmout, &suffix) < 1 ||
            optarg[0] == '-') {

          FATAL("Bad syntax used for -t");

        }

        if (afl->fsrv.exec_tmout < 5) { FATAL("Dangerously low value of -t"); }

        if (suffix == '+') {

          afl->timeout_given = 2;

        } else {

          afl->timeout_given = 1;

        }

        break;

      }

      case 'm': {                                              /* mem limit */

        u8 suffix = 'M';

        if (mem_limit_given) { FATAL("Multiple -m options not supported"); }
        mem_limit_given = 1;

        if (!optarg) { FATAL("Wrong usage of -m"); }

        if (!strcmp(optarg, "none")) {

          afl->fsrv.mem_limit = 0;
          break;

        }

        if (sscanf(optarg, "%llu%c", &afl->fsrv.mem_limit, &suffix) < 1 ||
            optarg[0] == '-') {

          FATAL("Bad syntax used for -m");

        }

        switch (suffix) {

          case 'T':
            afl->fsrv.mem_limit *= 1024 * 1024;
            break;
          case 'G':
            afl->fsrv.mem_limit *= 1024;
            break;
          case 'k':
            afl->fsrv.mem_limit /= 1024;
            break;
          case 'M':
            break;

          default:
            FATAL("Unsupported suffix or bad syntax for -m");

        }

        if (afl->fsrv.mem_limit < 5) { FATAL("Dangerously low value of -m"); }

        if (sizeof(rlim_t) == 4 && afl->fsrv.mem_limit > 2000) {

          FATAL("Value of -m out of range on 32-bit systems");

        }

      }

      break;

      case 'h':
        show_help++;
        break;  // not needed

      case 'R':

        FATAL(
            "Radamsa is now a custom mutator, please use that "
            "(custom_mutators/radamsa/).");

        break;

      default:
        if (!show_help) { show_help = 1; }

    }

  }
  
  if (optind == argc || !afl->in_dir || !afl->out_dir || show_help) {

    usage(argv[0]);
    return 1;

  }

  if (afl->fsrv.mem_limit && afl->shm.cmplog_mode) afl->fsrv.mem_limit += 260;

  // How many memory does memlog mode need ?
  if (afl->fsrv.mem_limit && afl->shm.memlog_mode) afl->fsrv.mem_limit += 260;

  afl->fsrv.kill_signal =
      parse_afl_kill_signal_env(afl->afl_env.afl_kill_signal, SIGKILL);

  setup_signal_handlers();
  check_asan_opts(afl);
 
  afl->power_name = power_names[afl->schedule];

  if (!strcmp(afl->in_dir, afl->out_dir)) {

    FATAL("Input and output directories can't be the same");

  }
  
  setenv("__AFL_OUT_DIR", afl->out_dir, 1);
  
  if (!afl->use_banner) { afl->use_banner = argv[optind]; }

  if (strchr(argv[optind], '/') == NULL) {

    WARNF(cLRD
          "Target binary called without a prefixed path, make sure you are "
          "fuzzing the right binary: " cRST "%s",
          argv[optind]);

  }
  
  switch (afl->schedule) {

    case FAST:
      OKF("Using exponential power schedule (FAST)");
      break;
    case COE:
      OKF("Using cut-off exponential power schedule (COE)");
      break;
    case EXPLOIT:
      OKF("Using exploitation-based constant power schedule (EXPLOIT)");
      break;
    case LIN:
      OKF("Using linear power schedule (LIN)");
      break;
    case QUAD:
      OKF("Using quadratic power schedule (QUAD)");
      break;
    case MMOPT:
      OKF("Using modified MOpt power schedule (MMOPT)");
      break;
    case RARE:
      OKF("Using rare edge focus power schedule (RARE)");
      break;
    case SEEK:
      OKF("Using seek power schedule (SEEK)");
      break;
    case EXPLORE:
      OKF("Using exploration-based constant power schedule (EXPLORE)");
      break;
    default:
      FATAL("Unknown power schedule");
      break;

  }

  if (afl->shm.cmplog_mode) { OKF("CmpLog level: %u", afl->cmplog_lvl); }
  
  /* Dynamically allocate memory for AFLFast schedules */
  if (afl->schedule >= FAST && afl->schedule <= RARE) {

    afl->n_fuzz = ck_alloc(N_FUZZ_SIZE * sizeof(u32));

  }

  if (afl->afl_env.afl_hang_tmout) {

    s32 hang_tmout = atoi(afl->afl_env.afl_hang_tmout);
    if (hang_tmout < 1) { FATAL("Invalid value for AFL_HANG_TMOUT"); }
    afl->hang_tmout = (u32)hang_tmout;

  }

  if (afl->afl_env.afl_exit_on_time) {

    u64 exit_on_time = atoi(afl->afl_env.afl_exit_on_time);
    afl->exit_on_time = (u64)exit_on_time * 1000;

  }

  if (afl->afl_env.afl_testcache_size) {

    afl->q_testcase_max_cache_size =
        (u64)atoi(afl->afl_env.afl_testcache_size) * 1048576;

  }

  if (afl->afl_env.afl_testcache_entries) {

    afl->q_testcase_max_cache_entries =
        (u32)atoi(afl->afl_env.afl_testcache_entries);

    // user_set_cache = 1;

  }

  if (!afl->afl_env.afl_testcache_size || !afl->afl_env.afl_testcache_entries) {

    afl->afl_env.afl_testcache_entries = 0;
    afl->afl_env.afl_testcache_size = 0;

  }

  if (!afl->q_testcase_max_cache_size) {

    ACTF(
        "No testcache was configured. it is recommended to use a testcache, it "
        "improves performance: set AFL_TESTCACHE_SIZE=(value in MB)");

  } else if (afl->q_testcase_max_cache_size < 2 * MAX_FILE) {

    FATAL("AFL_TESTCACHE_SIZE must be set to %ld or more, or 0 to disable",
          (2 * MAX_FILE) % 1048576 == 0 ? (2 * MAX_FILE) / 1048576
                                        : 1 + ((2 * MAX_FILE) / 1048576));

  } else {

    OKF("Enabled testcache with %llu MB",
        afl->q_testcase_max_cache_size / 1048576);

  }

  if (afl->afl_env.afl_forksrv_init_tmout) {

    afl->fsrv.init_tmout = atoi(afl->afl_env.afl_forksrv_init_tmout);
    if (!afl->fsrv.init_tmout) {

      FATAL("Invalid value of AFL_FORKSRV_INIT_TMOUT");

    }

  } else {

    afl->fsrv.init_tmout = afl->fsrv.exec_tmout * FORK_WAIT_MULT;

  }

  check_crash_handling();
  check_cpu_governor(afl);

  if (getenv("LD_PRELOAD")) {

    WARNF(
        "LD_PRELOAD is set, are you sure that is what to you want to do "
        "instead of using AFL_PRELOAD?");

  }
  
  if (afl->afl_env.afl_preload) {

    /* CoreSight mode uses the default behavior. */

    setenv("LD_PRELOAD", getenv("AFL_PRELOAD"), 1);
    setenv("DYLD_INSERT_LIBRARIES", getenv("AFL_PRELOAD"), 1);

  }
  
  if (afl->afl_env.afl_target_env &&
      !extract_and_set_env(afl->afl_env.afl_target_env)) {

    FATAL("Bad value of AFL_TARGET_ENV");

  }

  save_cmdline(afl, argc, argv);
  check_if_tty(afl);
  if (afl->afl_env.afl_force_ui) { afl->not_on_tty = 0; }

  get_core_count(afl);

  atexit(at_exit);

  setup_dirs_fds(afl);

  #ifdef HAVE_AFFINITY
  bind_to_free_cpu(afl);
  #endif                                                   /* HAVE_AFFINITY */

  #ifdef __HAIKU__
  /* Prioritizes performance over power saving */
  set_scheduler_mode(SCHEDULER_MODE_LOW_LATENCY);
  #endif

  #ifdef __APPLE__
  if (pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0) != 0) {

    WARNF("general thread priority settings failed");

  }

  #endif

  init_count_class16();

  write_setup_file(afl, argc, argv);

  setup_cmdline_file(afl, argv + optind);

  read_testcases(afl, NULL);

  pivot_inputs(afl);

  if (!afl->timeout_given) { find_timeout(afl); }  // only for resumes!

  if ((afl->tmp_dir = afl->afl_env.afl_tmpdir) != NULL &&
      !afl->in_place_resume) {

    char tmpfile[PATH_MAX];

    if (afl->file_extension) {

      snprintf(tmpfile, PATH_MAX, "%s/.cur_input.%s", afl->tmp_dir,
               afl->file_extension);

    } else {

      snprintf(tmpfile, PATH_MAX, "%s/.cur_input", afl->tmp_dir);

    }

    /* there is still a race condition here, but well ... */
    if (access(tmpfile, F_OK) != -1) {

      FATAL(
          "AFL_TMPDIR already has an existing temporary input file: %s - if "
          "this is not from another instance, then just remove the file.",
          tmpfile);

    }

  } else {

    afl->tmp_dir = afl->out_dir;

  }

  if (!afl->fsrv.out_file) {

    u32 j = optind + 1;
    while (argv[j]) {

      u8 *aa_loc = strstr(argv[j], "@@");

      if (aa_loc && !afl->fsrv.out_file) {

        afl->fsrv.use_stdin = 0;

        if (afl->file_extension) {

          afl->fsrv.out_file = alloc_printf("%s/.cur_input.%s", afl->tmp_dir,
                                            afl->file_extension);

        } else {

          afl->fsrv.out_file = alloc_printf("%s/.cur_input", afl->tmp_dir);

        }

        detect_file_args(argv + optind + 1, afl->fsrv.out_file,
                         &afl->fsrv.use_stdin);
        break;

      }

      ++j;

    }

  }

  if (!afl->fsrv.out_file) { setup_stdio_file(afl); }

  if (afl->cmplog_binary) {

    check_binary(afl, afl->cmplog_binary);
  
  }

  if (afl->memlog_binary) {

    check_binary(afl, afl->memlog_binary);

  }

  check_binary(afl, argv[optind]);
  
  if (afl->shmem_testcase_mode) { setup_testcase_shmem(afl); }

  use_argv = argv + optind;
  afl->argv = use_argv;
  afl->fsrv.trace_bits =
      afl_shm_init(&afl->shm, afl->fsrv.map_size, afl->non_instrumented_mode);
  
  if (map_size <= DEFAULT_SHMEM_SIZE) {

    afl->fsrv.map_size = DEFAULT_SHMEM_SIZE;  // dummy temporary value
    char vbuf[16];
    snprintf(vbuf, sizeof(vbuf), "%u", DEFAULT_SHMEM_SIZE);
    setenv("AFL_MAP_SIZE", vbuf, 1);

  }

  u32 new_map_size = afl_fsrv_get_mapsize(
    &afl->fsrv, afl->argv, &afl->stop_soon, afl->afl_env.afl_debug_child);

  // only reinitialize if the map needs to be larger than what we have.
  if (map_size < new_map_size) {

    OKF("Re-initializing maps to %u bytes", new_map_size);

    afl->virgin_bits = ck_realloc(afl->virgin_bits, new_map_size);
    afl->virgin_tmout = ck_realloc(afl->virgin_tmout, new_map_size);
    afl->virgin_crash = ck_realloc(afl->virgin_crash, new_map_size);
    afl->var_bytes = ck_realloc(afl->var_bytes, new_map_size);
    afl->top_rated =
        ck_realloc(afl->top_rated, new_map_size * sizeof(void *));
    afl->clean_trace = ck_realloc(afl->clean_trace, new_map_size);
    afl->clean_trace_custom =
        ck_realloc(afl->clean_trace_custom, new_map_size);
    afl->first_trace = ck_realloc(afl->first_trace, new_map_size);
    afl->map_tmp_buf = ck_realloc(afl->map_tmp_buf, new_map_size);

    afl_fsrv_kill(&afl->fsrv);
    afl_shm_deinit(&afl->shm);
    afl->fsrv.map_size = new_map_size;
    afl->fsrv.trace_bits =
        afl_shm_init(&afl->shm, new_map_size, afl->non_instrumented_mode);
    setenv("AFL_NO_AUTODICT", "1", 1);  // loaded already
    afl_fsrv_start(&afl->fsrv, afl->argv, &afl->stop_soon,
                        afl->afl_env.afl_debug_child);

    map_size = new_map_size;

  }

  if (afl->cmplog_binary) {

    ACTF("Spawning cmplog forkserver");
    afl_fsrv_init_dup(&afl->cmplog_fsrv, &afl->fsrv);
    // TODO: this is semi-nice
    afl->cmplog_fsrv.trace_bits = afl->fsrv.trace_bits;
    afl->cmplog_fsrv.cs_mode = afl->fsrv.cs_mode;
    afl->cmplog_fsrv.qemu_mode = afl->fsrv.qemu_mode;
    afl->cmplog_fsrv.frida_mode = afl->fsrv.frida_mode;
    afl->cmplog_fsrv.cmplog_binary = afl->cmplog_binary;
    afl->cmplog_fsrv.init_child_func = cmplog_exec_child;

    if ((map_size <= DEFAULT_SHMEM_SIZE ||
         afl->cmplog_fsrv.map_size < map_size) &&
        !afl->non_instrumented_mode && !afl->fsrv.qemu_mode &&
        !afl->fsrv.frida_mode && !afl->unicorn_mode && !afl->fsrv.cs_mode &&
        !afl->afl_env.afl_skip_bin_check) {

      afl->cmplog_fsrv.map_size = MAX(map_size, (u32)DEFAULT_SHMEM_SIZE);
      char vbuf[16];
      snprintf(vbuf, sizeof(vbuf), "%u", afl->cmplog_fsrv.map_size);
      setenv("AFL_MAP_SIZE", vbuf, 1);

    }

    u32 new_map_size =
        afl_fsrv_get_mapsize(&afl->cmplog_fsrv, afl->argv, &afl->stop_soon,
                             afl->afl_env.afl_debug_child);

    // only reinitialize when it needs to be larger
    if (map_size < new_map_size) {

      OKF("Re-initializing maps to %u bytes due cmplog", new_map_size);

      afl->virgin_bits = ck_realloc(afl->virgin_bits, new_map_size);
      afl->virgin_tmout = ck_realloc(afl->virgin_tmout, new_map_size);
      afl->virgin_crash = ck_realloc(afl->virgin_crash, new_map_size);
      afl->var_bytes = ck_realloc(afl->var_bytes, new_map_size);
      afl->top_rated =
          ck_realloc(afl->top_rated, new_map_size * sizeof(void *));
      afl->clean_trace = ck_realloc(afl->clean_trace, new_map_size);
      afl->clean_trace_custom =
          ck_realloc(afl->clean_trace_custom, new_map_size);
      afl->first_trace = ck_realloc(afl->first_trace, new_map_size);
      afl->map_tmp_buf = ck_realloc(afl->map_tmp_buf, new_map_size);

      afl_fsrv_kill(&afl->fsrv);
      afl_fsrv_kill(&afl->cmplog_fsrv);
      afl_shm_deinit(&afl->shm);

      afl->cmplog_fsrv.map_size = new_map_size;  // non-cmplog stays the same
      map_size = new_map_size;

      setenv("AFL_NO_AUTODICT", "1", 1);  // loaded already
      afl->fsrv.trace_bits =
          afl_shm_init(&afl->shm, new_map_size, afl->non_instrumented_mode);
      afl->cmplog_fsrv.trace_bits = afl->fsrv.trace_bits;
      afl_fsrv_start(&afl->fsrv, afl->argv, &afl->stop_soon,
                     afl->afl_env.afl_debug_child);
      afl_fsrv_start(&afl->cmplog_fsrv, afl->argv, &afl->stop_soon,
                     afl->afl_env.afl_debug_child);

    }

    OKF("Cmplog forkserver successfully started");

  }

  if (afl->memlog_binary) {

    ACTF("Spawning memlog forkserver");
    afl_fsrv_init_dup(&afl->memlog_fsrv, &afl->fsrv);
    // TODO: this is semi-nice
    afl->memlog_fsrv.trace_bits = afl->fsrv.trace_bits;
    afl->memlog_fsrv.cs_mode = afl->fsrv.cs_mode;
    afl->memlog_fsrv.qemu_mode = afl->fsrv.qemu_mode;
    afl->memlog_fsrv.frida_mode = afl->fsrv.frida_mode;
    afl->memlog_fsrv.memlog_binary = afl->memlog_binary;
    afl->memlog_fsrv.init_child_func = memlog_exec_child;

    if ((map_size <= DEFAULT_SHMEM_SIZE ||
         afl->memlog_fsrv.map_size < map_size) &&
        !afl->non_instrumented_mode && !afl->fsrv.qemu_mode &&
        !afl->fsrv.frida_mode && !afl->unicorn_mode && !afl->fsrv.cs_mode &&
        !afl->afl_env.afl_skip_bin_check) {

      afl->memlog_fsrv.map_size = MAX(map_size, (u32)DEFAULT_SHMEM_SIZE);
      char vbuf[16];
      snprintf(vbuf, sizeof(vbuf), "%u", afl->memlog_fsrv.map_size);
      setenv("AFL_MAP_SIZE", vbuf, 1);

    }

    u32 new_map_size =
        afl_fsrv_get_mapsize(&afl->memlog_fsrv, afl->argv, &afl->stop_soon,
                             afl->afl_env.afl_debug_child);

    // only reinitialize when it needs to be larger
    if (map_size < new_map_size) {

      OKF("Re-initializing maps to %u bytes due memlog", new_map_size);

      afl->virgin_bits = ck_realloc(afl->virgin_bits, new_map_size);
      afl->virgin_tmout = ck_realloc(afl->virgin_tmout, new_map_size);
      afl->virgin_crash = ck_realloc(afl->virgin_crash, new_map_size);
      afl->var_bytes = ck_realloc(afl->var_bytes, new_map_size);
      afl->top_rated =
          ck_realloc(afl->top_rated, new_map_size * sizeof(void *));
      afl->clean_trace = ck_realloc(afl->clean_trace, new_map_size);
      afl->clean_trace_custom =
          ck_realloc(afl->clean_trace_custom, new_map_size);
      afl->first_trace = ck_realloc(afl->first_trace, new_map_size);
      afl->map_tmp_buf = ck_realloc(afl->map_tmp_buf, new_map_size);

      afl_fsrv_kill(&afl->fsrv);
      afl_fsrv_kill(&afl->memlog_fsrv);
      afl_shm_deinit(&afl->shm);

      afl->memlog_fsrv.map_size = new_map_size;  // non-memlog stays the same
      map_size = new_map_size;

      setenv("AFL_NO_AUTODICT", "1", 1);  // loaded already
      afl->fsrv.trace_bits =
          afl_shm_init(&afl->shm, new_map_size, afl->non_instrumented_mode);
      afl->memlog_fsrv.trace_bits = afl->fsrv.trace_bits;
      afl_fsrv_start(&afl->fsrv, afl->argv, &afl->stop_soon,
                     afl->afl_env.afl_debug_child);
      afl_fsrv_start(&afl->memlog_fsrv, afl->argv, &afl->stop_soon,
                     afl->afl_env.afl_debug_child);

    }

    OKF("Memlog forkserver successfully started");
  
  }

  memset(afl->virgin_bits, 255, map_size);

  memset(afl->virgin_tmout, 255, map_size);
  memset(afl->virgin_crash, 255, map_size);
  
  perform_dry_run(afl);

  if (afl->q_testcase_max_cache_entries) {

    afl->q_testcase_cache =
        ck_alloc(afl->q_testcase_max_cache_entries * sizeof(size_t));
    if (!afl->q_testcase_cache) { PFATAL("malloc failed for cache entries"); }

  }
  
  show_init_stats(afl);
  // cull_queue(afl);
  afl->start_time = get_cur_time();
  
  // taint inference to each queue entries
  u8 *in_buf, *out_buf;
  u32 len;
  
  for (u32 i = 0; i < afl->queued_items; i++) {
    
    afl->queue_cur = afl->queue_buf[i];
    in_buf = queue_testcase_get(afl, afl->queue_cur);
    len = afl->queue_cur->len;
   
    out_buf = afl_realloc(AFL_BUF_PARAM(out), len);
    if (unlikely(!out_buf)) { PFATAL("alloc"); }
    
    // cmplog mode
    // if (unlikely(afl->shm.cmplog_mode) && (u32)len <= afl->cmplog_max_filesize) {
    if (unlikely(afl->shm.cmplog_mode)) {  
        memcpy(out_buf, in_buf, len);
        if (taint_inference_stage(afl, out_buf, in_buf, len, TAINT_CMP)) {

          goto taint_inference_next_iter;

        
        }
    }
    
    // memlog mode
    if (unlikely(afl->shm.memlog_mode)) {
        memcpy(out_buf, in_buf, len);
        if (taint_inference_stage(afl, out_buf, in_buf, len, TAINT_MEM)) {

          goto taint_inference_next_iter;

        }
        
    }
    
  taint_inference_next_iter:    
    if (afl->stop_soon) break;
  
  }

  SAYF(CURSOR_SHOW cLRD "\n\n+++ Testing aborted %s +++\n" cRST,
       afl->stop_soon == 2 ? "programmatically" : "by user");
  
  SAYF("taint %u queue entries, totally %u entries tainted\n", afl->queued_items, 
    MAX((u32)(afl->tainted_seed[TAINT_CMP]), (u32)(afl->tainted_seed[TAINT_MEM])));

  destroy_queue(afl);
  
  afl_shm_deinit(&afl->shm);

  if (afl->shm_fuzz) {

    afl_shm_deinit(afl->shm_fuzz);
    ck_free(afl->shm_fuzz);

  }

  afl_fsrv_deinit(&afl->fsrv);
  
  if (afl->orig_cmdline) { ck_free(afl->orig_cmdline); }
  ck_free(afl->fsrv.target_path);
  ck_free(afl->fsrv.out_file);

  if (afl->q_testcase_cache) { ck_free(afl->q_testcase_cache); }
  afl_state_deinit(afl);
  free(afl);                                                 /* not tracked */

  argv_cpy_free(argv);

  alloc_report();

  OKF("We're done here. Have a nice day!\n");

  exit(0);

}