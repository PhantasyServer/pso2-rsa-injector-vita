#include <psp2/io/fcntl.h>
#include <psp2/kernel/clib.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/net/net.h>
#include <psp2/net/netctl.h>
#include <psp2/sysmodule.h>
#include <stdlib.h>
#include <string.h>
#include <taihen.h>

uint8_t *__aeabi_unwind_cpp_pr0 = 0;
static SceUID thid_main = -1;

__attribute((unused)) void unused_fns(void) {
  memcmp(0, 0, 0);
  strlen(0);
  void *a = malloc(0);
  a = calloc(0, 0);
  free(a);
  taiGetModuleInfo(0, 0);
  taiHookRelease(0, 0);
  sceKernelGetModuleInfo(0, 0);
  sceIoOpen(0, 0, 0);
  sceIoClose(0);
  sceIoRead(0, 0, 0);
  taiHookFunctionImportForUser(0, 0);
  sceKernelDelayThread(1000 * 10);
  sceKernelCreateMutex(0, 0, 0, 0);
  sceKernelLockMutex(0, 0, 0);
  sceKernelUnlockMutex(0, 0);
  sceKernelGetProcessId();
  taiInjectAbs(0, 0, 0);
  taiInjectRelease(0);
}

// ------------------------------------
// Hooks
// ------------------------------------

void rust_main(void);

int main_thread(SceSize args, void *argp) {
  rust_main();
  sceKernelExitDeleteThread(0);
  return 0;
}

// ------------------------------------
// Entry point
// ------------------------------------

int _start(SceSize args, void *argp)
    __attribute__((weak, alias("module_start")));
int module_start(SceSize args, void *argp) {
  thid_main = sceKernelCreateThread("pso2_injector_main", main_thread, 64,
                                    0x2000, 0, 0x10000, 0);
  if (thid_main >= 0)
    sceKernelStartThread(thid_main, 0, NULL);
  return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize args, void *argp) {
  sceClibPrintf("module stop\n");
  return SCE_KERNEL_STOP_SUCCESS;
}

int module_exit(SceSize args, void *argp) {
  sceClibPrintf("module exit\n");
  return SCE_KERNEL_START_SUCCESS;
}
