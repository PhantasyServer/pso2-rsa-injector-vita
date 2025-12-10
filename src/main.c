#include "psp2/message_dialog.h"
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
  sceKernelCreateMutex(0, 0, 0, 0);
  sceKernelLockMutex(0, 0, 0);
  sceKernelUnlockMutex(0, 0);
  sceKernelGetProcessId();
  taiInjectAbs(0, 0, 0);
  taiInjectRelease(0);
  sceKernelExitProcess(0);
  sceMsgDialogInit(0);
  sceCommonDialogSetConfigParam(0);
  sceMsgDialogGetStatus();
  sceMsgDialogTerm();
}

void rust_main(void);

// ------------------------------------
// Entry point
// ------------------------------------

int _start(SceSize args, void *argp)
    __attribute__((weak, alias("module_start")));
int module_start(SceSize args, void *argp) {
  rust_main();
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
