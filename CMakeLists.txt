cmake_minimum_required(VERSION 3.10)

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  if(DEFINED ENV{VITASDK})
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VITASDK}/share/vita.toolchain.cmake" CACHE PATH "toolchain file")
  else()
    message(FATAL_ERROR "Please define VITASDK to point to your SDK path!")
  endif()
endif()

project(pso2_injector)
include("${VITASDK}/share/vita.cmake" REQUIRED)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-q -Wall -fvisibility=hidden -O2 -fno-inline -fno-builtin")

set(VITA_MAKE_FSELF_FLAGS "${VITA_MAKE_FSELF_FLAGS} -a 0x2F00000000000101")

enable_language(C)

include_directories(${PROJECT_NAME} PRIVATE thirdparty)

# set(Rust_CARGO_TARGET "armv7-sony-vita-newlibeabihf")
set(Rust_CARGO_TARGET "armv7a-none-eabihf")
set(Rust_TOOLCHAIN "nightly")
include(FetchContent)

FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
    GIT_TAG v0.5 # Optionally specify a commit hash, version tag or branch here
)
FetchContent_MakeAvailable(Corrosion)

# Import targets defined in a package or workspace manifest `Cargo.toml` file
corrosion_import_crate(
    MANIFEST_PATH rust-lib/Cargo.toml 
    NO_STD
    PROFILE "release"
    FLAGS "-Zbuild-std=core,alloc"
)

add_executable(${PROJECT_NAME}
  src/main.c
)

target_link_libraries(${PROJECT_NAME}
  rust_lib
  SceRtabi_stub
  SceIofilemgr_stub
  SceKernelThreadMgr_stub
  SceKernelModulemgr_stub
  SceLibc_stub
  SceLibKernel_stub
  taihen_stub
)

set_target_properties(${PROJECT_NAME}
  PROPERTIES LINK_FLAGS "-nostdlib"
  COMPILE_FLAGS "-D__PSP2_USER__"
)

vita_create_self(${PROJECT_NAME}.suprx ${PROJECT_NAME}
  STRIPPED
  REL_OPTIMIZE
  MODULE_ENTRY module_start,module_stop,module_exit
)
