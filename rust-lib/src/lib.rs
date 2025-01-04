#![no_std]
#![no_main]

mod bindings;
mod mutex;

extern crate alloc;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use bindings::{raw, NetFns, SceFile, SceNet};
use core::{
    ffi::{c_char, c_int},
    net::Ipv4Addr,
};
use embedded_io::Read;
use mutex::Mutex;

type ResolverFn = unsafe extern "C" fn(
    c_int,
    *const c_char,
    *mut raw::SceNetInAddr,
    c_int,
    c_int,
    c_int,
) -> c_int;
type SocketFn = unsafe extern "C" fn(*const c_char, c_int, c_int, c_int) -> c_int;
type SocketCloseFn = unsafe extern "C" fn(c_int) -> c_int;
type ConnectFn =
    unsafe extern "C" fn(c_int, *const raw::SceNetSockaddr, core::ffi::c_uint) -> c_int;
type RecvFn =
    unsafe extern "C" fn(c_int, *mut core::ffi::c_void, core::ffi::c_uint, c_int) -> c_int;

const RSAHEADER: [u8; 12] = [
    0x06, 0x02, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00, 0x52, 0x53, 0x41, 0x31,
];
const TAI_ERROR_SYSTEM: raw::SceUID = 0x90010000u32 as i32;

static RSA_ADDR: Mutex<usize> = Mutex::new(0, "RSA_ADDR");
static RESOLVER_HOOK: Mutex<HookInfo> = Mutex::new(HookInfo { uid: 0, hook: 0 }, "ResolverHook");
static CONNECT_HOOK: Mutex<HookInfo> = Mutex::new(HookInfo { uid: 0, hook: 0 }, "ConnectHook");
static SETTINGS: Mutex<Option<Settings>> = Mutex::new(None, "Settings");
static RSA_INJECT_ID: Mutex<Option<raw::SceUID>> = Mutex::new(None, "RSA_INJECT");
static KEYS: Mutex<Vec<Keys>> = Mutex::new(Vec::new(), "KEYS");
static USER_KEY: Mutex<Option<Vec<u8>>> = Mutex::new(None, "USER_KEY");

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(default)]
struct Settings {
    /// Path to user provided public key
    user_key: String,
    /// Enables address replacement feature
    replace_address: bool,
    /// Enables auto public key exchange
    auto_key_fetch: bool,
    /// List of addresses to replace
    addresses: Vec<AddrReplace>,
}

#[derive(Debug)]
struct Keys {
    ip: Ipv4Addr,
    key: Vec<u8>,
}

// Ship address to be replaced
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct AddrReplace {
    old: String,
    new: String,
}

#[derive(Default)]
struct HookInfo {
    uid: raw::SceUID,
    hook: raw::tai_hook_ref_t,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            replace_address: false,
            user_key: "ux0:data/publicKey.blob".to_string(),
            auto_key_fetch: false,
            addresses: alloc::vec![],
        }
    }
}

fn find_rsa(data: &mut [u8]) -> Option<&mut [u8]> {
    for i in 0..data.len() - RSAHEADER.len() {
        let tmp_data = &data[i..i + RSAHEADER.len()];
        if tmp_data == RSAHEADER {
            return Some(&mut data[i..]);
        }
    }

    None
}

// Based on TAI_CONTINUE
macro_rules! hook_to_fn {
    ($hook:ident) => {{
        let cur_hook = *($hook.hook as *const raw::_tai_hook_user);
        if cur_hook.next == 0 {
            #[allow(clippy::missing_transmute_annotations)]
            core::mem::transmute(cur_hook.old)
        } else {
            let next = *(cur_hook.next as *const raw::_tai_hook_user);
            #[allow(clippy::missing_transmute_annotations)]
            core::mem::transmute(next.func)
        }
    }};
}

extern "C" fn resolver_hook(
    rid: c_int,
    hostname: *const c_char,
    addr: *mut raw::SceNetInAddr,
    timeout: c_int,
    retry: c_int,
    flags: c_int,
) -> c_int {
    let owned_hostname;
    let mut hostname = hostname;
    let mut replaced = false;
    let c_str = unsafe { core::ffi::CStr::from_ptr(hostname) }.to_string_lossy();
    let settings = SETTINGS.lock();
    for addr in settings.as_ref().unwrap().addresses.iter() {
        if addr.old == c_str {
            owned_hostname = Some(alloc::ffi::CString::new(addr.new.clone()).unwrap());
            hostname = owned_hostname.as_ref().unwrap().as_ptr();
            replaced = true;
            break;
        }
    }
    let resolver_hook = RESOLVER_HOOK.lock();
    let func: ResolverFn = unsafe { hook_to_fn!(resolver_hook) };
    let ret = unsafe { func(rid, hostname, addr, timeout, retry, flags) };
    drop(resolver_hook);
    if ret != 0 {
        return ret;
    }
    if replaced && SETTINGS.lock().as_ref().unwrap().auto_key_fetch {
        let addr = core::net::Ipv4Addr::from_bits(unsafe { *addr }.s_addr.swap_bytes());
        rsa_uninject();
        let keys = get_keys(addr);
        *KEYS.lock() = keys;
    }

    ret
}

extern "C" fn connect_hook(
    socket: c_int,
    addr: *const raw::SceNetSockaddr,
    flags: core::ffi::c_uint,
) -> c_int {
    let connect_hook = CONNECT_HOOK.lock();
    let func: ConnectFn = unsafe { hook_to_fn!(connect_hook) };
    let ret = unsafe { func(socket, addr, flags) };

    let ipv4_addr = unsafe { *(addr as *const raw::SceNetSockaddrIn) };
    let ipv4_addr = core::net::Ipv4Addr::from_bits(ipv4_addr.sin_addr.s_addr.swap_bytes());
    for key in KEYS.lock().iter() {
        if key.ip == ipv4_addr {
            rsa_inject(&key.key);
            return ret;
        }
    }

    let lock = USER_KEY.lock();
    if let Some(key) = &*lock {
        rsa_inject(key)
    }

    ret
}

fn get_keys(addr: Ipv4Addr) -> Vec<Keys> {
    let mut keys = alloc::vec![];
    let socket = SceNet::connect("replacement", addr);
    let Some(mut socket) = socket else {
        return keys;
    };
    let mut len_buf = [0; 4];
    socket.read_exact(&mut len_buf).unwrap();
    let len = u32::from_le_bytes(len_buf);
    let mut data = alloc::vec![0; len as usize];
    socket.read_exact(&mut data).unwrap();
    let mut data = rmp::decode::Bytes::new(&data);

    let key_amount = rmp::decode::read_array_len(&mut data).unwrap();
    for _ in 0..key_amount {
        let _struct_size = rmp::decode::read_array_len(&mut data).unwrap();
        let _ip_size = rmp::decode::read_array_len(&mut data).unwrap();
        let mut ip_octets = [0u8; 4];
        for octet in &mut ip_octets {
            *octet = rmp::decode::read_int::<u8, _>(&mut data).unwrap();
        }
        let ip = Ipv4Addr::from_bits(u32::from_be_bytes(ip_octets));
        let key_len = rmp::decode::read_array_len(&mut data).unwrap();
        let mut key = alloc::vec![0u8; key_len as usize];
        for byte in &mut key {
            *byte = rmp::decode::read_int::<u8, _>(&mut data).unwrap();
        }
        keys.push(Keys { ip, key });
    }

    keys
}

fn rsa_inject(key: &[u8]) {
    rsa_uninject();
    let ptr = key.as_ptr() as *const core::ffi::c_void;
    let lock = *RSA_ADDR.lock();
    if lock != 0 {
        let dest = lock as *mut core::ffi::c_void;
        let res = unsafe { raw::taiInjectAbs(dest, ptr, key.len()) };
        if res >= 0 {
            *RSA_INJECT_ID.lock() = Some(res);
        }
    }
}

fn rsa_uninject() {
    let mut lock = RSA_INJECT_ID.lock();
    if let Some(id) = lock.take() {
        unsafe { raw::taiInjectRelease(id) };
    }
}

#[no_mangle]
pub extern "C" fn rust_main() {
    SETTINGS.init();
    bindings::NET_FUNCS.init();
    RSA_ADDR.init();
    RESOLVER_HOOK.init();
    CONNECT_HOOK.init();
    RSA_INJECT_ID.init();
    KEYS.init();
    USER_KEY.init();

    // read settings
    let file = SceFile::open_read("ux0:data/pso2.toml");
    let settings: Settings = if let Some(mut file) = file {
        let mut data = alloc::vec![0; 2048];
        let read = file.read(&mut data).unwrap();
        data.resize(read, 0);
        let data_str = alloc::string::String::from_utf8(data).unwrap_or_default();
        let settings = tomling::from_str(&data_str);
        match settings {
            Ok(s) => s,
            Err(e) => {
                println!("TOML error: {e}");
                Default::default()
            }
        }
    } else {
        println!("No file");
        Default::default()
    };
    *SETTINGS.lock() = Some(settings.clone());

    if !settings.user_key.is_empty() {
        if let Some(mut file) = SceFile::open_read(&settings.user_key) {
            let mut data = alloc::vec![0;2048];
            let read = file.read(&mut data).unwrap();
            data.resize(read, 0);
            *USER_KEY.lock() = Some(data);
        }
    }

    // get base address
    let mut tai_info = raw::tai_module_info_t {
        size: core::mem::size_of::<raw::tai_module_info_t>(),
        ..Default::default()
    };
    let mut self_info = raw::SceKernelModuleInfo {
        size: core::mem::size_of::<raw::SceKernelModuleInfo>() as u32,
        ..Default::default()
    };
    unsafe { raw::taiGetModuleInfo(c"pso2".as_ptr(), &raw mut tai_info) };
    unsafe { raw::sceKernelGetModuleInfo(tai_info.modid, &raw mut self_info) };
    let segment = unsafe {
        core::slice::from_raw_parts_mut(
            self_info.segments[0].vaddr as *mut u8,
            self_info.segments[0].memsz as usize,
        )
    };

    // find RSA key offset
    let rsa = find_rsa(segment);
    if let Some(rsa) = rsa {
        *RSA_ADDR.lock() = rsa.as_mut_ptr() as usize;
    }

    // hook SceNet::sceNetResolverStartNtoa
    if settings.replace_address {
        loop {
            unsafe {
                let mut args = raw::tai_hook_args_t {
                    size: core::mem::size_of::<raw::tai_hook_args_t>(),
                    module: c"pso2".as_ptr(),
                    library_nid: 0x6BF8B2A2,
                    func_nid: 0x1EB11857,
                    hook_func: resolver_hook as *const core::ffi::c_void,
                };
                let mut lock = RESOLVER_HOOK.lock();
                let res =
                    raw::taiHookFunctionImportForUser(&raw mut lock.hook, &raw mut args) as u32;
                if res < TAI_ERROR_SYSTEM as u32 {
                    lock.uid = res as i32;
                    break;
                } else {
                    lock.hook = 0;
                }
                raw::sceKernelDelayThread(1000 * 10);
            }
        }
    }

    // generate SceNet bindings
    let socket: SocketFn = unsafe { core::mem::transmute(get_fn_addr(0x6BF8B2A2, 0xF084FCE3)) };
    let connect: ConnectFn = unsafe { core::mem::transmute(get_fn_addr(0x6BF8B2A2, 0x11E5B6F6)) };
    let recv: RecvFn = unsafe { core::mem::transmute(get_fn_addr(0x6BF8B2A2, 0x023643B7)) };
    let socket_close: SocketCloseFn =
        unsafe { core::mem::transmute(get_fn_addr(0x6BF8B2A2, 0x29822B4D)) };
    bindings::install_net_fns(NetFns {
        socket,
        socket_close,
        connect,
        recv,
    });

    // hook SceNet::sceNetConnect
    loop {
        unsafe {
            let mut args = raw::tai_hook_args_t {
                size: core::mem::size_of::<raw::tai_hook_args_t>(),
                module: c"pso2".as_ptr(),
                library_nid: 0x6BF8B2A2,
                func_nid: 0x11E5B6F6,
                hook_func: connect_hook as *const core::ffi::c_void,
            };
            let mut lock = CONNECT_HOOK.lock();
            let res = raw::taiHookFunctionImportForUser(&raw mut lock.hook, &raw mut args) as u32;
            if res < TAI_ERROR_SYSTEM as u32 {
                lock.uid = res as i32;
                break;
            } else {
                lock.hook = 0;
            }
            raw::sceKernelDelayThread(1000 * 10);
        }
    }
}

fn get_fn_addr(lib_nid: u32, func_nid: u32) -> usize {
    let mut hook = HookInfo { uid: 0, hook: 0 };
    loop {
        unsafe {
            let mut args = raw::tai_hook_args_t {
                size: core::mem::size_of::<raw::tai_hook_args_t>(),
                module: c"pso2".as_ptr(),
                library_nid: lib_nid,
                func_nid,
                hook_func: resolver_hook as *const core::ffi::c_void,
            };
            let res = raw::taiHookFunctionImportForUser(&raw mut hook.hook, &raw mut args) as u32;
            if res < TAI_ERROR_SYSTEM as u32 {
                hook.uid = res as i32;
                let addr: usize = hook_to_fn!(hook);
                raw::taiHookRelease(hook.uid, hook.hook);
                break addr;
            } else {
                hook.hook = 0;
            }
            raw::sceKernelDelayThread(1000 * 10);
        }
    }
}

#[panic_handler]
fn panic(ex: &core::panic::PanicInfo) -> ! {
    println!("Rust panic: {ex}");
    loop {}
}
