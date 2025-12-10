use crate::{mutex::Mutex, println, ConnectFn, RecvFn, SocketCloseFn, SocketFn};
use core::ffi::c_int;

pub mod raw {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(unused)]

    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

mod hook_check {
    static _RESOLVER_FN_CHECK: crate::ResolverFn = crate::raw::sceNetResolverStartNtoa;
    static _RESOLVER_HOOK_CHECK: crate::ResolverFn = crate::resolver_hook;
    static _SOCKET_FN_CHECK: crate::SocketFn = crate::raw::sceNetSocket;
    static _SOCKET_CLOSE_FN_CHECK: crate::SocketCloseFn = crate::raw::sceNetSocketClose;
    static _CONNECT_FN_CHECK: crate::ConnectFn = crate::raw::sceNetConnect;
    static _CONNECT_HOOK_CHECK: crate::ConnectFn = crate::connect_hook;
    static _RECV_FN_CHECK: crate::RecvFn = crate::raw::sceNetRecv;
    static _LOAD_MODULE_FN_CHECK: crate::LoadFn = crate::raw::sceSysmoduleLoadModule;
    static _LOAD_MODULE_HOOK_CHECK: crate::LoadFn = crate::loadlib_hook;
    static _UNLOAD_MODULE_FN_CHECK: crate::LoadFn = crate::raw::sceSysmoduleUnloadModule;
    static _UNLOAD_MODULE_HOOK_CHECK: crate::LoadFn = crate::unloadlib_hook;
}

pub static NET_FUNCS: Mutex<Option<NetFns>> = Mutex::new(None, "NetFns");
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

extern "C" {
    fn malloc(size: usize) -> *mut ();
    fn free(ptr: *mut ());
}

struct Allocator;
pub struct ScePrintf;
pub struct SceFile {
    handle: raw::SceUID,
}
pub struct SceNet {
    socket: c_int,
}

pub struct NetFns {
    pub socket: SocketFn,
    pub socket_close: SocketCloseFn,
    pub connect: ConnectFn,
    pub recv: RecvFn,
}

unsafe impl alloc::alloc::GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let ptr = malloc(layout.pad_to_align().size()) as *mut u8;
        if ptr.is_null() {
            alloc::alloc::handle_alloc_error(layout)
        } else {
            ptr
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: core::alloc::Layout) {
        free(ptr as *mut ())
    }
}

impl core::fmt::Write for ScePrintf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let c_str = alloc::ffi::CString::new(s).unwrap();
        unsafe { raw::sceClibPrintf(c_str.as_ptr()) };
        Ok(())
    }
}

impl SceFile {
    pub fn open_read(path: &str) -> Option<SceFile> {
        let c_path = alloc::ffi::CString::new(path).unwrap();
        let handle =
            unsafe { raw::sceIoOpen(c_path.as_ptr(), raw::SceIoMode::SCE_O_RDONLY as i32, 0o777) };
        if handle < 0 {
            println!("Failed to open: {:X}", handle as u32);
            None
        } else {
            Some(Self { handle })
        }
    }
    #[allow(unused)]
    pub fn open_write(path: &str) -> Option<SceFile> {
        let c_path = alloc::ffi::CString::new(path).unwrap();
        let handle =
            unsafe { raw::sceIoOpen(c_path.as_ptr(), raw::SceIoMode::SCE_O_CREAT as i32, 0o777) };
        if handle < 0 {
            println!("Failed to open: {:X}", handle as u32);
            None
        } else {
            Some(Self { handle })
        }
    }
}
impl embedded_io::ErrorType for SceFile {
    type Error = embedded_io::ErrorKind;
}
impl embedded_io::Read for SceFile {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        Ok(unsafe {
            raw::sceIoRead(
                self.handle,
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                buf.len() as u32,
            )
        } as usize)
    }
}
impl embedded_io::Write for SceFile {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        Ok(unsafe {
            raw::sceIoWrite(
                self.handle,
                buf.as_ptr() as *const core::ffi::c_void,
                buf.len() as u32,
            )
        } as usize)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        unsafe { raw::sceIoSyncByFd(self.handle, 0) };
        Ok(())
    }
}
impl Drop for SceFile {
    fn drop(&mut self) {
        unsafe {
            raw::sceIoClose(self.handle);
        }
    }
}
impl SceNet {
    pub fn connect(name: &str, ip: core::net::Ipv4Addr) -> Option<Self> {
        let c_name = alloc::ffi::CString::new(name).unwrap();
        let net_fns = NET_FUNCS.lock();
        let net_fns = net_fns.as_ref().unwrap();
        let socket = unsafe {
            (net_fns.socket)(
                c_name.as_ptr(),
                raw::SCE_NET_AF_INET as i32,
                raw::SceNetSocketType::SCE_NET_SOCK_STREAM as i32,
                0,
            )
        };
        if socket < 0 {
            return None;
        }
        let addr_st = raw::SceNetSockaddrIn {
            sin_len: core::mem::size_of::<raw::SceNetSockaddrIn>() as u8,
            sin_family: raw::SCE_NET_AF_INET as u8,
            sin_port: 11000u16.swap_bytes(),
            sin_addr: raw::SceNetInAddr {
                s_addr: ip.to_bits().swap_bytes(),
            },
            ..Default::default()
        };
        let res = unsafe {
            (net_fns.connect)(
                socket,
                &addr_st as *const raw::SceNetSockaddrIn as *const raw::SceNetSockaddr,
                addr_st.sin_len as u32,
            )
        };
        if res < 0 {
            unsafe { (net_fns.socket_close)(socket) };
            return None;
        }
        Some(Self { socket })
    }
}
impl embedded_io::ErrorType for SceNet {
    type Error = embedded_io::ErrorKind;
}
impl embedded_io::Read for SceNet {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let net_fns = NET_FUNCS.lock();
        let net_fns = net_fns.as_ref().unwrap();
        Ok(unsafe {
            (net_fns.recv)(
                self.socket,
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                buf.len() as u32,
                0,
            )
        } as usize)
    }
}

impl Drop for SceNet {
    fn drop(&mut self) {
        let net_fns = NET_FUNCS.lock();
        let net_fns = net_fns.as_ref().unwrap();
        unsafe { (net_fns.socket_close)(self.socket) };
    }
}

pub fn install_net_fns(fns: NetFns) {
    *NET_FUNCS.lock() = Some(fns);
}
pub fn uninstall_net_fns() {
    *NET_FUNCS.lock() = None;
}

pub fn _print(args: core::fmt::Arguments) {
    use core::fmt::Write;
    ScePrintf.write_fmt(args).unwrap();
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        $crate::bindings::_print(core::format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! println {
    () => {
        $crate::print!("\n")
    };
    ($($arg:tt)*) => {{
        $crate::print!("{}\n", core::format_args!($($arg)*));
    }};
}
