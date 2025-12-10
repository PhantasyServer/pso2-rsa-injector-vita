use crate::raw;

pub struct Mutex<T> {
    name: &'static str,
    handle: core::cell::OnceCell<raw::SceUID>,
    data: core::cell::UnsafeCell<T>,
}
pub struct MutexGuard<'a, T> {
    ptr: &'a Mutex<T>,
}

unsafe impl<T: Send> Send for Mutex<T> {}
unsafe impl<T: Send> Sync for Mutex<T> {}
unsafe impl<T: Sync> Sync for MutexGuard<'_, T> {}

impl<T> Mutex<T> {
    pub const fn new(data: T, name: &'static str) -> Self {
        Self {
            name,
            handle: core::cell::OnceCell::new(),
            data: core::cell::UnsafeCell::new(data),
        }
    }
    pub fn init(&self) {
        let c_str = alloc::ffi::CString::new(self.name).unwrap();
        let handle =
            unsafe { raw::sceKernelCreateMutex(c_str.as_ptr(), 0, 1, core::ptr::null_mut()) };
        let _ = self.handle.set(handle);
    }
    pub fn lock(&self) -> MutexGuard<'_, T> {
        let handle = *self.handle.get().unwrap();
        unsafe { raw::sceKernelLockMutex(handle, 1, core::ptr::null_mut()) };
        MutexGuard { ptr: self }
    }
}

impl<T> core::ops::Deref for MutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.ptr.data.get() }
    }
}

impl<T> core::ops::DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.ptr.data.get() }
    }
}

impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        unsafe { raw::sceKernelUnlockMutex(*self.ptr.handle.get().unwrap(), 1) };
    }
}
