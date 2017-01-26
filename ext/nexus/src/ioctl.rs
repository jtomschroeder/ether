
#[macro_export]
macro_rules! ioctl {
    ( $fd:expr, $request:expr, $( $arg:expr ),* ) => {
        if unsafe { ::libc::ioctl($fd, $request, $( $arg, )* ) } == -1 {
            return Err(::std::io::Error::last_os_error());
        }
    };
}
