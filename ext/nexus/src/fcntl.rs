
#[macro_export]
macro_rules! fcntl {
    ( $fd:expr, $request:expr, $( $arg:expr ),* ) => {
        if unsafe { ::libc::fcntl($fd, $request, $( $arg, )*) } == -1 {
            return Err(::std::io::Error::last_os_error());
        }
    };
}
