// QNX Neutrino 6.6 / BlackBerry 10 compatibility stub
// The QNX ARMv7 SDK omits crtbegin.o; static destructors use libc atexit instead
// of the absent __dso_handle mechanism. Providing __dso_handle satisfies Dinkum C++
// template instantiations on QNX Neutrino 6.6.
#if defined(POSIX_TLS_QNX) || defined(__QNXNTO__)
extern "C" {
    void* __dso_handle = 0;
}
#endif
