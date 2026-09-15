cmake_minimum_required(VERSION 3.22.1)
project("apiaxessclient")

# Tiny JNI shim: read SO_ORIGINAL_DST from a redirected socket. There is no
# platform Java/Kotlin API that returns the sockaddr this getsockopt yields, so
# a small native call is the standard, correct way to recover the original
# destination of an iptables-REDIRECTed connection.
add_library(apiaxessclient SHARED original_dst.c)

find_library(log-lib log)
target_link_libraries(apiaxessclient ${log-lib})
