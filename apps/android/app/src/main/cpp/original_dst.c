// SO_ORIGINAL_DST reader for the APIaxess client relay (Phase C3).
//
// After `iptables -t nat ... -j REDIRECT --to-ports <relay>`, the kernel keeps
// the connection's original destination retrievable via getsockopt(). No Android
// Java/Kotlin API exposes the sockaddr this returns, so this ~50-line JNI shim is
// the standard way to recover it. It handles both IPv4 and IPv6 (netfilter uses
// optname 80 in both the SOL_IP and SOL_IPV6 namespaces).

#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef SOL_IP
#define SOL_IP 0
#endif
#ifndef SOL_IPV6
#define SOL_IPV6 41
#endif
// netfilter's SO_ORIGINAL_DST / IP6T_SO_ORIGINAL_DST are both 80.
#define APIAXESS_SO_ORIGINAL_DST 80

// Returns "ip:port" for IPv4, "[ip]:port" for IPv6, or NULL when the original
// destination is unavailable (e.g. the socket was not REDIRECTed).
JNIEXPORT jstring JNICALL
Java_com_apiaxess_client_capture_OriginalDst_nativeOriginalDst(
    JNIEnv *env, jclass clazz, jint fd) {
    (void) clazz;
    char out[80];

    // Try IPv4 first: the common REDIRECT case.
    struct sockaddr_in v4;
    socklen_t v4_len = sizeof(v4);
    memset(&v4, 0, sizeof(v4));
    if (getsockopt(fd, SOL_IP, APIAXESS_SO_ORIGINAL_DST, &v4, &v4_len) == 0 &&
        v4.sin_family == AF_INET) {
        char ip[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &v4.sin_addr, ip, sizeof(ip)) != NULL) {
            snprintf(out, sizeof(out), "%s:%d", ip, ntohs(v4.sin_port));
            return (*env)->NewStringUTF(env, out);
        }
    }

    // Then IPv6.
    struct sockaddr_in6 v6;
    socklen_t v6_len = sizeof(v6);
    memset(&v6, 0, sizeof(v6));
    if (getsockopt(fd, SOL_IPV6, APIAXESS_SO_ORIGINAL_DST, &v6, &v6_len) == 0 &&
        v6.sin6_family == AF_INET6) {
        char ip[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &v6.sin6_addr, ip, sizeof(ip)) != NULL) {
            snprintf(out, sizeof(out), "[%s]:%d", ip, ntohs(v6.sin6_port));
            return (*env)->NewStringUTF(env, out);
        }
    }

    return NULL;
}
