module zyre.generated;
import core.stdc.config;
import core.stdc.stdarg: va_list;
static import core.simd;
static import std.conv;

struct Int128 { long lower; long upper; }
struct UInt128 { ulong lower; ulong upper; }

struct __locale_data { int dummy; }



alias _Bool = bool;
struct dpp {
    static struct Opaque(int N) {
        void[N] bytes;
    }

    static bool isEmpty(T)() {
        return T.tupleof.length == 0;
    }
    static struct Move(T) {
        T* ptr;
    }


    static auto move(T)(ref T value) {
        return Move!T(&value);
    }
    mixin template EnumD(string name, T, string prefix) if(is(T == enum)) {
        private static string _memberMixinStr(string member) {
            import std.conv: text;
            import std.array: replace;
            return text(` `, member.replace(prefix, ""), ` = `, T.stringof, `.`, member, `,`);
        }
        private static string _enumMixinStr() {
            import std.array: join;
            string[] ret;
            ret ~= "enum " ~ name ~ "{";
            static foreach(member; __traits(allMembers, T)) {
                ret ~= _memberMixinStr(member);
            }
            ret ~= "}";
            return ret.join("\n");
        }
        mixin(_enumMixinStr());
    }
}

extern(C)
{
    void zuuid_test(bool) @nogc nothrow;
    _zuuid_t* zuuid_dup(_zuuid_t*) @nogc nothrow;
    bool zuuid_neq(_zuuid_t*, const(ubyte)*) @nogc nothrow;
    bool zuuid_eq(_zuuid_t*, const(ubyte)*) @nogc nothrow;
    void zuuid_export(_zuuid_t*, ubyte*) @nogc nothrow;
    const(char)* zuuid_str_canonical(_zuuid_t*) @nogc nothrow;
    const(char)* zuuid_str(_zuuid_t*) @nogc nothrow;
    c_ulong zuuid_size(_zuuid_t*) @nogc nothrow;
    const(ubyte)* zuuid_data(_zuuid_t*) @nogc nothrow;
    int zuuid_set_str(_zuuid_t*, const(char)*) @nogc nothrow;
    void zuuid_set(_zuuid_t*, const(ubyte)*) @nogc nothrow;
    void zuuid_destroy(_zuuid_t**) @nogc nothrow;
    _zuuid_t* zuuid_new_from(const(ubyte)*) @nogc nothrow;
    _zuuid_t* zuuid_new() @nogc nothrow;
    extern __gshared int zctx_interrupted;
    extern __gshared int zsys_interrupted;
    c_long zsys_file_size(const(char)*) @nogc nothrow;
    void zsys_test(bool) @nogc nothrow;
    void zsys_debug(const(char)*, ...) @nogc nothrow;
    void zsys_info(const(char)*, ...) @nogc nothrow;
    void zsys_notice(const(char)*, ...) @nogc nothrow;
    void zsys_warning(const(char)*, ...) @nogc nothrow;
    void zsys_error(const(char)*, ...) @nogc nothrow;
    void zsys_set_logsystem(bool) @nogc nothrow;
    void zsys_set_logsender(const(char)*) @nogc nothrow;
    void zsys_set_logstream(_IO_FILE*) @nogc nothrow;
    void zsys_set_logident(const(char)*) @nogc nothrow;
    int zsys_auto_use_fd() @nogc nothrow;
    void zsys_set_auto_use_fd(int) @nogc nothrow;
    const(char)* zsys_ipv6_mcast_address() @nogc nothrow;
    void zsys_set_ipv6_mcast_address(const(char)*) @nogc nothrow;
    const(char)* zsys_ipv6_address() @nogc nothrow;
    void zsys_set_ipv6_address(const(char)*) @nogc nothrow;
    const(char)* zsys_interface() @nogc nothrow;
    void zsys_set_interface(const(char)*) @nogc nothrow;
    int zsys_ipv6() @nogc nothrow;
    void zsys_set_ipv6(int) @nogc nothrow;
    c_ulong zsys_pipehwm() @nogc nothrow;
    void zsys_set_pipehwm(c_ulong) @nogc nothrow;
    void zsys_set_rcvhwm(c_ulong) @nogc nothrow;
    void zsys_set_sndhwm(c_ulong) @nogc nothrow;
    void zsys_set_linger(c_ulong) @nogc nothrow;
    int zsys_max_msgsz() @nogc nothrow;
    void zsys_set_max_msgsz(int) @nogc nothrow;
    c_ulong zsys_socket_limit() @nogc nothrow;
    void zsys_set_max_sockets(c_ulong) @nogc nothrow;
    void zsys_thread_affinity_cpu_remove(int) @nogc nothrow;
    void zsys_thread_affinity_cpu_add(int) @nogc nothrow;
    int zsys_thread_name_prefix() @nogc nothrow;
    void zsys_set_thread_name_prefix(int) @nogc nothrow;
    void zsys_set_thread_priority(int) @nogc nothrow;
    void zsys_set_thread_sched_policy(int) @nogc nothrow;
    void zsys_set_io_threads(c_ulong) @nogc nothrow;
    bool zsys_has_curve() @nogc nothrow;
    int zsys_run_as(const(char)*, const(char)*, const(char)*) @nogc nothrow;
    int zsys_daemonize(const(char)*) @nogc nothrow;
    char* zsys_hostname() @nogc nothrow;
    void zsys_socket_error(const(char)*) @nogc nothrow;
    _zframe_t* zsys_udp_recv(int, char*, int) @nogc nothrow;
    int zsys_udp_send(int, _zframe_t*, sockaddr_in*, int) @nogc nothrow;
    int zsys_udp_close(int) @nogc nothrow;
    int zsys_udp_new(bool) @nogc nothrow;
    char* zsys_vprintf(const(char)*, va_list*) @nogc nothrow;
    char* zsys_sprintf(const(char)*, ...) @nogc nothrow;
    void zsys_version(int*, int*, int*) @nogc nothrow;
    void zsys_file_mode_default() @nogc nothrow;
    void zsys_file_mode_private() @nogc nothrow;
    int zsys_dir_change(const(char)*) @nogc nothrow;
    int zsys_dir_delete(const(char)*, ...) @nogc nothrow;
    int zsys_dir_create(const(char)*, ...) @nogc nothrow;
    bool zsys_file_stable(const(char)*) @nogc nothrow;
    int zsys_file_delete(const(char)*) @nogc nothrow;
    int zsys_file_mode(const(char)*) @nogc nothrow;
    c_long zsys_file_modified(const(char)*) @nogc nothrow;
    bool zsys_file_exists(const(char)*) @nogc nothrow;
    void zsys_catch_interrupts() @nogc nothrow;
    void zsys_handler_reset() @nogc nothrow;
    void zsys_handler_set(void function(int)) @nogc nothrow;
    _zsock_t* zsys_create_pipe(_zsock_t**) @nogc nothrow;
    char* zsys_sockname(int) @nogc nothrow;
    int zsys_close(void*, const(char)*, c_ulong) @nogc nothrow;
    void* zsys_socket(int, const(char)*, c_ulong) @nogc nothrow;
    void zsys_shutdown() @nogc nothrow;
    void* zsys_init() @nogc nothrow;
    alias zsys_handler_fn = void function(int);
    char* zstr_recv_nowait(void*) @nogc nothrow;
    void zstr_test(bool) @nogc nothrow;
    void zstr_free(char**) @nogc nothrow;
    int zstr_sendx(void*, const(char)*, ...) @nogc nothrow;
    int zstr_sendfm(void*, const(char)*, ...) @nogc nothrow;
    int zstr_sendf(void*, const(char)*, ...) @nogc nothrow;
    int zstr_sendm(void*, const(char)*) @nogc nothrow;
    int zstr_send(void*, const(char)*) @nogc nothrow;
    int zstr_recvx(void*, char**, ...) @nogc nothrow;
    char* zstr_recv(void*) @nogc nothrow;
    _zsock_t* zsock_new_stream_checked(const(char)*, const(char)*, c_ulong) @nogc nothrow;
    _zsock_t* zsock_new_pair_checked(const(char)*, const(char)*, c_ulong) @nogc nothrow;
    _zsock_t* zsock_new_xsub_checked(const(char)*, const(char)*, c_ulong) @nogc nothrow;
    _zsock_t* zsock_new_xpub_checked(const(char)*, const(char)*, c_ulong) @nogc nothrow;
    _zsock_t* zsock_new_pull_checked(const(char)*, const(char)*, c_ulong) @nogc nothrow;
    _zsock_t* zsock_new_push_checked(const(char)*, const(char)*, c_ulong) @nogc nothrow;
    _zsock_t* zsock_new_router_checked(const(char)*, const(char)*, c_ulong) @nogc nothrow;
    _zsock_t* zsock_new_dealer_checked(const(char)*, const(char)*, c_ulong) @nogc nothrow;
    _zsock_t* zsock_new_rep_checked(const(char)*, const(char)*, c_ulong) @nogc nothrow;
    _zsock_t* zsock_new_req_checked(const(char)*, const(char)*, c_ulong) @nogc nothrow;
    _zsock_t* zsock_new_sub_checked(const(char)*, const(char)*, const(char)*, c_ulong) @nogc nothrow;
    _zsock_t* zsock_new_pub_checked(const(char)*, const(char)*, c_ulong) @nogc nothrow;
    void zsock_destroy_checked(_zsock_t**, const(char)*, c_ulong) @nogc nothrow;
    _zsock_t* zsock_new_checked(int, const(char)*, c_ulong) @nogc nothrow;
    void zsock_test(bool) @nogc nothrow;
    int zsock_events(void*) @nogc nothrow;
    int zsock_fd(void*) @nogc nothrow;
    int zsock_rcvmore(void*) @nogc nothrow;
    int zsock_type(void*) @nogc nothrow;
    void zsock_set_unsubscribe(void*, const(char)*) @nogc nothrow;
    void zsock_set_subscribe(void*, const(char)*) @nogc nothrow;
    void zsock_set_backlog(void*, int) @nogc nothrow;
    int zsock_backlog(void*) @nogc nothrow;
    void zsock_set_reconnect_ivl_max(void*, int) @nogc nothrow;
    int zsock_reconnect_ivl_max(void*) @nogc nothrow;
    void zsock_set_reconnect_ivl(void*, int) @nogc nothrow;
    int zsock_reconnect_ivl(void*) @nogc nothrow;
    void zsock_set_linger(void*, int) @nogc nothrow;
    int zsock_linger(void*) @nogc nothrow;
    void zsock_set_rcvbuf(void*, int) @nogc nothrow;
    int zsock_rcvbuf(void*) @nogc nothrow;
    void zsock_set_sndbuf(void*, int) @nogc nothrow;
    int zsock_sndbuf(void*) @nogc nothrow;
    void zsock_set_sndtimeo(void*, int) @nogc nothrow;
    int zsock_sndtimeo(void*) @nogc nothrow;
    void zsock_set_rcvtimeo(void*, int) @nogc nothrow;
    int zsock_rcvtimeo(void*) @nogc nothrow;
    void zsock_set_mcast_loop(void*, int) @nogc nothrow;
    int zsock_mcast_loop(void*) @nogc nothrow;
    void zsock_set_recovery_ivl_msec(void*, int) @nogc nothrow;
    int zsock_recovery_ivl_msec(void*) @nogc nothrow;
    void zsock_set_recovery_ivl(void*, int) @nogc nothrow;
    int zsock_recovery_ivl(void*) @nogc nothrow;
    void zsock_set_rate(void*, int) @nogc nothrow;
    int zsock_rate(void*) @nogc nothrow;
    void zsock_set_identity(void*, const(char)*) @nogc nothrow;
    char* zsock_identity(void*) @nogc nothrow;
    void zsock_set_affinity(void*, int) @nogc nothrow;
    int zsock_affinity(void*) @nogc nothrow;
    void zsock_set_swap(void*, int) @nogc nothrow;
    int zsock_swap(void*) @nogc nothrow;
    void zsock_set_hwm(void*, int) @nogc nothrow;
    int zsock_hwm(void*) @nogc nothrow;
    void zsock_set_delay_attach_on_connect(void*, int) @nogc nothrow;
    void zsock_set_ipv4only(void*, int) @nogc nothrow;
    int zsock_ipv4only(void*) @nogc nothrow;
    void zsock_set_router_raw(void*, int) @nogc nothrow;
    char* zsock_last_endpoint(void*) @nogc nothrow;
    void zsock_set_tcp_accept_filter(void*, const(char)*) @nogc nothrow;
    char* zsock_tcp_accept_filter(void*) @nogc nothrow;
    void zsock_set_tcp_keepalive_intvl(void*, int) @nogc nothrow;
    int zsock_tcp_keepalive_intvl(void*) @nogc nothrow;
    void zsock_set_tcp_keepalive_cnt(void*, int) @nogc nothrow;
    int zsock_tcp_keepalive_cnt(void*) @nogc nothrow;
    void zsock_set_tcp_keepalive_idle(void*, int) @nogc nothrow;
    int zsock_tcp_keepalive_idle(void*) @nogc nothrow;
    void zsock_set_tcp_keepalive(void*, int) @nogc nothrow;
    int zsock_tcp_keepalive(void*) @nogc nothrow;
    void zsock_set_xpub_verbose(void*, int) @nogc nothrow;
    void zsock_set_multicast_hops(void*, int) @nogc nothrow;
    int zsock_multicast_hops(void*) @nogc nothrow;
    pragma(mangle, "alloca") void* alloca_(c_ulong) @nogc nothrow;
    void zsock_set_maxmsgsize(void*, int) @nogc nothrow;
    uint inet_addr(const(char)*) @nogc nothrow;
    uint inet_lnaof(in_addr) @nogc nothrow;
    in_addr inet_makeaddr(uint, uint) @nogc nothrow;
    uint inet_netof(in_addr) @nogc nothrow;
    uint inet_network(const(char)*) @nogc nothrow;
    char* inet_ntoa(in_addr) @nogc nothrow;
    int inet_pton(int, const(char)*, void*) @nogc nothrow;
    const(char)* inet_ntop(int, const(void)*, char*, uint) @nogc nothrow;
    int inet_aton(const(char)*, in_addr*) @nogc nothrow;
    char* inet_neta(uint, char*, c_ulong) @nogc nothrow;
    char* inet_net_ntop(int, const(void)*, int, char*, c_ulong) @nogc nothrow;
    int inet_net_pton(int, const(char)*, void*, c_ulong) @nogc nothrow;
    uint inet_nsap_addr(const(char)*, ubyte*, int) @nogc nothrow;
    char* inet_nsap_ntoa(int, const(ubyte)*, char*) @nogc nothrow;
    int zsock_maxmsgsize(void*) @nogc nothrow;
    void zsock_set_rcvhwm(void*, int) @nogc nothrow;
    int zsock_rcvhwm(void*) @nogc nothrow;
    void zsock_set_sndhwm(void*, int) @nogc nothrow;
    int zsock_sndhwm(void*) @nogc nothrow;
    void zsock_set_immediate(void*, int) @nogc nothrow;
    int zsock_immediate(void*) @nogc nothrow;
    void zsock_set_ipv6(void*, int) @nogc nothrow;
    int zsock_ipv6(void*) @nogc nothrow;
    void zsock_set_gssapi_service_principal(void*, const(char)*) @nogc nothrow;
    char* zsock_gssapi_service_principal(void*) @nogc nothrow;
    void zsock_set_gssapi_principal(void*, const(char)*) @nogc nothrow;
    char* zsock_gssapi_principal(void*) @nogc nothrow;
    void zsock_set_gssapi_plaintext(void*, int) @nogc nothrow;
    int zsock_gssapi_plaintext(void*) @nogc nothrow;
    void zsock_set_gssapi_server(void*, int) @nogc nothrow;
    int zsock_gssapi_server(void*) @nogc nothrow;
    void zsock_set_curve_serverkey_bin(void*, const(ubyte)*) @nogc nothrow;
    void zsock_set_curve_serverkey(void*, const(char)*) @nogc nothrow;
    char* zsock_curve_serverkey(void*) @nogc nothrow;
    void zsock_set_curve_secretkey_bin(void*, const(ubyte)*) @nogc nothrow;
    void zsock_set_curve_secretkey(void*, const(char)*) @nogc nothrow;
    char* zsock_curve_secretkey(void*) @nogc nothrow;
    void zsock_set_curve_publickey_bin(void*, const(ubyte)*) @nogc nothrow;
    void zsock_set_curve_publickey(void*, const(char)*) @nogc nothrow;
    char* zsock_curve_publickey(void*) @nogc nothrow;
    void zsock_set_curve_server(void*, int) @nogc nothrow;
    int zsock_curve_server(void*) @nogc nothrow;
    void zsock_set_plain_password(void*, const(char)*) @nogc nothrow;
    char* zsock_plain_password(void*) @nogc nothrow;
    void zsock_set_plain_username(void*, const(char)*) @nogc nothrow;
    char* zsock_plain_username(void*) @nogc nothrow;
    void zsock_set_plain_server(void*, int) @nogc nothrow;
    int zsock_plain_server(void*) @nogc nothrow;
    int zsock_mechanism(void*) @nogc nothrow;
    void zsock_set_zap_domain(void*, const(char)*) @nogc nothrow;
    char* zsock_zap_domain(void*) @nogc nothrow;
    void zsock_set_conflate(void*, int) @nogc nothrow;
    void zsock_set_req_correlate(void*, int) @nogc nothrow;
    void zsock_set_req_relaxed(void*, int) @nogc nothrow;
    void zsock_set_probe_router(void*, int) @nogc nothrow;
    void zsock_set_router_mandatory(void*, int) @nogc nothrow;
    void zsock_set_xpub_nodrop(void*, int) @nogc nothrow;
    void zsock_set_socks_proxy(void*, const(char)*) @nogc nothrow;
    char* zsock_socks_proxy(void*) @nogc nothrow;
    void zsock_set_handshake_ivl(void*, int) @nogc nothrow;
    int zsock_handshake_ivl(void*) @nogc nothrow;
    void zsock_set_connect_rid_bin(void*, const(ubyte)*) @nogc nothrow;
    void zsock_set_connect_rid(void*, const(char)*) @nogc nothrow;
    void zsock_set_router_handover(void*, int) @nogc nothrow;
    void zsock_set_tos(void*, int) @nogc nothrow;
    int zsock_tos(void*) @nogc nothrow;
    void zsock_set_vmci_connect_timeout(void*, int) @nogc nothrow;
    int zsock_vmci_connect_timeout(void*) @nogc nothrow;
    void zsock_set_vmci_buffer_max_size(void*, int) @nogc nothrow;
    int zsock_vmci_buffer_max_size(void*) @nogc nothrow;
    void zsock_set_vmci_buffer_min_size(void*, int) @nogc nothrow;
    int zsock_vmci_buffer_min_size(void*) @nogc nothrow;
    void zsock_set_vmci_buffer_size(void*, int) @nogc nothrow;
    int zsock_vmci_buffer_size(void*) @nogc nothrow;
    void zsock_set_multicast_maxtpdu(void*, int) @nogc nothrow;
    int zsock_multicast_maxtpdu(void*) @nogc nothrow;
    int zsock_thread_safe(void*) @nogc nothrow;
    void zsock_set_tcp_maxrt(void*, int) @nogc nothrow;
    int zsock_tcp_maxrt(void*) @nogc nothrow;
    void zsock_set_connect_timeout(void*, int) @nogc nothrow;
    int zsock_connect_timeout(void*) @nogc nothrow;
    void zsock_set_xpub_verboser(void*, int) @nogc nothrow;
    void zsock_set_invert_matching(void*, int) @nogc nothrow;
    int zsock_invert_matching(void*) @nogc nothrow;
    void zsock_set_stream_notify(void*, int) @nogc nothrow;
    void zsock_set_xpub_welcome_msg(void*, const(char)*) @nogc nothrow;
    void zsock_set_xpub_manual(void*, int) @nogc nothrow;
    void zsock_set_use_fd(void*, int) @nogc nothrow;
    int zsock_use_fd(void*) @nogc nothrow;
    void zsock_set_heartbeat_timeout(void*, int) @nogc nothrow;
    int zsock_heartbeat_timeout(void*) @nogc nothrow;
    void zsock_set_heartbeat_ttl(void*, int) @nogc nothrow;
    int zsock_heartbeat_ttl(void*) @nogc nothrow;
    void zsock_set_heartbeat_ivl(void*, int) @nogc nothrow;
    int zsock_heartbeat_ivl(void*) @nogc nothrow;
    void zsock_set_bindtodevice(void*, const(char)*) @nogc nothrow;
    char* zsock_bindtodevice(void*) @nogc nothrow;
    void zsock_set_gssapi_service_principal_nametype(void*, int) @nogc nothrow;
    int zsock_gssapi_service_principal_nametype(void*) @nogc nothrow;
    void zsock_set_gssapi_principal_nametype(void*, int) @nogc nothrow;
    int zsock_gssapi_principal_nametype(void*) @nogc nothrow;
    void zsock_set_zap_enforce_domain(void*, int) @nogc nothrow;
    int zsock_zap_enforce_domain(void*) @nogc nothrow;
    void zsock_set_loopback_fastpath(void*, int) @nogc nothrow;
    int zsock_loopback_fastpath(void*) @nogc nothrow;
    void zsock_set_metadata(void*, const(char)*) @nogc nothrow;
    char* zsock_metadata(void*) @nogc nothrow;
    void zsock_set_multicast_loop(void*, int) @nogc nothrow;
    int zsock_multicast_loop(void*) @nogc nothrow;
    void zsock_set_router_notify(void*, int) @nogc nothrow;
    int zsock_router_notify(void*) @nogc nothrow;
    void zsock_set_xpub_manual_last_value(void*, int) @nogc nothrow;
    void zsock_set_socks_username(void*, const(char)*) @nogc nothrow;
    char* zsock_socks_username(void*) @nogc nothrow;
    void zsock_set_socks_password(void*, const(char)*) @nogc nothrow;
    char* zsock_socks_password(void*) @nogc nothrow;
    void zsock_set_in_batch_size(void*, int) @nogc nothrow;
    int zsock_in_batch_size(void*) @nogc nothrow;
    void zsock_set_out_batch_size(void*, int) @nogc nothrow;
    int zsock_out_batch_size(void*) @nogc nothrow;
    void zsock_set_wss_key_pem(void*, const(char)*) @nogc nothrow;
    void zsock_set_wss_cert_pem(void*, const(char)*) @nogc nothrow;
    void zsock_set_wss_trust_pem(void*, const(char)*) @nogc nothrow;
    void zsock_set_wss_hostname(void*, const(char)*) @nogc nothrow;
    void zsock_set_wss_trust_system(void*, int) @nogc nothrow;
    void zsock_set_disconnect_msg(void*, _zframe_t*) @nogc nothrow;
    void zsock_set_hello_msg(void*, _zframe_t*) @nogc nothrow;
    void zsock_set_only_first_subscribe(void*, int) @nogc nothrow;
    void* zsock_resolve(void*) @nogc nothrow;
    bool zsock_is(void*) @nogc nothrow;
    void zsock_flush(void*) @nogc nothrow;
    int zsock_wait(void*) @nogc nothrow;
    int zsock_signal(void*, ubyte) @nogc nothrow;
    void zsock_set_unbounded(void*) @nogc nothrow;
    int zsock_brecv(void*, const(char)*, ...) @nogc nothrow;
    int zsock_bsend(void*, const(char)*, ...) @nogc nothrow;
    int zsock_vrecv(void*, const(char)*, va_list*) @nogc nothrow;
    int zsock_recv(void*, const(char)*, ...) @nogc nothrow;
    int zsock_vsend(void*, const(char)*, va_list*) @nogc nothrow;
    int zsock_send(void*, const(char)*, ...) @nogc nothrow;
    const(char)* zsock_type_str(_zsock_t*) @nogc nothrow;
    int zsock_attach(_zsock_t*, const(char)*, bool) @nogc nothrow;
    int zsock_disconnect(_zsock_t*, const(char)*, ...) @nogc nothrow;
    int zsock_connect(_zsock_t*, const(char)*, ...) @nogc nothrow;
    alias __kernel_long_t = c_long;
    alias __kernel_ulong_t = c_ulong;
    alias __kernel_ino_t = c_ulong;
    alias __kernel_mode_t = uint;
    alias __kernel_pid_t = int;
    alias __kernel_ipc_pid_t = int;
    alias __kernel_uid_t = uint;
    alias __kernel_gid_t = uint;
    alias __kernel_suseconds_t = c_long;
    alias __kernel_daddr_t = int;
    alias __kernel_uid32_t = uint;
    alias __kernel_gid32_t = uint;
    alias __kernel_size_t = c_ulong;
    alias __kernel_ssize_t = c_long;
    alias __kernel_ptrdiff_t = c_long;
    struct __kernel_fsid_t
    {
        int[2] val;
    }
    alias __kernel_off_t = c_long;
    alias __kernel_loff_t = long;
    alias __kernel_old_time_t = c_long;
    alias __kernel_time_t = c_long;
    alias __kernel_time64_t = long;
    alias __kernel_clock_t = c_long;
    alias __kernel_timer_t = int;
    alias __kernel_clockid_t = int;
    alias __kernel_caddr_t = char*;
    alias __kernel_uid16_t = ushort;
    alias __kernel_gid16_t = ushort;
    int zsock_unbind(_zsock_t*, const(char)*, ...) @nogc nothrow;
    const(char)* zsock_endpoint(_zsock_t*) @nogc nothrow;
    int zsock_bind(_zsock_t*, const(char)*, ...) @nogc nothrow;
    pragma(mangle, "zsock_destroy") void zsock_destroy_(_zsock_t**) @nogc nothrow;
    pragma(mangle, "zsock_new_stream") _zsock_t* zsock_new_stream_(const(char)*) @nogc nothrow;
    pragma(mangle, "zsock_new_pair") _zsock_t* zsock_new_pair_(const(char)*) @nogc nothrow;
    pragma(mangle, "zsock_new_xsub") _zsock_t* zsock_new_xsub_(const(char)*) @nogc nothrow;
    pragma(mangle, "zsock_new_xpub") _zsock_t* zsock_new_xpub_(const(char)*) @nogc nothrow;
    pragma(mangle, "zsock_new_pull") _zsock_t* zsock_new_pull_(const(char)*) @nogc nothrow;
    pragma(mangle, "zsock_new_push") _zsock_t* zsock_new_push_(const(char)*) @nogc nothrow;
    pragma(mangle, "zsock_new_router") _zsock_t* zsock_new_router_(const(char)*) @nogc nothrow;
    pragma(mangle, "zsock_new_dealer") _zsock_t* zsock_new_dealer_(const(char)*) @nogc nothrow;
    pragma(mangle, "zsock_new_rep") _zsock_t* zsock_new_rep_(const(char)*) @nogc nothrow;
    pragma(mangle, "zsock_new_req") _zsock_t* zsock_new_req_(const(char)*) @nogc nothrow;
    pragma(mangle, "zsock_new_sub") _zsock_t* zsock_new_sub_(const(char)*, const(char)*) @nogc nothrow;
    pragma(mangle, "zsock_new_pub") _zsock_t* zsock_new_pub_(const(char)*) @nogc nothrow;
    pragma(mangle, "zsock_new") _zsock_t* zsock_new_(int) @nogc nothrow;
    void zrex_test(bool) @nogc nothrow;
    int zrex_fetch(_zrex_t*, const(char)**, ...) @nogc nothrow;
    const(char)* zrex_hit(_zrex_t*, uint) @nogc nothrow;
    int zrex_hits(_zrex_t*) @nogc nothrow;
    bool zrex_eq(_zrex_t*, const(char)*, const(char)*) @nogc nothrow;
    bool zrex_matches(_zrex_t*, const(char)*) @nogc nothrow;
    const(char)* zrex_strerror(_zrex_t*) @nogc nothrow;
    bool zrex_valid(_zrex_t*) @nogc nothrow;
    void zrex_destroy(_zrex_t**) @nogc nothrow;
    _zrex_t* zrex_new(const(char)*) @nogc nothrow;
    void zproxy_test(bool) @nogc nothrow;
    void zproxy(_zsock_t*, void*) @nogc nothrow;
    void zpoller_test(bool) @nogc nothrow;
    bool zpoller_terminated(_zpoller_t*) @nogc nothrow;
    bool zpoller_expired(_zpoller_t*) @nogc nothrow;
    void* zpoller_wait(_zpoller_t*, int) @nogc nothrow;
    void zpoller_set_nonstop(_zpoller_t*, bool) @nogc nothrow;
    int zpoller_remove(_zpoller_t*, void*) @nogc nothrow;
    int zpoller_add(_zpoller_t*, void*) @nogc nothrow;
    void zpoller_destroy(_zpoller_t**) @nogc nothrow;
    _zpoller_t* zpoller_new(void*, ...) @nogc nothrow;
    void zmsg_fprint(_zmsg_t*, _IO_FILE*) @nogc nothrow;
    alias __kernel_old_uid_t = ushort;
    alias __kernel_old_gid_t = ushort;
    alias __kernel_old_dev_t = c_ulong;
    int zmsg_add(_zmsg_t*, _zframe_t*) @nogc nothrow;
    int zmsg_push(_zmsg_t*, _zframe_t*) @nogc nothrow;
    void __assert_fail(const(char)*, const(char)*, uint, const(char)*) @nogc nothrow;
    void __assert_perror_fail(int, const(char)*, uint, const(char)*) @nogc nothrow;
    void __assert(const(char)*, const(char)*, int) @nogc nothrow;
    void zmsg_wrap(_zmsg_t*, _zframe_t*) @nogc nothrow;
    _zmsg_t* zmsg_recv_nowait(void*) @nogc nothrow;
    static ushort __bswap_16(ushort) @nogc nothrow;
    _zframe_t* zmsg_unwrap(_zmsg_t*) @nogc nothrow;
    static uint __bswap_32(uint) @nogc nothrow;
    static c_ulong __bswap_64(c_ulong) @nogc nothrow;
    enum _Anonymous_0
    {
        _PC_LINK_MAX = 0,
        _PC_MAX_CANON = 1,
        _PC_MAX_INPUT = 2,
        _PC_NAME_MAX = 3,
        _PC_PATH_MAX = 4,
        _PC_PIPE_BUF = 5,
        _PC_CHOWN_RESTRICTED = 6,
        _PC_NO_TRUNC = 7,
        _PC_VDISABLE = 8,
        _PC_SYNC_IO = 9,
        _PC_ASYNC_IO = 10,
        _PC_PRIO_IO = 11,
        _PC_SOCK_MAXBUF = 12,
        _PC_FILESIZEBITS = 13,
        _PC_REC_INCR_XFER_SIZE = 14,
        _PC_REC_MAX_XFER_SIZE = 15,
        _PC_REC_MIN_XFER_SIZE = 16,
        _PC_REC_XFER_ALIGN = 17,
        _PC_ALLOC_SIZE_MIN = 18,
        _PC_SYMLINK_MAX = 19,
        _PC_2_SYMLINKS = 20,
    }
    enum _PC_LINK_MAX = _Anonymous_0._PC_LINK_MAX;
    enum _PC_MAX_CANON = _Anonymous_0._PC_MAX_CANON;
    enum _PC_MAX_INPUT = _Anonymous_0._PC_MAX_INPUT;
    enum _PC_NAME_MAX = _Anonymous_0._PC_NAME_MAX;
    enum _PC_PATH_MAX = _Anonymous_0._PC_PATH_MAX;
    enum _PC_PIPE_BUF = _Anonymous_0._PC_PIPE_BUF;
    enum _PC_CHOWN_RESTRICTED = _Anonymous_0._PC_CHOWN_RESTRICTED;
    enum _PC_NO_TRUNC = _Anonymous_0._PC_NO_TRUNC;
    enum _PC_VDISABLE = _Anonymous_0._PC_VDISABLE;
    enum _PC_SYNC_IO = _Anonymous_0._PC_SYNC_IO;
    enum _PC_ASYNC_IO = _Anonymous_0._PC_ASYNC_IO;
    enum _PC_PRIO_IO = _Anonymous_0._PC_PRIO_IO;
    enum _PC_SOCK_MAXBUF = _Anonymous_0._PC_SOCK_MAXBUF;
    enum _PC_FILESIZEBITS = _Anonymous_0._PC_FILESIZEBITS;
    enum _PC_REC_INCR_XFER_SIZE = _Anonymous_0._PC_REC_INCR_XFER_SIZE;
    enum _PC_REC_MAX_XFER_SIZE = _Anonymous_0._PC_REC_MAX_XFER_SIZE;
    enum _PC_REC_MIN_XFER_SIZE = _Anonymous_0._PC_REC_MIN_XFER_SIZE;
    enum _PC_REC_XFER_ALIGN = _Anonymous_0._PC_REC_XFER_ALIGN;
    enum _PC_ALLOC_SIZE_MIN = _Anonymous_0._PC_ALLOC_SIZE_MIN;
    enum _PC_SYMLINK_MAX = _Anonymous_0._PC_SYMLINK_MAX;
    enum _PC_2_SYMLINKS = _Anonymous_0._PC_2_SYMLINKS;
    void zmsg_test(bool) @nogc nothrow;
    bool zmsg_is(void*) @nogc nothrow;
    int zmsg_signal(_zmsg_t*) @nogc nothrow;
    bool zmsg_eq(_zmsg_t*, _zmsg_t*) @nogc nothrow;
    void zmsg_print(_zmsg_t*) @nogc nothrow;
    _zmsg_t* zmsg_dup(_zmsg_t*) @nogc nothrow;
    _zframe_t* zmsg_encode(_zmsg_t*) @nogc nothrow;
    int zmsg_save(_zmsg_t*, _IO_FILE*) @nogc nothrow;
    _zframe_t* zmsg_last(_zmsg_t*) @nogc nothrow;
    _zframe_t* zmsg_next(_zmsg_t*) @nogc nothrow;
    enum _Anonymous_1
    {
        _SC_ARG_MAX = 0,
        _SC_CHILD_MAX = 1,
        _SC_CLK_TCK = 2,
        _SC_NGROUPS_MAX = 3,
        _SC_OPEN_MAX = 4,
        _SC_STREAM_MAX = 5,
        _SC_TZNAME_MAX = 6,
        _SC_JOB_CONTROL = 7,
        _SC_SAVED_IDS = 8,
        _SC_REALTIME_SIGNALS = 9,
        _SC_PRIORITY_SCHEDULING = 10,
        _SC_TIMERS = 11,
        _SC_ASYNCHRONOUS_IO = 12,
        _SC_PRIORITIZED_IO = 13,
        _SC_SYNCHRONIZED_IO = 14,
        _SC_FSYNC = 15,
        _SC_MAPPED_FILES = 16,
        _SC_MEMLOCK = 17,
        _SC_MEMLOCK_RANGE = 18,
        _SC_MEMORY_PROTECTION = 19,
        _SC_MESSAGE_PASSING = 20,
        _SC_SEMAPHORES = 21,
        _SC_SHARED_MEMORY_OBJECTS = 22,
        _SC_AIO_LISTIO_MAX = 23,
        _SC_AIO_MAX = 24,
        _SC_AIO_PRIO_DELTA_MAX = 25,
        _SC_DELAYTIMER_MAX = 26,
        _SC_MQ_OPEN_MAX = 27,
        _SC_MQ_PRIO_MAX = 28,
        _SC_VERSION = 29,
        _SC_PAGESIZE = 30,
        _SC_RTSIG_MAX = 31,
        _SC_SEM_NSEMS_MAX = 32,
        _SC_SEM_VALUE_MAX = 33,
        _SC_SIGQUEUE_MAX = 34,
        _SC_TIMER_MAX = 35,
        _SC_BC_BASE_MAX = 36,
        _SC_BC_DIM_MAX = 37,
        _SC_BC_SCALE_MAX = 38,
        _SC_BC_STRING_MAX = 39,
        _SC_COLL_WEIGHTS_MAX = 40,
        _SC_EQUIV_CLASS_MAX = 41,
        _SC_EXPR_NEST_MAX = 42,
        _SC_LINE_MAX = 43,
        _SC_RE_DUP_MAX = 44,
        _SC_CHARCLASS_NAME_MAX = 45,
        _SC_2_VERSION = 46,
        _SC_2_C_BIND = 47,
        _SC_2_C_DEV = 48,
        _SC_2_FORT_DEV = 49,
        _SC_2_FORT_RUN = 50,
        _SC_2_SW_DEV = 51,
        _SC_2_LOCALEDEF = 52,
        _SC_PII = 53,
        _SC_PII_XTI = 54,
        _SC_PII_SOCKET = 55,
        _SC_PII_INTERNET = 56,
        _SC_PII_OSI = 57,
        _SC_POLL = 58,
        _SC_SELECT = 59,
        _SC_UIO_MAXIOV = 60,
        _SC_IOV_MAX = 60,
        _SC_PII_INTERNET_STREAM = 61,
        _SC_PII_INTERNET_DGRAM = 62,
        _SC_PII_OSI_COTS = 63,
        _SC_PII_OSI_CLTS = 64,
        _SC_PII_OSI_M = 65,
        _SC_T_IOV_MAX = 66,
        _SC_THREADS = 67,
        _SC_THREAD_SAFE_FUNCTIONS = 68,
        _SC_GETGR_R_SIZE_MAX = 69,
        _SC_GETPW_R_SIZE_MAX = 70,
        _SC_LOGIN_NAME_MAX = 71,
        _SC_TTY_NAME_MAX = 72,
        _SC_THREAD_DESTRUCTOR_ITERATIONS = 73,
        _SC_THREAD_KEYS_MAX = 74,
        _SC_THREAD_STACK_MIN = 75,
        _SC_THREAD_THREADS_MAX = 76,
        _SC_THREAD_ATTR_STACKADDR = 77,
        _SC_THREAD_ATTR_STACKSIZE = 78,
        _SC_THREAD_PRIORITY_SCHEDULING = 79,
        _SC_THREAD_PRIO_INHERIT = 80,
        _SC_THREAD_PRIO_PROTECT = 81,
        _SC_THREAD_PROCESS_SHARED = 82,
        _SC_NPROCESSORS_CONF = 83,
        _SC_NPROCESSORS_ONLN = 84,
        _SC_PHYS_PAGES = 85,
        _SC_AVPHYS_PAGES = 86,
        _SC_ATEXIT_MAX = 87,
        _SC_PASS_MAX = 88,
        _SC_XOPEN_VERSION = 89,
        _SC_XOPEN_XCU_VERSION = 90,
        _SC_XOPEN_UNIX = 91,
        _SC_XOPEN_CRYPT = 92,
        _SC_XOPEN_ENH_I18N = 93,
        _SC_XOPEN_SHM = 94,
        _SC_2_CHAR_TERM = 95,
        _SC_2_C_VERSION = 96,
        _SC_2_UPE = 97,
        _SC_XOPEN_XPG2 = 98,
        _SC_XOPEN_XPG3 = 99,
        _SC_XOPEN_XPG4 = 100,
        _SC_CHAR_BIT = 101,
        _SC_CHAR_MAX = 102,
        _SC_CHAR_MIN = 103,
        _SC_INT_MAX = 104,
        _SC_INT_MIN = 105,
        _SC_LONG_BIT = 106,
        _SC_WORD_BIT = 107,
        _SC_MB_LEN_MAX = 108,
        _SC_NZERO = 109,
        _SC_SSIZE_MAX = 110,
        _SC_SCHAR_MAX = 111,
        _SC_SCHAR_MIN = 112,
        _SC_SHRT_MAX = 113,
        _SC_SHRT_MIN = 114,
        _SC_UCHAR_MAX = 115,
        _SC_UINT_MAX = 116,
        _SC_ULONG_MAX = 117,
        _SC_USHRT_MAX = 118,
        _SC_NL_ARGMAX = 119,
        _SC_NL_LANGMAX = 120,
        _SC_NL_MSGMAX = 121,
        _SC_NL_NMAX = 122,
        _SC_NL_SETMAX = 123,
        _SC_NL_TEXTMAX = 124,
        _SC_XBS5_ILP32_OFF32 = 125,
        _SC_XBS5_ILP32_OFFBIG = 126,
        _SC_XBS5_LP64_OFF64 = 127,
        _SC_XBS5_LPBIG_OFFBIG = 128,
        _SC_XOPEN_LEGACY = 129,
        _SC_XOPEN_REALTIME = 130,
        _SC_XOPEN_REALTIME_THREADS = 131,
        _SC_ADVISORY_INFO = 132,
        _SC_BARRIERS = 133,
        _SC_BASE = 134,
        _SC_C_LANG_SUPPORT = 135,
        _SC_C_LANG_SUPPORT_R = 136,
        _SC_CLOCK_SELECTION = 137,
        _SC_CPUTIME = 138,
        _SC_THREAD_CPUTIME = 139,
        _SC_DEVICE_IO = 140,
        _SC_DEVICE_SPECIFIC = 141,
        _SC_DEVICE_SPECIFIC_R = 142,
        _SC_FD_MGMT = 143,
        _SC_FIFO = 144,
        _SC_PIPE = 145,
        _SC_FILE_ATTRIBUTES = 146,
        _SC_FILE_LOCKING = 147,
        _SC_FILE_SYSTEM = 148,
        _SC_MONOTONIC_CLOCK = 149,
        _SC_MULTI_PROCESS = 150,
        _SC_SINGLE_PROCESS = 151,
        _SC_NETWORKING = 152,
        _SC_READER_WRITER_LOCKS = 153,
        _SC_SPIN_LOCKS = 154,
        _SC_REGEXP = 155,
        _SC_REGEX_VERSION = 156,
        _SC_SHELL = 157,
        _SC_SIGNALS = 158,
        _SC_SPAWN = 159,
        _SC_SPORADIC_SERVER = 160,
        _SC_THREAD_SPORADIC_SERVER = 161,
        _SC_SYSTEM_DATABASE = 162,
        _SC_SYSTEM_DATABASE_R = 163,
        _SC_TIMEOUTS = 164,
        _SC_TYPED_MEMORY_OBJECTS = 165,
        _SC_USER_GROUPS = 166,
        _SC_USER_GROUPS_R = 167,
        _SC_2_PBS = 168,
        _SC_2_PBS_ACCOUNTING = 169,
        _SC_2_PBS_LOCATE = 170,
        _SC_2_PBS_MESSAGE = 171,
        _SC_2_PBS_TRACK = 172,
        _SC_SYMLOOP_MAX = 173,
        _SC_STREAMS = 174,
        _SC_2_PBS_CHECKPOINT = 175,
        _SC_V6_ILP32_OFF32 = 176,
        _SC_V6_ILP32_OFFBIG = 177,
        _SC_V6_LP64_OFF64 = 178,
        _SC_V6_LPBIG_OFFBIG = 179,
        _SC_HOST_NAME_MAX = 180,
        _SC_TRACE = 181,
        _SC_TRACE_EVENT_FILTER = 182,
        _SC_TRACE_INHERIT = 183,
        _SC_TRACE_LOG = 184,
        _SC_LEVEL1_ICACHE_SIZE = 185,
        _SC_LEVEL1_ICACHE_ASSOC = 186,
        _SC_LEVEL1_ICACHE_LINESIZE = 187,
        _SC_LEVEL1_DCACHE_SIZE = 188,
        _SC_LEVEL1_DCACHE_ASSOC = 189,
        _SC_LEVEL1_DCACHE_LINESIZE = 190,
        _SC_LEVEL2_CACHE_SIZE = 191,
        _SC_LEVEL2_CACHE_ASSOC = 192,
        _SC_LEVEL2_CACHE_LINESIZE = 193,
        _SC_LEVEL3_CACHE_SIZE = 194,
        _SC_LEVEL3_CACHE_ASSOC = 195,
        _SC_LEVEL3_CACHE_LINESIZE = 196,
        _SC_LEVEL4_CACHE_SIZE = 197,
        _SC_LEVEL4_CACHE_ASSOC = 198,
        _SC_LEVEL4_CACHE_LINESIZE = 199,
        _SC_IPV6 = 235,
        _SC_RAW_SOCKETS = 236,
        _SC_V7_ILP32_OFF32 = 237,
        _SC_V7_ILP32_OFFBIG = 238,
        _SC_V7_LP64_OFF64 = 239,
        _SC_V7_LPBIG_OFFBIG = 240,
        _SC_SS_REPL_MAX = 241,
        _SC_TRACE_EVENT_NAME_MAX = 242,
        _SC_TRACE_NAME_MAX = 243,
        _SC_TRACE_SYS_MAX = 244,
        _SC_TRACE_USER_EVENT_MAX = 245,
        _SC_XOPEN_STREAMS = 246,
        _SC_THREAD_ROBUST_PRIO_INHERIT = 247,
        _SC_THREAD_ROBUST_PRIO_PROTECT = 248,
    }
    enum _SC_ARG_MAX = _Anonymous_1._SC_ARG_MAX;
    enum _SC_CHILD_MAX = _Anonymous_1._SC_CHILD_MAX;
    enum _SC_CLK_TCK = _Anonymous_1._SC_CLK_TCK;
    enum _SC_NGROUPS_MAX = _Anonymous_1._SC_NGROUPS_MAX;
    enum _SC_OPEN_MAX = _Anonymous_1._SC_OPEN_MAX;
    enum _SC_STREAM_MAX = _Anonymous_1._SC_STREAM_MAX;
    enum _SC_TZNAME_MAX = _Anonymous_1._SC_TZNAME_MAX;
    enum _SC_JOB_CONTROL = _Anonymous_1._SC_JOB_CONTROL;
    enum _SC_SAVED_IDS = _Anonymous_1._SC_SAVED_IDS;
    enum _SC_REALTIME_SIGNALS = _Anonymous_1._SC_REALTIME_SIGNALS;
    enum _SC_PRIORITY_SCHEDULING = _Anonymous_1._SC_PRIORITY_SCHEDULING;
    enum _SC_TIMERS = _Anonymous_1._SC_TIMERS;
    enum _SC_ASYNCHRONOUS_IO = _Anonymous_1._SC_ASYNCHRONOUS_IO;
    enum _SC_PRIORITIZED_IO = _Anonymous_1._SC_PRIORITIZED_IO;
    enum _SC_SYNCHRONIZED_IO = _Anonymous_1._SC_SYNCHRONIZED_IO;
    enum _SC_FSYNC = _Anonymous_1._SC_FSYNC;
    enum _SC_MAPPED_FILES = _Anonymous_1._SC_MAPPED_FILES;
    enum _SC_MEMLOCK = _Anonymous_1._SC_MEMLOCK;
    enum _SC_MEMLOCK_RANGE = _Anonymous_1._SC_MEMLOCK_RANGE;
    enum _SC_MEMORY_PROTECTION = _Anonymous_1._SC_MEMORY_PROTECTION;
    enum _SC_MESSAGE_PASSING = _Anonymous_1._SC_MESSAGE_PASSING;
    enum _SC_SEMAPHORES = _Anonymous_1._SC_SEMAPHORES;
    enum _SC_SHARED_MEMORY_OBJECTS = _Anonymous_1._SC_SHARED_MEMORY_OBJECTS;
    enum _SC_AIO_LISTIO_MAX = _Anonymous_1._SC_AIO_LISTIO_MAX;
    enum _SC_AIO_MAX = _Anonymous_1._SC_AIO_MAX;
    enum _SC_AIO_PRIO_DELTA_MAX = _Anonymous_1._SC_AIO_PRIO_DELTA_MAX;
    enum _SC_DELAYTIMER_MAX = _Anonymous_1._SC_DELAYTIMER_MAX;
    enum _SC_MQ_OPEN_MAX = _Anonymous_1._SC_MQ_OPEN_MAX;
    enum _SC_MQ_PRIO_MAX = _Anonymous_1._SC_MQ_PRIO_MAX;
    enum _SC_VERSION = _Anonymous_1._SC_VERSION;
    enum _SC_PAGESIZE = _Anonymous_1._SC_PAGESIZE;
    enum _SC_RTSIG_MAX = _Anonymous_1._SC_RTSIG_MAX;
    enum _SC_SEM_NSEMS_MAX = _Anonymous_1._SC_SEM_NSEMS_MAX;
    enum _SC_SEM_VALUE_MAX = _Anonymous_1._SC_SEM_VALUE_MAX;
    enum _SC_SIGQUEUE_MAX = _Anonymous_1._SC_SIGQUEUE_MAX;
    enum _SC_TIMER_MAX = _Anonymous_1._SC_TIMER_MAX;
    enum _SC_BC_BASE_MAX = _Anonymous_1._SC_BC_BASE_MAX;
    enum _SC_BC_DIM_MAX = _Anonymous_1._SC_BC_DIM_MAX;
    enum _SC_BC_SCALE_MAX = _Anonymous_1._SC_BC_SCALE_MAX;
    enum _SC_BC_STRING_MAX = _Anonymous_1._SC_BC_STRING_MAX;
    enum _SC_COLL_WEIGHTS_MAX = _Anonymous_1._SC_COLL_WEIGHTS_MAX;
    enum _SC_EQUIV_CLASS_MAX = _Anonymous_1._SC_EQUIV_CLASS_MAX;
    enum _SC_EXPR_NEST_MAX = _Anonymous_1._SC_EXPR_NEST_MAX;
    enum _SC_LINE_MAX = _Anonymous_1._SC_LINE_MAX;
    enum _SC_RE_DUP_MAX = _Anonymous_1._SC_RE_DUP_MAX;
    enum _SC_CHARCLASS_NAME_MAX = _Anonymous_1._SC_CHARCLASS_NAME_MAX;
    enum _SC_2_VERSION = _Anonymous_1._SC_2_VERSION;
    enum _SC_2_C_BIND = _Anonymous_1._SC_2_C_BIND;
    enum _SC_2_C_DEV = _Anonymous_1._SC_2_C_DEV;
    enum _SC_2_FORT_DEV = _Anonymous_1._SC_2_FORT_DEV;
    enum _SC_2_FORT_RUN = _Anonymous_1._SC_2_FORT_RUN;
    enum _SC_2_SW_DEV = _Anonymous_1._SC_2_SW_DEV;
    enum _SC_2_LOCALEDEF = _Anonymous_1._SC_2_LOCALEDEF;
    enum _SC_PII = _Anonymous_1._SC_PII;
    enum _SC_PII_XTI = _Anonymous_1._SC_PII_XTI;
    enum _SC_PII_SOCKET = _Anonymous_1._SC_PII_SOCKET;
    enum _SC_PII_INTERNET = _Anonymous_1._SC_PII_INTERNET;
    enum _SC_PII_OSI = _Anonymous_1._SC_PII_OSI;
    enum _SC_POLL = _Anonymous_1._SC_POLL;
    enum _SC_SELECT = _Anonymous_1._SC_SELECT;
    enum _SC_UIO_MAXIOV = _Anonymous_1._SC_UIO_MAXIOV;
    enum _SC_IOV_MAX = _Anonymous_1._SC_IOV_MAX;
    enum _SC_PII_INTERNET_STREAM = _Anonymous_1._SC_PII_INTERNET_STREAM;
    enum _SC_PII_INTERNET_DGRAM = _Anonymous_1._SC_PII_INTERNET_DGRAM;
    enum _SC_PII_OSI_COTS = _Anonymous_1._SC_PII_OSI_COTS;
    enum _SC_PII_OSI_CLTS = _Anonymous_1._SC_PII_OSI_CLTS;
    enum _SC_PII_OSI_M = _Anonymous_1._SC_PII_OSI_M;
    enum _SC_T_IOV_MAX = _Anonymous_1._SC_T_IOV_MAX;
    enum _SC_THREADS = _Anonymous_1._SC_THREADS;
    enum _SC_THREAD_SAFE_FUNCTIONS = _Anonymous_1._SC_THREAD_SAFE_FUNCTIONS;
    enum _SC_GETGR_R_SIZE_MAX = _Anonymous_1._SC_GETGR_R_SIZE_MAX;
    enum _SC_GETPW_R_SIZE_MAX = _Anonymous_1._SC_GETPW_R_SIZE_MAX;
    enum _SC_LOGIN_NAME_MAX = _Anonymous_1._SC_LOGIN_NAME_MAX;
    enum _SC_TTY_NAME_MAX = _Anonymous_1._SC_TTY_NAME_MAX;
    enum _SC_THREAD_DESTRUCTOR_ITERATIONS = _Anonymous_1._SC_THREAD_DESTRUCTOR_ITERATIONS;
    enum _SC_THREAD_KEYS_MAX = _Anonymous_1._SC_THREAD_KEYS_MAX;
    enum _SC_THREAD_STACK_MIN = _Anonymous_1._SC_THREAD_STACK_MIN;
    enum _SC_THREAD_THREADS_MAX = _Anonymous_1._SC_THREAD_THREADS_MAX;
    enum _SC_THREAD_ATTR_STACKADDR = _Anonymous_1._SC_THREAD_ATTR_STACKADDR;
    enum _SC_THREAD_ATTR_STACKSIZE = _Anonymous_1._SC_THREAD_ATTR_STACKSIZE;
    enum _SC_THREAD_PRIORITY_SCHEDULING = _Anonymous_1._SC_THREAD_PRIORITY_SCHEDULING;
    enum _SC_THREAD_PRIO_INHERIT = _Anonymous_1._SC_THREAD_PRIO_INHERIT;
    enum _SC_THREAD_PRIO_PROTECT = _Anonymous_1._SC_THREAD_PRIO_PROTECT;
    enum _SC_THREAD_PROCESS_SHARED = _Anonymous_1._SC_THREAD_PROCESS_SHARED;
    enum _SC_NPROCESSORS_CONF = _Anonymous_1._SC_NPROCESSORS_CONF;
    enum _SC_NPROCESSORS_ONLN = _Anonymous_1._SC_NPROCESSORS_ONLN;
    enum _SC_PHYS_PAGES = _Anonymous_1._SC_PHYS_PAGES;
    enum _SC_AVPHYS_PAGES = _Anonymous_1._SC_AVPHYS_PAGES;
    enum _SC_ATEXIT_MAX = _Anonymous_1._SC_ATEXIT_MAX;
    enum _SC_PASS_MAX = _Anonymous_1._SC_PASS_MAX;
    enum _SC_XOPEN_VERSION = _Anonymous_1._SC_XOPEN_VERSION;
    enum _SC_XOPEN_XCU_VERSION = _Anonymous_1._SC_XOPEN_XCU_VERSION;
    enum _SC_XOPEN_UNIX = _Anonymous_1._SC_XOPEN_UNIX;
    enum _SC_XOPEN_CRYPT = _Anonymous_1._SC_XOPEN_CRYPT;
    enum _SC_XOPEN_ENH_I18N = _Anonymous_1._SC_XOPEN_ENH_I18N;
    enum _SC_XOPEN_SHM = _Anonymous_1._SC_XOPEN_SHM;
    enum _SC_2_CHAR_TERM = _Anonymous_1._SC_2_CHAR_TERM;
    enum _SC_2_C_VERSION = _Anonymous_1._SC_2_C_VERSION;
    enum _SC_2_UPE = _Anonymous_1._SC_2_UPE;
    enum _SC_XOPEN_XPG2 = _Anonymous_1._SC_XOPEN_XPG2;
    enum _SC_XOPEN_XPG3 = _Anonymous_1._SC_XOPEN_XPG3;
    enum _SC_XOPEN_XPG4 = _Anonymous_1._SC_XOPEN_XPG4;
    enum _SC_CHAR_BIT = _Anonymous_1._SC_CHAR_BIT;
    enum _SC_CHAR_MAX = _Anonymous_1._SC_CHAR_MAX;
    enum _SC_CHAR_MIN = _Anonymous_1._SC_CHAR_MIN;
    enum _SC_INT_MAX = _Anonymous_1._SC_INT_MAX;
    enum _SC_INT_MIN = _Anonymous_1._SC_INT_MIN;
    enum _SC_LONG_BIT = _Anonymous_1._SC_LONG_BIT;
    enum _SC_WORD_BIT = _Anonymous_1._SC_WORD_BIT;
    enum _SC_MB_LEN_MAX = _Anonymous_1._SC_MB_LEN_MAX;
    enum _SC_NZERO = _Anonymous_1._SC_NZERO;
    enum _SC_SSIZE_MAX = _Anonymous_1._SC_SSIZE_MAX;
    enum _SC_SCHAR_MAX = _Anonymous_1._SC_SCHAR_MAX;
    enum _SC_SCHAR_MIN = _Anonymous_1._SC_SCHAR_MIN;
    enum _SC_SHRT_MAX = _Anonymous_1._SC_SHRT_MAX;
    enum _SC_SHRT_MIN = _Anonymous_1._SC_SHRT_MIN;
    enum _SC_UCHAR_MAX = _Anonymous_1._SC_UCHAR_MAX;
    enum _SC_UINT_MAX = _Anonymous_1._SC_UINT_MAX;
    enum _SC_ULONG_MAX = _Anonymous_1._SC_ULONG_MAX;
    enum _SC_USHRT_MAX = _Anonymous_1._SC_USHRT_MAX;
    enum _SC_NL_ARGMAX = _Anonymous_1._SC_NL_ARGMAX;
    enum _SC_NL_LANGMAX = _Anonymous_1._SC_NL_LANGMAX;
    enum _SC_NL_MSGMAX = _Anonymous_1._SC_NL_MSGMAX;
    enum _SC_NL_NMAX = _Anonymous_1._SC_NL_NMAX;
    enum _SC_NL_SETMAX = _Anonymous_1._SC_NL_SETMAX;
    enum _SC_NL_TEXTMAX = _Anonymous_1._SC_NL_TEXTMAX;
    enum _SC_XBS5_ILP32_OFF32 = _Anonymous_1._SC_XBS5_ILP32_OFF32;
    enum _SC_XBS5_ILP32_OFFBIG = _Anonymous_1._SC_XBS5_ILP32_OFFBIG;
    enum _SC_XBS5_LP64_OFF64 = _Anonymous_1._SC_XBS5_LP64_OFF64;
    enum _SC_XBS5_LPBIG_OFFBIG = _Anonymous_1._SC_XBS5_LPBIG_OFFBIG;
    enum _SC_XOPEN_LEGACY = _Anonymous_1._SC_XOPEN_LEGACY;
    enum _SC_XOPEN_REALTIME = _Anonymous_1._SC_XOPEN_REALTIME;
    enum _SC_XOPEN_REALTIME_THREADS = _Anonymous_1._SC_XOPEN_REALTIME_THREADS;
    enum _SC_ADVISORY_INFO = _Anonymous_1._SC_ADVISORY_INFO;
    enum _SC_BARRIERS = _Anonymous_1._SC_BARRIERS;
    enum _SC_BASE = _Anonymous_1._SC_BASE;
    enum _SC_C_LANG_SUPPORT = _Anonymous_1._SC_C_LANG_SUPPORT;
    enum _SC_C_LANG_SUPPORT_R = _Anonymous_1._SC_C_LANG_SUPPORT_R;
    enum _SC_CLOCK_SELECTION = _Anonymous_1._SC_CLOCK_SELECTION;
    enum _SC_CPUTIME = _Anonymous_1._SC_CPUTIME;
    enum _SC_THREAD_CPUTIME = _Anonymous_1._SC_THREAD_CPUTIME;
    enum _SC_DEVICE_IO = _Anonymous_1._SC_DEVICE_IO;
    enum _SC_DEVICE_SPECIFIC = _Anonymous_1._SC_DEVICE_SPECIFIC;
    enum _SC_DEVICE_SPECIFIC_R = _Anonymous_1._SC_DEVICE_SPECIFIC_R;
    enum _SC_FD_MGMT = _Anonymous_1._SC_FD_MGMT;
    enum _SC_FIFO = _Anonymous_1._SC_FIFO;
    enum _SC_PIPE = _Anonymous_1._SC_PIPE;
    enum _SC_FILE_ATTRIBUTES = _Anonymous_1._SC_FILE_ATTRIBUTES;
    enum _SC_FILE_LOCKING = _Anonymous_1._SC_FILE_LOCKING;
    enum _SC_FILE_SYSTEM = _Anonymous_1._SC_FILE_SYSTEM;
    enum _SC_MONOTONIC_CLOCK = _Anonymous_1._SC_MONOTONIC_CLOCK;
    enum _SC_MULTI_PROCESS = _Anonymous_1._SC_MULTI_PROCESS;
    enum _SC_SINGLE_PROCESS = _Anonymous_1._SC_SINGLE_PROCESS;
    enum _SC_NETWORKING = _Anonymous_1._SC_NETWORKING;
    enum _SC_READER_WRITER_LOCKS = _Anonymous_1._SC_READER_WRITER_LOCKS;
    enum _SC_SPIN_LOCKS = _Anonymous_1._SC_SPIN_LOCKS;
    enum _SC_REGEXP = _Anonymous_1._SC_REGEXP;
    enum _SC_REGEX_VERSION = _Anonymous_1._SC_REGEX_VERSION;
    enum _SC_SHELL = _Anonymous_1._SC_SHELL;
    enum _SC_SIGNALS = _Anonymous_1._SC_SIGNALS;
    enum _SC_SPAWN = _Anonymous_1._SC_SPAWN;
    enum _SC_SPORADIC_SERVER = _Anonymous_1._SC_SPORADIC_SERVER;
    enum _SC_THREAD_SPORADIC_SERVER = _Anonymous_1._SC_THREAD_SPORADIC_SERVER;
    enum _SC_SYSTEM_DATABASE = _Anonymous_1._SC_SYSTEM_DATABASE;
    enum _SC_SYSTEM_DATABASE_R = _Anonymous_1._SC_SYSTEM_DATABASE_R;
    enum _SC_TIMEOUTS = _Anonymous_1._SC_TIMEOUTS;
    enum _SC_TYPED_MEMORY_OBJECTS = _Anonymous_1._SC_TYPED_MEMORY_OBJECTS;
    enum _SC_USER_GROUPS = _Anonymous_1._SC_USER_GROUPS;
    enum _SC_USER_GROUPS_R = _Anonymous_1._SC_USER_GROUPS_R;
    enum _SC_2_PBS = _Anonymous_1._SC_2_PBS;
    enum _SC_2_PBS_ACCOUNTING = _Anonymous_1._SC_2_PBS_ACCOUNTING;
    enum _SC_2_PBS_LOCATE = _Anonymous_1._SC_2_PBS_LOCATE;
    enum _SC_2_PBS_MESSAGE = _Anonymous_1._SC_2_PBS_MESSAGE;
    enum _SC_2_PBS_TRACK = _Anonymous_1._SC_2_PBS_TRACK;
    enum _SC_SYMLOOP_MAX = _Anonymous_1._SC_SYMLOOP_MAX;
    enum _SC_STREAMS = _Anonymous_1._SC_STREAMS;
    enum _SC_2_PBS_CHECKPOINT = _Anonymous_1._SC_2_PBS_CHECKPOINT;
    enum _SC_V6_ILP32_OFF32 = _Anonymous_1._SC_V6_ILP32_OFF32;
    enum _SC_V6_ILP32_OFFBIG = _Anonymous_1._SC_V6_ILP32_OFFBIG;
    enum _SC_V6_LP64_OFF64 = _Anonymous_1._SC_V6_LP64_OFF64;
    enum _SC_V6_LPBIG_OFFBIG = _Anonymous_1._SC_V6_LPBIG_OFFBIG;
    enum _SC_HOST_NAME_MAX = _Anonymous_1._SC_HOST_NAME_MAX;
    enum _SC_TRACE = _Anonymous_1._SC_TRACE;
    enum _SC_TRACE_EVENT_FILTER = _Anonymous_1._SC_TRACE_EVENT_FILTER;
    enum _SC_TRACE_INHERIT = _Anonymous_1._SC_TRACE_INHERIT;
    enum _SC_TRACE_LOG = _Anonymous_1._SC_TRACE_LOG;
    enum _SC_LEVEL1_ICACHE_SIZE = _Anonymous_1._SC_LEVEL1_ICACHE_SIZE;
    enum _SC_LEVEL1_ICACHE_ASSOC = _Anonymous_1._SC_LEVEL1_ICACHE_ASSOC;
    enum _SC_LEVEL1_ICACHE_LINESIZE = _Anonymous_1._SC_LEVEL1_ICACHE_LINESIZE;
    enum _SC_LEVEL1_DCACHE_SIZE = _Anonymous_1._SC_LEVEL1_DCACHE_SIZE;
    enum _SC_LEVEL1_DCACHE_ASSOC = _Anonymous_1._SC_LEVEL1_DCACHE_ASSOC;
    enum _SC_LEVEL1_DCACHE_LINESIZE = _Anonymous_1._SC_LEVEL1_DCACHE_LINESIZE;
    enum _SC_LEVEL2_CACHE_SIZE = _Anonymous_1._SC_LEVEL2_CACHE_SIZE;
    enum _SC_LEVEL2_CACHE_ASSOC = _Anonymous_1._SC_LEVEL2_CACHE_ASSOC;
    enum _SC_LEVEL2_CACHE_LINESIZE = _Anonymous_1._SC_LEVEL2_CACHE_LINESIZE;
    enum _SC_LEVEL3_CACHE_SIZE = _Anonymous_1._SC_LEVEL3_CACHE_SIZE;
    enum _SC_LEVEL3_CACHE_ASSOC = _Anonymous_1._SC_LEVEL3_CACHE_ASSOC;
    enum _SC_LEVEL3_CACHE_LINESIZE = _Anonymous_1._SC_LEVEL3_CACHE_LINESIZE;
    enum _SC_LEVEL4_CACHE_SIZE = _Anonymous_1._SC_LEVEL4_CACHE_SIZE;
    enum _SC_LEVEL4_CACHE_ASSOC = _Anonymous_1._SC_LEVEL4_CACHE_ASSOC;
    enum _SC_LEVEL4_CACHE_LINESIZE = _Anonymous_1._SC_LEVEL4_CACHE_LINESIZE;
    enum _SC_IPV6 = _Anonymous_1._SC_IPV6;
    enum _SC_RAW_SOCKETS = _Anonymous_1._SC_RAW_SOCKETS;
    enum _SC_V7_ILP32_OFF32 = _Anonymous_1._SC_V7_ILP32_OFF32;
    enum _SC_V7_ILP32_OFFBIG = _Anonymous_1._SC_V7_ILP32_OFFBIG;
    enum _SC_V7_LP64_OFF64 = _Anonymous_1._SC_V7_LP64_OFF64;
    enum _SC_V7_LPBIG_OFFBIG = _Anonymous_1._SC_V7_LPBIG_OFFBIG;
    enum _SC_SS_REPL_MAX = _Anonymous_1._SC_SS_REPL_MAX;
    enum _SC_TRACE_EVENT_NAME_MAX = _Anonymous_1._SC_TRACE_EVENT_NAME_MAX;
    enum _SC_TRACE_NAME_MAX = _Anonymous_1._SC_TRACE_NAME_MAX;
    enum _SC_TRACE_SYS_MAX = _Anonymous_1._SC_TRACE_SYS_MAX;
    enum _SC_TRACE_USER_EVENT_MAX = _Anonymous_1._SC_TRACE_USER_EVENT_MAX;
    enum _SC_XOPEN_STREAMS = _Anonymous_1._SC_XOPEN_STREAMS;
    enum _SC_THREAD_ROBUST_PRIO_INHERIT = _Anonymous_1._SC_THREAD_ROBUST_PRIO_INHERIT;
    enum _SC_THREAD_ROBUST_PRIO_PROTECT = _Anonymous_1._SC_THREAD_ROBUST_PRIO_PROTECT;
    _zframe_t* zmsg_first(_zmsg_t*) @nogc nothrow;
    void zmsg_remove(_zmsg_t*, _zframe_t*) @nogc nothrow;
    _zmsg_t* zmsg_popmsg(_zmsg_t*) @nogc nothrow;
    int zmsg_addmsg(_zmsg_t*, _zmsg_t**) @nogc nothrow;
    char* zmsg_popstr(_zmsg_t*) @nogc nothrow;
    int zmsg_addstrf(_zmsg_t*, const(char)*, ...) @nogc nothrow;
    int zmsg_pushstrf(_zmsg_t*, const(char)*, ...) @nogc nothrow;
    int zmsg_addstr(_zmsg_t*, const(char)*) @nogc nothrow;
    int zmsg_pushstr(_zmsg_t*, const(char)*) @nogc nothrow;
    int zmsg_addmem(_zmsg_t*, const(void)*, c_ulong) @nogc nothrow;
    int zmsg_pushmem(_zmsg_t*, const(void)*, c_ulong) @nogc nothrow;
    _zframe_t* zmsg_pop(_zmsg_t*) @nogc nothrow;
    int zmsg_append(_zmsg_t*, _zframe_t**) @nogc nothrow;
    int zmsg_prepend(_zmsg_t*, _zframe_t**) @nogc nothrow;
    c_ulong zmsg_content_size(_zmsg_t*) @nogc nothrow;
    c_ulong zmsg_size(_zmsg_t*) @nogc nothrow;
    int zmsg_sendm(_zmsg_t**, void*) @nogc nothrow;
    int zmsg_send(_zmsg_t**, void*) @nogc nothrow;
    void zmsg_destroy(_zmsg_t**) @nogc nothrow;
    _zmsg_t* zmsg_new_signal(ubyte) @nogc nothrow;
    _zmsg_t* zmsg_decode(_zframe_t*) @nogc nothrow;
    _zmsg_t* zmsg_load(_IO_FILE*) @nogc nothrow;
    _zmsg_t* zmsg_recv(void*) @nogc nothrow;
    _zmsg_t* zmsg_new() @nogc nothrow;
    void zmonitor_test(bool) @nogc nothrow;
    void zmonitor(_zsock_t*, void*) @nogc nothrow;
    void zloop_test(bool) @nogc nothrow;
    int zloop_start(_zloop_t*) @nogc nothrow;
    void zloop_set_nonstop(_zloop_t*, bool) @nogc nothrow;
    void zloop_set_verbose(_zloop_t*, bool) @nogc nothrow;
    void zloop_set_max_timers(_zloop_t*, c_ulong) @nogc nothrow;
    void zloop_set_ticket_delay(_zloop_t*, c_ulong) @nogc nothrow;
    void zloop_ticket_delete(_zloop_t*, void*) @nogc nothrow;
    void zloop_ticket_reset(_zloop_t*, void*) @nogc nothrow;
    void* zloop_ticket(_zloop_t*, int function(_zloop_t*, int, void*), void*) @nogc nothrow;
    int zloop_timer_end(_zloop_t*, int) @nogc nothrow;
    int zloop_timer(_zloop_t*, c_ulong, c_ulong, int function(_zloop_t*, int, void*), void*) @nogc nothrow;
    void zloop_poller_set_tolerant(_zloop_t*, zmq_pollitem_t*) @nogc nothrow;
    void zloop_poller_end(_zloop_t*, zmq_pollitem_t*) @nogc nothrow;
    int zloop_poller(_zloop_t*, zmq_pollitem_t*, int function(_zloop_t*, zmq_pollitem_t*, void*), void*) @nogc nothrow;
    void zloop_reader_set_tolerant(_zloop_t*, _zsock_t*) @nogc nothrow;
    void zloop_reader_end(_zloop_t*, _zsock_t*) @nogc nothrow;
    int zloop_reader(_zloop_t*, _zsock_t*, int function(_zloop_t*, _zsock_t*, void*), void*) @nogc nothrow;
    void zloop_destroy(_zloop_t**) @nogc nothrow;
    _zloop_t* zloop_new() @nogc nothrow;
    alias zloop_timer_fn = int function(_zloop_t*, int, void*);
    alias zloop_fn = int function(_zloop_t*, zmq_pollitem_t*, void*);
    alias zloop_reader_fn = int function(_zloop_t*, _zsock_t*, void*);
    void zlistx_test(bool) @nogc nothrow;
    void zlistx_set_comparator(_zlistx_t*, int function(const(void)*, const(void)*)) @nogc nothrow;
    void zlistx_set_duplicator(_zlistx_t*, void* function(const(void)*)) @nogc nothrow;
    void zlistx_set_destructor(_zlistx_t*, void function(void**)) @nogc nothrow;
    _zlistx_t* zlistx_dup(_zlistx_t*) @nogc nothrow;
    void zlistx_reorder(_zlistx_t*, void*, bool) @nogc nothrow;
    void* zlistx_insert(_zlistx_t*, void*, bool) @nogc nothrow;
    void zlistx_sort(_zlistx_t*) @nogc nothrow;
    void zlistx_purge(_zlistx_t*) @nogc nothrow;
    void zlistx_move_end(_zlistx_t*, void*) @nogc nothrow;
    void zlistx_move_start(_zlistx_t*, void*) @nogc nothrow;
    int zlistx_delete(_zlistx_t*, void*) @nogc nothrow;
    void* zlistx_detach_cur(_zlistx_t*) @nogc nothrow;
    void* zlistx_detach(_zlistx_t*, void*) @nogc nothrow;
    void* zlistx_find(_zlistx_t*, void*) @nogc nothrow;
    void* zlistx_handle_item(void*) @nogc nothrow;
    void* zlistx_cursor(_zlistx_t*) @nogc nothrow;
    void* zlistx_item(_zlistx_t*) @nogc nothrow;
    void* zlistx_last(_zlistx_t*) @nogc nothrow;
    void* zlistx_prev(_zlistx_t*) @nogc nothrow;
    void* zlistx_next(_zlistx_t*) @nogc nothrow;
    void* zlistx_first(_zlistx_t*) @nogc nothrow;
    void* zlistx_tail(_zlistx_t*) @nogc nothrow;
    void* zlistx_head(_zlistx_t*) @nogc nothrow;
    c_ulong zlistx_size(_zlistx_t*) @nogc nothrow;
    void* zlistx_add_end(_zlistx_t*, void*) @nogc nothrow;
    void* zlistx_add_start(_zlistx_t*, void*) @nogc nothrow;
    void zlistx_destroy(_zlistx_t**) @nogc nothrow;
    _zlistx_t* zlistx_new() @nogc nothrow;
    alias zlistx_comparator_fn = int function(const(void)*, const(void)*);
    alias zlistx_duplicator_fn = void* function(const(void)*);
    alias zlistx_destructor_fn = void function(void**);
    void zlist_test(bool) @nogc nothrow;
    void* zlist_freefn(_zlist_t*, void*, void function(void*), bool) @nogc nothrow;
    void zlist_comparefn(_zlist_t*, int function(void*, void*)) @nogc nothrow;
    void zlist_autofree(_zlist_t*) @nogc nothrow;
    void zlist_sort(_zlist_t*, int function(void*, void*)) @nogc nothrow;
    c_ulong zlist_size(_zlist_t*) @nogc nothrow;
    void zlist_purge(_zlist_t*) @nogc nothrow;
    _zlist_t* zlist_dup(_zlist_t*) @nogc nothrow;
    void zlist_remove(_zlist_t*, void*) @nogc nothrow;
    bool zlist_exists(_zlist_t*, void*) @nogc nothrow;
    void* zlist_pop(_zlist_t*) @nogc nothrow;
    int zlist_push(_zlist_t*, void*) @nogc nothrow;
    int zlist_append(_zlist_t*, void*) @nogc nothrow;
    void* zlist_item(_zlist_t*) @nogc nothrow;
    void* zlist_tail(_zlist_t*) @nogc nothrow;
    void* zlist_head(_zlist_t*) @nogc nothrow;
    void* zlist_last(_zlist_t*) @nogc nothrow;
    void* zlist_next(_zlist_t*) @nogc nothrow;
    void* zlist_first(_zlist_t*) @nogc nothrow;
    void zlist_destroy(_zlist_t**) @nogc nothrow;
    _zlist_t* zlist_new() @nogc nothrow;
    alias zlist_free_fn = void function(void*);
    alias zlist_compare_fn = int function(void*, void*);
    void ziflist_test(bool) @nogc nothrow;
    enum _Anonymous_2
    {
        _CS_PATH = 0,
        _CS_V6_WIDTH_RESTRICTED_ENVS = 1,
        _CS_GNU_LIBC_VERSION = 2,
        _CS_GNU_LIBPTHREAD_VERSION = 3,
        _CS_V5_WIDTH_RESTRICTED_ENVS = 4,
        _CS_V7_WIDTH_RESTRICTED_ENVS = 5,
        _CS_LFS_CFLAGS = 1000,
        _CS_LFS_LDFLAGS = 1001,
        _CS_LFS_LIBS = 1002,
        _CS_LFS_LINTFLAGS = 1003,
        _CS_LFS64_CFLAGS = 1004,
        _CS_LFS64_LDFLAGS = 1005,
        _CS_LFS64_LIBS = 1006,
        _CS_LFS64_LINTFLAGS = 1007,
        _CS_XBS5_ILP32_OFF32_CFLAGS = 1100,
        _CS_XBS5_ILP32_OFF32_LDFLAGS = 1101,
        _CS_XBS5_ILP32_OFF32_LIBS = 1102,
        _CS_XBS5_ILP32_OFF32_LINTFLAGS = 1103,
        _CS_XBS5_ILP32_OFFBIG_CFLAGS = 1104,
        _CS_XBS5_ILP32_OFFBIG_LDFLAGS = 1105,
        _CS_XBS5_ILP32_OFFBIG_LIBS = 1106,
        _CS_XBS5_ILP32_OFFBIG_LINTFLAGS = 1107,
        _CS_XBS5_LP64_OFF64_CFLAGS = 1108,
        _CS_XBS5_LP64_OFF64_LDFLAGS = 1109,
        _CS_XBS5_LP64_OFF64_LIBS = 1110,
        _CS_XBS5_LP64_OFF64_LINTFLAGS = 1111,
        _CS_XBS5_LPBIG_OFFBIG_CFLAGS = 1112,
        _CS_XBS5_LPBIG_OFFBIG_LDFLAGS = 1113,
        _CS_XBS5_LPBIG_OFFBIG_LIBS = 1114,
        _CS_XBS5_LPBIG_OFFBIG_LINTFLAGS = 1115,
        _CS_POSIX_V6_ILP32_OFF32_CFLAGS = 1116,
        _CS_POSIX_V6_ILP32_OFF32_LDFLAGS = 1117,
        _CS_POSIX_V6_ILP32_OFF32_LIBS = 1118,
        _CS_POSIX_V6_ILP32_OFF32_LINTFLAGS = 1119,
        _CS_POSIX_V6_ILP32_OFFBIG_CFLAGS = 1120,
        _CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS = 1121,
        _CS_POSIX_V6_ILP32_OFFBIG_LIBS = 1122,
        _CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS = 1123,
        _CS_POSIX_V6_LP64_OFF64_CFLAGS = 1124,
        _CS_POSIX_V6_LP64_OFF64_LDFLAGS = 1125,
        _CS_POSIX_V6_LP64_OFF64_LIBS = 1126,
        _CS_POSIX_V6_LP64_OFF64_LINTFLAGS = 1127,
        _CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS = 1128,
        _CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS = 1129,
        _CS_POSIX_V6_LPBIG_OFFBIG_LIBS = 1130,
        _CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS = 1131,
        _CS_POSIX_V7_ILP32_OFF32_CFLAGS = 1132,
        _CS_POSIX_V7_ILP32_OFF32_LDFLAGS = 1133,
        _CS_POSIX_V7_ILP32_OFF32_LIBS = 1134,
        _CS_POSIX_V7_ILP32_OFF32_LINTFLAGS = 1135,
        _CS_POSIX_V7_ILP32_OFFBIG_CFLAGS = 1136,
        _CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS = 1137,
        _CS_POSIX_V7_ILP32_OFFBIG_LIBS = 1138,
        _CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS = 1139,
        _CS_POSIX_V7_LP64_OFF64_CFLAGS = 1140,
        _CS_POSIX_V7_LP64_OFF64_LDFLAGS = 1141,
        _CS_POSIX_V7_LP64_OFF64_LIBS = 1142,
        _CS_POSIX_V7_LP64_OFF64_LINTFLAGS = 1143,
        _CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS = 1144,
        _CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS = 1145,
        _CS_POSIX_V7_LPBIG_OFFBIG_LIBS = 1146,
        _CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS = 1147,
        _CS_V6_ENV = 1148,
        _CS_V7_ENV = 1149,
    }
    enum _CS_PATH = _Anonymous_2._CS_PATH;
    enum _CS_V6_WIDTH_RESTRICTED_ENVS = _Anonymous_2._CS_V6_WIDTH_RESTRICTED_ENVS;
    enum _CS_GNU_LIBC_VERSION = _Anonymous_2._CS_GNU_LIBC_VERSION;
    enum _CS_GNU_LIBPTHREAD_VERSION = _Anonymous_2._CS_GNU_LIBPTHREAD_VERSION;
    enum _CS_V5_WIDTH_RESTRICTED_ENVS = _Anonymous_2._CS_V5_WIDTH_RESTRICTED_ENVS;
    enum _CS_V7_WIDTH_RESTRICTED_ENVS = _Anonymous_2._CS_V7_WIDTH_RESTRICTED_ENVS;
    enum _CS_LFS_CFLAGS = _Anonymous_2._CS_LFS_CFLAGS;
    enum _CS_LFS_LDFLAGS = _Anonymous_2._CS_LFS_LDFLAGS;
    enum _CS_LFS_LIBS = _Anonymous_2._CS_LFS_LIBS;
    enum _CS_LFS_LINTFLAGS = _Anonymous_2._CS_LFS_LINTFLAGS;
    enum _CS_LFS64_CFLAGS = _Anonymous_2._CS_LFS64_CFLAGS;
    enum _CS_LFS64_LDFLAGS = _Anonymous_2._CS_LFS64_LDFLAGS;
    enum _CS_LFS64_LIBS = _Anonymous_2._CS_LFS64_LIBS;
    enum _CS_LFS64_LINTFLAGS = _Anonymous_2._CS_LFS64_LINTFLAGS;
    enum _CS_XBS5_ILP32_OFF32_CFLAGS = _Anonymous_2._CS_XBS5_ILP32_OFF32_CFLAGS;
    enum _CS_XBS5_ILP32_OFF32_LDFLAGS = _Anonymous_2._CS_XBS5_ILP32_OFF32_LDFLAGS;
    enum _CS_XBS5_ILP32_OFF32_LIBS = _Anonymous_2._CS_XBS5_ILP32_OFF32_LIBS;
    enum _CS_XBS5_ILP32_OFF32_LINTFLAGS = _Anonymous_2._CS_XBS5_ILP32_OFF32_LINTFLAGS;
    enum _CS_XBS5_ILP32_OFFBIG_CFLAGS = _Anonymous_2._CS_XBS5_ILP32_OFFBIG_CFLAGS;
    enum _CS_XBS5_ILP32_OFFBIG_LDFLAGS = _Anonymous_2._CS_XBS5_ILP32_OFFBIG_LDFLAGS;
    enum _CS_XBS5_ILP32_OFFBIG_LIBS = _Anonymous_2._CS_XBS5_ILP32_OFFBIG_LIBS;
    enum _CS_XBS5_ILP32_OFFBIG_LINTFLAGS = _Anonymous_2._CS_XBS5_ILP32_OFFBIG_LINTFLAGS;
    enum _CS_XBS5_LP64_OFF64_CFLAGS = _Anonymous_2._CS_XBS5_LP64_OFF64_CFLAGS;
    enum _CS_XBS5_LP64_OFF64_LDFLAGS = _Anonymous_2._CS_XBS5_LP64_OFF64_LDFLAGS;
    enum _CS_XBS5_LP64_OFF64_LIBS = _Anonymous_2._CS_XBS5_LP64_OFF64_LIBS;
    enum _CS_XBS5_LP64_OFF64_LINTFLAGS = _Anonymous_2._CS_XBS5_LP64_OFF64_LINTFLAGS;
    enum _CS_XBS5_LPBIG_OFFBIG_CFLAGS = _Anonymous_2._CS_XBS5_LPBIG_OFFBIG_CFLAGS;
    enum _CS_XBS5_LPBIG_OFFBIG_LDFLAGS = _Anonymous_2._CS_XBS5_LPBIG_OFFBIG_LDFLAGS;
    enum _CS_XBS5_LPBIG_OFFBIG_LIBS = _Anonymous_2._CS_XBS5_LPBIG_OFFBIG_LIBS;
    enum _CS_XBS5_LPBIG_OFFBIG_LINTFLAGS = _Anonymous_2._CS_XBS5_LPBIG_OFFBIG_LINTFLAGS;
    enum _CS_POSIX_V6_ILP32_OFF32_CFLAGS = _Anonymous_2._CS_POSIX_V6_ILP32_OFF32_CFLAGS;
    enum _CS_POSIX_V6_ILP32_OFF32_LDFLAGS = _Anonymous_2._CS_POSIX_V6_ILP32_OFF32_LDFLAGS;
    enum _CS_POSIX_V6_ILP32_OFF32_LIBS = _Anonymous_2._CS_POSIX_V6_ILP32_OFF32_LIBS;
    enum _CS_POSIX_V6_ILP32_OFF32_LINTFLAGS = _Anonymous_2._CS_POSIX_V6_ILP32_OFF32_LINTFLAGS;
    enum _CS_POSIX_V6_ILP32_OFFBIG_CFLAGS = _Anonymous_2._CS_POSIX_V6_ILP32_OFFBIG_CFLAGS;
    enum _CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS = _Anonymous_2._CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS;
    enum _CS_POSIX_V6_ILP32_OFFBIG_LIBS = _Anonymous_2._CS_POSIX_V6_ILP32_OFFBIG_LIBS;
    enum _CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS = _Anonymous_2._CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS;
    enum _CS_POSIX_V6_LP64_OFF64_CFLAGS = _Anonymous_2._CS_POSIX_V6_LP64_OFF64_CFLAGS;
    enum _CS_POSIX_V6_LP64_OFF64_LDFLAGS = _Anonymous_2._CS_POSIX_V6_LP64_OFF64_LDFLAGS;
    enum _CS_POSIX_V6_LP64_OFF64_LIBS = _Anonymous_2._CS_POSIX_V6_LP64_OFF64_LIBS;
    enum _CS_POSIX_V6_LP64_OFF64_LINTFLAGS = _Anonymous_2._CS_POSIX_V6_LP64_OFF64_LINTFLAGS;
    enum _CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS = _Anonymous_2._CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS;
    enum _CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS = _Anonymous_2._CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS;
    enum _CS_POSIX_V6_LPBIG_OFFBIG_LIBS = _Anonymous_2._CS_POSIX_V6_LPBIG_OFFBIG_LIBS;
    enum _CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS = _Anonymous_2._CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS;
    enum _CS_POSIX_V7_ILP32_OFF32_CFLAGS = _Anonymous_2._CS_POSIX_V7_ILP32_OFF32_CFLAGS;
    enum _CS_POSIX_V7_ILP32_OFF32_LDFLAGS = _Anonymous_2._CS_POSIX_V7_ILP32_OFF32_LDFLAGS;
    enum _CS_POSIX_V7_ILP32_OFF32_LIBS = _Anonymous_2._CS_POSIX_V7_ILP32_OFF32_LIBS;
    enum _CS_POSIX_V7_ILP32_OFF32_LINTFLAGS = _Anonymous_2._CS_POSIX_V7_ILP32_OFF32_LINTFLAGS;
    enum _CS_POSIX_V7_ILP32_OFFBIG_CFLAGS = _Anonymous_2._CS_POSIX_V7_ILP32_OFFBIG_CFLAGS;
    enum _CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS = _Anonymous_2._CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS;
    enum _CS_POSIX_V7_ILP32_OFFBIG_LIBS = _Anonymous_2._CS_POSIX_V7_ILP32_OFFBIG_LIBS;
    enum _CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS = _Anonymous_2._CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS;
    enum _CS_POSIX_V7_LP64_OFF64_CFLAGS = _Anonymous_2._CS_POSIX_V7_LP64_OFF64_CFLAGS;
    enum _CS_POSIX_V7_LP64_OFF64_LDFLAGS = _Anonymous_2._CS_POSIX_V7_LP64_OFF64_LDFLAGS;
    enum _CS_POSIX_V7_LP64_OFF64_LIBS = _Anonymous_2._CS_POSIX_V7_LP64_OFF64_LIBS;
    enum _CS_POSIX_V7_LP64_OFF64_LINTFLAGS = _Anonymous_2._CS_POSIX_V7_LP64_OFF64_LINTFLAGS;
    enum _CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS = _Anonymous_2._CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS;
    enum _CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS = _Anonymous_2._CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS;
    enum _CS_POSIX_V7_LPBIG_OFFBIG_LIBS = _Anonymous_2._CS_POSIX_V7_LPBIG_OFFBIG_LIBS;
    enum _CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS = _Anonymous_2._CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS;
    enum _CS_V6_ENV = _Anonymous_2._CS_V6_ENV;
    enum _CS_V7_ENV = _Anonymous_2._CS_V7_ENV;
    void ziflist_print(_ziflist_t*) @nogc nothrow;
    const(char)* ziflist_netmask(_ziflist_t*) @nogc nothrow;
    const(char)* ziflist_broadcast(_ziflist_t*) @nogc nothrow;
    const(char)* ziflist_address(_ziflist_t*) @nogc nothrow;
    const(char)* ziflist_next(_ziflist_t*) @nogc nothrow;
    const(char)* ziflist_first(_ziflist_t*) @nogc nothrow;
    c_ulong ziflist_size(_ziflist_t*) @nogc nothrow;
    void ziflist_reload(_ziflist_t*) @nogc nothrow;
    void ziflist_destroy(_ziflist_t**) @nogc nothrow;
    _ziflist_t* ziflist_new() @nogc nothrow;
    void zhashx_test(bool) @nogc nothrow;
    _zhashx_t* zhashx_dup_v2(_zhashx_t*) @nogc nothrow;
    void zhashx_set_key_hasher(_zhashx_t*, c_ulong function(const(void)*)) @nogc nothrow;
    void zhashx_set_key_comparator(_zhashx_t*, int function(const(void)*, const(void)*)) @nogc nothrow;
    void zhashx_set_key_duplicator(_zhashx_t*, void* function(const(void)*)) @nogc nothrow;
    void zhashx_set_key_destructor(_zhashx_t*, void function(void**)) @nogc nothrow;
    void zhashx_set_duplicator(_zhashx_t*, void* function(const(void)*)) @nogc nothrow;
    void zhashx_set_destructor(_zhashx_t*, void function(void**)) @nogc nothrow;
    _zhashx_t* zhashx_dup(_zhashx_t*) @nogc nothrow;
    _zframe_t* zhashx_pack(_zhashx_t*) @nogc nothrow;
    int zhashx_refresh(_zhashx_t*) @nogc nothrow;
    int zhashx_load(_zhashx_t*, const(char)*) @nogc nothrow;
    int zhashx_save(_zhashx_t*, const(char)*) @nogc nothrow;
    void zhashx_comment(_zhashx_t*, const(char)*, ...) @nogc nothrow;
    const(void)* zhashx_cursor(_zhashx_t*) @nogc nothrow;
    void* zhashx_next(_zhashx_t*) @nogc nothrow;
    void* zhashx_first(_zhashx_t*) @nogc nothrow;
    _zlistx_t* zhashx_values(_zhashx_t*) @nogc nothrow;
    _zlistx_t* zhashx_keys(_zhashx_t*) @nogc nothrow;
    c_ulong zhashx_size(_zhashx_t*) @nogc nothrow;
    void* zhashx_freefn(_zhashx_t*, const(void)*, void function(void*)) @nogc nothrow;
    int zhashx_rename(_zhashx_t*, const(void)*, const(void)*) @nogc nothrow;
    void* zhashx_lookup(_zhashx_t*, const(void)*) @nogc nothrow;
    void zhashx_purge(_zhashx_t*) @nogc nothrow;
    alias __cpu_mask = c_ulong;
    void zhashx_delete(_zhashx_t*, const(void)*) @nogc nothrow;
    struct cpu_set_t
    {
        c_ulong[16] __bits;
    }
    void zhashx_update(_zhashx_t*, const(void)*, void*) @nogc nothrow;
    int zhashx_insert(_zhashx_t*, const(void)*, void*) @nogc nothrow;
    void zhashx_destroy(_zhashx_t**) @nogc nothrow;
    _zhashx_t* zhashx_unpack(_zframe_t*) @nogc nothrow;
    _zhashx_t* zhashx_new() @nogc nothrow;
    alias zhashx_deserializer_fn = void* function(const(char)*);
    int __sched_cpucount(c_ulong, const(cpu_set_t)*) @nogc nothrow;
    cpu_set_t* __sched_cpualloc(c_ulong) @nogc nothrow;
    void __sched_cpufree(cpu_set_t*) @nogc nothrow;
    struct dirent
    {
        c_ulong d_ino;
        c_long d_off;
        ushort d_reclen;
        ubyte d_type;
        char[256] d_name;
    }
    alias zhashx_serializer_fn = char* function(const(void)*);
    alias zhashx_hash_fn = c_ulong function(const(void)*);
    alias zhashx_free_fn = void function(void*);
    alias zhashx_comparator_fn = int function(const(void)*, const(void)*);
    alias zhashx_duplicator_fn = void* function(const(void)*);
    alias zhashx_destructor_fn = void function(void**);
    void zhash_test(bool) @nogc nothrow;
    void zhash_autofree(_zhash_t*) @nogc nothrow;
    int zhash_refresh(_zhash_t*) @nogc nothrow;
    int zhash_load(_zhash_t*, const(char)*) @nogc nothrow;
    int zhash_save(_zhash_t*, const(char)*) @nogc nothrow;
    _zframe_t* zhash_pack(_zhash_t*) @nogc nothrow;
    void zhash_comment(_zhash_t*, const(char)*, ...) @nogc nothrow;
    const(char)* zhash_cursor(_zhash_t*) @nogc nothrow;
    void* zhash_next(_zhash_t*) @nogc nothrow;
    void* zhash_first(_zhash_t*) @nogc nothrow;
    _zlist_t* zhash_keys(_zhash_t*) @nogc nothrow;
    _zhash_t* zhash_dup(_zhash_t*) @nogc nothrow;
    c_ulong zhash_size(_zhash_t*) @nogc nothrow;
    void* zhash_freefn(_zhash_t*, const(char)*, void function(void*)) @nogc nothrow;
    int zhash_rename(_zhash_t*, const(char)*, const(char)*) @nogc nothrow;
    void* zhash_lookup(_zhash_t*, const(char)*) @nogc nothrow;
    void zhash_delete(_zhash_t*, const(char)*) @nogc nothrow;
    void zhash_update(_zhash_t*, const(char)*, void*) @nogc nothrow;
    int zhash_insert(_zhash_t*, const(char)*, void*) @nogc nothrow;
    void zhash_destroy(_zhash_t**) @nogc nothrow;
    _zhash_t* zhash_unpack(_zframe_t*) @nogc nothrow;
    _zhash_t* zhash_new() @nogc nothrow;
    alias zhash_free_fn = void function(void*);
    void zgossip_test(bool) @nogc nothrow;
    void zgossip(_zsock_t*, void*) @nogc nothrow;
    void zframe_fprint(_zframe_t*, const(char)*, _IO_FILE*) @nogc nothrow;
    _zframe_t* zframe_recv_nowait(void*) @nogc nothrow;
    void zframe_test(bool) @nogc nothrow;
    bool zframe_is(void*) @nogc nothrow;
    void zframe_print(_zframe_t*, const(char)*) @nogc nothrow;
    void zframe_reset(_zframe_t*, const(void)*, c_ulong) @nogc nothrow;
    bool zframe_eq(_zframe_t*, _zframe_t*) @nogc nothrow;
    void zframe_set_more(_zframe_t*, int) @nogc nothrow;
    int zframe_more(_zframe_t*) @nogc nothrow;
    bool zframe_streq(_zframe_t*, const(char)*) @nogc nothrow;
    char* zframe_strdup(_zframe_t*) @nogc nothrow;
    char* zframe_strhex(_zframe_t*) @nogc nothrow;
    _zframe_t* zframe_dup(_zframe_t*) @nogc nothrow;
    const(char)* zframe_meta(_zframe_t*, const(char)*) @nogc nothrow;
    ubyte* zframe_data(_zframe_t*) @nogc nothrow;
    c_ulong zframe_size(_zframe_t*) @nogc nothrow;
    int zframe_send(_zframe_t**, void*, int) @nogc nothrow;
    struct flock
    {
        short l_type;
        short l_whence;
        c_long l_start;
        c_long l_len;
        int l_pid;
    }
    void zframe_destroy(_zframe_t**) @nogc nothrow;
    _zframe_t* zframe_recv(void*) @nogc nothrow;
    _zframe_t* zframe_from(const(char)*) @nogc nothrow;
    _zframe_t* zframe_new_empty() @nogc nothrow;
    _zframe_t* zframe_new(const(void)*, c_ulong) @nogc nothrow;
    void zfile_mode_default() @nogc nothrow;
    void zfile_mode_private() @nogc nothrow;
    int zfile_rmdir(const(char)*) @nogc nothrow;
    int zfile_mkdir(const(char)*) @nogc nothrow;
    bool zfile_stable(const(char)*) @nogc nothrow;
    int zfile_delete(const(char)*) @nogc nothrow;
    alias _Float32 = float;
    uint zfile_mode(const(char)*) @nogc nothrow;
    c_long zfile_size(const(char)*) @nogc nothrow;
    alias _Float64 = double;
    bool zfile_exists(const(char)*) @nogc nothrow;
    alias _Float32x = double;
    void zfile_test(bool) @nogc nothrow;
    const(char)* zfile_digest(_zfile_t*) @nogc nothrow;
    alias _Float64x = real;
    _IO_FILE* zfile_handle(_zfile_t*) @nogc nothrow;
    void zfile_close(_zfile_t*) @nogc nothrow;
    const(char)* zfile_readln(_zfile_t*) @nogc nothrow;
    int zfile_write(_zfile_t*, _zchunk_t*, c_long) @nogc nothrow;
    bool zfile_eof(_zfile_t*) @nogc nothrow;
    _zchunk_t* zfile_read(_zfile_t*, c_ulong, c_long) @nogc nothrow;
    extern __gshared char* optarg;
    extern __gshared int optind;
    extern __gshared int opterr;
    extern __gshared int optopt;
    int getopt(int, char**, const(char)*) @nogc nothrow;
    int zfile_output(_zfile_t*) @nogc nothrow;
    int zfile_input(_zfile_t*) @nogc nothrow;
    void zfile_remove(_zfile_t*) @nogc nothrow;
    bool zfile_has_changed(_zfile_t*) @nogc nothrow;
    bool zfile_is_stable(_zfile_t*) @nogc nothrow;
    bool zfile_is_writeable(_zfile_t*) @nogc nothrow;
    bool zfile_is_readable(_zfile_t*) @nogc nothrow;
    bool zfile_is_regular(_zfile_t*) @nogc nothrow;
    bool zfile_is_directory(_zfile_t*) @nogc nothrow;
    c_long zfile_cursize(_zfile_t*) @nogc nothrow;
    c_long zfile_modified(_zfile_t*) @nogc nothrow;
    void zfile_restat(_zfile_t*) @nogc nothrow;
    const(char)* zfile_filename(_zfile_t*, const(char)*) @nogc nothrow;
    _zfile_t* zfile_dup(_zfile_t*) @nogc nothrow;
    void zfile_destroy(_zfile_t**) @nogc nothrow;
    _zfile_t* zfile_new(const(char)*, const(char)*) @nogc nothrow;
    void zdir_patch_test(bool) @nogc nothrow;
    const(char)* zdir_patch_digest(_zdir_patch_t*) @nogc nothrow;
    void zdir_patch_digest_set(_zdir_patch_t*) @nogc nothrow;
    const(char)* zdir_patch_vpath(_zdir_patch_t*) @nogc nothrow;
    int zdir_patch_op(_zdir_patch_t*) @nogc nothrow;
    _zfile_t* zdir_patch_file(_zdir_patch_t*) @nogc nothrow;
    const(char)* zdir_patch_path(_zdir_patch_t*) @nogc nothrow;
    _zdir_patch_t* zdir_patch_dup(_zdir_patch_t*) @nogc nothrow;
    void zdir_patch_destroy(_zdir_patch_t**) @nogc nothrow;
    _zdir_patch_t* zdir_patch_new(const(char)*, _zfile_t*, int, const(char)*) @nogc nothrow;
    void zdir_flatten_free(_zfile_t***) @nogc nothrow;
    _zfile_t** zdir_flatten(_zdir_t*) @nogc nothrow;
    void zdir_test(bool) @nogc nothrow;
    void zdir_watch(_zsock_t*, void*) @nogc nothrow;
    void zdir_print(_zdir_t*, int) @nogc nothrow;
    void zdir_fprint(_zdir_t*, _IO_FILE*, int) @nogc nothrow;
    _zhash_t* zdir_cache(_zdir_t*) @nogc nothrow;
    struct ip_opts
    {
        in_addr ip_dst;
        char[40] ip_opts_;
    }
    struct ip_mreqn
    {
        in_addr imr_multiaddr;
        in_addr imr_address;
        int imr_ifindex;
    }
    struct in_pktinfo
    {
        int ipi_ifindex;
        in_addr ipi_spec_dst;
        in_addr ipi_addr;
    }
    _zlist_t* zdir_resync(_zdir_t*, const(char)*) @nogc nothrow;
    _zlist_t* zdir_diff(_zdir_t*, _zdir_t*, const(char)*) @nogc nothrow;
    void zdir_remove(_zdir_t*, bool) @nogc nothrow;
    _zlist_t* zdir_list(_zdir_t*) @nogc nothrow;
    c_ulong zdir_count(_zdir_t*) @nogc nothrow;
    c_long zdir_cursize(_zdir_t*) @nogc nothrow;
    c_long zdir_modified(_zdir_t*) @nogc nothrow;
    const(char)* zdir_path(_zdir_t*) @nogc nothrow;
    void zdir_destroy(_zdir_t**) @nogc nothrow;
    _zdir_t* zdir_new(const(char)*, const(char)*) @nogc nothrow;
    void zdigest_test(bool) @nogc nothrow;
    char* zdigest_string(_zdigest_t*) @nogc nothrow;
    c_ulong zdigest_size(_zdigest_t*) @nogc nothrow;
    const(ubyte)* zdigest_data(_zdigest_t*) @nogc nothrow;
    void zdigest_update(_zdigest_t*, const(ubyte)*, c_ulong) @nogc nothrow;
    void zdigest_destroy(_zdigest_t**) @nogc nothrow;
    _zdigest_t* zdigest_new() @nogc nothrow;
    void zconfig_test(bool) @nogc nothrow;
    void zconfig_print(_zconfig_t*) @nogc nothrow;
    void zconfig_fprint(_zconfig_t*, _IO_FILE*) @nogc nothrow;
    bool zconfig_has_changed(_zconfig_t*) @nogc nothrow;
    char* zconfig_str_save(_zconfig_t*) @nogc nothrow;
    _zconfig_t* zconfig_str_load(const(char)*) @nogc nothrow;
    _zchunk_t* zconfig_chunk_save(_zconfig_t*) @nogc nothrow;
    _zconfig_t* zconfig_chunk_load(_zchunk_t*) @nogc nothrow;
    int zconfig_reload(_zconfig_t**) @nogc nothrow;
    const(char)* zconfig_filename(_zconfig_t*) @nogc nothrow;
    int zconfig_savef(_zconfig_t*, const(char)*, ...) @nogc nothrow;
    int zconfig_save(_zconfig_t*, const(char)*) @nogc nothrow;
    _zlist_t* zconfig_comments(_zconfig_t*) @nogc nothrow;
    struct winsize
    {
        ushort ws_row;
        ushort ws_col;
        ushort ws_xpixel;
        ushort ws_ypixel;
    }
    struct termio
    {
        ushort c_iflag;
        ushort c_oflag;
        ushort c_cflag;
        ushort c_lflag;
        ubyte c_line;
        ubyte[8] c_cc;
    }
    void zconfig_set_comment(_zconfig_t*, const(char)*, ...) @nogc nothrow;
    int zconfig_execute(_zconfig_t*, int function(_zconfig_t*, void*, int), void*) @nogc nothrow;
    _zconfig_t* zconfig_at_depth(_zconfig_t*, int) @nogc nothrow;
    _zconfig_t* zconfig_locate(_zconfig_t*, const(char)*) @nogc nothrow;
    _zconfig_t* zconfig_next(_zconfig_t*) @nogc nothrow;
    _zconfig_t* zconfig_child(_zconfig_t*) @nogc nothrow;
    void zconfig_set_value(_zconfig_t*, const(char)*, ...) @nogc nothrow;
    void zconfig_set_name(_zconfig_t*, const(char)*) @nogc nothrow;
    char* zconfig_get(_zconfig_t*, const(char)*, const(char)*) @nogc nothrow;
    void zconfig_putf(_zconfig_t*, const(char)*, const(char)*, ...) @nogc nothrow;
    void zconfig_put(_zconfig_t*, const(char)*, const(char)*) @nogc nothrow;
    char* zconfig_value(_zconfig_t*) @nogc nothrow;
    char* zconfig_name(_zconfig_t*) @nogc nothrow;
    void zconfig_destroy(_zconfig_t**) @nogc nothrow;
    _zconfig_t* zconfig_loadf(const(char)*, ...) @nogc nothrow;
    _zconfig_t* zconfig_load(const(char)*) @nogc nothrow;
    _zconfig_t* zconfig_new(const(char)*, _zconfig_t*) @nogc nothrow;
    alias zconfig_fct = int function(_zconfig_t*, void*, int);
    void zclock_log(const(char)*, ...) @nogc nothrow;
    void zclock_test(bool) @nogc nothrow;
    char* zclock_timestr() @nogc nothrow;
    c_long zclock_usecs() @nogc nothrow;
    c_long zclock_mono() @nogc nothrow;
    c_long zclock_time() @nogc nothrow;
    void zclock_sleep(int) @nogc nothrow;
    void zchunk_test(bool) @nogc nothrow;
    bool zchunk_is(void*) @nogc nothrow;
    void zchunk_print(_zchunk_t*) @nogc nothrow;
    void zchunk_fprint(_zchunk_t*, _IO_FILE*) @nogc nothrow;
    const(char)* zchunk_digest(_zchunk_t*) @nogc nothrow;
    _zchunk_t* zchunk_unpack(_zframe_t*) @nogc nothrow;
    _zframe_t* zchunk_pack(_zchunk_t*) @nogc nothrow;
    bool zchunk_streq(_zchunk_t*, const(char)*) @nogc nothrow;
    char* zchunk_strdup(_zchunk_t*) @nogc nothrow;
    char* zchunk_strhex(_zchunk_t*) @nogc nothrow;
    _zchunk_t* zchunk_dup(_zchunk_t*) @nogc nothrow;
    _zchunk_t* zchunk_slurp(const(char)*, c_ulong) @nogc nothrow;
    int zchunk_write(_zchunk_t*, _IO_FILE*) @nogc nothrow;
    _zchunk_t* zchunk_read(_IO_FILE*, c_ulong) @nogc nothrow;
    bool zchunk_exhausted(_zchunk_t*) @nogc nothrow;
    c_ulong zchunk_consume(_zchunk_t*, _zchunk_t*) @nogc nothrow;
    c_ulong zchunk_extend(_zchunk_t*, const(void)*, c_ulong) @nogc nothrow;
    c_ulong zchunk_append(_zchunk_t*, const(void)*, c_ulong) @nogc nothrow;
    c_ulong zchunk_fill(_zchunk_t*, ubyte, c_ulong) @nogc nothrow;
    c_ulong zchunk_set(_zchunk_t*, const(void)*, c_ulong) @nogc nothrow;
    ubyte* zchunk_data(_zchunk_t*) @nogc nothrow;
    c_ulong zchunk_max_size(_zchunk_t*) @nogc nothrow;
    c_ulong zchunk_size(_zchunk_t*) @nogc nothrow;
    void zchunk_resize(_zchunk_t*, c_ulong) @nogc nothrow;
    void zchunk_destroy(_zchunk_t**) @nogc nothrow;
    _zchunk_t* zchunk_new(const(void)*, c_ulong) @nogc nothrow;
    void zcertstore_test(bool) @nogc nothrow;
    void zcertstore_print(_zcertstore_t*) @nogc nothrow;
    void zcertstore_insert(_zcertstore_t*, _zcert_t**) @nogc nothrow;
    _zcert_t* zcertstore_lookup(_zcertstore_t*, const(char)*) @nogc nothrow;
    void zcertstore_destroy(_zcertstore_t**) @nogc nothrow;
    _zcertstore_t* zcertstore_new(const(char)*) @nogc nothrow;
    void zcert_test(bool) @nogc nothrow;
    void zcert_print(_zcert_t*) @nogc nothrow;
    bool zcert_eq(_zcert_t*, _zcert_t*) @nogc nothrow;
    _zcert_t* zcert_dup(_zcert_t*) @nogc nothrow;
    void zcert_apply(_zcert_t*, void*) @nogc nothrow;
    int zcert_save_secret(_zcert_t*, const(char)*) @nogc nothrow;
    int zcert_save_public(_zcert_t*, const(char)*) @nogc nothrow;
    int zcert_save(_zcert_t*, const(char)*) @nogc nothrow;
    _zlist_t* zcert_meta_keys(_zcert_t*) @nogc nothrow;
    const(char)* zcert_meta(_zcert_t*, const(char)*) @nogc nothrow;
    void zcert_set_meta(_zcert_t*, const(char)*, const(char)*, ...) @nogc nothrow;
    const(char)* zcert_secret_txt(_zcert_t*) @nogc nothrow;
    const(char)* zcert_public_txt(_zcert_t*) @nogc nothrow;
    const(ubyte)* zcert_secret_key(_zcert_t*) @nogc nothrow;
    const(ubyte)* zcert_public_key(_zcert_t*) @nogc nothrow;
    void zcert_destroy(_zcert_t**) @nogc nothrow;
    _zcert_t* zcert_load(const(char)*) @nogc nothrow;
    _zcert_t* zcert_new_from(const(ubyte)*, const(ubyte)*) @nogc nothrow;
    _zcert_t* zcert_new() @nogc nothrow;
    void zbeacon_test(bool) @nogc nothrow;
    void zbeacon(_zsock_t*, void*) @nogc nothrow;
    void zauth_test(bool) @nogc nothrow;
    void zauth(_zsock_t*, void*) @nogc nothrow;
    void zarmour_test(bool) @nogc nothrow;
    void zarmour_print(_zarmour_t*) @nogc nothrow;
    void zarmour_set_line_length(_zarmour_t*, c_ulong) @nogc nothrow;
    c_ulong zarmour_line_length(_zarmour_t*) @nogc nothrow;
    void zarmour_set_line_breaks(_zarmour_t*, bool) @nogc nothrow;
    bool zarmour_line_breaks(_zarmour_t*) @nogc nothrow;
    void zarmour_set_pad_char(_zarmour_t*, char) @nogc nothrow;
    char zarmour_pad_char(_zarmour_t*) @nogc nothrow;
    void zarmour_set_pad(_zarmour_t*, bool) @nogc nothrow;
    int __fpclassify(double) @nogc nothrow;
    int __fpclassifyl(real) @nogc nothrow;
    int __fpclassifyf(float) @nogc nothrow;
    int __signbitl(real) @nogc nothrow;
    int __signbit(double) @nogc nothrow;
    int __signbitf(float) @nogc nothrow;
    int __isinff(float) @nogc nothrow;
    int __isinf(double) @nogc nothrow;
    int __isinfl(real) @nogc nothrow;
    int __finitel(real) @nogc nothrow;
    int __finitef(float) @nogc nothrow;
    int __finite(double) @nogc nothrow;
    int __isnan(double) @nogc nothrow;
    int __isnanf(float) @nogc nothrow;
    int __isnanl(real) @nogc nothrow;
    int __iseqsigf(float, float) @nogc nothrow;
    int __iseqsig(double, double) @nogc nothrow;
    int __iseqsigl(real, real) @nogc nothrow;
    int __issignalingl(real) @nogc nothrow;
    int __issignalingf(float) @nogc nothrow;
    int __issignaling(double) @nogc nothrow;
    float __acosf(float) @nogc nothrow;
    float acosf(float) @nogc nothrow;
    double __acos(double) @nogc nothrow;
    real acosl(real) @nogc nothrow;
    real __acosl(real) @nogc nothrow;
    double acos(double) @nogc nothrow;
    real __asinl(real) @nogc nothrow;
    float __asinf(float) @nogc nothrow;
    float asinf(float) @nogc nothrow;
    double __asin(double) @nogc nothrow;
    real asinl(real) @nogc nothrow;
    double asin(double) @nogc nothrow;
    float __atanf(float) @nogc nothrow;
    float atanf(float) @nogc nothrow;
    real atanl(real) @nogc nothrow;
    real __atanl(real) @nogc nothrow;
    double __atan(double) @nogc nothrow;
    double atan(double) @nogc nothrow;
    float __atan2f(float, float) @nogc nothrow;
    float atan2f(float, float) @nogc nothrow;
    real atan2l(real, real) @nogc nothrow;
    real __atan2l(real, real) @nogc nothrow;
    double __atan2(double, double) @nogc nothrow;
    double atan2(double, double) @nogc nothrow;
    real __cosl(real) @nogc nothrow;
    real cosl(real) @nogc nothrow;
    double __cos(double) @nogc nothrow;
    float cosf(float) @nogc nothrow;
    float __cosf(float) @nogc nothrow;
    double cos(double) @nogc nothrow;
    float sinf(float) @nogc nothrow;
    float __sinf(float) @nogc nothrow;
    real sinl(real) @nogc nothrow;
    real __sinl(real) @nogc nothrow;
    double __sin(double) @nogc nothrow;
    double sin(double) @nogc nothrow;
    double __tan(double) @nogc nothrow;
    real __tanl(real) @nogc nothrow;
    real tanl(real) @nogc nothrow;
    float tanf(float) @nogc nothrow;
    float __tanf(float) @nogc nothrow;
    double tan(double) @nogc nothrow;
    real coshl(real) @nogc nothrow;
    double __cosh(double) @nogc nothrow;
    float coshf(float) @nogc nothrow;
    float __coshf(float) @nogc nothrow;
    real __coshl(real) @nogc nothrow;
    double cosh(double) @nogc nothrow;
    double __sinh(double) @nogc nothrow;
    float __sinhf(float) @nogc nothrow;
    float sinhf(float) @nogc nothrow;
    real __sinhl(real) @nogc nothrow;
    real sinhl(real) @nogc nothrow;
    double sinh(double) @nogc nothrow;
    double __tanh(double) @nogc nothrow;
    real tanhl(real) @nogc nothrow;
    real __tanhl(real) @nogc nothrow;
    float __tanhf(float) @nogc nothrow;
    float tanhf(float) @nogc nothrow;
    double tanh(double) @nogc nothrow;
    real acoshl(real) @nogc nothrow;
    double __acosh(double) @nogc nothrow;
    real __acoshl(real) @nogc nothrow;
    float acoshf(float) @nogc nothrow;
    float __acoshf(float) @nogc nothrow;
    double acosh(double) @nogc nothrow;
    float __asinhf(float) @nogc nothrow;
    float asinhf(float) @nogc nothrow;
    double __asinh(double) @nogc nothrow;
    real __asinhl(real) @nogc nothrow;
    real asinhl(real) @nogc nothrow;
    double asinh(double) @nogc nothrow;
    float __atanhf(float) @nogc nothrow;
    double __atanh(double) @nogc nothrow;
    real __atanhl(real) @nogc nothrow;
    real atanhl(real) @nogc nothrow;
    float atanhf(float) @nogc nothrow;
    double atanh(double) @nogc nothrow;
    float expf(float) @nogc nothrow;
    double __exp(double) @nogc nothrow;
    real __expl(real) @nogc nothrow;
    real expl(real) @nogc nothrow;
    float __expf(float) @nogc nothrow;
    double exp(double) @nogc nothrow;
    real frexpl(real, int*) @nogc nothrow;
    real __frexpl(real, int*) @nogc nothrow;
    double __frexp(double, int*) @nogc nothrow;
    float frexpf(float, int*) @nogc nothrow;
    float __frexpf(float, int*) @nogc nothrow;
    double frexp(double, int*) @nogc nothrow;
    double __ldexp(double, int) @nogc nothrow;
    float __ldexpf(float, int) @nogc nothrow;
    real __ldexpl(real, int) @nogc nothrow;
    real ldexpl(real, int) @nogc nothrow;
    float ldexpf(float, int) @nogc nothrow;
    double ldexp(double, int) @nogc nothrow;
    float logf(float) @nogc nothrow;
    float __logf(float) @nogc nothrow;
    double __log(double) @nogc nothrow;
    real __logl(real) @nogc nothrow;
    real logl(real) @nogc nothrow;
    double log(double) @nogc nothrow;
    float __log10f(float) @nogc nothrow;
    double __log10(double) @nogc nothrow;
    float log10f(float) @nogc nothrow;
    real __log10l(real) @nogc nothrow;
    real log10l(real) @nogc nothrow;
    double log10(double) @nogc nothrow;
    double __modf(double, double*) @nogc nothrow;
    real __modfl(real, real*) @nogc nothrow;
    real modfl(real, real*) @nogc nothrow;
    float modff(float, float*) @nogc nothrow;
    float __modff(float, float*) @nogc nothrow;
    double modf(double, double*) @nogc nothrow;
    double __expm1(double) @nogc nothrow;
    real __expm1l(real) @nogc nothrow;
    real expm1l(real) @nogc nothrow;
    float expm1f(float) @nogc nothrow;
    float __expm1f(float) @nogc nothrow;
    double expm1(double) @nogc nothrow;
    double __log1p(double) @nogc nothrow;
    real __log1pl(real) @nogc nothrow;
    real log1pl(real) @nogc nothrow;
    float log1pf(float) @nogc nothrow;
    float __log1pf(float) @nogc nothrow;
    double log1p(double) @nogc nothrow;
    float __logbf(float) @nogc nothrow;
    double __logb(double) @nogc nothrow;
    real __logbl(real) @nogc nothrow;
    real logbl(real) @nogc nothrow;
    float logbf(float) @nogc nothrow;
    double logb(double) @nogc nothrow;
    real __exp2l(real) @nogc nothrow;
    real exp2l(real) @nogc nothrow;
    double __exp2(double) @nogc nothrow;
    float exp2f(float) @nogc nothrow;
    float __exp2f(float) @nogc nothrow;
    double exp2(double) @nogc nothrow;
    real __log2l(real) @nogc nothrow;
    double __log2(double) @nogc nothrow;
    float log2f(float) @nogc nothrow;
    float __log2f(float) @nogc nothrow;
    real log2l(real) @nogc nothrow;
    double log2(double) @nogc nothrow;
    double __pow(double, double) @nogc nothrow;
    float powf(float, float) @nogc nothrow;
    float __powf(float, float) @nogc nothrow;
    real powl(real, real) @nogc nothrow;
    real __powl(real, real) @nogc nothrow;
    double pow(double, double) @nogc nothrow;
    float __sqrtf(float) @nogc nothrow;
    float sqrtf(float) @nogc nothrow;
    real __sqrtl(real) @nogc nothrow;
    double __sqrt(double) @nogc nothrow;
    real sqrtl(real) @nogc nothrow;
    double sqrt(double) @nogc nothrow;
    double __hypot(double, double) @nogc nothrow;
    real __hypotl(real, real) @nogc nothrow;
    real hypotl(real, real) @nogc nothrow;
    float hypotf(float, float) @nogc nothrow;
    float __hypotf(float, float) @nogc nothrow;
    double hypot(double, double) @nogc nothrow;
    float __cbrtf(float) @nogc nothrow;
    float cbrtf(float) @nogc nothrow;
    double __cbrt(double) @nogc nothrow;
    real cbrtl(real) @nogc nothrow;
    real __cbrtl(real) @nogc nothrow;
    double cbrt(double) @nogc nothrow;
    float __ceilf(float) @nogc nothrow;
    float ceilf(float) @nogc nothrow;
    double __ceil(double) @nogc nothrow;
    real __ceill(real) @nogc nothrow;
    real ceill(real) @nogc nothrow;
    double ceil(double) @nogc nothrow;
    double __fabs(double) @nogc nothrow;
    real __fabsl(real) @nogc nothrow;
    real fabsl(real) @nogc nothrow;
    float __fabsf(float) @nogc nothrow;
    float fabsf(float) @nogc nothrow;
    double fabs(double) @nogc nothrow;
    real floorl(real) @nogc nothrow;
    real __floorl(real) @nogc nothrow;
    double __floor(double) @nogc nothrow;
    float floorf(float) @nogc nothrow;
    float __floorf(float) @nogc nothrow;
    double floor(double) @nogc nothrow;
    double __fmod(double, double) @nogc nothrow;
    float fmodf(float, float) @nogc nothrow;
    real __fmodl(real, real) @nogc nothrow;
    real fmodl(real, real) @nogc nothrow;
    float __fmodf(float, float) @nogc nothrow;
    double fmod(double, double) @nogc nothrow;
    pragma(mangle, "isinf") int isinf_(double) @nogc nothrow;
    int isinfl(real) @nogc nothrow;
    int isinff(float) @nogc nothrow;
    int finitel(real) @nogc nothrow;
    int finitef(float) @nogc nothrow;
    int finite(double) @nogc nothrow;
    double drem(double, double) @nogc nothrow;
    real __dreml(real, real) @nogc nothrow;
    real dreml(real, real) @nogc nothrow;
    float dremf(float, float) @nogc nothrow;
    float __dremf(float, float) @nogc nothrow;
    double __drem(double, double) @nogc nothrow;
    real __significandl(real) @nogc nothrow;
    real significandl(real) @nogc nothrow;
    float __significandf(float) @nogc nothrow;
    double significand(double) @nogc nothrow;
    double __significand(double) @nogc nothrow;
    float significandf(float) @nogc nothrow;
    float __copysignf(float, float) @nogc nothrow;
    float copysignf(float, float) @nogc nothrow;
    double __copysign(double, double) @nogc nothrow;
    real copysignl(real, real) @nogc nothrow;
    real __copysignl(real, real) @nogc nothrow;
    double copysign(double, double) @nogc nothrow;
    real __nanl(const(char)*) @nogc nothrow;
    double __nan(const(char)*) @nogc nothrow;
    float nanf(const(char)*) @nogc nothrow;
    float __nanf(const(char)*) @nogc nothrow;
    real nanl(const(char)*) @nogc nothrow;
    double nan(const(char)*) @nogc nothrow;
    int isnanf(float) @nogc nothrow;
    pragma(mangle, "isnan") int isnan_(double) @nogc nothrow;
    int isnanl(real) @nogc nothrow;
    float j0f(float) @nogc nothrow;
    real __j0l(real) @nogc nothrow;
    real j0l(real) @nogc nothrow;
    float __j0f(float) @nogc nothrow;
    double j0(double) @nogc nothrow;
    double __j0(double) @nogc nothrow;
    float __j1f(float) @nogc nothrow;
    float j1f(float) @nogc nothrow;
    real __j1l(real) @nogc nothrow;
    real j1l(real) @nogc nothrow;
    double __j1(double) @nogc nothrow;
    double j1(double) @nogc nothrow;
    double jn(int, double) @nogc nothrow;
    real __jnl(int, real) @nogc nothrow;
    real jnl(int, real) @nogc nothrow;
    double __jn(int, double) @nogc nothrow;
    float jnf(int, float) @nogc nothrow;
    float __jnf(int, float) @nogc nothrow;
    double __y0(double) @nogc nothrow;
    float __y0f(float) @nogc nothrow;
    real __y0l(real) @nogc nothrow;
    real y0l(real) @nogc nothrow;
    float y0f(float) @nogc nothrow;
    double y0(double) @nogc nothrow;
    real __y1l(real) @nogc nothrow;
    real y1l(real) @nogc nothrow;
    double y1(double) @nogc nothrow;
    float y1f(float) @nogc nothrow;
    float __y1f(float) @nogc nothrow;
    double __y1(double) @nogc nothrow;
    float ynf(int, float) @nogc nothrow;
    float __ynf(int, float) @nogc nothrow;
    double yn(int, double) @nogc nothrow;
    double __yn(int, double) @nogc nothrow;
    real ynl(int, real) @nogc nothrow;
    real __ynl(int, real) @nogc nothrow;
    double __erf(double) @nogc nothrow;
    float __erff(float) @nogc nothrow;
    float erff(float) @nogc nothrow;
    real erfl(real) @nogc nothrow;
    real __erfl(real) @nogc nothrow;
    double erf(double) @nogc nothrow;
    float erfcf(float) @nogc nothrow;
    float __erfcf(float) @nogc nothrow;
    double __erfc(double) @nogc nothrow;
    real erfcl(real) @nogc nothrow;
    real __erfcl(real) @nogc nothrow;
    double erfc(double) @nogc nothrow;
    float lgammaf(float) @nogc nothrow;
    float __lgammaf(float) @nogc nothrow;
    double __lgamma(double) @nogc nothrow;
    real lgammal(real) @nogc nothrow;
    real __lgammal(real) @nogc nothrow;
    double lgamma(double) @nogc nothrow;
    real tgammal(real) @nogc nothrow;
    double __tgamma(double) @nogc nothrow;
    float tgammaf(float) @nogc nothrow;
    float __tgammaf(float) @nogc nothrow;
    real __tgammal(real) @nogc nothrow;
    double tgamma(double) @nogc nothrow;
    float __gammaf(float) @nogc nothrow;
    float gammaf(float) @nogc nothrow;
    double gamma(double) @nogc nothrow;
    real gammal(real) @nogc nothrow;
    real __gammal(real) @nogc nothrow;
    double __gamma(double) @nogc nothrow;
    float __lgammaf_r(float, int*) @nogc nothrow;
    float lgammaf_r(float, int*) @nogc nothrow;
    real lgammal_r(real, int*) @nogc nothrow;
    real __lgammal_r(real, int*) @nogc nothrow;
    double __lgamma_r(double, int*) @nogc nothrow;
    double lgamma_r(double, int*) @nogc nothrow;
    float __rintf(float) @nogc nothrow;
    double __rint(double) @nogc nothrow;
    float rintf(float) @nogc nothrow;
    real __rintl(real) @nogc nothrow;
    real rintl(real) @nogc nothrow;
    double rint(double) @nogc nothrow;
    float __nextafterf(float, float) @nogc nothrow;
    float nextafterf(float, float) @nogc nothrow;
    double __nextafter(double, double) @nogc nothrow;
    real __nextafterl(real, real) @nogc nothrow;
    real nextafterl(real, real) @nogc nothrow;
    double nextafter(double, double) @nogc nothrow;
    real __nexttowardl(real, real) @nogc nothrow;
    float __nexttowardf(float, real) @nogc nothrow;
    real nexttowardl(real, real) @nogc nothrow;
    double __nexttoward(double, real) @nogc nothrow;
    float nexttowardf(float, real) @nogc nothrow;
    double nexttoward(double, real) @nogc nothrow;
    double __remainder(double, double) @nogc nothrow;
    float remainderf(float, float) @nogc nothrow;
    float __remainderf(float, float) @nogc nothrow;
    real __remainderl(real, real) @nogc nothrow;
    real remainderl(real, real) @nogc nothrow;
    double remainder(double, double) @nogc nothrow;
    double __scalbn(double, int) @nogc nothrow;
    float scalbnf(float, int) @nogc nothrow;
    float __scalbnf(float, int) @nogc nothrow;
    real __scalbnl(real, int) @nogc nothrow;
    real scalbnl(real, int) @nogc nothrow;
    double scalbn(double, int) @nogc nothrow;
    int __ilogbl(real) @nogc nothrow;
    int __ilogbf(float) @nogc nothrow;
    int ilogbl(real) @nogc nothrow;
    int __ilogb(double) @nogc nothrow;
    int ilogbf(float) @nogc nothrow;
    int ilogb(double) @nogc nothrow;
    double __scalbln(double, c_long) @nogc nothrow;
    real __scalblnl(real, c_long) @nogc nothrow;
    float __scalblnf(float, c_long) @nogc nothrow;
    float scalblnf(float, c_long) @nogc nothrow;
    real scalblnl(real, c_long) @nogc nothrow;
    double scalbln(double, c_long) @nogc nothrow;
    real __nearbyintl(real) @nogc nothrow;
    real nearbyintl(real) @nogc nothrow;
    float __nearbyintf(float) @nogc nothrow;
    float nearbyintf(float) @nogc nothrow;
    double __nearbyint(double) @nogc nothrow;
    double nearbyint(double) @nogc nothrow;
    float __roundf(float) @nogc nothrow;
    float roundf(float) @nogc nothrow;
    double __round(double) @nogc nothrow;
    real __roundl(real) @nogc nothrow;
    real roundl(real) @nogc nothrow;
    double round(double) @nogc nothrow;
    float truncf(float) @nogc nothrow;
    real truncl(real) @nogc nothrow;
    float __truncf(float) @nogc nothrow;
    real __truncl(real) @nogc nothrow;
    double __trunc(double) @nogc nothrow;
    double trunc(double) @nogc nothrow;
    real remquol(real, real, int*) @nogc nothrow;
    real __remquol(real, real, int*) @nogc nothrow;
    double __remquo(double, double, int*) @nogc nothrow;
    float __remquof(float, float, int*) @nogc nothrow;
    float remquof(float, float, int*) @nogc nothrow;
    double remquo(double, double, int*) @nogc nothrow;
    c_long __lrintf(float) @nogc nothrow;
    c_long lrintl(real) @nogc nothrow;
    c_long lrintf(float) @nogc nothrow;
    c_long __lrintl(real) @nogc nothrow;
    c_long __lrint(double) @nogc nothrow;
    c_long lrint(double) @nogc nothrow;
    long llrintl(real) @nogc nothrow;
    long __llrintl(real) @nogc nothrow;
    long __llrint(double) @nogc nothrow;
    long __llrintf(float) @nogc nothrow;
    long llrintf(float) @nogc nothrow;
    long llrint(double) @nogc nothrow;
    c_long __lroundl(real) @nogc nothrow;
    c_long lroundl(real) @nogc nothrow;
    c_long __lround(double) @nogc nothrow;
    c_long lroundf(float) @nogc nothrow;
    c_long __lroundf(float) @nogc nothrow;
    c_long lround(double) @nogc nothrow;
    long __llround(double) @nogc nothrow;
    long llroundf(float) @nogc nothrow;
    long __llroundf(float) @nogc nothrow;
    long llroundl(real) @nogc nothrow;
    long __llroundl(real) @nogc nothrow;
    long llround(double) @nogc nothrow;
    real fdiml(real, real) @nogc nothrow;
    real __fdiml(real, real) @nogc nothrow;
    float __fdimf(float, float) @nogc nothrow;
    float fdimf(float, float) @nogc nothrow;
    double __fdim(double, double) @nogc nothrow;
    double fdim(double, double) @nogc nothrow;
    float __fmaxf(float, float) @nogc nothrow;
    float fmaxf(float, float) @nogc nothrow;
    double __fmax(double, double) @nogc nothrow;
    real fmaxl(real, real) @nogc nothrow;
    real __fmaxl(real, real) @nogc nothrow;
    double fmax(double, double) @nogc nothrow;
    real fminl(real, real) @nogc nothrow;
    real __fminl(real, real) @nogc nothrow;
    float __fminf(float, float) @nogc nothrow;
    double __fmin(double, double) @nogc nothrow;
    float fminf(float, float) @nogc nothrow;
    double fmin(double, double) @nogc nothrow;
    double __fma(double, double, double) @nogc nothrow;
    float fmaf(float, float, float) @nogc nothrow;
    float __fmaf(float, float, float) @nogc nothrow;
    real fmal(real, real, real) @nogc nothrow;
    real __fmal(real, real, real) @nogc nothrow;
    double fma(double, double, double) @nogc nothrow;
    real __scalbl(real, real) @nogc nothrow;
    real scalbl(real, real) @nogc nothrow;
    float __scalbf(float, float) @nogc nothrow;
    float scalbf(float, float) @nogc nothrow;
    double __scalb(double, double) @nogc nothrow;
    double scalb(double, double) @nogc nothrow;
    struct netent
    {
        char* n_name;
        char** n_aliases;
        int n_addrtype;
        uint n_net;
    }
    bool zarmour_pad(_zarmour_t*) @nogc nothrow;
    void zarmour_set_mode(_zarmour_t*, int) @nogc nothrow;
    const(char)* zarmour_mode_str(_zarmour_t*) @nogc nothrow;
    int zarmour_mode(_zarmour_t*) @nogc nothrow;
    _zchunk_t* zarmour_decode(_zarmour_t*, const(char)*) @nogc nothrow;
    char* zarmour_encode(_zarmour_t*, const(ubyte)*, c_ulong) @nogc nothrow;
    void zarmour_destroy(_zarmour_t**) @nogc nothrow;
    _zarmour_t* zarmour_new() @nogc nothrow;
    void zactor_test(bool) @nogc nothrow;
    _zsock_t* zactor_sock(_zactor_t*) @nogc nothrow;
    void* zactor_resolve(void*) @nogc nothrow;
    bool zactor_is(void*) @nogc nothrow;
    _zmsg_t* zactor_recv(_zactor_t*) @nogc nothrow;
    int zactor_send(_zactor_t*, _zmsg_t**) @nogc nothrow;
    void zactor_destroy(_zactor_t**) @nogc nothrow;
    _zactor_t* zactor_new(void function(_zsock_t*, void*), void*) @nogc nothrow;
    alias zactor_fn = void function(_zsock_t*, void*);
    alias SOCKET = int;
    static void* safe_malloc(c_ulong, const(char)*, uint) @nogc nothrow;
    struct inaddr_storage_t
    {
        static union _Anonymous_3
        {
            sockaddr_in __addr;
            sockaddr_in6 __addr6;
        }
        _Anonymous_3 __inaddr_u;
        int inaddrlen;
    }
    alias in6addr_t = sockaddr_in6;
    alias inaddr_t = sockaddr_in;
    alias qbyte = uint;
    alias dbyte = ushort;
    alias byte_ = ubyte;
    alias pthread_t = c_ulong;
    union pthread_mutexattr_t
    {
        char[4] __size;
        int __align;
    }
    union pthread_condattr_t
    {
        char[4] __size;
        int __align;
    }
    alias pthread_key_t = uint;
    alias pthread_once_t = int;
    union pthread_attr_t
    {
        char[56] __size;
        c_long __align;
    }
    union pthread_mutex_t
    {
        __pthread_mutex_s __data;
        char[40] __size;
        c_long __align;
    }
    union pthread_cond_t
    {
        __pthread_cond_s __data;
        char[48] __size;
        long __align;
    }
    union pthread_rwlock_t
    {
        __pthread_rwlock_arch_t __data;
        char[56] __size;
        c_long __align;
    }
    union pthread_rwlockattr_t
    {
        char[8] __size;
        c_long __align;
    }
    alias pthread_spinlock_t = int;
    union pthread_barrier_t
    {
        char[32] __size;
        c_long __align;
    }
    union pthread_barrierattr_t
    {
        char[4] __size;
        int __align;
    }
    alias __jmp_buf = c_long[8];
    struct sigaction
    {
        static union _Anonymous_4
        {
            void function(int) sa_handler;
            void function(int, siginfo_t*, void*) sa_sigaction;
        }
        _Anonymous_4 __sigaction_handler;
        __sigset_t sa_mask;
        int sa_flags;
        void function() sa_restorer;
    }
    struct _zrex_t;
    alias zrex_t = _zrex_t;
    struct _zproxy_t;
    alias zproxy_t = _zproxy_t;
    struct _zmonitor_t;
    alias zmonitor_t = _zmonitor_t;
    struct _zgossip_t;
    alias zgossip_t = _zgossip_t;
    struct _zbeacon_t;
    alias zbeacon_t = _zbeacon_t;
    struct _zauth_t;
    struct _fpx_sw_bytes
    {
        uint magic1;
        uint extended_size;
        c_ulong xstate_bv;
        uint xstate_size;
        uint[7] __glibc_reserved1;
    }
    struct _fpreg
    {
        ushort[4] significand;
        ushort exponent;
    }
    struct _fpxreg
    {
        ushort[4] significand;
        ushort exponent;
        ushort[3] __glibc_reserved1;
    }
    struct _xmmreg
    {
        uint[4] element;
    }
    struct _fpstate
    {
        ushort cwd;
        ushort swd;
        ushort ftw;
        ushort fop;
        c_ulong rip;
        c_ulong rdp;
        uint mxcsr;
        uint mxcr_mask;
        _fpxreg[8] _st;
        _xmmreg[16] _xmm;
        uint[24] __glibc_reserved1;
    }
    struct sigcontext
    {
        c_ulong r8;
        c_ulong r9;
        c_ulong r10;
        c_ulong r11;
        c_ulong r12;
        c_ulong r13;
        c_ulong r14;
        c_ulong r15;
        c_ulong rdi;
        c_ulong rsi;
        c_ulong rbp;
        c_ulong rbx;
        c_ulong rdx;
        c_ulong rax;
        c_ulong rcx;
        c_ulong rsp;
        c_ulong rip;
        c_ulong eflags;
        ushort cs;
        ushort gs;
        ushort fs;
        ushort __pad0;
        c_ulong err;
        c_ulong trapno;
        c_ulong oldmask;
        c_ulong cr2;
        static union _Anonymous_5
        {
            _fpstate* fpstate;
            c_ulong __fpstate_word;
        }
        _Anonymous_5 _anonymous_6;
        auto fpstate() @property @nogc pure nothrow { return _anonymous_6.fpstate; }
        void fpstate(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_6.fpstate = val; }
        auto __fpstate_word() @property @nogc pure nothrow { return _anonymous_6.__fpstate_word; }
        void __fpstate_word(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_6.__fpstate_word = val; }
        c_ulong[8] __reserved1;
    }
    struct _xsave_hdr
    {
        c_ulong xstate_bv;
        c_ulong[2] __glibc_reserved1;
        c_ulong[5] __glibc_reserved2;
    }
    struct _ymmh_state
    {
        uint[64] ymmh_space;
    }
    struct _xstate
    {
        _fpstate fpstate;
        _xsave_hdr xstate_hdr;
        _ymmh_state ymmh;
    }
    alias zauth_t = _zauth_t;
    enum _Anonymous_7
    {
        SIGEV_SIGNAL = 0,
        SIGEV_NONE = 1,
        SIGEV_THREAD = 2,
        SIGEV_THREAD_ID = 4,
    }
    enum SIGEV_SIGNAL = _Anonymous_7.SIGEV_SIGNAL;
    enum SIGEV_NONE = _Anonymous_7.SIGEV_NONE;
    enum SIGEV_THREAD = _Anonymous_7.SIGEV_THREAD;
    enum SIGEV_THREAD_ID = _Anonymous_7.SIGEV_THREAD_ID;
    struct _zuuid_t;
    alias zuuid_t = _zuuid_t;
    struct _zsys_t;
    alias zsys_t = _zsys_t;
    struct _zstr_t;
    alias zstr_t = _zstr_t;
    struct _zsock_t;
    enum _Anonymous_8
    {
        SI_ASYNCNL = -60,
        SI_DETHREAD = -7,
        SI_TKILL = -6,
        SI_SIGIO = -5,
        SI_ASYNCIO = -4,
        SI_MESGQ = -3,
        SI_TIMER = -2,
        SI_QUEUE = -1,
        SI_USER = 0,
        SI_KERNEL = 128,
    }
    enum SI_ASYNCNL = _Anonymous_8.SI_ASYNCNL;
    enum SI_DETHREAD = _Anonymous_8.SI_DETHREAD;
    enum SI_TKILL = _Anonymous_8.SI_TKILL;
    enum SI_SIGIO = _Anonymous_8.SI_SIGIO;
    enum SI_ASYNCIO = _Anonymous_8.SI_ASYNCIO;
    enum SI_MESGQ = _Anonymous_8.SI_MESGQ;
    enum SI_TIMER = _Anonymous_8.SI_TIMER;
    enum SI_QUEUE = _Anonymous_8.SI_QUEUE;
    enum SI_USER = _Anonymous_8.SI_USER;
    enum SI_KERNEL = _Anonymous_8.SI_KERNEL;
    alias zsock_t = _zsock_t;
    struct _zpoller_t;
    alias zpoller_t = _zpoller_t;
    struct _zmsg_t;
    alias zmsg_t = _zmsg_t;
    struct _zloop_t;
    alias zloop_t = _zloop_t;
    struct _zlistx_t;
    alias zlistx_t = _zlistx_t;
    struct _zlist_t;
    alias zlist_t = _zlist_t;
    enum _Anonymous_9
    {
        ILL_ILLOPC = 1,
        ILL_ILLOPN = 2,
        ILL_ILLADR = 3,
        ILL_ILLTRP = 4,
        ILL_PRVOPC = 5,
        ILL_PRVREG = 6,
        ILL_COPROC = 7,
        ILL_BADSTK = 8,
        ILL_BADIADDR = 9,
    }
    enum ILL_ILLOPC = _Anonymous_9.ILL_ILLOPC;
    enum ILL_ILLOPN = _Anonymous_9.ILL_ILLOPN;
    enum ILL_ILLADR = _Anonymous_9.ILL_ILLADR;
    enum ILL_ILLTRP = _Anonymous_9.ILL_ILLTRP;
    enum ILL_PRVOPC = _Anonymous_9.ILL_PRVOPC;
    enum ILL_PRVREG = _Anonymous_9.ILL_PRVREG;
    enum ILL_COPROC = _Anonymous_9.ILL_COPROC;
    enum ILL_BADSTK = _Anonymous_9.ILL_BADSTK;
    enum ILL_BADIADDR = _Anonymous_9.ILL_BADIADDR;
    struct _ziflist_t;
    alias ziflist_t = _ziflist_t;
    struct _zhashx_t;
    alias zhashx_t = _zhashx_t;
    struct _zhash_t;
    alias zhash_t = _zhash_t;
    struct _zframe_t;
    alias zframe_t = _zframe_t;
    struct _zfile_t;
    enum _Anonymous_10
    {
        FPE_INTDIV = 1,
        FPE_INTOVF = 2,
        FPE_FLTDIV = 3,
        FPE_FLTOVF = 4,
        FPE_FLTUND = 5,
        FPE_FLTRES = 6,
        FPE_FLTINV = 7,
        FPE_FLTSUB = 8,
        FPE_FLTUNK = 14,
        FPE_CONDTRAP = 15,
    }
    enum FPE_INTDIV = _Anonymous_10.FPE_INTDIV;
    enum FPE_INTOVF = _Anonymous_10.FPE_INTOVF;
    enum FPE_FLTDIV = _Anonymous_10.FPE_FLTDIV;
    enum FPE_FLTOVF = _Anonymous_10.FPE_FLTOVF;
    enum FPE_FLTUND = _Anonymous_10.FPE_FLTUND;
    enum FPE_FLTRES = _Anonymous_10.FPE_FLTRES;
    enum FPE_FLTINV = _Anonymous_10.FPE_FLTINV;
    enum FPE_FLTSUB = _Anonymous_10.FPE_FLTSUB;
    enum FPE_FLTUNK = _Anonymous_10.FPE_FLTUNK;
    enum FPE_CONDTRAP = _Anonymous_10.FPE_CONDTRAP;
    alias zfile_t = _zfile_t;
    struct _zdir_patch_t;
    alias zdir_patch_t = _zdir_patch_t;
    struct _zdir_t;
    alias zdir_t = _zdir_t;
    struct _zdigest_t;
    alias zdigest_t = _zdigest_t;
    struct _zconfig_t;
    alias zconfig_t = _zconfig_t;
    struct _zclock_t;
    enum _Anonymous_11
    {
        SEGV_MAPERR = 1,
        SEGV_ACCERR = 2,
        SEGV_BNDERR = 3,
        SEGV_PKUERR = 4,
        SEGV_ACCADI = 5,
        SEGV_ADIDERR = 6,
        SEGV_ADIPERR = 7,
    }
    enum SEGV_MAPERR = _Anonymous_11.SEGV_MAPERR;
    enum SEGV_ACCERR = _Anonymous_11.SEGV_ACCERR;
    enum SEGV_BNDERR = _Anonymous_11.SEGV_BNDERR;
    enum SEGV_PKUERR = _Anonymous_11.SEGV_PKUERR;
    enum SEGV_ACCADI = _Anonymous_11.SEGV_ACCADI;
    enum SEGV_ADIDERR = _Anonymous_11.SEGV_ADIDERR;
    enum SEGV_ADIPERR = _Anonymous_11.SEGV_ADIPERR;
    alias zclock_t = _zclock_t;
    struct _zchunk_t;
    alias zchunk_t = _zchunk_t;
    struct _zcertstore_t;
    alias zcertstore_t = _zcertstore_t;
    struct _zcert_t;
    alias zcert_t = _zcert_t;
    enum _Anonymous_12
    {
        BUS_ADRALN = 1,
        BUS_ADRERR = 2,
        BUS_OBJERR = 3,
        BUS_MCEERR_AR = 4,
        BUS_MCEERR_AO = 5,
    }
    enum BUS_ADRALN = _Anonymous_12.BUS_ADRALN;
    enum BUS_ADRERR = _Anonymous_12.BUS_ADRERR;
    enum BUS_OBJERR = _Anonymous_12.BUS_OBJERR;
    enum BUS_MCEERR_AR = _Anonymous_12.BUS_MCEERR_AR;
    enum BUS_MCEERR_AO = _Anonymous_12.BUS_MCEERR_AO;
    struct _zarmour_t;
    alias zarmour_t = _zarmour_t;
    struct _zactor_t;
    alias zactor_t = _zactor_t;
    enum _Anonymous_13
    {
        CLD_EXITED = 1,
        CLD_KILLED = 2,
        CLD_DUMPED = 3,
        CLD_TRAPPED = 4,
        CLD_STOPPED = 5,
        CLD_CONTINUED = 6,
    }
    enum CLD_EXITED = _Anonymous_13.CLD_EXITED;
    enum CLD_KILLED = _Anonymous_13.CLD_KILLED;
    enum CLD_DUMPED = _Anonymous_13.CLD_DUMPED;
    enum CLD_TRAPPED = _Anonymous_13.CLD_TRAPPED;
    enum CLD_STOPPED = _Anonymous_13.CLD_STOPPED;
    enum CLD_CONTINUED = _Anonymous_13.CLD_CONTINUED;
    alias czmq_comparator = int function(const(void)*, const(void)*);
    alias czmq_duplicator = void* function(const(void)*);
    enum _Anonymous_14
    {
        POLL_IN = 1,
        POLL_OUT = 2,
        POLL_MSG = 3,
        POLL_ERR = 4,
        POLL_PRI = 5,
        POLL_HUP = 6,
    }
    enum POLL_IN = _Anonymous_14.POLL_IN;
    enum POLL_OUT = _Anonymous_14.POLL_OUT;
    enum POLL_MSG = _Anonymous_14.POLL_MSG;
    enum POLL_ERR = _Anonymous_14.POLL_ERR;
    enum POLL_PRI = _Anonymous_14.POLL_PRI;
    enum POLL_HUP = _Anonymous_14.POLL_HUP;
    alias czmq_destructor = void function(void**);
    alias wchar_t = int;
    alias size_t = c_ulong;
    int pthread_sigmask(int, const(__sigset_t)*, __sigset_t*) @nogc nothrow;
    int pthread_kill(c_ulong, int) @nogc nothrow;
    alias sa_family_t = ushort;
    alias socklen_t = uint;
    alias ptrdiff_t = c_long;
    struct max_align_t
    {
        long __clang_max_align_nonce1;
        real __clang_max_align_nonce2;
    }
    struct _zyre_event_t;
    alias zyre_event_t = _zyre_event_t;
    struct _zyre_t;
    alias zyre_t = _zyre_t;
    struct sockaddr
    {
        ushort sa_family;
        char[14] sa_data;
    }
    struct sockaddr_storage
    {
        ushort ss_family;
        char[118] __ss_padding;
        c_ulong __ss_align;
    }
    enum _Anonymous_15
    {
        MSG_OOB = 1,
        MSG_PEEK = 2,
        MSG_DONTROUTE = 4,
        MSG_CTRUNC = 8,
        MSG_PROXY = 16,
        MSG_TRUNC = 32,
        MSG_DONTWAIT = 64,
        MSG_EOR = 128,
        MSG_WAITALL = 256,
        MSG_FIN = 512,
        MSG_SYN = 1024,
        MSG_CONFIRM = 2048,
        MSG_RST = 4096,
        MSG_ERRQUEUE = 8192,
        MSG_NOSIGNAL = 16384,
        MSG_MORE = 32768,
        MSG_WAITFORONE = 65536,
        MSG_BATCH = 262144,
        MSG_ZEROCOPY = 67108864,
        MSG_FASTOPEN = 536870912,
        MSG_CMSG_CLOEXEC = 1073741824,
    }
    enum MSG_OOB = _Anonymous_15.MSG_OOB;
    enum MSG_PEEK = _Anonymous_15.MSG_PEEK;
    enum MSG_DONTROUTE = _Anonymous_15.MSG_DONTROUTE;
    enum MSG_CTRUNC = _Anonymous_15.MSG_CTRUNC;
    enum MSG_PROXY = _Anonymous_15.MSG_PROXY;
    enum MSG_TRUNC = _Anonymous_15.MSG_TRUNC;
    enum MSG_DONTWAIT = _Anonymous_15.MSG_DONTWAIT;
    enum MSG_EOR = _Anonymous_15.MSG_EOR;
    enum MSG_WAITALL = _Anonymous_15.MSG_WAITALL;
    enum MSG_FIN = _Anonymous_15.MSG_FIN;
    enum MSG_SYN = _Anonymous_15.MSG_SYN;
    enum MSG_CONFIRM = _Anonymous_15.MSG_CONFIRM;
    enum MSG_RST = _Anonymous_15.MSG_RST;
    enum MSG_ERRQUEUE = _Anonymous_15.MSG_ERRQUEUE;
    enum MSG_NOSIGNAL = _Anonymous_15.MSG_NOSIGNAL;
    enum MSG_MORE = _Anonymous_15.MSG_MORE;
    enum MSG_WAITFORONE = _Anonymous_15.MSG_WAITFORONE;
    enum MSG_BATCH = _Anonymous_15.MSG_BATCH;
    enum MSG_ZEROCOPY = _Anonymous_15.MSG_ZEROCOPY;
    enum MSG_FASTOPEN = _Anonymous_15.MSG_FASTOPEN;
    enum MSG_CMSG_CLOEXEC = _Anonymous_15.MSG_CMSG_CLOEXEC;
    void zyre_event_test(bool) @nogc nothrow;
    void zyre_event_print(_zyre_event_t*) @nogc nothrow;
    _zmsg_t* zyre_event_get_msg(_zyre_event_t*) @nogc nothrow;
    _zmsg_t* zyre_event_msg(_zyre_event_t*) @nogc nothrow;
    const(char)* zyre_event_group(_zyre_event_t*) @nogc nothrow;
    const(char)* zyre_event_header(_zyre_event_t*, const(char)*) @nogc nothrow;
    _zhash_t* zyre_event_headers(_zyre_event_t*) @nogc nothrow;
    const(char)* zyre_event_peer_addr(_zyre_event_t*) @nogc nothrow;
    const(char)* zyre_event_peer_name(_zyre_event_t*) @nogc nothrow;
    const(char)* zyre_event_peer_uuid(_zyre_event_t*) @nogc nothrow;
    struct msghdr
    {
        void* msg_name;
        uint msg_namelen;
        iovec* msg_iov;
        c_ulong msg_iovlen;
        void* msg_control;
        c_ulong msg_controllen;
        int msg_flags;
    }
    struct cmsghdr
    {
        c_ulong cmsg_len;
        int cmsg_level;
        int cmsg_type;
        ubyte[0] __cmsg_data;
    }
    const(char)* zyre_event_type(_zyre_event_t*) @nogc nothrow;
    void zyre_event_destroy(_zyre_event_t**) @nogc nothrow;
    _zyre_event_t* zyre_event_new(_zyre_t*) @nogc nothrow;
    cmsghdr* __cmsg_nxthdr(msghdr*, cmsghdr*) @nogc nothrow;
    enum _Anonymous_16
    {
        SCM_RIGHTS = 1,
    }
    enum SCM_RIGHTS = _Anonymous_16.SCM_RIGHTS;
    struct linger
    {
        int l_onoff;
        int l_linger;
    }
    enum __socket_type
    {
        SOCK_STREAM = 1,
        SOCK_DGRAM = 2,
        SOCK_RAW = 3,
        SOCK_RDM = 4,
        SOCK_SEQPACKET = 5,
        SOCK_DCCP = 6,
        SOCK_PACKET = 10,
        SOCK_CLOEXEC = 524288,
        SOCK_NONBLOCK = 2048,
    }
    enum SOCK_STREAM = __socket_type.SOCK_STREAM;
    enum SOCK_DGRAM = __socket_type.SOCK_DGRAM;
    enum SOCK_RAW = __socket_type.SOCK_RAW;
    enum SOCK_RDM = __socket_type.SOCK_RDM;
    enum SOCK_SEQPACKET = __socket_type.SOCK_SEQPACKET;
    enum SOCK_DCCP = __socket_type.SOCK_DCCP;
    enum SOCK_PACKET = __socket_type.SOCK_PACKET;
    enum SOCK_CLOEXEC = __socket_type.SOCK_CLOEXEC;
    enum SOCK_NONBLOCK = __socket_type.SOCK_NONBLOCK;
    void zyre_test(bool) @nogc nothrow;
    c_ulong zyre_version() @nogc nothrow;
    void zyre_print(_zyre_t*) @nogc nothrow;
    _zsock_t* zyre_socket(_zyre_t*) @nogc nothrow;
    char* zyre_peer_header_value(_zyre_t*, const(char)*, const(char)*) @nogc nothrow;
    enum _Anonymous_17
    {
        SS_ONSTACK = 1,
        SS_DISABLE = 2,
    }
    enum SS_ONSTACK = _Anonymous_17.SS_ONSTACK;
    enum SS_DISABLE = _Anonymous_17.SS_DISABLE;
    char* zyre_peer_address(_zyre_t*, const(char)*) @nogc nothrow;
    _zlist_t* zyre_peer_groups(_zyre_t*) @nogc nothrow;
    _zlist_t* zyre_own_groups(_zyre_t*) @nogc nothrow;
    struct stat
    {
        c_ulong st_dev;
        c_ulong st_ino;
        c_ulong st_nlink;
        uint st_mode;
        uint st_uid;
        uint st_gid;
        int __pad0;
        c_ulong st_rdev;
        c_long st_size;
        c_long st_blksize;
        c_long st_blocks;
        timespec st_atim;
        timespec st_mtim;
        timespec st_ctim;
        c_long[3] __glibc_reserved;
    }
    _zlist_t* zyre_peers_by_group(_zyre_t*, const(char)*) @nogc nothrow;
    _zlist_t* zyre_peers(_zyre_t*) @nogc nothrow;
    int zyre_shouts(_zyre_t*, const(char)*, const(char)*, ...) @nogc nothrow;
    int zyre_whispers(_zyre_t*, const(char)*, const(char)*, ...) @nogc nothrow;
    int zyre_shout(_zyre_t*, const(char)*, _zmsg_t**) @nogc nothrow;
    int zyre_whisper(_zyre_t*, const(char)*, _zmsg_t**) @nogc nothrow;
    _zmsg_t* zyre_recv(_zyre_t*) @nogc nothrow;
    int zyre_leave(_zyre_t*, const(char)*) @nogc nothrow;
    int zyre_join(_zyre_t*, const(char)*) @nogc nothrow;
    void zyre_stop(_zyre_t*) @nogc nothrow;
    int zyre_start(_zyre_t*) @nogc nothrow;
    void zyre_gossip_connect(_zyre_t*, const(char)*, ...) @nogc nothrow;
    alias int8_t = byte;
    alias int16_t = short;
    alias int32_t = int;
    alias int64_t = c_long;
    alias uint8_t = ubyte;
    alias uint16_t = ushort;
    alias uint32_t = uint;
    alias uint64_t = ulong;
    void zyre_gossip_bind(_zyre_t*, const(char)*, ...) @nogc nothrow;
    int zyre_set_endpoint(_zyre_t*, const(char)*, ...) @nogc nothrow;
    void zyre_set_interface(_zyre_t*, const(char)*) @nogc nothrow;
    struct __pthread_mutex_s
    {
        int __lock;
        uint __count;
        int __owner;
        uint __nusers;
        int __kind;
        short __spins;
        short __elision;
        __pthread_internal_list __list;
    }
    void zyre_set_interval(_zyre_t*, c_ulong) @nogc nothrow;
    void zyre_set_expired_timeout(_zyre_t*, int) @nogc nothrow;
    struct __pthread_rwlock_arch_t
    {
        uint __readers;
        uint __writers;
        uint __wrphase_futex;
        uint __writers_futex;
        uint __pad3;
        uint __pad4;
        int __cur_writer;
        int __shared;
        byte __rwelision;
        ubyte[7] __pad1;
        c_ulong __pad2;
        uint __flags;
    }
    void zyre_set_silent_timeout(_zyre_t*, int) @nogc nothrow;
    extern __gshared int sys_nerr;
    extern __gshared const(const(char)*)[0] sys_errlist;
    void zyre_set_evasive_timeout(_zyre_t*, int) @nogc nothrow;
    alias __pthread_list_t = __pthread_internal_list;
    struct __pthread_internal_list
    {
        __pthread_internal_list* __prev;
        __pthread_internal_list* __next;
    }
    alias __pthread_slist_t = __pthread_internal_slist;
    struct __pthread_internal_slist
    {
        __pthread_internal_slist* __next;
    }
    struct __pthread_cond_s
    {
        static union _Anonymous_18
        {
            ulong __wseq;
            static struct _Anonymous_19
            {
                uint __low;
                uint __high;
            }
            _Anonymous_19 __wseq32;
        }
        _Anonymous_18 _anonymous_20;
        auto __wseq() @property @nogc pure nothrow { return _anonymous_20.__wseq; }
        void __wseq(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_20.__wseq = val; }
        auto __wseq32() @property @nogc pure nothrow { return _anonymous_20.__wseq32; }
        void __wseq32(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_20.__wseq32 = val; }
        static union _Anonymous_21
        {
            ulong __g1_start;
            static struct _Anonymous_22
            {
                uint __low;
                uint __high;
            }
            _Anonymous_22 __g1_start32;
        }
        _Anonymous_21 _anonymous_23;
        auto __g1_start() @property @nogc pure nothrow { return _anonymous_23.__g1_start; }
        void __g1_start(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_23.__g1_start = val; }
        auto __g1_start32() @property @nogc pure nothrow { return _anonymous_23.__g1_start32; }
        void __g1_start32(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_23.__g1_start32 = val; }
        uint[2] __g_refs;
        uint[2] __g_size;
        uint __g1_orig_size;
        uint __wrefs;
        uint[2] __g_signals;
    }
    void zyre_set_port(_zyre_t*, int) @nogc nothrow;
    void zyre_set_verbose(_zyre_t*) @nogc nothrow;
    void zyre_set_header(_zyre_t*, const(char)*, const(char)*, ...) @nogc nothrow;
    void zyre_set_name(_zyre_t*, const(char)*) @nogc nothrow;
    const(char)* zyre_name(_zyre_t*) @nogc nothrow;
    const(char)* zyre_uuid(_zyre_t*) @nogc nothrow;
    void zyre_destroy(_zyre_t**) @nogc nothrow;
    _zyre_t* zyre_new(const(char)*) @nogc nothrow;
    alias __u_char = ubyte;
    alias __u_short = ushort;
    alias __u_int = uint;
    alias __u_long = c_ulong;
    alias __int8_t = byte;
    alias __uint8_t = ubyte;
    alias __int16_t = short;
    alias __uint16_t = ushort;
    alias __int32_t = int;
    alias __uint32_t = uint;
    alias __int64_t = c_long;
    alias __uint64_t = c_ulong;
    alias __int_least8_t = byte;
    alias __uint_least8_t = ubyte;
    alias __int_least16_t = short;
    alias __uint_least16_t = ushort;
    alias __int_least32_t = int;
    alias __uint_least32_t = uint;
    alias __int_least64_t = c_long;
    alias __uint_least64_t = c_ulong;
    alias __quad_t = c_long;
    alias __u_quad_t = c_ulong;
    alias __intmax_t = c_long;
    alias __uintmax_t = c_ulong;
    void zmq_threadclose(void*) @nogc nothrow;
    void* zmq_threadstart(void function(void*), void*) @nogc nothrow;
    alias zmq_thread_fn = void function(void*);
    void zmq_sleep(int) @nogc nothrow;
    c_ulong zmq_stopwatch_stop(void*) @nogc nothrow;
    c_ulong zmq_stopwatch_intermediate(void*) @nogc nothrow;
    void* zmq_stopwatch_start() @nogc nothrow;
    int zmq_timers_execute(void*) @nogc nothrow;
    alias __dev_t = c_ulong;
    alias __uid_t = uint;
    alias __gid_t = uint;
    alias __ino_t = c_ulong;
    alias __ino64_t = c_ulong;
    alias __mode_t = uint;
    alias __nlink_t = c_ulong;
    alias __off_t = c_long;
    alias __off64_t = c_long;
    alias __pid_t = int;
    struct __fsid_t
    {
        int[2] __val;
    }
    alias __clock_t = c_long;
    alias __rlim_t = c_ulong;
    alias __rlim64_t = c_ulong;
    alias __id_t = uint;
    alias __time_t = c_long;
    alias __useconds_t = uint;
    alias __suseconds_t = c_long;
    alias __daddr_t = int;
    alias __key_t = int;
    alias __clockid_t = int;
    alias __timer_t = void*;
    alias __blksize_t = c_long;
    alias __blkcnt_t = c_long;
    alias __blkcnt64_t = c_long;
    alias __fsblkcnt_t = c_ulong;
    alias __fsblkcnt64_t = c_ulong;
    alias __fsfilcnt_t = c_ulong;
    alias __fsfilcnt64_t = c_ulong;
    alias __fsword_t = c_long;
    alias __ssize_t = c_long;
    alias __syscall_slong_t = c_long;
    alias __syscall_ulong_t = c_ulong;
    alias __loff_t = c_long;
    alias __caddr_t = char*;
    alias __intptr_t = c_long;
    alias __socklen_t = uint;
    alias __sig_atomic_t = int;
    c_long zmq_timers_timeout(void*) @nogc nothrow;
    alias FILE = _IO_FILE;
    struct _IO_FILE
    {
        int _flags;
        char* _IO_read_ptr;
        char* _IO_read_end;
        char* _IO_read_base;
        char* _IO_write_base;
        char* _IO_write_ptr;
        char* _IO_write_end;
        char* _IO_buf_base;
        char* _IO_buf_end;
        char* _IO_save_base;
        char* _IO_backup_base;
        char* _IO_save_end;
        _IO_marker* _markers;
        _IO_FILE* _chain;
        int _fileno;
        int _flags2;
        c_long _old_offset;
        ushort _cur_column;
        byte _vtable_offset;
        char[1] _shortbuf;
        void* _lock;
        c_long _offset;
        _IO_codecvt* _codecvt;
        _IO_wide_data* _wide_data;
        _IO_FILE* _freeres_list;
        void* _freeres_buf;
        c_ulong __pad5;
        int _mode;
        char[20] _unused2;
    }
    alias __FILE = _IO_FILE;
    int zmq_timers_reset(void*, int) @nogc nothrow;
    alias __fpos64_t = _G_fpos64_t;
    struct _G_fpos64_t
    {
        c_long __pos;
        __mbstate_t __state;
    }
    alias __fpos_t = _G_fpos_t;
    struct _G_fpos_t
    {
        c_long __pos;
        __mbstate_t __state;
    }
    int zmq_timers_set_interval(void*, int, c_ulong) @nogc nothrow;
    struct __locale_struct
    {
        __locale_data*[13] __locales;
        const(ushort)* __ctype_b;
        const(int)* __ctype_tolower;
        const(int)* __ctype_toupper;
        const(char)*[13] __names;
    }
    alias __locale_t = __locale_struct*;
    struct __mbstate_t
    {
        int __count;
        static union _Anonymous_24
        {
            uint __wch;
            char[4] __wchb;
        }
        _Anonymous_24 __value;
    }
    int zmq_timers_cancel(void*, int) @nogc nothrow;
    struct __sigset_t
    {
        c_ulong[16] __val;
    }
    int zmq_timers_add(void*, c_ulong, void function(int, void*), void*) @nogc nothrow;
    union sigval
    {
        int sival_int;
        void* sival_ptr;
    }
    alias __sigval_t = sigval;
    alias clock_t = c_long;
    alias clockid_t = int;
    int zmq_timers_destroy(void**) @nogc nothrow;
    alias locale_t = __locale_struct*;
    alias sig_atomic_t = int;
    void* zmq_timers_new() @nogc nothrow;
    alias zmq_timer_fn = void function(int, void*);
    alias sigevent_t = sigevent;
    void zmq_atomic_counter_destroy(void**) @nogc nothrow;
    int zmq_atomic_counter_value(void*) @nogc nothrow;
    int zmq_atomic_counter_dec(void*) @nogc nothrow;
    int zmq_atomic_counter_inc(void*) @nogc nothrow;
    void zmq_atomic_counter_set(void*, int) @nogc nothrow;
    void* zmq_atomic_counter_new() @nogc nothrow;
    struct siginfo_t
    {
        int si_signo;
        int si_errno;
        int si_code;
        int __pad0;
        static union _Anonymous_25
        {
            int[28] _pad;
            static struct _Anonymous_26
            {
                int si_pid;
                uint si_uid;
            }
            _Anonymous_26 _kill;
            static struct _Anonymous_27
            {
                int si_tid;
                int si_overrun;
                sigval si_sigval;
            }
            _Anonymous_27 _timer;
            static struct _Anonymous_28
            {
                int si_pid;
                uint si_uid;
                sigval si_sigval;
            }
            _Anonymous_28 _rt;
            static struct _Anonymous_29
            {
                int si_pid;
                uint si_uid;
                int si_status;
                c_long si_utime;
                c_long si_stime;
            }
            _Anonymous_29 _sigchld;
            static struct _Anonymous_30
            {
                void* si_addr;
                short si_addr_lsb;
                static union _Anonymous_31
                {
                    static struct _Anonymous_32
                    {
                        void* _lower;
                        void* _upper;
                    }
                    _Anonymous_32 _addr_bnd;
                    uint _pkey;
                }
                _Anonymous_31 _bounds;
            }
            _Anonymous_30 _sigfault;
            static struct _Anonymous_33
            {
                c_long si_band;
                int si_fd;
            }
            _Anonymous_33 _sigpoll;
            static struct _Anonymous_34
            {
                void* _call_addr;
                int _syscall;
                uint _arch;
            }
            _Anonymous_34 _sigsys;
        }
        _Anonymous_25 _sifields;
    }
    int zmq_curve_public(char*, const(char)*) @nogc nothrow;
    int zmq_curve_keypair(char*, char*) @nogc nothrow;
    ubyte* zmq_z85_decode(ubyte*, const(char)*) @nogc nothrow;
    char* zmq_z85_encode(char*, const(ubyte)*, c_ulong) @nogc nothrow;
    int zmq_recviov(void*, iovec*, c_ulong*, int) @nogc nothrow;
    int zmq_sendiov(void*, iovec*, c_ulong, int) @nogc nothrow;
    struct iovec
    {
        void* iov_base;
        c_ulong iov_len;
    }
    int zmq_recvmsg(void*, zmq_msg_t*, int) @nogc nothrow;
    int zmq_sendmsg(void*, zmq_msg_t*, int) @nogc nothrow;
    int zmq_device(int, void*, void*) @nogc nothrow;
    int zmq_has(const(char)*) @nogc nothrow;
    alias sigset_t = __sigset_t;
    alias sigval_t = sigval;
    int zmq_proxy_steerable(void*, void*, void*, void*) @nogc nothrow;
    struct stack_t
    {
        void* ss_sp;
        int ss_flags;
        c_ulong ss_size;
    }
    int zmq_proxy(void*, void*, void*) @nogc nothrow;
    struct _IO_marker;
    struct _IO_codecvt;
    struct _IO_wide_data;
    alias _IO_lock_t = void;
    int zmq_poll(zmq_pollitem_t*, int, c_long) @nogc nothrow;
    struct zmq_pollitem_t
    {
        void* socket;
        int fd;
        short events;
        short revents;
    }
    int zmq_socket_monitor(void*, const(char)*, int) @nogc nothrow;
    int zmq_recv(void*, void*, c_ulong, int) @nogc nothrow;
    int zmq_send_const(void*, const(void)*, c_ulong, int) @nogc nothrow;
    struct itimerspec
    {
        timespec it_interval;
        timespec it_value;
    }
    int zmq_send(void*, const(void)*, c_ulong, int) @nogc nothrow;
    struct osockaddr
    {
        ushort sa_family;
        ubyte[14] sa_data;
    }
    struct sched_param
    {
        int sched_priority;
    }
    int zmq_disconnect(void*, const(char)*) @nogc nothrow;
    struct sigstack
    {
        void* ss_sp;
        int ss_onstack;
    }
    struct timespec
    {
        c_long tv_sec;
        c_long tv_nsec;
    }
    int zmq_unbind(void*, const(char)*) @nogc nothrow;
    struct timeval
    {
        c_long tv_sec;
        c_long tv_usec;
    }
    struct tm
    {
        int tm_sec;
        int tm_min;
        int tm_hour;
        int tm_mday;
        int tm_mon;
        int tm_year;
        int tm_wday;
        int tm_yday;
        int tm_isdst;
        c_long tm_gmtoff;
        const(char)* tm_zone;
    }
    int zmq_connect(void*, const(char)*) @nogc nothrow;
    alias time_t = c_long;
    alias timer_t = void*;
    int zmq_bind(void*, const(char)*) @nogc nothrow;
    int zmq_getsockopt(void*, int, void*, c_ulong*) @nogc nothrow;
    int zmq_setsockopt(void*, int, const(void)*, c_ulong) @nogc nothrow;
    int zmq_close(void*) @nogc nothrow;
    void* zmq_socket(void*, int) @nogc nothrow;
    const(char)* zmq_msg_gets(const(zmq_msg_t)*, const(char)*) @nogc nothrow;
    int zmq_msg_set(zmq_msg_t*, int, int) @nogc nothrow;
    int zmq_msg_get(const(zmq_msg_t)*, int) @nogc nothrow;
    int zmq_msg_more(const(zmq_msg_t)*) @nogc nothrow;
    c_ulong zmq_msg_size(const(zmq_msg_t)*) @nogc nothrow;
    void* zmq_msg_data(zmq_msg_t*) @nogc nothrow;
    int zmq_msg_copy(zmq_msg_t*, zmq_msg_t*) @nogc nothrow;
    int zmq_msg_move(zmq_msg_t*, zmq_msg_t*) @nogc nothrow;
    int zmq_msg_close(zmq_msg_t*) @nogc nothrow;
    int zmq_msg_recv(zmq_msg_t*, void*, int) @nogc nothrow;
    int zmq_msg_send(zmq_msg_t*, void*, int) @nogc nothrow;
    int zmq_msg_init_data(zmq_msg_t*, void*, c_ulong, void function(void*, void*), void*) @nogc nothrow;
    int zmq_msg_init_size(zmq_msg_t*, c_ulong) @nogc nothrow;
    int zmq_msg_init(zmq_msg_t*) @nogc nothrow;
    alias zmq_free_fn = void function(void*, void*);
    struct zmq_msg_t
    {
        ubyte[64] _;
    }
    static ushort __uint16_identity(ushort) @nogc nothrow;
    static uint __uint32_identity(uint) @nogc nothrow;
    static c_ulong __uint64_identity(c_ulong) @nogc nothrow;
    int zmq_ctx_destroy(void*) @nogc nothrow;
    int zmq_term(void*) @nogc nothrow;
    void* zmq_init(int) @nogc nothrow;
    int zmq_ctx_get(void*, int) @nogc nothrow;
    int zmq_ctx_set(void*, int, int) @nogc nothrow;
    int zmq_ctx_shutdown(void*) @nogc nothrow;
    int zmq_ctx_term(void*) @nogc nothrow;
    void* zmq_ctx_new() @nogc nothrow;
    void zmq_version(int*, int*, int*) @nogc nothrow;
    const(char)* zmq_strerror(int) @nogc nothrow;
    int zmq_errno() @nogc nothrow;
    int utime(const(char)*, const(utimbuf)*) @nogc nothrow;
    struct utimbuf
    {
        c_long actime;
        c_long modtime;
    }
    enum _Anonymous_35
    {
        _ISupper = 256,
        _ISlower = 512,
        _ISalpha = 1024,
        _ISdigit = 2048,
        _ISxdigit = 4096,
        _ISspace = 8192,
        _ISprint = 16384,
        _ISgraph = 32768,
        _ISblank = 1,
        _IScntrl = 2,
        _ISpunct = 4,
        _ISalnum = 8,
    }
    enum _ISupper = _Anonymous_35._ISupper;
    enum _ISlower = _Anonymous_35._ISlower;
    enum _ISalpha = _Anonymous_35._ISalpha;
    enum _ISdigit = _Anonymous_35._ISdigit;
    enum _ISxdigit = _Anonymous_35._ISxdigit;
    enum _ISspace = _Anonymous_35._ISspace;
    enum _ISprint = _Anonymous_35._ISprint;
    enum _ISgraph = _Anonymous_35._ISgraph;
    enum _ISblank = _Anonymous_35._ISblank;
    enum _IScntrl = _Anonymous_35._IScntrl;
    enum _ISpunct = _Anonymous_35._ISpunct;
    enum _ISalnum = _Anonymous_35._ISalnum;
    const(ushort)** __ctype_b_loc() @nogc nothrow;
    const(int)** __ctype_tolower_loc() @nogc nothrow;
    const(int)** __ctype_toupper_loc() @nogc nothrow;
    int getentropy(void*, c_ulong) @nogc nothrow;
    int isalnum(int) @nogc nothrow;
    int isalpha(int) @nogc nothrow;
    int iscntrl(int) @nogc nothrow;
    int isdigit(int) @nogc nothrow;
    int islower(int) @nogc nothrow;
    int isgraph(int) @nogc nothrow;
    int isprint(int) @nogc nothrow;
    int ispunct(int) @nogc nothrow;
    int isspace(int) @nogc nothrow;
    int isupper(int) @nogc nothrow;
    int isxdigit(int) @nogc nothrow;
    int tolower(int) @nogc nothrow;
    int toupper(int) @nogc nothrow;
    int isblank(int) @nogc nothrow;
    int isascii(int) @nogc nothrow;
    int toascii(int) @nogc nothrow;
    int _toupper(int) @nogc nothrow;
    int _tolower(int) @nogc nothrow;
    int isalnum_l(int, __locale_struct*) @nogc nothrow;
    int isalpha_l(int, __locale_struct*) @nogc nothrow;
    int iscntrl_l(int, __locale_struct*) @nogc nothrow;
    int isdigit_l(int, __locale_struct*) @nogc nothrow;
    int islower_l(int, __locale_struct*) @nogc nothrow;
    int isgraph_l(int, __locale_struct*) @nogc nothrow;
    int isprint_l(int, __locale_struct*) @nogc nothrow;
    int ispunct_l(int, __locale_struct*) @nogc nothrow;
    int isspace_l(int, __locale_struct*) @nogc nothrow;
    int isupper_l(int, __locale_struct*) @nogc nothrow;
    int isxdigit_l(int, __locale_struct*) @nogc nothrow;
    int isblank_l(int, __locale_struct*) @nogc nothrow;
    int __tolower_l(int, __locale_struct*) @nogc nothrow;
    int tolower_l(int, __locale_struct*) @nogc nothrow;
    int __toupper_l(int, __locale_struct*) @nogc nothrow;
    int toupper_l(int, __locale_struct*) @nogc nothrow;
    char* crypt(const(char)*, const(char)*) @nogc nothrow;
    int fdatasync(int) @nogc nothrow;
    enum _Anonymous_36
    {
        DT_UNKNOWN = 0,
        DT_FIFO = 1,
        DT_CHR = 2,
        DT_DIR = 4,
        DT_BLK = 6,
        DT_REG = 8,
        DT_LNK = 10,
        DT_SOCK = 12,
        DT_WHT = 14,
    }
    enum DT_UNKNOWN = _Anonymous_36.DT_UNKNOWN;
    enum DT_FIFO = _Anonymous_36.DT_FIFO;
    enum DT_CHR = _Anonymous_36.DT_CHR;
    enum DT_DIR = _Anonymous_36.DT_DIR;
    enum DT_BLK = _Anonymous_36.DT_BLK;
    enum DT_REG = _Anonymous_36.DT_REG;
    enum DT_LNK = _Anonymous_36.DT_LNK;
    enum DT_SOCK = _Anonymous_36.DT_SOCK;
    enum DT_WHT = _Anonymous_36.DT_WHT;
    c_long syscall(c_long, ...) @nogc nothrow;
    void* sbrk(c_long) @nogc nothrow;
    int brk(void*) @nogc nothrow;
    alias DIR = __dirstream;
    struct __dirstream;
    __dirstream* opendir(const(char)*) @nogc nothrow;
    __dirstream* fdopendir(int) @nogc nothrow;
    int closedir(__dirstream*) @nogc nothrow;
    dirent* readdir(__dirstream*) @nogc nothrow;
    int readdir_r(__dirstream*, dirent*, dirent**) @nogc nothrow;
    void rewinddir(__dirstream*) @nogc nothrow;
    void seekdir(__dirstream*, c_long) @nogc nothrow;
    c_long telldir(__dirstream*) @nogc nothrow;
    int dirfd(__dirstream*) @nogc nothrow;
    int scandir(const(char)*, dirent***, int function(const(dirent)*), int function(const(dirent)**, const(dirent)**)) @nogc nothrow;
    int alphasort(const(dirent)**, const(dirent)**) @nogc nothrow;
    c_long getdirentries(int, char*, c_ulong, c_long*) @nogc nothrow;
    int ftruncate(int, c_long) @nogc nothrow;
    int truncate(const(char)*, c_long) @nogc nothrow;
    int getdtablesize() @nogc nothrow;
    int getpagesize() @nogc nothrow;
    void sync() @nogc nothrow;
    int* __errno_location() @nogc nothrow;
    c_long gethostid() @nogc nothrow;
    int fsync(int) @nogc nothrow;
    char* getpass(const(char)*) @nogc nothrow;
    int chroot(const(char)*) @nogc nothrow;
    int daemon(int, int) @nogc nothrow;
    void setusershell() @nogc nothrow;
    void endusershell() @nogc nothrow;
    char* getusershell() @nogc nothrow;
    int acct(const(char)*) @nogc nothrow;
    int profil(ushort*, c_ulong, c_ulong, uint) @nogc nothrow;
    int revoke(const(char)*) @nogc nothrow;
    int vhangup() @nogc nothrow;
    int setdomainname(const(char)*, c_ulong) @nogc nothrow;
    int fcntl(int, int, ...) @nogc nothrow;
    int open(const(char)*, int, ...) @nogc nothrow;
    int openat(int, const(char)*, int, ...) @nogc nothrow;
    int creat(const(char)*, uint) @nogc nothrow;
    int getdomainname(char*, c_ulong) @nogc nothrow;
    int sethostid(c_long) @nogc nothrow;
    int lockf(int, int, c_long) @nogc nothrow;
    int posix_fadvise(int, c_long, c_long, int) @nogc nothrow;
    int posix_fallocate(int, c_long, c_long) @nogc nothrow;
    int sethostname(const(char)*, c_ulong) @nogc nothrow;
    int gethostname(char*, c_ulong) @nogc nothrow;
    int setlogin(const(char)*) @nogc nothrow;
    int getlogin_r(char*, c_ulong) @nogc nothrow;
    char* getlogin() @nogc nothrow;
    int tcsetpgrp(int, int) @nogc nothrow;
    int tcgetpgrp(int) @nogc nothrow;
    int rmdir(const(char)*) @nogc nothrow;
    int unlinkat(int, const(char)*, int) @nogc nothrow;
    int unlink(const(char)*) @nogc nothrow;
    c_long readlinkat(int, const(char)*, char*, c_ulong) @nogc nothrow;
    int symlinkat(const(char)*, int, const(char)*) @nogc nothrow;
    struct group
    {
        char* gr_name;
        char* gr_passwd;
        uint gr_gid;
        char** gr_mem;
    }
    void setgrent() @nogc nothrow;
    void endgrent() @nogc nothrow;
    group* getgrent() @nogc nothrow;
    group* fgetgrent(_IO_FILE*) @nogc nothrow;
    group* getgrgid(uint) @nogc nothrow;
    group* getgrnam(const(char)*) @nogc nothrow;
    int getgrgid_r(uint, group*, char*, c_ulong, group**) @nogc nothrow;
    int getgrnam_r(const(char)*, group*, char*, c_ulong, group**) @nogc nothrow;
    int fgetgrent_r(_IO_FILE*, group*, char*, c_ulong, group**) @nogc nothrow;
    int setgroups(c_ulong, const(uint)*) @nogc nothrow;
    int getgrouplist(const(char)*, uint, uint*, int*) @nogc nothrow;
    int initgroups(const(char)*, uint) @nogc nothrow;
    c_long readlink(const(char)*, char*, c_ulong) @nogc nothrow;
    struct ifaddrs
    {
        ifaddrs* ifa_next;
        char* ifa_name;
        uint ifa_flags;
        sockaddr* ifa_addr;
        sockaddr* ifa_netmask;
        static union _Anonymous_37
        {
            sockaddr* ifu_broadaddr;
            sockaddr* ifu_dstaddr;
        }
        _Anonymous_37 ifa_ifu;
        void* ifa_data;
    }
    int getifaddrs(ifaddrs**) @nogc nothrow;
    void freeifaddrs(ifaddrs*) @nogc nothrow;
    alias __gwchar_t = int;
    int symlink(const(char)*, const(char)*) @nogc nothrow;
    int linkat(int, const(char)*, int, const(char)*, int) @nogc nothrow;
    int link(const(char)*, const(char)*) @nogc nothrow;
    int ttyslot() @nogc nothrow;
    int isatty(int) @nogc nothrow;
    int ttyname_r(int, char*, c_ulong) @nogc nothrow;
    char* ttyname(int) @nogc nothrow;
    int vfork() @nogc nothrow;
    int fork() @nogc nothrow;
    int setegid(uint) @nogc nothrow;
    int setregid(uint, uint) @nogc nothrow;
    int setgid(uint) @nogc nothrow;
    int seteuid(uint) @nogc nothrow;
    int setreuid(uint, uint) @nogc nothrow;
    int setuid(uint) @nogc nothrow;
    int getgroups(int, uint*) @nogc nothrow;
    uint getegid() @nogc nothrow;
    uint getgid() @nogc nothrow;
    uint geteuid() @nogc nothrow;
    uint getuid() @nogc nothrow;
    int getsid(int) @nogc nothrow;
    int setsid() @nogc nothrow;
    int setpgrp() @nogc nothrow;
    int setpgid(int, int) @nogc nothrow;
    int getpgid(int) @nogc nothrow;
    int __getpgid(int) @nogc nothrow;
    int getpgrp() @nogc nothrow;
    int getppid() @nogc nothrow;
    int getpid() @nogc nothrow;
    c_ulong confstr(int, char*, c_ulong) @nogc nothrow;
    c_long sysconf(int) @nogc nothrow;
    c_long fpathconf(int, int) @nogc nothrow;
    c_long pathconf(const(char)*, int) @nogc nothrow;
    void _exit(int) @nogc nothrow;
    int nice(int) @nogc nothrow;
    int execlp(const(char)*, const(char)*, ...) @nogc nothrow;
    int execvp(const(char)*, char**) @nogc nothrow;
    int execl(const(char)*, const(char)*, ...) @nogc nothrow;
    int execle(const(char)*, const(char)*, ...) @nogc nothrow;
    int execv(const(char)*, char**) @nogc nothrow;
    int fexecve(int, char**, char**) @nogc nothrow;
    int execve(const(char)*, char**, char**) @nogc nothrow;
    extern __gshared char** __environ;
    int dup2(int, int) @nogc nothrow;
    int dup(int) @nogc nothrow;
    char* getwd(char*) @nogc nothrow;
    char* getcwd(char*, c_ulong) @nogc nothrow;
    int fchdir(int) @nogc nothrow;
    int chdir(const(char)*) @nogc nothrow;
    int fchownat(int, const(char)*, uint, uint, int) @nogc nothrow;
    int lchown(const(char)*, uint, uint) @nogc nothrow;
    int fchown(int, uint, uint) @nogc nothrow;
    struct imaxdiv_t
    {
        c_long quot;
        c_long rem;
    }
    c_long imaxabs(c_long) @nogc nothrow;
    imaxdiv_t imaxdiv(c_long, c_long) @nogc nothrow;
    c_long strtoimax(const(char)*, char**, int) @nogc nothrow;
    c_ulong strtoumax(const(char)*, char**, int) @nogc nothrow;
    c_long wcstoimax(const(int)*, int**, int) @nogc nothrow;
    c_ulong wcstoumax(const(int)*, int**, int) @nogc nothrow;
    int chown(const(char)*, uint, uint) @nogc nothrow;
    int pause() @nogc nothrow;
    int usleep(uint) @nogc nothrow;
    uint ualarm(uint, uint) @nogc nothrow;
    uint sleep(uint) @nogc nothrow;
    uint alarm(uint) @nogc nothrow;
    int pipe(int*) @nogc nothrow;
    c_long pwrite(int, const(void)*, c_ulong, c_long) @nogc nothrow;
    c_long pread(int, void*, c_ulong, c_long) @nogc nothrow;
    c_long write(int, const(void)*, c_ulong) @nogc nothrow;
    struct __kernel_fd_set
    {
        c_ulong[16] fds_bits;
    }
    alias __kernel_sighandler_t = void function(int);
    alias __kernel_key_t = int;
    alias __kernel_mqd_t = int;
    c_long read(int, void*, c_ulong) @nogc nothrow;
    int close(int) @nogc nothrow;
    c_long lseek(int, c_long, int) @nogc nothrow;
    alias float_t = float;
    alias double_t = double;
    int faccessat(int, const(char)*, int, int) @nogc nothrow;
    int access(const(char)*, int) @nogc nothrow;
    alias useconds_t = uint;
    int timespec_get(timespec*, int) @nogc nothrow;
    int timer_getoverrun(void*) @nogc nothrow;
    int timer_gettime(void*, itimerspec*) @nogc nothrow;
    int timer_settime(void*, int, const(itimerspec)*, itimerspec*) @nogc nothrow;
    int timer_delete(void*) @nogc nothrow;
    int timer_create(int, sigevent*, void**) @nogc nothrow;
    int clock_getcpuclockid(int, int*) @nogc nothrow;
    extern __gshared int signgam;
    int clock_nanosleep(int, int, const(timespec)*, timespec*) @nogc nothrow;
    enum _Anonymous_38
    {
        FP_NAN = 0,
        FP_INFINITE = 1,
        FP_ZERO = 2,
        FP_SUBNORMAL = 3,
        FP_NORMAL = 4,
    }
    enum FP_NAN = _Anonymous_38.FP_NAN;
    enum FP_INFINITE = _Anonymous_38.FP_INFINITE;
    enum FP_ZERO = _Anonymous_38.FP_ZERO;
    enum FP_SUBNORMAL = _Anonymous_38.FP_SUBNORMAL;
    enum FP_NORMAL = _Anonymous_38.FP_NORMAL;
    int clock_settime(int, const(timespec)*) @nogc nothrow;
    int clock_gettime(int, timespec*) @nogc nothrow;
    int clock_getres(int, timespec*) @nogc nothrow;
    int nanosleep(const(timespec)*, timespec*) @nogc nothrow;
    int dysize(int) @nogc nothrow;
    c_long timelocal(tm*) @nogc nothrow;
    c_long timegm(tm*) @nogc nothrow;
    pragma(mangle, "timezone") extern __gshared c_long timezone_;
    extern __gshared int daylight;
    void tzset() @nogc nothrow;
    extern __gshared char*[2] tzname;
    extern __gshared c_long __timezone;
    extern __gshared int __daylight;
    extern __gshared char*[2] __tzname;
    char* ctime_r(const(c_long)*, char*) @nogc nothrow;
    char* asctime_r(const(tm)*, char*) @nogc nothrow;
    char* ctime(const(c_long)*) @nogc nothrow;
    char* asctime(const(tm)*) @nogc nothrow;
    tm* localtime_r(const(c_long)*, tm*) @nogc nothrow;
    tm* gmtime_r(const(c_long)*, tm*) @nogc nothrow;
    int* __h_errno_location() @nogc nothrow;
    tm* localtime(const(c_long)*) @nogc nothrow;
    tm* gmtime(const(c_long)*) @nogc nothrow;
    c_ulong strftime_l(char*, c_ulong, const(char)*, const(tm)*, __locale_struct*) @nogc nothrow;
    void herror(const(char)*) @nogc nothrow;
    const(char)* hstrerror(int) @nogc nothrow;
    struct hostent
    {
        char* h_name;
        char** h_aliases;
        int h_addrtype;
        int h_length;
        char** h_addr_list;
    }
    void sethostent(int) @nogc nothrow;
    void endhostent() @nogc nothrow;
    hostent* gethostent() @nogc nothrow;
    hostent* gethostbyaddr(const(void)*, uint, int) @nogc nothrow;
    hostent* gethostbyname(const(char)*) @nogc nothrow;
    hostent* gethostbyname2(const(char)*, int) @nogc nothrow;
    int gethostent_r(hostent*, char*, c_ulong, hostent**, int*) @nogc nothrow;
    int gethostbyaddr_r(const(void)*, uint, int, hostent*, char*, c_ulong, hostent**, int*) @nogc nothrow;
    int gethostbyname_r(const(char)*, hostent*, char*, c_ulong, hostent**, int*) @nogc nothrow;
    int gethostbyname2_r(const(char)*, int, hostent*, char*, c_ulong, hostent**, int*) @nogc nothrow;
    void setnetent(int) @nogc nothrow;
    void endnetent() @nogc nothrow;
    netent* getnetent() @nogc nothrow;
    netent* getnetbyaddr(uint, int) @nogc nothrow;
    netent* getnetbyname(const(char)*) @nogc nothrow;
    int getnetent_r(netent*, char*, c_ulong, netent**, int*) @nogc nothrow;
    int getnetbyaddr_r(uint, int, netent*, char*, c_ulong, netent**, int*) @nogc nothrow;
    int getnetbyname_r(const(char)*, netent*, char*, c_ulong, netent**, int*) @nogc nothrow;
    struct servent
    {
        char* s_name;
        char** s_aliases;
        int s_port;
        char* s_proto;
    }
    void setservent(int) @nogc nothrow;
    void endservent() @nogc nothrow;
    servent* getservent() @nogc nothrow;
    servent* getservbyname(const(char)*, const(char)*) @nogc nothrow;
    servent* getservbyport(int, const(char)*) @nogc nothrow;
    int getservent_r(servent*, char*, c_ulong, servent**) @nogc nothrow;
    int getservbyname_r(const(char)*, const(char)*, servent*, char*, c_ulong, servent**) @nogc nothrow;
    int getservbyport_r(int, const(char)*, servent*, char*, c_ulong, servent**) @nogc nothrow;
    struct protoent
    {
        char* p_name;
        char** p_aliases;
        int p_proto;
    }
    void setprotoent(int) @nogc nothrow;
    void endprotoent() @nogc nothrow;
    protoent* getprotoent() @nogc nothrow;
    protoent* getprotobyname(const(char)*) @nogc nothrow;
    protoent* getprotobynumber(int) @nogc nothrow;
    int getprotoent_r(protoent*, char*, c_ulong, protoent**) @nogc nothrow;
    int getprotobyname_r(const(char)*, protoent*, char*, c_ulong, protoent**) @nogc nothrow;
    int getprotobynumber_r(int, protoent*, char*, c_ulong, protoent**) @nogc nothrow;
    int setnetgrent(const(char)*) @nogc nothrow;
    void endnetgrent() @nogc nothrow;
    int getnetgrent(char**, char**, char**) @nogc nothrow;
    int innetgr(const(char)*, const(char)*, const(char)*, const(char)*) @nogc nothrow;
    int getnetgrent_r(char**, char**, char**, char*, c_ulong) @nogc nothrow;
    int rcmd(char**, ushort, const(char)*, const(char)*, const(char)*, int*) @nogc nothrow;
    int rcmd_af(char**, ushort, const(char)*, const(char)*, const(char)*, int*, ushort) @nogc nothrow;
    int rexec(char**, int, const(char)*, const(char)*, const(char)*, int*) @nogc nothrow;
    int rexec_af(char**, int, const(char)*, const(char)*, const(char)*, int*, ushort) @nogc nothrow;
    int ruserok(const(char)*, int, const(char)*, const(char)*) @nogc nothrow;
    int ruserok_af(const(char)*, int, const(char)*, const(char)*, ushort) @nogc nothrow;
    int iruserok(uint, int, const(char)*, const(char)*) @nogc nothrow;
    int iruserok_af(const(void)*, int, const(char)*, const(char)*, ushort) @nogc nothrow;
    int rresvport(int*) @nogc nothrow;
    int rresvport_af(int*, ushort) @nogc nothrow;
    struct addrinfo
    {
        int ai_flags;
        int ai_family;
        int ai_socktype;
        int ai_protocol;
        uint ai_addrlen;
        sockaddr* ai_addr;
        char* ai_canonname;
        addrinfo* ai_next;
    }
    c_ulong strftime(char*, c_ulong, const(char)*, const(tm)*) @nogc nothrow;
    c_long mktime(tm*) @nogc nothrow;
    double difftime(c_long, c_long) @nogc nothrow;
    c_long time(c_long*) @nogc nothrow;
    c_long clock() @nogc nothrow;
    struct sigevent
    {
        sigval sigev_value;
        int sigev_signo;
        int sigev_notify;
        static union _Anonymous_39
        {
            int[12] _pad;
            int _tid;
            static struct _Anonymous_40
            {
                void function(sigval) _function;
                pthread_attr_t* _attribute;
            }
            _Anonymous_40 _sigev_thread;
        }
        _Anonymous_39 _sigev_un;
    }
    int getaddrinfo(const(char)*, const(char)*, const(addrinfo)*, addrinfo**) @nogc nothrow;
    void freeaddrinfo(addrinfo*) @nogc nothrow;
    const(char)* gai_strerror(int) @nogc nothrow;
    int getnameinfo(const(sockaddr)*, uint, char*, uint, char*, uint, int) @nogc nothrow;
    alias in_addr_t = uint;
    struct in_addr
    {
        uint s_addr;
    }
    enum _Anonymous_41
    {
        IPPROTO_IP = 0,
        IPPROTO_ICMP = 1,
        IPPROTO_IGMP = 2,
        IPPROTO_IPIP = 4,
        IPPROTO_TCP = 6,
        IPPROTO_EGP = 8,
        IPPROTO_PUP = 12,
        IPPROTO_UDP = 17,
        IPPROTO_IDP = 22,
        IPPROTO_TP = 29,
        IPPROTO_DCCP = 33,
        IPPROTO_IPV6 = 41,
        IPPROTO_RSVP = 46,
        IPPROTO_GRE = 47,
        IPPROTO_ESP = 50,
        IPPROTO_AH = 51,
        IPPROTO_MTP = 92,
        IPPROTO_BEETPH = 94,
        IPPROTO_ENCAP = 98,
        IPPROTO_PIM = 103,
        IPPROTO_COMP = 108,
        IPPROTO_SCTP = 132,
        IPPROTO_UDPLITE = 136,
        IPPROTO_MPLS = 137,
        IPPROTO_RAW = 255,
        IPPROTO_MAX = 256,
    }
    enum IPPROTO_IP = _Anonymous_41.IPPROTO_IP;
    enum IPPROTO_ICMP = _Anonymous_41.IPPROTO_ICMP;
    enum IPPROTO_IGMP = _Anonymous_41.IPPROTO_IGMP;
    enum IPPROTO_IPIP = _Anonymous_41.IPPROTO_IPIP;
    enum IPPROTO_TCP = _Anonymous_41.IPPROTO_TCP;
    enum IPPROTO_EGP = _Anonymous_41.IPPROTO_EGP;
    enum IPPROTO_PUP = _Anonymous_41.IPPROTO_PUP;
    enum IPPROTO_UDP = _Anonymous_41.IPPROTO_UDP;
    enum IPPROTO_IDP = _Anonymous_41.IPPROTO_IDP;
    enum IPPROTO_TP = _Anonymous_41.IPPROTO_TP;
    enum IPPROTO_DCCP = _Anonymous_41.IPPROTO_DCCP;
    enum IPPROTO_IPV6 = _Anonymous_41.IPPROTO_IPV6;
    enum IPPROTO_RSVP = _Anonymous_41.IPPROTO_RSVP;
    enum IPPROTO_GRE = _Anonymous_41.IPPROTO_GRE;
    enum IPPROTO_ESP = _Anonymous_41.IPPROTO_ESP;
    enum IPPROTO_AH = _Anonymous_41.IPPROTO_AH;
    enum IPPROTO_MTP = _Anonymous_41.IPPROTO_MTP;
    enum IPPROTO_BEETPH = _Anonymous_41.IPPROTO_BEETPH;
    enum IPPROTO_ENCAP = _Anonymous_41.IPPROTO_ENCAP;
    enum IPPROTO_PIM = _Anonymous_41.IPPROTO_PIM;
    enum IPPROTO_COMP = _Anonymous_41.IPPROTO_COMP;
    enum IPPROTO_SCTP = _Anonymous_41.IPPROTO_SCTP;
    enum IPPROTO_UDPLITE = _Anonymous_41.IPPROTO_UDPLITE;
    enum IPPROTO_MPLS = _Anonymous_41.IPPROTO_MPLS;
    enum IPPROTO_RAW = _Anonymous_41.IPPROTO_RAW;
    enum IPPROTO_MAX = _Anonymous_41.IPPROTO_MAX;
    int wait4(int, int*, int, rusage*) @nogc nothrow;
    int wait3(int*, int, rusage*) @nogc nothrow;
    struct rusage;
    int waitid(idtype_t, uint, siginfo_t*, int) @nogc nothrow;
    int waitpid(int, int*, int) @nogc nothrow;
    int wait(int*) @nogc nothrow;
    enum _Anonymous_42
    {
        P_ALL = 0,
        P_PID = 1,
        P_PGID = 2,
    }
    enum P_ALL = _Anonymous_42.P_ALL;
    enum P_PID = _Anonymous_42.P_PID;
    enum P_PGID = _Anonymous_42.P_PGID;
    alias idtype_t = _Anonymous_42;
    enum _Anonymous_43
    {
        IPPROTO_HOPOPTS = 0,
        IPPROTO_ROUTING = 43,
        IPPROTO_FRAGMENT = 44,
        IPPROTO_ICMPV6 = 58,
        IPPROTO_NONE = 59,
        IPPROTO_DSTOPTS = 60,
        IPPROTO_MH = 135,
    }
    enum IPPROTO_HOPOPTS = _Anonymous_43.IPPROTO_HOPOPTS;
    enum IPPROTO_ROUTING = _Anonymous_43.IPPROTO_ROUTING;
    enum IPPROTO_FRAGMENT = _Anonymous_43.IPPROTO_FRAGMENT;
    enum IPPROTO_ICMPV6 = _Anonymous_43.IPPROTO_ICMPV6;
    enum IPPROTO_NONE = _Anonymous_43.IPPROTO_NONE;
    enum IPPROTO_DSTOPTS = _Anonymous_43.IPPROTO_DSTOPTS;
    enum IPPROTO_MH = _Anonymous_43.IPPROTO_MH;
    alias in_port_t = ushort;
    enum _Anonymous_44
    {
        IPPORT_ECHO = 7,
        IPPORT_DISCARD = 9,
        IPPORT_SYSTAT = 11,
        IPPORT_DAYTIME = 13,
        IPPORT_NETSTAT = 15,
        IPPORT_FTP = 21,
        IPPORT_TELNET = 23,
        IPPORT_SMTP = 25,
        IPPORT_TIMESERVER = 37,
        IPPORT_NAMESERVER = 42,
        IPPORT_WHOIS = 43,
        IPPORT_MTP = 57,
        IPPORT_TFTP = 69,
        IPPORT_RJE = 77,
        IPPORT_FINGER = 79,
        IPPORT_TTYLINK = 87,
        IPPORT_SUPDUP = 95,
        IPPORT_EXECSERVER = 512,
        IPPORT_LOGINSERVER = 513,
        IPPORT_CMDSERVER = 514,
        IPPORT_EFSSERVER = 520,
        IPPORT_BIFFUDP = 512,
        IPPORT_WHOSERVER = 513,
        IPPORT_ROUTESERVER = 520,
        IPPORT_RESERVED = 1024,
        IPPORT_USERRESERVED = 5000,
    }
    enum IPPORT_ECHO = _Anonymous_44.IPPORT_ECHO;
    enum IPPORT_DISCARD = _Anonymous_44.IPPORT_DISCARD;
    enum IPPORT_SYSTAT = _Anonymous_44.IPPORT_SYSTAT;
    enum IPPORT_DAYTIME = _Anonymous_44.IPPORT_DAYTIME;
    enum IPPORT_NETSTAT = _Anonymous_44.IPPORT_NETSTAT;
    enum IPPORT_FTP = _Anonymous_44.IPPORT_FTP;
    enum IPPORT_TELNET = _Anonymous_44.IPPORT_TELNET;
    enum IPPORT_SMTP = _Anonymous_44.IPPORT_SMTP;
    enum IPPORT_TIMESERVER = _Anonymous_44.IPPORT_TIMESERVER;
    enum IPPORT_NAMESERVER = _Anonymous_44.IPPORT_NAMESERVER;
    enum IPPORT_WHOIS = _Anonymous_44.IPPORT_WHOIS;
    enum IPPORT_MTP = _Anonymous_44.IPPORT_MTP;
    enum IPPORT_TFTP = _Anonymous_44.IPPORT_TFTP;
    enum IPPORT_RJE = _Anonymous_44.IPPORT_RJE;
    enum IPPORT_FINGER = _Anonymous_44.IPPORT_FINGER;
    enum IPPORT_TTYLINK = _Anonymous_44.IPPORT_TTYLINK;
    enum IPPORT_SUPDUP = _Anonymous_44.IPPORT_SUPDUP;
    enum IPPORT_EXECSERVER = _Anonymous_44.IPPORT_EXECSERVER;
    enum IPPORT_LOGINSERVER = _Anonymous_44.IPPORT_LOGINSERVER;
    enum IPPORT_CMDSERVER = _Anonymous_44.IPPORT_CMDSERVER;
    enum IPPORT_EFSSERVER = _Anonymous_44.IPPORT_EFSSERVER;
    enum IPPORT_BIFFUDP = _Anonymous_44.IPPORT_BIFFUDP;
    enum IPPORT_WHOSERVER = _Anonymous_44.IPPORT_WHOSERVER;
    enum IPPORT_ROUTESERVER = _Anonymous_44.IPPORT_ROUTESERVER;
    enum IPPORT_RESERVED = _Anonymous_44.IPPORT_RESERVED;
    enum IPPORT_USERRESERVED = _Anonymous_44.IPPORT_USERRESERVED;
    struct sockaddr_un
    {
        ushort sun_family;
        char[108] sun_path;
    }
    c_long pwritev(int, const(iovec)*, int, c_long) @nogc nothrow;
    c_long preadv(int, const(iovec)*, int, c_long) @nogc nothrow;
    c_long writev(int, const(iovec)*, int) @nogc nothrow;
    c_long readv(int, const(iovec)*, int) @nogc nothrow;
    struct ucontext_t
    {
        c_ulong uc_flags;
        ucontext_t* uc_link;
        stack_t uc_stack;
        mcontext_t uc_mcontext;
        __sigset_t uc_sigmask;
        _libc_fpstate __fpregs_mem;
        ulong[4] __ssp;
    }
    struct in6_addr
    {
        static union _Anonymous_45
        {
            ubyte[16] __u6_addr8;
            ushort[8] __u6_addr16;
            uint[4] __u6_addr32;
        }
        _Anonymous_45 __in6_u;
    }
    extern __gshared const(in6_addr) in6addr_any;
    extern __gshared const(in6_addr) in6addr_loopback;
    struct mcontext_t
    {
        long[23] gregs;
        _libc_fpstate* fpregs;
        ulong[8] __reserved1;
    }
    alias fpregset_t = _libc_fpstate*;
    struct sockaddr_in
    {
        ushort sin_family;
        ushort sin_port;
        in_addr sin_addr;
        ubyte[8] sin_zero;
    }
    struct sockaddr_in6
    {
        ushort sin6_family;
        ushort sin6_port;
        uint sin6_flowinfo;
        in6_addr sin6_addr;
        uint sin6_scope_id;
    }
    struct ip_mreq
    {
        in_addr imr_multiaddr;
        in_addr imr_interface;
    }
    struct ip_mreq_source
    {
        in_addr imr_multiaddr;
        in_addr imr_interface;
        in_addr imr_sourceaddr;
    }
    struct ipv6_mreq
    {
        in6_addr ipv6mr_multiaddr;
        uint ipv6mr_interface;
    }
    struct group_req
    {
        uint gr_interface;
        sockaddr_storage gr_group;
    }
    struct group_source_req
    {
        uint gsr_interface;
        sockaddr_storage gsr_group;
        sockaddr_storage gsr_source;
    }
    struct ip_msfilter
    {
        in_addr imsf_multiaddr;
        in_addr imsf_interface;
        uint imsf_fmode;
        uint imsf_numsrc;
        in_addr[1] imsf_slist;
    }
    struct group_filter
    {
        uint gf_interface;
        sockaddr_storage gf_group;
        uint gf_fmode;
        uint gf_numsrc;
        sockaddr_storage[1] gf_slist;
    }
    uint ntohl(uint) @nogc nothrow;
    ushort ntohs(ushort) @nogc nothrow;
    uint htonl(uint) @nogc nothrow;
    ushort htons(ushort) @nogc nothrow;
    struct _libc_fpstate
    {
        ushort cwd;
        ushort swd;
        ushort ftw;
        ushort fop;
        c_ulong rip;
        c_ulong rdp;
        uint mxcsr;
        uint mxcr_mask;
        _libc_fpxreg[8] _st;
        _libc_xmmreg[16] _xmm;
        uint[24] __glibc_reserved1;
    }
    struct _libc_xmmreg
    {
        uint[4] element;
    }
    int bindresvport(int, sockaddr_in*) @nogc nothrow;
    int bindresvport6(int, sockaddr_in6*) @nogc nothrow;
    struct _libc_fpxreg
    {
        ushort[4] significand;
        ushort exponent;
        ushort[3] __glibc_reserved1;
    }
    alias gregset_t = long[23];
    alias greg_t = long;
    alias fsfilcnt_t = c_ulong;
    alias fsblkcnt_t = c_ulong;
    alias blkcnt_t = c_long;
    alias blksize_t = c_long;
    alias register_t = c_long;
    alias u_int64_t = c_ulong;
    alias u_int32_t = uint;
    alias u_int16_t = ushort;
    alias u_int8_t = ubyte;
    alias key_t = int;
    alias caddr_t = char*;
    alias daddr_t = int;
    alias tcp_seq = uint;
    struct tcphdr
    {
        static union _Anonymous_46
        {
            static struct _Anonymous_47
            {
                import std.bitmanip: bitfields;

                align(4):
                ushort th_sport;
                ushort th_dport;
                uint th_seq;
                uint th_ack;
                mixin(bitfields!(
                    ubyte, "th_x2", 4,
                    ubyte, "th_off", 4,
                ));
                ubyte th_flags;
                ushort th_win;
                ushort th_sum;
                ushort th_urp;
            }
            _Anonymous_47 _anonymous_48;
            auto th_sport() @property @nogc pure nothrow { return _anonymous_48.th_sport; }
            void th_sport(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_48.th_sport = val; }
            auto th_dport() @property @nogc pure nothrow { return _anonymous_48.th_dport; }
            void th_dport(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_48.th_dport = val; }
            auto th_seq() @property @nogc pure nothrow { return _anonymous_48.th_seq; }
            void th_seq(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_48.th_seq = val; }
            auto th_ack() @property @nogc pure nothrow { return _anonymous_48.th_ack; }
            void th_ack(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_48.th_ack = val; }
            auto th_x2() @property @nogc pure nothrow { return _anonymous_48.th_x2; }
            void th_x2(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_48.th_x2 = val; }
            auto th_off() @property @nogc pure nothrow { return _anonymous_48.th_off; }
            void th_off(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_48.th_off = val; }
            auto th_flags() @property @nogc pure nothrow { return _anonymous_48.th_flags; }
            void th_flags(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_48.th_flags = val; }
            auto th_win() @property @nogc pure nothrow { return _anonymous_48.th_win; }
            void th_win(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_48.th_win = val; }
            auto th_sum() @property @nogc pure nothrow { return _anonymous_48.th_sum; }
            void th_sum(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_48.th_sum = val; }
            auto th_urp() @property @nogc pure nothrow { return _anonymous_48.th_urp; }
            void th_urp(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_48.th_urp = val; }
            static struct _Anonymous_49
            {
                import std.bitmanip: bitfields;

                align(4):
                ushort source;
                ushort dest;
                uint seq;
                uint ack_seq;
                mixin(bitfields!(
                    ushort, "res1", 4,
                    ushort, "doff", 4,
                    ushort, "fin", 1,
                    ushort, "syn", 1,
                    ushort, "rst", 1,
                    ushort, "psh", 1,
                    ushort, "ack", 1,
                    ushort, "urg", 1,
                    ushort, "res2", 2,
                ));
                ushort window;
                ushort check;
                ushort urg_ptr;
            }
            _Anonymous_49 _anonymous_50;
            auto source() @property @nogc pure nothrow { return _anonymous_50.source; }
            void source(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_50.source = val; }
            auto dest() @property @nogc pure nothrow { return _anonymous_50.dest; }
            void dest(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_50.dest = val; }
            auto seq() @property @nogc pure nothrow { return _anonymous_50.seq; }
            void seq(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_50.seq = val; }
            auto ack_seq() @property @nogc pure nothrow { return _anonymous_50.ack_seq; }
            void ack_seq(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_50.ack_seq = val; }
            auto res1() @property @nogc pure nothrow { return _anonymous_50.res1; }
            void res1(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_50.res1 = val; }
            auto doff() @property @nogc pure nothrow { return _anonymous_50.doff; }
            void doff(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_50.doff = val; }
            auto fin() @property @nogc pure nothrow { return _anonymous_50.fin; }
            void fin(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_50.fin = val; }
            auto syn() @property @nogc pure nothrow { return _anonymous_50.syn; }
            void syn(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_50.syn = val; }
            auto rst() @property @nogc pure nothrow { return _anonymous_50.rst; }
            void rst(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_50.rst = val; }
            auto psh() @property @nogc pure nothrow { return _anonymous_50.psh; }
            void psh(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_50.psh = val; }
            auto ack() @property @nogc pure nothrow { return _anonymous_50.ack; }
            void ack(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_50.ack = val; }
            auto urg() @property @nogc pure nothrow { return _anonymous_50.urg; }
            void urg(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_50.urg = val; }
            auto res2() @property @nogc pure nothrow { return _anonymous_50.res2; }
            void res2(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_50.res2 = val; }
            auto window() @property @nogc pure nothrow { return _anonymous_50.window; }
            void window(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_50.window = val; }
            auto check() @property @nogc pure nothrow { return _anonymous_50.check; }
            void check(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_50.check = val; }
            auto urg_ptr() @property @nogc pure nothrow { return _anonymous_50.urg_ptr; }
            void urg_ptr(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_50.urg_ptr = val; }
        }
        _Anonymous_46 _anonymous_51;
        auto th_sport() @property @nogc pure nothrow { return _anonymous_51.th_sport; }
        void th_sport(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_51.th_sport = val; }
        auto th_dport() @property @nogc pure nothrow { return _anonymous_51.th_dport; }
        void th_dport(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_51.th_dport = val; }
        auto th_seq() @property @nogc pure nothrow { return _anonymous_51.th_seq; }
        void th_seq(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_51.th_seq = val; }
        auto th_ack() @property @nogc pure nothrow { return _anonymous_51.th_ack; }
        void th_ack(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_51.th_ack = val; }
        auto th_x2() @property @nogc pure nothrow { return _anonymous_51.th_x2; }
        void th_x2(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_51.th_x2 = val; }
        auto th_off() @property @nogc pure nothrow { return _anonymous_51.th_off; }
        void th_off(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_51.th_off = val; }
        auto th_flags() @property @nogc pure nothrow { return _anonymous_51.th_flags; }
        void th_flags(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_51.th_flags = val; }
        auto th_win() @property @nogc pure nothrow { return _anonymous_51.th_win; }
        void th_win(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_51.th_win = val; }
        auto th_sum() @property @nogc pure nothrow { return _anonymous_51.th_sum; }
        void th_sum(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_51.th_sum = val; }
        auto th_urp() @property @nogc pure nothrow { return _anonymous_51.th_urp; }
        void th_urp(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_51.th_urp = val; }
        auto source() @property @nogc pure nothrow { return _anonymous_51.source; }
        void source(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_51.source = val; }
        auto dest() @property @nogc pure nothrow { return _anonymous_51.dest; }
        void dest(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_51.dest = val; }
        auto seq() @property @nogc pure nothrow { return _anonymous_51.seq; }
        void seq(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_51.seq = val; }
        auto ack_seq() @property @nogc pure nothrow { return _anonymous_51.ack_seq; }
        void ack_seq(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_51.ack_seq = val; }
        auto res1() @property @nogc pure nothrow { return _anonymous_51.res1; }
        void res1(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_51.res1 = val; }
        auto doff() @property @nogc pure nothrow { return _anonymous_51.doff; }
        void doff(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_51.doff = val; }
        auto fin() @property @nogc pure nothrow { return _anonymous_51.fin; }
        void fin(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_51.fin = val; }
        auto syn() @property @nogc pure nothrow { return _anonymous_51.syn; }
        void syn(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_51.syn = val; }
        auto rst() @property @nogc pure nothrow { return _anonymous_51.rst; }
        void rst(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_51.rst = val; }
        auto psh() @property @nogc pure nothrow { return _anonymous_51.psh; }
        void psh(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_51.psh = val; }
        auto ack() @property @nogc pure nothrow { return _anonymous_51.ack; }
        void ack(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_51.ack = val; }
        auto urg() @property @nogc pure nothrow { return _anonymous_51.urg; }
        void urg(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_51.urg = val; }
        auto res2() @property @nogc pure nothrow { return _anonymous_51.res2; }
        void res2(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_51.res2 = val; }
        auto window() @property @nogc pure nothrow { return _anonymous_51.window; }
        void window(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_51.window = val; }
        auto check() @property @nogc pure nothrow { return _anonymous_51.check; }
        void check(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_51.check = val; }
        auto urg_ptr() @property @nogc pure nothrow { return _anonymous_51.urg_ptr; }
        void urg_ptr(_T_)(auto ref _T_ val) @property @nogc pure nothrow { _anonymous_51.urg_ptr = val; }
    }
    alias id_t = uint;
    alias pid_t = int;
    alias uid_t = uint;
    alias nlink_t = c_ulong;
    enum _Anonymous_52
    {
        TCP_ESTABLISHED = 1,
        TCP_SYN_SENT = 2,
        TCP_SYN_RECV = 3,
        TCP_FIN_WAIT1 = 4,
        TCP_FIN_WAIT2 = 5,
        TCP_TIME_WAIT = 6,
        TCP_CLOSE = 7,
        TCP_CLOSE_WAIT = 8,
        TCP_LAST_ACK = 9,
        TCP_LISTEN = 10,
        TCP_CLOSING = 11,
    }
    enum TCP_ESTABLISHED = _Anonymous_52.TCP_ESTABLISHED;
    enum TCP_SYN_SENT = _Anonymous_52.TCP_SYN_SENT;
    enum TCP_SYN_RECV = _Anonymous_52.TCP_SYN_RECV;
    enum TCP_FIN_WAIT1 = _Anonymous_52.TCP_FIN_WAIT1;
    enum TCP_FIN_WAIT2 = _Anonymous_52.TCP_FIN_WAIT2;
    enum TCP_TIME_WAIT = _Anonymous_52.TCP_TIME_WAIT;
    enum TCP_CLOSE = _Anonymous_52.TCP_CLOSE;
    enum TCP_CLOSE_WAIT = _Anonymous_52.TCP_CLOSE_WAIT;
    enum TCP_LAST_ACK = _Anonymous_52.TCP_LAST_ACK;
    enum TCP_LISTEN = _Anonymous_52.TCP_LISTEN;
    enum TCP_CLOSING = _Anonymous_52.TCP_CLOSING;
    alias mode_t = uint;
    alias gid_t = uint;
    alias dev_t = c_ulong;
    alias ino_t = c_ulong;
    alias loff_t = c_long;
    alias fsid_t = __fsid_t;
    alias u_quad_t = c_ulong;
    alias quad_t = c_long;
    alias u_long = c_ulong;
    alias u_int = uint;
    alias u_short = ushort;
    alias u_char = ubyte;
    int futimes(int, const(timeval)*) @nogc nothrow;
    enum tcp_ca_state
    {
        TCP_CA_Open = 0,
        TCP_CA_Disorder = 1,
        TCP_CA_CWR = 2,
        TCP_CA_Recovery = 3,
        TCP_CA_Loss = 4,
    }
    enum TCP_CA_Open = tcp_ca_state.TCP_CA_Open;
    enum TCP_CA_Disorder = tcp_ca_state.TCP_CA_Disorder;
    enum TCP_CA_CWR = tcp_ca_state.TCP_CA_CWR;
    enum TCP_CA_Recovery = tcp_ca_state.TCP_CA_Recovery;
    enum TCP_CA_Loss = tcp_ca_state.TCP_CA_Loss;
    struct tcp_info
    {
        import std.bitmanip: bitfields;

        align(4):
        ubyte tcpi_state;
        ubyte tcpi_ca_state;
        ubyte tcpi_retransmits;
        ubyte tcpi_probes;
        ubyte tcpi_backoff;
        ubyte tcpi_options;
        mixin(bitfields!(
            ubyte, "tcpi_snd_wscale", 4,
            ubyte, "tcpi_rcv_wscale", 4,
        ));
        uint tcpi_rto;
        uint tcpi_ato;
        uint tcpi_snd_mss;
        uint tcpi_rcv_mss;
        uint tcpi_unacked;
        uint tcpi_sacked;
        uint tcpi_lost;
        uint tcpi_retrans;
        uint tcpi_fackets;
        uint tcpi_last_data_sent;
        uint tcpi_last_ack_sent;
        uint tcpi_last_data_recv;
        uint tcpi_last_ack_recv;
        uint tcpi_pmtu;
        uint tcpi_rcv_ssthresh;
        uint tcpi_rtt;
        uint tcpi_rttvar;
        uint tcpi_snd_ssthresh;
        uint tcpi_snd_cwnd;
        uint tcpi_advmss;
        uint tcpi_reordering;
        uint tcpi_rcv_rtt;
        uint tcpi_rcv_space;
        uint tcpi_total_retrans;
    }
    int lutimes(const(char)*, const(timeval)*) @nogc nothrow;
    struct tcp_md5sig
    {
        sockaddr_storage tcpm_addr;
        ubyte tcpm_flags;
        ubyte tcpm_prefixlen;
        ushort tcpm_keylen;
        uint __tcpm_pad;
        ubyte[80] tcpm_key;
    }
    struct tcp_repair_opt
    {
        uint opt_code;
        uint opt_val;
    }
    enum _Anonymous_53
    {
        TCP_NO_QUEUE = 0,
        TCP_RECV_QUEUE = 1,
        TCP_SEND_QUEUE = 2,
        TCP_QUEUES_NR = 3,
    }
    enum TCP_NO_QUEUE = _Anonymous_53.TCP_NO_QUEUE;
    enum TCP_RECV_QUEUE = _Anonymous_53.TCP_RECV_QUEUE;
    enum TCP_SEND_QUEUE = _Anonymous_53.TCP_SEND_QUEUE;
    enum TCP_QUEUES_NR = _Anonymous_53.TCP_QUEUES_NR;
    int utimes(const(char)*, const(timeval)*) @nogc nothrow;
    int setitimer(int, const(itimerval)*, itimerval*) @nogc nothrow;
    int getitimer(int, itimerval*) @nogc nothrow;
    alias __itimer_which_t = int;
    struct tcp_cookie_transactions
    {
        ushort tcpct_flags;
        ubyte __tcpct_pad1;
        ubyte tcpct_cookie_desired;
        ushort tcpct_s_data_desired;
        ushort tcpct_used;
        ubyte[536] tcpct_value;
    }
    struct tcp_repair_window
    {
        uint snd_wl1;
        uint snd_wnd;
        uint max_window;
        uint rcv_wnd;
        uint rcv_wup;
    }
    struct tcp_zerocopy_receive
    {
        c_ulong address;
        uint length;
        uint recv_skip_hint;
    }
    struct itimerval
    {
        timeval it_interval;
        timeval it_value;
    }
    enum _Anonymous_54
    {
        PTHREAD_CREATE_JOINABLE = 0,
        PTHREAD_CREATE_DETACHED = 1,
    }
    enum PTHREAD_CREATE_JOINABLE = _Anonymous_54.PTHREAD_CREATE_JOINABLE;
    enum PTHREAD_CREATE_DETACHED = _Anonymous_54.PTHREAD_CREATE_DETACHED;
    enum __itimer_which
    {
        ITIMER_REAL = 0,
        ITIMER_VIRTUAL = 1,
        ITIMER_PROF = 2,
    }
    enum ITIMER_REAL = __itimer_which.ITIMER_REAL;
    enum ITIMER_VIRTUAL = __itimer_which.ITIMER_VIRTUAL;
    enum ITIMER_PROF = __itimer_which.ITIMER_PROF;
    enum _Anonymous_55
    {
        PTHREAD_MUTEX_TIMED_NP = 0,
        PTHREAD_MUTEX_RECURSIVE_NP = 1,
        PTHREAD_MUTEX_ERRORCHECK_NP = 2,
        PTHREAD_MUTEX_ADAPTIVE_NP = 3,
        PTHREAD_MUTEX_NORMAL = 0,
        PTHREAD_MUTEX_RECURSIVE = 1,
        PTHREAD_MUTEX_ERRORCHECK = 2,
        PTHREAD_MUTEX_DEFAULT = 0,
    }
    enum PTHREAD_MUTEX_TIMED_NP = _Anonymous_55.PTHREAD_MUTEX_TIMED_NP;
    enum PTHREAD_MUTEX_RECURSIVE_NP = _Anonymous_55.PTHREAD_MUTEX_RECURSIVE_NP;
    enum PTHREAD_MUTEX_ERRORCHECK_NP = _Anonymous_55.PTHREAD_MUTEX_ERRORCHECK_NP;
    enum PTHREAD_MUTEX_ADAPTIVE_NP = _Anonymous_55.PTHREAD_MUTEX_ADAPTIVE_NP;
    enum PTHREAD_MUTEX_NORMAL = _Anonymous_55.PTHREAD_MUTEX_NORMAL;
    enum PTHREAD_MUTEX_RECURSIVE = _Anonymous_55.PTHREAD_MUTEX_RECURSIVE;
    enum PTHREAD_MUTEX_ERRORCHECK = _Anonymous_55.PTHREAD_MUTEX_ERRORCHECK;
    enum PTHREAD_MUTEX_DEFAULT = _Anonymous_55.PTHREAD_MUTEX_DEFAULT;
    enum _Anonymous_56
    {
        PTHREAD_MUTEX_STALLED = 0,
        PTHREAD_MUTEX_STALLED_NP = 0,
        PTHREAD_MUTEX_ROBUST = 1,
        PTHREAD_MUTEX_ROBUST_NP = 1,
    }
    enum PTHREAD_MUTEX_STALLED = _Anonymous_56.PTHREAD_MUTEX_STALLED;
    enum PTHREAD_MUTEX_STALLED_NP = _Anonymous_56.PTHREAD_MUTEX_STALLED_NP;
    enum PTHREAD_MUTEX_ROBUST = _Anonymous_56.PTHREAD_MUTEX_ROBUST;
    enum PTHREAD_MUTEX_ROBUST_NP = _Anonymous_56.PTHREAD_MUTEX_ROBUST_NP;
    enum _Anonymous_57
    {
        PTHREAD_PRIO_NONE = 0,
        PTHREAD_PRIO_INHERIT = 1,
        PTHREAD_PRIO_PROTECT = 2,
    }
    enum PTHREAD_PRIO_NONE = _Anonymous_57.PTHREAD_PRIO_NONE;
    enum PTHREAD_PRIO_INHERIT = _Anonymous_57.PTHREAD_PRIO_INHERIT;
    enum PTHREAD_PRIO_PROTECT = _Anonymous_57.PTHREAD_PRIO_PROTECT;
    int adjtime(const(timeval)*, timeval*) @nogc nothrow;
    enum _Anonymous_58
    {
        PTHREAD_RWLOCK_PREFER_READER_NP = 0,
        PTHREAD_RWLOCK_PREFER_WRITER_NP = 1,
        PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP = 2,
        PTHREAD_RWLOCK_DEFAULT_NP = 0,
    }
    enum PTHREAD_RWLOCK_PREFER_READER_NP = _Anonymous_58.PTHREAD_RWLOCK_PREFER_READER_NP;
    enum PTHREAD_RWLOCK_PREFER_WRITER_NP = _Anonymous_58.PTHREAD_RWLOCK_PREFER_WRITER_NP;
    enum PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP = _Anonymous_58.PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP;
    enum PTHREAD_RWLOCK_DEFAULT_NP = _Anonymous_58.PTHREAD_RWLOCK_DEFAULT_NP;
    enum _Anonymous_59
    {
        PTHREAD_INHERIT_SCHED = 0,
        PTHREAD_EXPLICIT_SCHED = 1,
    }
    enum PTHREAD_INHERIT_SCHED = _Anonymous_59.PTHREAD_INHERIT_SCHED;
    enum PTHREAD_EXPLICIT_SCHED = _Anonymous_59.PTHREAD_EXPLICIT_SCHED;
    int settimeofday(const(timeval)*, const(timezone)*) @nogc nothrow;
    enum _Anonymous_60
    {
        PTHREAD_SCOPE_SYSTEM = 0,
        PTHREAD_SCOPE_PROCESS = 1,
    }
    enum PTHREAD_SCOPE_SYSTEM = _Anonymous_60.PTHREAD_SCOPE_SYSTEM;
    enum PTHREAD_SCOPE_PROCESS = _Anonymous_60.PTHREAD_SCOPE_PROCESS;
    enum _Anonymous_61
    {
        PTHREAD_PROCESS_PRIVATE = 0,
        PTHREAD_PROCESS_SHARED = 1,
    }
    enum PTHREAD_PROCESS_PRIVATE = _Anonymous_61.PTHREAD_PROCESS_PRIVATE;
    enum PTHREAD_PROCESS_SHARED = _Anonymous_61.PTHREAD_PROCESS_SHARED;
    int gettimeofday(timeval*, void*) @nogc nothrow;
    struct timezone
    {
        int tz_minuteswest;
        int tz_dsttime;
    }
    struct _pthread_cleanup_buffer
    {
        void function(void*) __routine;
        void* __arg;
        int __canceltype;
        _pthread_cleanup_buffer* __prev;
    }
    enum _Anonymous_62
    {
        PTHREAD_CANCEL_ENABLE = 0,
        PTHREAD_CANCEL_DISABLE = 1,
    }
    enum PTHREAD_CANCEL_ENABLE = _Anonymous_62.PTHREAD_CANCEL_ENABLE;
    enum PTHREAD_CANCEL_DISABLE = _Anonymous_62.PTHREAD_CANCEL_DISABLE;
    enum _Anonymous_63
    {
        PTHREAD_CANCEL_DEFERRED = 0,
        PTHREAD_CANCEL_ASYNCHRONOUS = 1,
    }
    enum PTHREAD_CANCEL_DEFERRED = _Anonymous_63.PTHREAD_CANCEL_DEFERRED;
    enum PTHREAD_CANCEL_ASYNCHRONOUS = _Anonymous_63.PTHREAD_CANCEL_ASYNCHRONOUS;
    int pthread_create(c_ulong*, const(pthread_attr_t)*, void* function(void*), void*) @nogc nothrow;
    void pthread_exit(void*) @nogc nothrow;
    int pthread_join(c_ulong, void**) @nogc nothrow;
    int pthread_detach(c_ulong) @nogc nothrow;
    c_ulong pthread_self() @nogc nothrow;
    int pthread_equal(c_ulong, c_ulong) @nogc nothrow;
    int pthread_attr_init(pthread_attr_t*) @nogc nothrow;
    int pthread_attr_destroy(pthread_attr_t*) @nogc nothrow;
    int pthread_attr_getdetachstate(const(pthread_attr_t)*, int*) @nogc nothrow;
    int pthread_attr_setdetachstate(pthread_attr_t*, int) @nogc nothrow;
    int pthread_attr_getguardsize(const(pthread_attr_t)*, c_ulong*) @nogc nothrow;
    int pthread_attr_setguardsize(pthread_attr_t*, c_ulong) @nogc nothrow;
    int pthread_attr_getschedparam(const(pthread_attr_t)*, sched_param*) @nogc nothrow;
    int pthread_attr_setschedparam(pthread_attr_t*, const(sched_param)*) @nogc nothrow;
    int pthread_attr_getschedpolicy(const(pthread_attr_t)*, int*) @nogc nothrow;
    int pthread_attr_setschedpolicy(pthread_attr_t*, int) @nogc nothrow;
    int pthread_attr_getinheritsched(const(pthread_attr_t)*, int*) @nogc nothrow;
    int pthread_attr_setinheritsched(pthread_attr_t*, int) @nogc nothrow;
    int pthread_attr_getscope(const(pthread_attr_t)*, int*) @nogc nothrow;
    int pthread_attr_setscope(pthread_attr_t*, int) @nogc nothrow;
    int pthread_attr_getstackaddr(const(pthread_attr_t)*, void**) @nogc nothrow;
    int pthread_attr_setstackaddr(pthread_attr_t*, void*) @nogc nothrow;
    int pthread_attr_getstacksize(const(pthread_attr_t)*, c_ulong*) @nogc nothrow;
    int pthread_attr_setstacksize(pthread_attr_t*, c_ulong) @nogc nothrow;
    int pthread_attr_getstack(const(pthread_attr_t)*, void**, c_ulong*) @nogc nothrow;
    int pthread_attr_setstack(pthread_attr_t*, void*, c_ulong) @nogc nothrow;
    int pthread_setschedparam(c_ulong, int, const(sched_param)*) @nogc nothrow;
    int pthread_getschedparam(c_ulong, int*, sched_param*) @nogc nothrow;
    int pthread_setschedprio(c_ulong, int) @nogc nothrow;
    int pthread_once(int*, void function()) @nogc nothrow;
    int pthread_setcancelstate(int, int*) @nogc nothrow;
    int pthread_setcanceltype(int, int*) @nogc nothrow;
    int pthread_cancel(c_ulong) @nogc nothrow;
    void pthread_testcancel() @nogc nothrow;
    struct __pthread_unwind_buf_t
    {
        static struct _Anonymous_64
        {
            c_long[8] __cancel_jmp_buf;
            int __mask_was_saved;
        }
        _Anonymous_64[1] __cancel_jmp_buf;
        void*[4] __pad;
    }
    struct __pthread_cleanup_frame
    {
        void function(void*) __cancel_routine;
        void* __cancel_arg;
        int __do_it;
        int __cancel_type;
    }
    void __pthread_register_cancel(__pthread_unwind_buf_t*) @nogc nothrow;
    void __pthread_unregister_cancel(__pthread_unwind_buf_t*) @nogc nothrow;
    void __pthread_unwind_next(__pthread_unwind_buf_t*) @nogc nothrow;
    int pthread_mutex_init(pthread_mutex_t*, const(pthread_mutexattr_t)*) @nogc nothrow;
    int pthread_mutex_destroy(pthread_mutex_t*) @nogc nothrow;
    int pthread_mutex_trylock(pthread_mutex_t*) @nogc nothrow;
    int pthread_mutex_lock(pthread_mutex_t*) @nogc nothrow;
    int pthread_mutex_timedlock(pthread_mutex_t*, const(timespec)*) @nogc nothrow;
    int pthread_mutex_unlock(pthread_mutex_t*) @nogc nothrow;
    int pthread_mutex_getprioceiling(const(pthread_mutex_t)*, int*) @nogc nothrow;
    int pthread_mutex_setprioceiling(pthread_mutex_t*, int, int*) @nogc nothrow;
    int pthread_mutex_consistent(pthread_mutex_t*) @nogc nothrow;
    int pthread_mutexattr_init(pthread_mutexattr_t*) @nogc nothrow;
    int pthread_mutexattr_destroy(pthread_mutexattr_t*) @nogc nothrow;
    int pthread_mutexattr_getpshared(const(pthread_mutexattr_t)*, int*) @nogc nothrow;
    int pthread_mutexattr_setpshared(pthread_mutexattr_t*, int) @nogc nothrow;
    int pthread_mutexattr_gettype(const(pthread_mutexattr_t)*, int*) @nogc nothrow;
    int pthread_mutexattr_settype(pthread_mutexattr_t*, int) @nogc nothrow;
    int pthread_mutexattr_getprotocol(const(pthread_mutexattr_t)*, int*) @nogc nothrow;
    int pthread_mutexattr_setprotocol(pthread_mutexattr_t*, int) @nogc nothrow;
    int pthread_mutexattr_getprioceiling(const(pthread_mutexattr_t)*, int*) @nogc nothrow;
    int pthread_mutexattr_setprioceiling(pthread_mutexattr_t*, int) @nogc nothrow;
    int pthread_mutexattr_getrobust(const(pthread_mutexattr_t)*, int*) @nogc nothrow;
    int pthread_mutexattr_setrobust(pthread_mutexattr_t*, int) @nogc nothrow;
    int pthread_rwlock_init(pthread_rwlock_t*, const(pthread_rwlockattr_t)*) @nogc nothrow;
    int pthread_rwlock_destroy(pthread_rwlock_t*) @nogc nothrow;
    int pthread_rwlock_rdlock(pthread_rwlock_t*) @nogc nothrow;
    int pthread_rwlock_tryrdlock(pthread_rwlock_t*) @nogc nothrow;
    int pthread_rwlock_timedrdlock(pthread_rwlock_t*, const(timespec)*) @nogc nothrow;
    int pthread_rwlock_wrlock(pthread_rwlock_t*) @nogc nothrow;
    int pthread_rwlock_trywrlock(pthread_rwlock_t*) @nogc nothrow;
    int pthread_rwlock_timedwrlock(pthread_rwlock_t*, const(timespec)*) @nogc nothrow;
    int pthread_rwlock_unlock(pthread_rwlock_t*) @nogc nothrow;
    int pthread_rwlockattr_init(pthread_rwlockattr_t*) @nogc nothrow;
    int pthread_rwlockattr_destroy(pthread_rwlockattr_t*) @nogc nothrow;
    int pthread_rwlockattr_getpshared(const(pthread_rwlockattr_t)*, int*) @nogc nothrow;
    int pthread_rwlockattr_setpshared(pthread_rwlockattr_t*, int) @nogc nothrow;
    int pthread_rwlockattr_getkind_np(const(pthread_rwlockattr_t)*, int*) @nogc nothrow;
    int pthread_rwlockattr_setkind_np(pthread_rwlockattr_t*, int) @nogc nothrow;
    int pthread_cond_init(pthread_cond_t*, const(pthread_condattr_t)*) @nogc nothrow;
    int pthread_cond_destroy(pthread_cond_t*) @nogc nothrow;
    int pthread_cond_signal(pthread_cond_t*) @nogc nothrow;
    int pthread_cond_broadcast(pthread_cond_t*) @nogc nothrow;
    int pthread_cond_wait(pthread_cond_t*, pthread_mutex_t*) @nogc nothrow;
    int pthread_cond_timedwait(pthread_cond_t*, pthread_mutex_t*, const(timespec)*) @nogc nothrow;
    int pthread_condattr_init(pthread_condattr_t*) @nogc nothrow;
    int pthread_condattr_destroy(pthread_condattr_t*) @nogc nothrow;
    int pthread_condattr_getpshared(const(pthread_condattr_t)*, int*) @nogc nothrow;
    int pthread_condattr_setpshared(pthread_condattr_t*, int) @nogc nothrow;
    int pthread_condattr_getclock(const(pthread_condattr_t)*, int*) @nogc nothrow;
    int pthread_condattr_setclock(pthread_condattr_t*, int) @nogc nothrow;
    int pthread_spin_init(int*, int) @nogc nothrow;
    int pthread_spin_destroy(int*) @nogc nothrow;
    int pthread_spin_lock(int*) @nogc nothrow;
    int pthread_spin_trylock(int*) @nogc nothrow;
    int pthread_spin_unlock(int*) @nogc nothrow;
    int pthread_barrier_init(pthread_barrier_t*, const(pthread_barrierattr_t)*, uint) @nogc nothrow;
    int pthread_barrier_destroy(pthread_barrier_t*) @nogc nothrow;
    int pthread_barrier_wait(pthread_barrier_t*) @nogc nothrow;
    int pthread_barrierattr_init(pthread_barrierattr_t*) @nogc nothrow;
    int pthread_barrierattr_destroy(pthread_barrierattr_t*) @nogc nothrow;
    int pthread_barrierattr_getpshared(const(pthread_barrierattr_t)*, int*) @nogc nothrow;
    int pthread_barrierattr_setpshared(pthread_barrierattr_t*, int) @nogc nothrow;
    int pthread_key_create(uint*, void function(void*)) @nogc nothrow;
    int pthread_key_delete(uint) @nogc nothrow;
    void* pthread_getspecific(uint) @nogc nothrow;
    int pthread_setspecific(uint, const(void)*) @nogc nothrow;
    int pthread_getcpuclockid(c_ulong, int*) @nogc nothrow;
    int pthread_atfork(void function(), void function(), void function()) @nogc nothrow;
    void vsyslog(int, const(char)*, va_list*) @nogc nothrow;
    struct passwd
    {
        char* pw_name;
        char* pw_passwd;
        uint pw_uid;
        uint pw_gid;
        char* pw_gecos;
        char* pw_dir;
        char* pw_shell;
    }
    void setpwent() @nogc nothrow;
    void endpwent() @nogc nothrow;
    passwd* getpwent() @nogc nothrow;
    passwd* fgetpwent(_IO_FILE*) @nogc nothrow;
    int putpwent(const(passwd)*, _IO_FILE*) @nogc nothrow;
    passwd* getpwuid(uint) @nogc nothrow;
    passwd* getpwnam(const(char)*) @nogc nothrow;
    void syslog(int, const(char)*, ...) @nogc nothrow;
    int getpwent_r(passwd*, char*, c_ulong, passwd**) @nogc nothrow;
    int getpwuid_r(uint, passwd*, char*, c_ulong, passwd**) @nogc nothrow;
    int getpwnam_r(const(char)*, passwd*, char*, c_ulong, passwd**) @nogc nothrow;
    int fgetpwent_r(_IO_FILE*, passwd*, char*, c_ulong, passwd**) @nogc nothrow;
    int setlogmask(int) @nogc nothrow;
    struct rpcent
    {
        char* r_name;
        char** r_aliases;
        int r_number;
    }
    void setrpcent(int) @nogc nothrow;
    void endrpcent() @nogc nothrow;
    rpcent* getrpcbyname(const(char)*) @nogc nothrow;
    rpcent* getrpcbynumber(int) @nogc nothrow;
    rpcent* getrpcent() @nogc nothrow;
    int getrpcbyname_r(const(char)*, rpcent*, char*, c_ulong, rpcent**) @nogc nothrow;
    int getrpcbynumber_r(int, rpcent*, char*, c_ulong, rpcent**) @nogc nothrow;
    int getrpcent_r(rpcent*, char*, c_ulong, rpcent**) @nogc nothrow;
    void openlog(const(char)*, int, int) @nogc nothrow;
    void closelog() @nogc nothrow;
    int sched_setparam(int, const(sched_param)*) @nogc nothrow;
    int sched_getparam(int, sched_param*) @nogc nothrow;
    int sched_setscheduler(int, int, const(sched_param)*) @nogc nothrow;
    int sched_getscheduler(int) @nogc nothrow;
    int sched_yield() @nogc nothrow;
    int sched_get_priority_max(int) @nogc nothrow;
    int sched_get_priority_min(int) @nogc nothrow;
    int sched_rr_get_interval(int, timespec*) @nogc nothrow;
    struct __jmp_buf_tag
    {
        c_long[8] __jmpbuf;
        int __mask_was_saved;
        __sigset_t __saved_mask;
    }
    alias jmp_buf = __jmp_buf_tag[1];
    pragma(mangle, "setjmp") int setjmp_(__jmp_buf_tag*) @nogc nothrow;
    int __sigsetjmp(__jmp_buf_tag*, int) @nogc nothrow;
    int _setjmp(__jmp_buf_tag*) @nogc nothrow;
    void longjmp(__jmp_buf_tag*, int) @nogc nothrow;
    void _longjmp(__jmp_buf_tag*, int) @nogc nothrow;
    alias sigjmp_buf = __jmp_buf_tag[1];
    void siglongjmp(__jmp_buf_tag*, int) @nogc nothrow;
    alias __sighandler_t = void function(int);
    void function(int) __sysv_signal(int, void function(int)) @nogc nothrow;
    void function(int) signal(int, void function(int)) @nogc nothrow;
    int kill(int, int) @nogc nothrow;
    int killpg(int, int) @nogc nothrow;
    int raise(int) @nogc nothrow;
    void function(int) ssignal(int, void function(int)) @nogc nothrow;
    int gsignal(int) @nogc nothrow;
    void psignal(int, const(char)*) @nogc nothrow;
    void psiginfo(const(siginfo_t)*, const(char)*) @nogc nothrow;
    int __xmknodat(int, int, const(char)*, uint, c_ulong*) @nogc nothrow;
    int sigblock(int) @nogc nothrow;
    int sigsetmask(int) @nogc nothrow;
    int siggetmask() @nogc nothrow;
    alias sig_t = void function(int);
    int sigemptyset(__sigset_t*) @nogc nothrow;
    int sigfillset(__sigset_t*) @nogc nothrow;
    int sigaddset(__sigset_t*, int) @nogc nothrow;
    int sigdelset(__sigset_t*, int) @nogc nothrow;
    int sigismember(const(__sigset_t)*, int) @nogc nothrow;
    int sigprocmask(int, const(__sigset_t)*, __sigset_t*) @nogc nothrow;
    int sigsuspend(const(__sigset_t)*) @nogc nothrow;
    pragma(mangle, "sigaction") int sigaction_(int, const(sigaction)*, sigaction*) @nogc nothrow;
    int sigpending(__sigset_t*) @nogc nothrow;
    int sigwait(const(__sigset_t)*, int*) @nogc nothrow;
    int sigwaitinfo(const(__sigset_t)*, siginfo_t*) @nogc nothrow;
    int sigtimedwait(const(__sigset_t)*, siginfo_t*, const(timespec)*) @nogc nothrow;
    int sigqueue(int, int, const(sigval)) @nogc nothrow;
    extern __gshared const(const(char)*)[65] _sys_siglist;
    extern __gshared const(const(char)*)[65] sys_siglist;
    int sigreturn(sigcontext*) @nogc nothrow;
    int siginterrupt(int, int) @nogc nothrow;
    int sigaltstack(const(stack_t)*, stack_t*) @nogc nothrow;
    pragma(mangle, "sigstack") int sigstack_(sigstack*, sigstack*) @nogc nothrow;
    int __libc_current_sigrtmin() @nogc nothrow;
    int __libc_current_sigrtmax() @nogc nothrow;
    int __xmknod(int, const(char)*, uint, c_ulong*) @nogc nothrow;
    int __fxstatat(int, int, const(char)*, stat*, int) @nogc nothrow;
    int __lxstat(int, const(char)*, stat*) @nogc nothrow;
    alias int_least8_t = byte;
    alias int_least16_t = short;
    alias int_least32_t = int;
    alias int_least64_t = c_long;
    alias uint_least8_t = ubyte;
    alias uint_least16_t = ushort;
    alias uint_least32_t = uint;
    alias uint_least64_t = c_ulong;
    alias int_fast8_t = byte;
    alias int_fast16_t = c_long;
    alias int_fast32_t = c_long;
    alias int_fast64_t = c_long;
    alias uint_fast8_t = ubyte;
    alias uint_fast16_t = c_ulong;
    alias uint_fast32_t = c_ulong;
    alias uint_fast64_t = c_ulong;
    alias intptr_t = c_long;
    alias uintptr_t = c_ulong;
    alias intmax_t = c_long;
    alias uintmax_t = c_ulong;
    int __xstat(int, const(char)*, stat*) @nogc nothrow;
    int __fxstat(int, int, stat*) @nogc nothrow;
    int futimens(int, const(timespec)*) @nogc nothrow;
    int utimensat(int, const(char)*, const(timespec)*, int) @nogc nothrow;
    int mkfifoat(int, const(char)*, uint) @nogc nothrow;
    int mkfifo(const(char)*, uint) @nogc nothrow;
    int mknodat(int, const(char)*, uint, c_ulong) @nogc nothrow;
    int mknod(const(char)*, uint, c_ulong) @nogc nothrow;
    int mkdirat(int, const(char)*, uint) @nogc nothrow;
    int mkdir(const(char)*, uint) @nogc nothrow;
    uint umask(uint) @nogc nothrow;
    int fchmodat(int, const(char)*, uint, int) @nogc nothrow;
    int fchmod(int, uint) @nogc nothrow;
    int lchmod(const(char)*, uint) @nogc nothrow;
    int chmod(const(char)*, uint) @nogc nothrow;
    int lstat(const(char)*, stat*) @nogc nothrow;
    int fstatat(int, const(char)*, stat*, int) @nogc nothrow;
    int fstat(int, stat*) @nogc nothrow;
    pragma(mangle, "stat") int stat_(const(char)*, stat*) @nogc nothrow;
    alias off_t = c_long;
    alias ssize_t = c_long;
    alias fpos_t = _G_fpos_t;
    extern __gshared _IO_FILE* stdin;
    extern __gshared _IO_FILE* stdout;
    extern __gshared _IO_FILE* stderr;
    int remove(const(char)*) @nogc nothrow;
    int rename(const(char)*, const(char)*) @nogc nothrow;
    int renameat(int, const(char)*, int, const(char)*) @nogc nothrow;
    _IO_FILE* tmpfile() @nogc nothrow;
    char* tmpnam(char*) @nogc nothrow;
    char* tmpnam_r(char*) @nogc nothrow;
    char* tempnam(const(char)*, const(char)*) @nogc nothrow;
    int fclose(_IO_FILE*) @nogc nothrow;
    int fflush(_IO_FILE*) @nogc nothrow;
    int fflush_unlocked(_IO_FILE*) @nogc nothrow;
    _IO_FILE* fopen(const(char)*, const(char)*) @nogc nothrow;
    _IO_FILE* freopen(const(char)*, const(char)*, _IO_FILE*) @nogc nothrow;
    _IO_FILE* fdopen(int, const(char)*) @nogc nothrow;
    _IO_FILE* fmemopen(void*, c_ulong, const(char)*) @nogc nothrow;
    _IO_FILE* open_memstream(char**, c_ulong*) @nogc nothrow;
    void setbuf(_IO_FILE*, char*) @nogc nothrow;
    int setvbuf(_IO_FILE*, char*, int, c_ulong) @nogc nothrow;
    void setbuffer(_IO_FILE*, char*, c_ulong) @nogc nothrow;
    void setlinebuf(_IO_FILE*) @nogc nothrow;
    int fprintf(_IO_FILE*, const(char)*, ...) @nogc nothrow;
    int printf(const(char)*, ...) @nogc nothrow;
    int sprintf(char*, const(char)*, ...) @nogc nothrow;
    int vfprintf(_IO_FILE*, const(char)*, va_list*) @nogc nothrow;
    int vprintf(const(char)*, va_list*) @nogc nothrow;
    int vsprintf(char*, const(char)*, va_list*) @nogc nothrow;
    int snprintf(char*, c_ulong, const(char)*, ...) @nogc nothrow;
    int vsnprintf(char*, c_ulong, const(char)*, va_list*) @nogc nothrow;
    int vdprintf(int, const(char)*, va_list*) @nogc nothrow;
    int dprintf(int, const(char)*, ...) @nogc nothrow;
    int fscanf(_IO_FILE*, const(char)*, ...) @nogc nothrow;
    int scanf(const(char)*, ...) @nogc nothrow;
    int sscanf(const(char)*, const(char)*, ...) @nogc nothrow;
    int vfscanf(_IO_FILE*, const(char)*, va_list*) @nogc nothrow;
    int vscanf(const(char)*, va_list*) @nogc nothrow;
    int vsscanf(const(char)*, const(char)*, va_list*) @nogc nothrow;
    int fgetc(_IO_FILE*) @nogc nothrow;
    int getc(_IO_FILE*) @nogc nothrow;
    int getchar() @nogc nothrow;
    int getc_unlocked(_IO_FILE*) @nogc nothrow;
    int getchar_unlocked() @nogc nothrow;
    int fgetc_unlocked(_IO_FILE*) @nogc nothrow;
    int fputc(int, _IO_FILE*) @nogc nothrow;
    int putc(int, _IO_FILE*) @nogc nothrow;
    int putchar(int) @nogc nothrow;
    int fputc_unlocked(int, _IO_FILE*) @nogc nothrow;
    int putc_unlocked(int, _IO_FILE*) @nogc nothrow;
    int putchar_unlocked(int) @nogc nothrow;
    int getw(_IO_FILE*) @nogc nothrow;
    int putw(int, _IO_FILE*) @nogc nothrow;
    char* fgets(char*, int, _IO_FILE*) @nogc nothrow;
    c_long __getdelim(char**, c_ulong*, int, _IO_FILE*) @nogc nothrow;
    c_long getdelim(char**, c_ulong*, int, _IO_FILE*) @nogc nothrow;
    c_long getline(char**, c_ulong*, _IO_FILE*) @nogc nothrow;
    int fputs(const(char)*, _IO_FILE*) @nogc nothrow;
    int puts(const(char)*) @nogc nothrow;
    int ungetc(int, _IO_FILE*) @nogc nothrow;
    c_ulong fread(void*, c_ulong, c_ulong, _IO_FILE*) @nogc nothrow;
    c_ulong fwrite(const(void)*, c_ulong, c_ulong, _IO_FILE*) @nogc nothrow;
    c_ulong fread_unlocked(void*, c_ulong, c_ulong, _IO_FILE*) @nogc nothrow;
    c_ulong fwrite_unlocked(const(void)*, c_ulong, c_ulong, _IO_FILE*) @nogc nothrow;
    int fseek(_IO_FILE*, c_long, int) @nogc nothrow;
    c_long ftell(_IO_FILE*) @nogc nothrow;
    void rewind(_IO_FILE*) @nogc nothrow;
    int fseeko(_IO_FILE*, c_long, int) @nogc nothrow;
    c_long ftello(_IO_FILE*) @nogc nothrow;
    int fgetpos(_IO_FILE*, _G_fpos_t*) @nogc nothrow;
    int fsetpos(_IO_FILE*, const(_G_fpos_t)*) @nogc nothrow;
    void clearerr(_IO_FILE*) @nogc nothrow;
    int feof(_IO_FILE*) @nogc nothrow;
    int ferror(_IO_FILE*) @nogc nothrow;
    void clearerr_unlocked(_IO_FILE*) @nogc nothrow;
    int feof_unlocked(_IO_FILE*) @nogc nothrow;
    int ferror_unlocked(_IO_FILE*) @nogc nothrow;
    void perror(const(char)*) @nogc nothrow;
    int fileno(_IO_FILE*) @nogc nothrow;
    int fileno_unlocked(_IO_FILE*) @nogc nothrow;
    _IO_FILE* popen(const(char)*, const(char)*) @nogc nothrow;
    int pclose(_IO_FILE*) @nogc nothrow;
    char* ctermid(char*) @nogc nothrow;
    void flockfile(_IO_FILE*) @nogc nothrow;
    int ftrylockfile(_IO_FILE*) @nogc nothrow;
    void funlockfile(_IO_FILE*) @nogc nothrow;
    int __uflow(_IO_FILE*) @nogc nothrow;
    int __overflow(_IO_FILE*, int) @nogc nothrow;
    struct div_t
    {
        int quot;
        int rem;
    }
    struct ldiv_t
    {
        c_long quot;
        c_long rem;
    }
    struct lldiv_t
    {
        long quot;
        long rem;
    }
    int isfdtype(int, int) @nogc nothrow;
    c_ulong __ctype_get_mb_cur_max() @nogc nothrow;
    double atof(const(char)*) @nogc nothrow;
    int atoi(const(char)*) @nogc nothrow;
    c_long atol(const(char)*) @nogc nothrow;
    long atoll(const(char)*) @nogc nothrow;
    double strtod(const(char)*, char**) @nogc nothrow;
    float strtof(const(char)*, char**) @nogc nothrow;
    real strtold(const(char)*, char**) @nogc nothrow;
    c_long strtol(const(char)*, char**, int) @nogc nothrow;
    c_ulong strtoul(const(char)*, char**, int) @nogc nothrow;
    long strtoq(const(char)*, char**, int) @nogc nothrow;
    ulong strtouq(const(char)*, char**, int) @nogc nothrow;
    long strtoll(const(char)*, char**, int) @nogc nothrow;
    ulong strtoull(const(char)*, char**, int) @nogc nothrow;
    char* l64a(c_long) @nogc nothrow;
    c_long a64l(const(char)*) @nogc nothrow;
    c_long random() @nogc nothrow;
    void srandom(uint) @nogc nothrow;
    char* initstate(uint, char*, c_ulong) @nogc nothrow;
    char* setstate(char*) @nogc nothrow;
    struct random_data
    {
        int* fptr;
        int* rptr;
        int* state;
        int rand_type;
        int rand_deg;
        int rand_sep;
        int* end_ptr;
    }
    int random_r(random_data*, int*) @nogc nothrow;
    int srandom_r(uint, random_data*) @nogc nothrow;
    int initstate_r(uint, char*, c_ulong, random_data*) @nogc nothrow;
    int setstate_r(char*, random_data*) @nogc nothrow;
    int rand() @nogc nothrow;
    void srand(uint) @nogc nothrow;
    int rand_r(uint*) @nogc nothrow;
    double drand48() @nogc nothrow;
    double erand48(ushort*) @nogc nothrow;
    c_long lrand48() @nogc nothrow;
    c_long nrand48(ushort*) @nogc nothrow;
    c_long mrand48() @nogc nothrow;
    c_long jrand48(ushort*) @nogc nothrow;
    void srand48(c_long) @nogc nothrow;
    ushort* seed48(ushort*) @nogc nothrow;
    void lcong48(ushort*) @nogc nothrow;
    struct drand48_data
    {
        ushort[3] __x;
        ushort[3] __old_x;
        ushort __c;
        ushort __init;
        ulong __a;
    }
    int drand48_r(drand48_data*, double*) @nogc nothrow;
    int erand48_r(ushort*, drand48_data*, double*) @nogc nothrow;
    int lrand48_r(drand48_data*, c_long*) @nogc nothrow;
    int nrand48_r(ushort*, drand48_data*, c_long*) @nogc nothrow;
    int mrand48_r(drand48_data*, c_long*) @nogc nothrow;
    int jrand48_r(ushort*, drand48_data*, c_long*) @nogc nothrow;
    int srand48_r(c_long, drand48_data*) @nogc nothrow;
    int seed48_r(ushort*, drand48_data*) @nogc nothrow;
    int lcong48_r(ushort*, drand48_data*) @nogc nothrow;
    void* malloc(c_ulong) @nogc nothrow;
    void* calloc(c_ulong, c_ulong) @nogc nothrow;
    void* realloc(void*, c_ulong) @nogc nothrow;
    void* reallocarray(void*, c_ulong, c_ulong) @nogc nothrow;
    void free(void*) @nogc nothrow;
    void* valloc(c_ulong) @nogc nothrow;
    int posix_memalign(void**, c_ulong, c_ulong) @nogc nothrow;
    void* aligned_alloc(c_ulong, c_ulong) @nogc nothrow;
    void abort() @nogc nothrow;
    int atexit(void function()) @nogc nothrow;
    int at_quick_exit(void function()) @nogc nothrow;
    int on_exit(void function(int, void*), void*) @nogc nothrow;
    void exit(int) @nogc nothrow;
    void quick_exit(int) @nogc nothrow;
    void _Exit(int) @nogc nothrow;
    char* getenv(const(char)*) @nogc nothrow;
    int putenv(char*) @nogc nothrow;
    int setenv(const(char)*, const(char)*, int) @nogc nothrow;
    int unsetenv(const(char)*) @nogc nothrow;
    int clearenv() @nogc nothrow;
    char* mktemp(char*) @nogc nothrow;
    int mkstemp(char*) @nogc nothrow;
    int mkstemps(char*, int) @nogc nothrow;
    char* mkdtemp(char*) @nogc nothrow;
    int system(const(char)*) @nogc nothrow;
    char* realpath(const(char)*, char*) @nogc nothrow;
    alias __compar_fn_t = int function(const(void)*, const(void)*);
    void* bsearch(const(void)*, const(void)*, c_ulong, c_ulong, int function(const(void)*, const(void)*)) @nogc nothrow;
    void qsort(void*, c_ulong, c_ulong, int function(const(void)*, const(void)*)) @nogc nothrow;
    int abs(int) @nogc nothrow;
    c_long labs(c_long) @nogc nothrow;
    long llabs(long) @nogc nothrow;
    div_t div(int, int) @nogc nothrow;
    ldiv_t ldiv(c_long, c_long) @nogc nothrow;
    lldiv_t lldiv(long, long) @nogc nothrow;
    char* ecvt(double, int, int*, int*) @nogc nothrow;
    char* fcvt(double, int, int*, int*) @nogc nothrow;
    char* gcvt(double, int, char*) @nogc nothrow;
    char* qecvt(real, int, int*, int*) @nogc nothrow;
    char* qfcvt(real, int, int*, int*) @nogc nothrow;
    char* qgcvt(real, int, char*) @nogc nothrow;
    int ecvt_r(double, int, int*, int*, char*, c_ulong) @nogc nothrow;
    int fcvt_r(double, int, int*, int*, char*, c_ulong) @nogc nothrow;
    int qecvt_r(real, int, int*, int*, char*, c_ulong) @nogc nothrow;
    int qfcvt_r(real, int, int*, int*, char*, c_ulong) @nogc nothrow;
    int mblen(const(char)*, c_ulong) @nogc nothrow;
    int mbtowc(int*, const(char)*, c_ulong) @nogc nothrow;
    int wctomb(char*, int) @nogc nothrow;
    c_ulong mbstowcs(int*, const(char)*, c_ulong) @nogc nothrow;
    c_ulong wcstombs(char*, const(int)*, c_ulong) @nogc nothrow;
    int rpmatch(const(char)*) @nogc nothrow;
    int getsubopt(char**, char**, char**) @nogc nothrow;
    int getloadavg(double*, int) @nogc nothrow;
    int sockatmark(int) @nogc nothrow;
    int shutdown(int, int) @nogc nothrow;
    void* memcpy(void*, const(void)*, c_ulong) @nogc nothrow;
    void* memmove(void*, const(void)*, c_ulong) @nogc nothrow;
    void* memccpy(void*, const(void)*, int, c_ulong) @nogc nothrow;
    void* memset(void*, int, c_ulong) @nogc nothrow;
    int memcmp(const(void)*, const(void)*, c_ulong) @nogc nothrow;
    void* memchr(const(void)*, int, c_ulong) @nogc nothrow;
    char* strcpy(char*, const(char)*) @nogc nothrow;
    char* strncpy(char*, const(char)*, c_ulong) @nogc nothrow;
    char* strcat(char*, const(char)*) @nogc nothrow;
    char* strncat(char*, const(char)*, c_ulong) @nogc nothrow;
    int strcmp(const(char)*, const(char)*) @nogc nothrow;
    int strncmp(const(char)*, const(char)*, c_ulong) @nogc nothrow;
    int strcoll(const(char)*, const(char)*) @nogc nothrow;
    c_ulong strxfrm(char*, const(char)*, c_ulong) @nogc nothrow;
    int strcoll_l(const(char)*, const(char)*, __locale_struct*) @nogc nothrow;
    c_ulong strxfrm_l(char*, const(char)*, c_ulong, __locale_struct*) @nogc nothrow;
    char* strdup(const(char)*) @nogc nothrow;
    char* strndup(const(char)*, c_ulong) @nogc nothrow;
    char* strchr(const(char)*, int) @nogc nothrow;
    char* strrchr(const(char)*, int) @nogc nothrow;
    c_ulong strcspn(const(char)*, const(char)*) @nogc nothrow;
    c_ulong strspn(const(char)*, const(char)*) @nogc nothrow;
    char* strpbrk(const(char)*, const(char)*) @nogc nothrow;
    char* strstr(const(char)*, const(char)*) @nogc nothrow;
    char* strtok(char*, const(char)*) @nogc nothrow;
    char* __strtok_r(char*, const(char)*, char**) @nogc nothrow;
    char* strtok_r(char*, const(char)*, char**) @nogc nothrow;
    c_ulong strlen(const(char)*) @nogc nothrow;
    c_ulong strnlen(const(char)*, c_ulong) @nogc nothrow;
    char* strerror(int) @nogc nothrow;
    int strerror_r(int, char*, c_ulong) @nogc nothrow;
    char* strerror_l(int, __locale_struct*) @nogc nothrow;
    void explicit_bzero(void*, c_ulong) @nogc nothrow;
    char* strsep(char**, const(char)*) @nogc nothrow;
    char* strsignal(int) @nogc nothrow;
    char* __stpcpy(char*, const(char)*) @nogc nothrow;
    char* stpcpy(char*, const(char)*) @nogc nothrow;
    char* __stpncpy(char*, const(char)*, c_ulong) @nogc nothrow;
    char* stpncpy(char*, const(char)*, c_ulong) @nogc nothrow;
    int accept(int, sockaddr*, uint*) @nogc nothrow;
    int bcmp(const(void)*, const(void)*, c_ulong) @nogc nothrow;
    void bcopy(const(void)*, void*, c_ulong) @nogc nothrow;
    void bzero(void*, c_ulong) @nogc nothrow;
    char* index(const(char)*, int) @nogc nothrow;
    char* rindex(const(char)*, int) @nogc nothrow;
    int ffs(int) @nogc nothrow;
    int ffsl(c_long) @nogc nothrow;
    int ffsll(long) @nogc nothrow;
    int strcasecmp(const(char)*, const(char)*) @nogc nothrow;
    int strncasecmp(const(char)*, const(char)*, c_ulong) @nogc nothrow;
    int strcasecmp_l(const(char)*, const(char)*, __locale_struct*) @nogc nothrow;
    int strncasecmp_l(const(char)*, const(char)*, c_ulong, __locale_struct*) @nogc nothrow;
    int listen(int, int) @nogc nothrow;
    int setsockopt(int, int, int, const(void)*, uint) @nogc nothrow;
    int getsockopt(int, int, int, void*, uint*) @nogc nothrow;
    c_long recvmsg(int, msghdr*, int) @nogc nothrow;
    c_long sendmsg(int, const(msghdr)*, int) @nogc nothrow;
    c_long recvfrom(int, void*, c_ulong, int, sockaddr*, uint*) @nogc nothrow;
    c_long sendto(int, const(void)*, c_ulong, int, const(sockaddr)*, uint) @nogc nothrow;
    c_long recv(int, void*, c_ulong, int) @nogc nothrow;
    c_long send(int, const(void)*, c_ulong, int) @nogc nothrow;
    int getpeername(int, sockaddr*, uint*) @nogc nothrow;
    int connect(int, const(sockaddr)*, uint) @nogc nothrow;
    int getsockname(int, sockaddr*, uint*) @nogc nothrow;
    int bind(int, const(sockaddr)*, uint) @nogc nothrow;
    int socketpair(int, int, int, int*) @nogc nothrow;
    int socket(int, int, int) @nogc nothrow;
    enum _Anonymous_65
    {
        SHUT_RD = 0,
        SHUT_WR = 1,
        SHUT_RDWR = 2,
    }
    enum SHUT_RD = _Anonymous_65.SHUT_RD;
    enum SHUT_WR = _Anonymous_65.SHUT_WR;
    enum SHUT_RDWR = _Anonymous_65.SHUT_RDWR;
    int pselect(int, fd_set*, fd_set*, fd_set*, const(timespec)*, const(__sigset_t)*) @nogc nothrow;
    int select(int, fd_set*, fd_set*, fd_set*, timeval*) @nogc nothrow;
    alias fd_mask = c_long;
    struct fd_set
    {
        c_long[16] __fds_bits;
    }
    alias __fd_mask = c_long;
    alias suseconds_t = c_long;
    pragma(mangle, "flock") int flock_(int, int) @nogc nothrow;
    int ioctl(int, c_ulong, ...) @nogc nothrow;



    static if(!is(typeof(NGROUPS))) {
        private enum enumMixinStr_NGROUPS = `enum NGROUPS = NGROUPS_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr_NGROUPS); }))) {
            mixin(enumMixinStr_NGROUPS);
        }
    }




    static if(!is(typeof(NBBY))) {
        private enum enumMixinStr_NBBY = `enum NBBY = CHAR_BIT;`;
        static if(is(typeof({ mixin(enumMixinStr_NBBY); }))) {
            mixin(enumMixinStr_NBBY);
        }
    }






    static if(!is(typeof(CANBSIZ))) {
        private enum enumMixinStr_CANBSIZ = `enum CANBSIZ = MAX_CANON;`;
        static if(is(typeof({ mixin(enumMixinStr_CANBSIZ); }))) {
            mixin(enumMixinStr_CANBSIZ);
        }
    }




    static if(!is(typeof(_SYS_PARAM_H))) {
        private enum enumMixinStr__SYS_PARAM_H = `enum _SYS_PARAM_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__SYS_PARAM_H); }))) {
            mixin(enumMixinStr__SYS_PARAM_H);
        }
    }




    static if(!is(typeof(MAXPATHLEN))) {
        private enum enumMixinStr_MAXPATHLEN = `enum MAXPATHLEN = PATH_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr_MAXPATHLEN); }))) {
            mixin(enumMixinStr_MAXPATHLEN);
        }
    }




    static if(!is(typeof(_SYS_IOCTL_H))) {
        private enum enumMixinStr__SYS_IOCTL_H = `enum _SYS_IOCTL_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__SYS_IOCTL_H); }))) {
            mixin(enumMixinStr__SYS_IOCTL_H);
        }
    }




    static if(!is(typeof(LOCK_NB))) {
        private enum enumMixinStr_LOCK_NB = `enum LOCK_NB = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_LOCK_NB); }))) {
            mixin(enumMixinStr_LOCK_NB);
        }
    }




    static if(!is(typeof(LOCK_UN))) {
        private enum enumMixinStr_LOCK_UN = `enum LOCK_UN = 8;`;
        static if(is(typeof({ mixin(enumMixinStr_LOCK_UN); }))) {
            mixin(enumMixinStr_LOCK_UN);
        }
    }




    static if(!is(typeof(LOCK_EX))) {
        private enum enumMixinStr_LOCK_EX = `enum LOCK_EX = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_LOCK_EX); }))) {
            mixin(enumMixinStr_LOCK_EX);
        }
    }




    static if(!is(typeof(LOCK_SH))) {
        private enum enumMixinStr_LOCK_SH = `enum LOCK_SH = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_LOCK_SH); }))) {
            mixin(enumMixinStr_LOCK_SH);
        }
    }




    static if(!is(typeof(NODEV))) {
        private enum enumMixinStr_NODEV = `enum NODEV = ( cast( dev_t ) - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_NODEV); }))) {
            mixin(enumMixinStr_NODEV);
        }
    }




    static if(!is(typeof(DEV_BSIZE))) {
        private enum enumMixinStr_DEV_BSIZE = `enum DEV_BSIZE = 512;`;
        static if(is(typeof({ mixin(enumMixinStr_DEV_BSIZE); }))) {
            mixin(enumMixinStr_DEV_BSIZE);
        }
    }
    static if(!is(typeof(_SYS_FILE_H))) {
        private enum enumMixinStr__SYS_FILE_H = `enum _SYS_FILE_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__SYS_FILE_H); }))) {
            mixin(enumMixinStr__SYS_FILE_H);
        }
    }
    static if(!is(typeof(_SYS_SELECT_H))) {
        private enum enumMixinStr__SYS_SELECT_H = `enum _SYS_SELECT_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__SYS_SELECT_H); }))) {
            mixin(enumMixinStr__SYS_SELECT_H);
        }
    }




    static if(!is(typeof(__HAVE_GENERIC_SELECTION))) {
        private enum enumMixinStr___HAVE_GENERIC_SELECTION = `enum __HAVE_GENERIC_SELECTION = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___HAVE_GENERIC_SELECTION); }))) {
            mixin(enumMixinStr___HAVE_GENERIC_SELECTION);
        }
    }
    static if(!is(typeof(__NFDBITS))) {
        private enum enumMixinStr___NFDBITS = `enum __NFDBITS = ( 8 * cast( int ) ( __fd_mask ) .sizeof );`;
        static if(is(typeof({ mixin(enumMixinStr___NFDBITS); }))) {
            mixin(enumMixinStr___NFDBITS);
        }
    }
    static if(!is(typeof(FD_SETSIZE))) {
        private enum enumMixinStr_FD_SETSIZE = `enum FD_SETSIZE = __FD_SETSIZE;`;
        static if(is(typeof({ mixin(enumMixinStr_FD_SETSIZE); }))) {
            mixin(enumMixinStr_FD_SETSIZE);
        }
    }






    static if(!is(typeof(__restrict_arr))) {
        private enum enumMixinStr___restrict_arr = `enum __restrict_arr = __restrict;`;
        static if(is(typeof({ mixin(enumMixinStr___restrict_arr); }))) {
            mixin(enumMixinStr___restrict_arr);
        }
    }




    static if(!is(typeof(NFDBITS))) {
        private enum enumMixinStr_NFDBITS = `enum NFDBITS = ( 8 * cast( int ) ( __fd_mask ) .sizeof );`;
        static if(is(typeof({ mixin(enumMixinStr_NFDBITS); }))) {
            mixin(enumMixinStr_NFDBITS);
        }
    }
    static if(!is(typeof(__fortify_function))) {
        private enum enumMixinStr___fortify_function = `enum __fortify_function = __extern_always_inline __attribute_artificial__;`;
        static if(is(typeof({ mixin(enumMixinStr___fortify_function); }))) {
            mixin(enumMixinStr___fortify_function);
        }
    }




    static if(!is(typeof(__extern_always_inline))) {
        private enum enumMixinStr___extern_always_inline = `enum __extern_always_inline = extern __always_inline __attribute__ ( ( __gnu_inline__ ) );`;
        static if(is(typeof({ mixin(enumMixinStr___extern_always_inline); }))) {
            mixin(enumMixinStr___extern_always_inline);
        }
    }




    static if(!is(typeof(__extern_inline))) {
        private enum enumMixinStr___extern_inline = `enum __extern_inline = extern __inline __attribute__ ( ( __gnu_inline__ ) );`;
        static if(is(typeof({ mixin(enumMixinStr___extern_inline); }))) {
            mixin(enumMixinStr___extern_inline);
        }
    }






    static if(!is(typeof(__always_inline))) {
        private enum enumMixinStr___always_inline = `enum __always_inline = __inline __attribute__ ( ( __always_inline__ ) );`;
        static if(is(typeof({ mixin(enumMixinStr___always_inline); }))) {
            mixin(enumMixinStr___always_inline);
        }
    }






    static if(!is(typeof(__attribute_warn_unused_result__))) {
        private enum enumMixinStr___attribute_warn_unused_result__ = `enum __attribute_warn_unused_result__ = __attribute__ ( ( __warn_unused_result__ ) );`;
        static if(is(typeof({ mixin(enumMixinStr___attribute_warn_unused_result__); }))) {
            mixin(enumMixinStr___attribute_warn_unused_result__);
        }
    }




    static if(!is(typeof(_SYS_SOCKET_H))) {
        private enum enumMixinStr__SYS_SOCKET_H = `enum _SYS_SOCKET_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__SYS_SOCKET_H); }))) {
            mixin(enumMixinStr__SYS_SOCKET_H);
        }
    }
    static if(!is(typeof(__attribute_deprecated__))) {
        private enum enumMixinStr___attribute_deprecated__ = `enum __attribute_deprecated__ = __attribute__ ( ( __deprecated__ ) );`;
        static if(is(typeof({ mixin(enumMixinStr___attribute_deprecated__); }))) {
            mixin(enumMixinStr___attribute_deprecated__);
        }
    }




    static if(!is(typeof(__attribute_noinline__))) {
        private enum enumMixinStr___attribute_noinline__ = `enum __attribute_noinline__ = __attribute__ ( ( __noinline__ ) );`;
        static if(is(typeof({ mixin(enumMixinStr___attribute_noinline__); }))) {
            mixin(enumMixinStr___attribute_noinline__);
        }
    }




    static if(!is(typeof(__attribute_used__))) {
        private enum enumMixinStr___attribute_used__ = `enum __attribute_used__ = __attribute__ ( ( __used__ ) );`;
        static if(is(typeof({ mixin(enumMixinStr___attribute_used__); }))) {
            mixin(enumMixinStr___attribute_used__);
        }
    }




    static if(!is(typeof(__attribute_const__))) {
        private enum enumMixinStr___attribute_const__ = `enum __attribute_const__ = __attribute__ ( cast( __const__ ) );`;
        static if(is(typeof({ mixin(enumMixinStr___attribute_const__); }))) {
            mixin(enumMixinStr___attribute_const__);
        }
    }




    static if(!is(typeof(SHUT_RD))) {
        private enum enumMixinStr_SHUT_RD = `enum SHUT_RD = SHUT_RD;`;
        static if(is(typeof({ mixin(enumMixinStr_SHUT_RD); }))) {
            mixin(enumMixinStr_SHUT_RD);
        }
    }




    static if(!is(typeof(SHUT_WR))) {
        private enum enumMixinStr_SHUT_WR = `enum SHUT_WR = SHUT_WR;`;
        static if(is(typeof({ mixin(enumMixinStr_SHUT_WR); }))) {
            mixin(enumMixinStr_SHUT_WR);
        }
    }




    static if(!is(typeof(SHUT_RDWR))) {
        private enum enumMixinStr_SHUT_RDWR = `enum SHUT_RDWR = SHUT_RDWR;`;
        static if(is(typeof({ mixin(enumMixinStr_SHUT_RDWR); }))) {
            mixin(enumMixinStr_SHUT_RDWR);
        }
    }




    static if(!is(typeof(__attribute_pure__))) {
        private enum enumMixinStr___attribute_pure__ = `enum __attribute_pure__ = __attribute__ ( ( __pure__ ) );`;
        static if(is(typeof({ mixin(enumMixinStr___attribute_pure__); }))) {
            mixin(enumMixinStr___attribute_pure__);
        }
    }




    static if(!is(typeof(__SOCKADDR_ARG))) {
        private enum enumMixinStr___SOCKADDR_ARG = `enum __SOCKADDR_ARG = sockaddr * __restrict;`;
        static if(is(typeof({ mixin(enumMixinStr___SOCKADDR_ARG); }))) {
            mixin(enumMixinStr___SOCKADDR_ARG);
        }
    }




    static if(!is(typeof(__CONST_SOCKADDR_ARG))) {
        private enum enumMixinStr___CONST_SOCKADDR_ARG = `enum __CONST_SOCKADDR_ARG = const sockaddr *;`;
        static if(is(typeof({ mixin(enumMixinStr___CONST_SOCKADDR_ARG); }))) {
            mixin(enumMixinStr___CONST_SOCKADDR_ARG);
        }
    }






    static if(!is(typeof(__attribute_malloc__))) {
        private enum enumMixinStr___attribute_malloc__ = `enum __attribute_malloc__ = __attribute__ ( ( __malloc__ ) );`;
        static if(is(typeof({ mixin(enumMixinStr___attribute_malloc__); }))) {
            mixin(enumMixinStr___attribute_malloc__);
        }
    }
    static if(!is(typeof(__glibc_c99_flexarr_available))) {
        private enum enumMixinStr___glibc_c99_flexarr_available = `enum __glibc_c99_flexarr_available = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___glibc_c99_flexarr_available); }))) {
            mixin(enumMixinStr___glibc_c99_flexarr_available);
        }
    }




    static if(!is(typeof(__flexarr))) {
        private enum enumMixinStr___flexarr = `enum __flexarr = [ ];`;
        static if(is(typeof({ mixin(enumMixinStr___flexarr); }))) {
            mixin(enumMixinStr___flexarr);
        }
    }
    static if(!is(typeof(__ptr_t))) {
        private enum enumMixinStr___ptr_t = `enum __ptr_t = void *;`;
        static if(is(typeof({ mixin(enumMixinStr___ptr_t); }))) {
            mixin(enumMixinStr___ptr_t);
        }
    }
    static if(!is(typeof(__THROWNL))) {
        private enum enumMixinStr___THROWNL = `enum __THROWNL = __attribute__ ( ( __nothrow__ ) );`;
        static if(is(typeof({ mixin(enumMixinStr___THROWNL); }))) {
            mixin(enumMixinStr___THROWNL);
        }
    }




    static if(!is(typeof(__THROW))) {
        private enum enumMixinStr___THROW = `enum __THROW = __attribute__ ( ( __nothrow__ __LEAF ) );`;
        static if(is(typeof({ mixin(enumMixinStr___THROW); }))) {
            mixin(enumMixinStr___THROW);
        }
    }
    static if(!is(typeof(_SYS_CDEFS_H))) {
        private enum enumMixinStr__SYS_CDEFS_H = `enum _SYS_CDEFS_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__SYS_CDEFS_H); }))) {
            mixin(enumMixinStr__SYS_CDEFS_H);
        }
    }




    static if(!is(typeof(_STRINGS_H))) {
        private enum enumMixinStr__STRINGS_H = `enum _STRINGS_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__STRINGS_H); }))) {
            mixin(enumMixinStr__STRINGS_H);
        }
    }






    static if(!is(typeof(_STRING_H))) {
        private enum enumMixinStr__STRING_H = `enum _STRING_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__STRING_H); }))) {
            mixin(enumMixinStr__STRING_H);
        }
    }






    static if(!is(typeof(MB_CUR_MAX))) {
        private enum enumMixinStr_MB_CUR_MAX = `enum MB_CUR_MAX = ( __ctype_get_mb_cur_max ( ) );`;
        static if(is(typeof({ mixin(enumMixinStr_MB_CUR_MAX); }))) {
            mixin(enumMixinStr_MB_CUR_MAX);
        }
    }




    static if(!is(typeof(EXIT_SUCCESS))) {
        private enum enumMixinStr_EXIT_SUCCESS = `enum EXIT_SUCCESS = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_EXIT_SUCCESS); }))) {
            mixin(enumMixinStr_EXIT_SUCCESS);
        }
    }




    static if(!is(typeof(EXIT_FAILURE))) {
        private enum enumMixinStr_EXIT_FAILURE = `enum EXIT_FAILURE = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_EXIT_FAILURE); }))) {
            mixin(enumMixinStr_EXIT_FAILURE);
        }
    }




    static if(!is(typeof(RAND_MAX))) {
        private enum enumMixinStr_RAND_MAX = `enum RAND_MAX = 2147483647;`;
        static if(is(typeof({ mixin(enumMixinStr_RAND_MAX); }))) {
            mixin(enumMixinStr_RAND_MAX);
        }
    }




    static if(!is(typeof(__lldiv_t_defined))) {
        private enum enumMixinStr___lldiv_t_defined = `enum __lldiv_t_defined = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___lldiv_t_defined); }))) {
            mixin(enumMixinStr___lldiv_t_defined);
        }
    }




    static if(!is(typeof(__ldiv_t_defined))) {
        private enum enumMixinStr___ldiv_t_defined = `enum __ldiv_t_defined = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___ldiv_t_defined); }))) {
            mixin(enumMixinStr___ldiv_t_defined);
        }
    }




    static if(!is(typeof(_SYS_STAT_H))) {
        private enum enumMixinStr__SYS_STAT_H = `enum _SYS_STAT_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__SYS_STAT_H); }))) {
            mixin(enumMixinStr__SYS_STAT_H);
        }
    }
    static if(!is(typeof(_STDLIB_H))) {
        private enum enumMixinStr__STDLIB_H = `enum _STDLIB_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__STDLIB_H); }))) {
            mixin(enumMixinStr__STDLIB_H);
        }
    }






    static if(!is(typeof(stderr))) {
        private enum enumMixinStr_stderr = `enum stderr = stderr;`;
        static if(is(typeof({ mixin(enumMixinStr_stderr); }))) {
            mixin(enumMixinStr_stderr);
        }
    }




    static if(!is(typeof(stdout))) {
        private enum enumMixinStr_stdout = `enum stdout = stdout;`;
        static if(is(typeof({ mixin(enumMixinStr_stdout); }))) {
            mixin(enumMixinStr_stdout);
        }
    }




    static if(!is(typeof(stdin))) {
        private enum enumMixinStr_stdin = `enum stdin = stdin;`;
        static if(is(typeof({ mixin(enumMixinStr_stdin); }))) {
            mixin(enumMixinStr_stdin);
        }
    }




    static if(!is(typeof(P_tmpdir))) {
        private enum enumMixinStr_P_tmpdir = `enum P_tmpdir = "/tmp";`;
        static if(is(typeof({ mixin(enumMixinStr_P_tmpdir); }))) {
            mixin(enumMixinStr_P_tmpdir);
        }
    }




    static if(!is(typeof(S_IFMT))) {
        private enum enumMixinStr_S_IFMT = `enum S_IFMT = __S_IFMT;`;
        static if(is(typeof({ mixin(enumMixinStr_S_IFMT); }))) {
            mixin(enumMixinStr_S_IFMT);
        }
    }




    static if(!is(typeof(S_IFDIR))) {
        private enum enumMixinStr_S_IFDIR = `enum S_IFDIR = __S_IFDIR;`;
        static if(is(typeof({ mixin(enumMixinStr_S_IFDIR); }))) {
            mixin(enumMixinStr_S_IFDIR);
        }
    }




    static if(!is(typeof(S_IFCHR))) {
        private enum enumMixinStr_S_IFCHR = `enum S_IFCHR = __S_IFCHR;`;
        static if(is(typeof({ mixin(enumMixinStr_S_IFCHR); }))) {
            mixin(enumMixinStr_S_IFCHR);
        }
    }




    static if(!is(typeof(S_IFBLK))) {
        private enum enumMixinStr_S_IFBLK = `enum S_IFBLK = __S_IFBLK;`;
        static if(is(typeof({ mixin(enumMixinStr_S_IFBLK); }))) {
            mixin(enumMixinStr_S_IFBLK);
        }
    }




    static if(!is(typeof(S_IFREG))) {
        private enum enumMixinStr_S_IFREG = `enum S_IFREG = __S_IFREG;`;
        static if(is(typeof({ mixin(enumMixinStr_S_IFREG); }))) {
            mixin(enumMixinStr_S_IFREG);
        }
    }




    static if(!is(typeof(SEEK_END))) {
        private enum enumMixinStr_SEEK_END = `enum SEEK_END = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_SEEK_END); }))) {
            mixin(enumMixinStr_SEEK_END);
        }
    }




    static if(!is(typeof(S_IFIFO))) {
        private enum enumMixinStr_S_IFIFO = `enum S_IFIFO = __S_IFIFO;`;
        static if(is(typeof({ mixin(enumMixinStr_S_IFIFO); }))) {
            mixin(enumMixinStr_S_IFIFO);
        }
    }




    static if(!is(typeof(SEEK_CUR))) {
        private enum enumMixinStr_SEEK_CUR = `enum SEEK_CUR = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_SEEK_CUR); }))) {
            mixin(enumMixinStr_SEEK_CUR);
        }
    }




    static if(!is(typeof(S_IFLNK))) {
        private enum enumMixinStr_S_IFLNK = `enum S_IFLNK = __S_IFLNK;`;
        static if(is(typeof({ mixin(enumMixinStr_S_IFLNK); }))) {
            mixin(enumMixinStr_S_IFLNK);
        }
    }




    static if(!is(typeof(SEEK_SET))) {
        private enum enumMixinStr_SEEK_SET = `enum SEEK_SET = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_SEEK_SET); }))) {
            mixin(enumMixinStr_SEEK_SET);
        }
    }




    static if(!is(typeof(EOF))) {
        private enum enumMixinStr_EOF = `enum EOF = ( - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_EOF); }))) {
            mixin(enumMixinStr_EOF);
        }
    }




    static if(!is(typeof(S_IFSOCK))) {
        private enum enumMixinStr_S_IFSOCK = `enum S_IFSOCK = __S_IFSOCK;`;
        static if(is(typeof({ mixin(enumMixinStr_S_IFSOCK); }))) {
            mixin(enumMixinStr_S_IFSOCK);
        }
    }
    static if(!is(typeof(BUFSIZ))) {
        private enum enumMixinStr_BUFSIZ = `enum BUFSIZ = 8192;`;
        static if(is(typeof({ mixin(enumMixinStr_BUFSIZ); }))) {
            mixin(enumMixinStr_BUFSIZ);
        }
    }






    static if(!is(typeof(_IONBF))) {
        private enum enumMixinStr__IONBF = `enum _IONBF = 2;`;
        static if(is(typeof({ mixin(enumMixinStr__IONBF); }))) {
            mixin(enumMixinStr__IONBF);
        }
    }






    static if(!is(typeof(_IOLBF))) {
        private enum enumMixinStr__IOLBF = `enum _IOLBF = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__IOLBF); }))) {
            mixin(enumMixinStr__IOLBF);
        }
    }




    static if(!is(typeof(_IOFBF))) {
        private enum enumMixinStr__IOFBF = `enum _IOFBF = 0;`;
        static if(is(typeof({ mixin(enumMixinStr__IOFBF); }))) {
            mixin(enumMixinStr__IOFBF);
        }
    }
    static if(!is(typeof(S_ISUID))) {
        private enum enumMixinStr_S_ISUID = `enum S_ISUID = __S_ISUID;`;
        static if(is(typeof({ mixin(enumMixinStr_S_ISUID); }))) {
            mixin(enumMixinStr_S_ISUID);
        }
    }




    static if(!is(typeof(S_ISGID))) {
        private enum enumMixinStr_S_ISGID = `enum S_ISGID = __S_ISGID;`;
        static if(is(typeof({ mixin(enumMixinStr_S_ISGID); }))) {
            mixin(enumMixinStr_S_ISGID);
        }
    }






    static if(!is(typeof(S_ISVTX))) {
        private enum enumMixinStr_S_ISVTX = `enum S_ISVTX = __S_ISVTX;`;
        static if(is(typeof({ mixin(enumMixinStr_S_ISVTX); }))) {
            mixin(enumMixinStr_S_ISVTX);
        }
    }




    static if(!is(typeof(S_IRUSR))) {
        private enum enumMixinStr_S_IRUSR = `enum S_IRUSR = __S_IREAD;`;
        static if(is(typeof({ mixin(enumMixinStr_S_IRUSR); }))) {
            mixin(enumMixinStr_S_IRUSR);
        }
    }




    static if(!is(typeof(S_IWUSR))) {
        private enum enumMixinStr_S_IWUSR = `enum S_IWUSR = __S_IWRITE;`;
        static if(is(typeof({ mixin(enumMixinStr_S_IWUSR); }))) {
            mixin(enumMixinStr_S_IWUSR);
        }
    }




    static if(!is(typeof(S_IXUSR))) {
        private enum enumMixinStr_S_IXUSR = `enum S_IXUSR = __S_IEXEC;`;
        static if(is(typeof({ mixin(enumMixinStr_S_IXUSR); }))) {
            mixin(enumMixinStr_S_IXUSR);
        }
    }




    static if(!is(typeof(S_IRWXU))) {
        private enum enumMixinStr_S_IRWXU = `enum S_IRWXU = ( __S_IREAD | __S_IWRITE | __S_IEXEC );`;
        static if(is(typeof({ mixin(enumMixinStr_S_IRWXU); }))) {
            mixin(enumMixinStr_S_IRWXU);
        }
    }




    static if(!is(typeof(S_IREAD))) {
        private enum enumMixinStr_S_IREAD = `enum S_IREAD = __S_IREAD;`;
        static if(is(typeof({ mixin(enumMixinStr_S_IREAD); }))) {
            mixin(enumMixinStr_S_IREAD);
        }
    }




    static if(!is(typeof(S_IWRITE))) {
        private enum enumMixinStr_S_IWRITE = `enum S_IWRITE = __S_IWRITE;`;
        static if(is(typeof({ mixin(enumMixinStr_S_IWRITE); }))) {
            mixin(enumMixinStr_S_IWRITE);
        }
    }




    static if(!is(typeof(S_IEXEC))) {
        private enum enumMixinStr_S_IEXEC = `enum S_IEXEC = __S_IEXEC;`;
        static if(is(typeof({ mixin(enumMixinStr_S_IEXEC); }))) {
            mixin(enumMixinStr_S_IEXEC);
        }
    }




    static if(!is(typeof(S_IRGRP))) {
        private enum enumMixinStr_S_IRGRP = `enum S_IRGRP = ( __S_IREAD >> 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_S_IRGRP); }))) {
            mixin(enumMixinStr_S_IRGRP);
        }
    }




    static if(!is(typeof(S_IWGRP))) {
        private enum enumMixinStr_S_IWGRP = `enum S_IWGRP = ( __S_IWRITE >> 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_S_IWGRP); }))) {
            mixin(enumMixinStr_S_IWGRP);
        }
    }




    static if(!is(typeof(S_IXGRP))) {
        private enum enumMixinStr_S_IXGRP = `enum S_IXGRP = ( __S_IEXEC >> 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_S_IXGRP); }))) {
            mixin(enumMixinStr_S_IXGRP);
        }
    }




    static if(!is(typeof(S_IRWXG))) {
        private enum enumMixinStr_S_IRWXG = `enum S_IRWXG = ( ( __S_IREAD | __S_IWRITE | __S_IEXEC ) >> 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_S_IRWXG); }))) {
            mixin(enumMixinStr_S_IRWXG);
        }
    }




    static if(!is(typeof(S_IROTH))) {
        private enum enumMixinStr_S_IROTH = `enum S_IROTH = ( ( __S_IREAD >> 3 ) >> 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_S_IROTH); }))) {
            mixin(enumMixinStr_S_IROTH);
        }
    }




    static if(!is(typeof(S_IWOTH))) {
        private enum enumMixinStr_S_IWOTH = `enum S_IWOTH = ( ( __S_IWRITE >> 3 ) >> 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_S_IWOTH); }))) {
            mixin(enumMixinStr_S_IWOTH);
        }
    }




    static if(!is(typeof(S_IXOTH))) {
        private enum enumMixinStr_S_IXOTH = `enum S_IXOTH = ( ( __S_IEXEC >> 3 ) >> 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_S_IXOTH); }))) {
            mixin(enumMixinStr_S_IXOTH);
        }
    }




    static if(!is(typeof(S_IRWXO))) {
        private enum enumMixinStr_S_IRWXO = `enum S_IRWXO = ( ( ( __S_IREAD | __S_IWRITE | __S_IEXEC ) >> 3 ) >> 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_S_IRWXO); }))) {
            mixin(enumMixinStr_S_IRWXO);
        }
    }




    static if(!is(typeof(ACCESSPERMS))) {
        private enum enumMixinStr_ACCESSPERMS = `enum ACCESSPERMS = ( ( __S_IREAD | __S_IWRITE | __S_IEXEC ) | ( ( __S_IREAD | __S_IWRITE | __S_IEXEC ) >> 3 ) | ( ( ( __S_IREAD | __S_IWRITE | __S_IEXEC ) >> 3 ) >> 3 ) );`;
        static if(is(typeof({ mixin(enumMixinStr_ACCESSPERMS); }))) {
            mixin(enumMixinStr_ACCESSPERMS);
        }
    }




    static if(!is(typeof(ALLPERMS))) {
        private enum enumMixinStr_ALLPERMS = `enum ALLPERMS = ( __S_ISUID | __S_ISGID | __S_ISVTX | ( __S_IREAD | __S_IWRITE | __S_IEXEC ) | ( ( __S_IREAD | __S_IWRITE | __S_IEXEC ) >> 3 ) | ( ( ( __S_IREAD | __S_IWRITE | __S_IEXEC ) >> 3 ) >> 3 ) );`;
        static if(is(typeof({ mixin(enumMixinStr_ALLPERMS); }))) {
            mixin(enumMixinStr_ALLPERMS);
        }
    }




    static if(!is(typeof(DEFFILEMODE))) {
        private enum enumMixinStr_DEFFILEMODE = `enum DEFFILEMODE = ( __S_IREAD | __S_IWRITE | ( __S_IREAD >> 3 ) | ( __S_IWRITE >> 3 ) | ( ( __S_IREAD >> 3 ) >> 3 ) | ( ( __S_IWRITE >> 3 ) >> 3 ) );`;
        static if(is(typeof({ mixin(enumMixinStr_DEFFILEMODE); }))) {
            mixin(enumMixinStr_DEFFILEMODE);
        }
    }




    static if(!is(typeof(S_BLKSIZE))) {
        private enum enumMixinStr_S_BLKSIZE = `enum S_BLKSIZE = 512;`;
        static if(is(typeof({ mixin(enumMixinStr_S_BLKSIZE); }))) {
            mixin(enumMixinStr_S_BLKSIZE);
        }
    }




    static if(!is(typeof(_STDIO_H))) {
        private enum enumMixinStr__STDIO_H = `enum _STDIO_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__STDIO_H); }))) {
            mixin(enumMixinStr__STDIO_H);
        }
    }
    static if(!is(typeof(WINT_MAX))) {
        private enum enumMixinStr_WINT_MAX = `enum WINT_MAX = ( 4294967295u );`;
        static if(is(typeof({ mixin(enumMixinStr_WINT_MAX); }))) {
            mixin(enumMixinStr_WINT_MAX);
        }
    }




    static if(!is(typeof(WINT_MIN))) {
        private enum enumMixinStr_WINT_MIN = `enum WINT_MIN = ( 0u );`;
        static if(is(typeof({ mixin(enumMixinStr_WINT_MIN); }))) {
            mixin(enumMixinStr_WINT_MIN);
        }
    }




    static if(!is(typeof(WCHAR_MAX))) {
        private enum enumMixinStr_WCHAR_MAX = `enum WCHAR_MAX = __WCHAR_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr_WCHAR_MAX); }))) {
            mixin(enumMixinStr_WCHAR_MAX);
        }
    }




    static if(!is(typeof(WCHAR_MIN))) {
        private enum enumMixinStr_WCHAR_MIN = `enum WCHAR_MIN = __WCHAR_MIN;`;
        static if(is(typeof({ mixin(enumMixinStr_WCHAR_MIN); }))) {
            mixin(enumMixinStr_WCHAR_MIN);
        }
    }




    static if(!is(typeof(SIZE_MAX))) {
        private enum enumMixinStr_SIZE_MAX = `enum SIZE_MAX = ( 18446744073709551615UL );`;
        static if(is(typeof({ mixin(enumMixinStr_SIZE_MAX); }))) {
            mixin(enumMixinStr_SIZE_MAX);
        }
    }




    static if(!is(typeof(SIG_ATOMIC_MAX))) {
        private enum enumMixinStr_SIG_ATOMIC_MAX = `enum SIG_ATOMIC_MAX = ( 2147483647 );`;
        static if(is(typeof({ mixin(enumMixinStr_SIG_ATOMIC_MAX); }))) {
            mixin(enumMixinStr_SIG_ATOMIC_MAX);
        }
    }




    static if(!is(typeof(SIG_ATOMIC_MIN))) {
        private enum enumMixinStr_SIG_ATOMIC_MIN = `enum SIG_ATOMIC_MIN = ( - 2147483647 - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_SIG_ATOMIC_MIN); }))) {
            mixin(enumMixinStr_SIG_ATOMIC_MIN);
        }
    }




    static if(!is(typeof(PTRDIFF_MAX))) {
        private enum enumMixinStr_PTRDIFF_MAX = `enum PTRDIFF_MAX = ( 9223372036854775807L );`;
        static if(is(typeof({ mixin(enumMixinStr_PTRDIFF_MAX); }))) {
            mixin(enumMixinStr_PTRDIFF_MAX);
        }
    }




    static if(!is(typeof(PTRDIFF_MIN))) {
        private enum enumMixinStr_PTRDIFF_MIN = `enum PTRDIFF_MIN = ( - 9223372036854775807L - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_PTRDIFF_MIN); }))) {
            mixin(enumMixinStr_PTRDIFF_MIN);
        }
    }




    static if(!is(typeof(UINTMAX_MAX))) {
        private enum enumMixinStr_UINTMAX_MAX = `enum UINTMAX_MAX = ( 18446744073709551615UL );`;
        static if(is(typeof({ mixin(enumMixinStr_UINTMAX_MAX); }))) {
            mixin(enumMixinStr_UINTMAX_MAX);
        }
    }




    static if(!is(typeof(INTMAX_MAX))) {
        private enum enumMixinStr_INTMAX_MAX = `enum INTMAX_MAX = ( 9223372036854775807L );`;
        static if(is(typeof({ mixin(enumMixinStr_INTMAX_MAX); }))) {
            mixin(enumMixinStr_INTMAX_MAX);
        }
    }




    static if(!is(typeof(INTMAX_MIN))) {
        private enum enumMixinStr_INTMAX_MIN = `enum INTMAX_MIN = ( - 9223372036854775807L - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_INTMAX_MIN); }))) {
            mixin(enumMixinStr_INTMAX_MIN);
        }
    }




    static if(!is(typeof(UINTPTR_MAX))) {
        private enum enumMixinStr_UINTPTR_MAX = `enum UINTPTR_MAX = ( 18446744073709551615UL );`;
        static if(is(typeof({ mixin(enumMixinStr_UINTPTR_MAX); }))) {
            mixin(enumMixinStr_UINTPTR_MAX);
        }
    }




    static if(!is(typeof(INTPTR_MAX))) {
        private enum enumMixinStr_INTPTR_MAX = `enum INTPTR_MAX = ( 9223372036854775807L );`;
        static if(is(typeof({ mixin(enumMixinStr_INTPTR_MAX); }))) {
            mixin(enumMixinStr_INTPTR_MAX);
        }
    }




    static if(!is(typeof(INTPTR_MIN))) {
        private enum enumMixinStr_INTPTR_MIN = `enum INTPTR_MIN = ( - 9223372036854775807L - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_INTPTR_MIN); }))) {
            mixin(enumMixinStr_INTPTR_MIN);
        }
    }




    static if(!is(typeof(UINT_FAST64_MAX))) {
        private enum enumMixinStr_UINT_FAST64_MAX = `enum UINT_FAST64_MAX = ( 18446744073709551615UL );`;
        static if(is(typeof({ mixin(enumMixinStr_UINT_FAST64_MAX); }))) {
            mixin(enumMixinStr_UINT_FAST64_MAX);
        }
    }




    static if(!is(typeof(UINT_FAST32_MAX))) {
        private enum enumMixinStr_UINT_FAST32_MAX = `enum UINT_FAST32_MAX = ( 18446744073709551615UL );`;
        static if(is(typeof({ mixin(enumMixinStr_UINT_FAST32_MAX); }))) {
            mixin(enumMixinStr_UINT_FAST32_MAX);
        }
    }




    static if(!is(typeof(UINT_FAST16_MAX))) {
        private enum enumMixinStr_UINT_FAST16_MAX = `enum UINT_FAST16_MAX = ( 18446744073709551615UL );`;
        static if(is(typeof({ mixin(enumMixinStr_UINT_FAST16_MAX); }))) {
            mixin(enumMixinStr_UINT_FAST16_MAX);
        }
    }




    static if(!is(typeof(UINT_FAST8_MAX))) {
        private enum enumMixinStr_UINT_FAST8_MAX = `enum UINT_FAST8_MAX = ( 255 );`;
        static if(is(typeof({ mixin(enumMixinStr_UINT_FAST8_MAX); }))) {
            mixin(enumMixinStr_UINT_FAST8_MAX);
        }
    }




    static if(!is(typeof(INT_FAST64_MAX))) {
        private enum enumMixinStr_INT_FAST64_MAX = `enum INT_FAST64_MAX = ( 9223372036854775807L );`;
        static if(is(typeof({ mixin(enumMixinStr_INT_FAST64_MAX); }))) {
            mixin(enumMixinStr_INT_FAST64_MAX);
        }
    }




    static if(!is(typeof(INT_FAST32_MAX))) {
        private enum enumMixinStr_INT_FAST32_MAX = `enum INT_FAST32_MAX = ( 9223372036854775807L );`;
        static if(is(typeof({ mixin(enumMixinStr_INT_FAST32_MAX); }))) {
            mixin(enumMixinStr_INT_FAST32_MAX);
        }
    }




    static if(!is(typeof(INT_FAST16_MAX))) {
        private enum enumMixinStr_INT_FAST16_MAX = `enum INT_FAST16_MAX = ( 9223372036854775807L );`;
        static if(is(typeof({ mixin(enumMixinStr_INT_FAST16_MAX); }))) {
            mixin(enumMixinStr_INT_FAST16_MAX);
        }
    }




    static if(!is(typeof(INT_FAST8_MAX))) {
        private enum enumMixinStr_INT_FAST8_MAX = `enum INT_FAST8_MAX = ( 127 );`;
        static if(is(typeof({ mixin(enumMixinStr_INT_FAST8_MAX); }))) {
            mixin(enumMixinStr_INT_FAST8_MAX);
        }
    }




    static if(!is(typeof(INT_FAST64_MIN))) {
        private enum enumMixinStr_INT_FAST64_MIN = `enum INT_FAST64_MIN = ( - 9223372036854775807L - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_INT_FAST64_MIN); }))) {
            mixin(enumMixinStr_INT_FAST64_MIN);
        }
    }




    static if(!is(typeof(INT_FAST32_MIN))) {
        private enum enumMixinStr_INT_FAST32_MIN = `enum INT_FAST32_MIN = ( - 9223372036854775807L - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_INT_FAST32_MIN); }))) {
            mixin(enumMixinStr_INT_FAST32_MIN);
        }
    }




    static if(!is(typeof(INT_FAST16_MIN))) {
        private enum enumMixinStr_INT_FAST16_MIN = `enum INT_FAST16_MIN = ( - 9223372036854775807L - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_INT_FAST16_MIN); }))) {
            mixin(enumMixinStr_INT_FAST16_MIN);
        }
    }




    static if(!is(typeof(INT_FAST8_MIN))) {
        private enum enumMixinStr_INT_FAST8_MIN = `enum INT_FAST8_MIN = ( - 128 );`;
        static if(is(typeof({ mixin(enumMixinStr_INT_FAST8_MIN); }))) {
            mixin(enumMixinStr_INT_FAST8_MIN);
        }
    }




    static if(!is(typeof(UINT_LEAST64_MAX))) {
        private enum enumMixinStr_UINT_LEAST64_MAX = `enum UINT_LEAST64_MAX = ( 18446744073709551615UL );`;
        static if(is(typeof({ mixin(enumMixinStr_UINT_LEAST64_MAX); }))) {
            mixin(enumMixinStr_UINT_LEAST64_MAX);
        }
    }




    static if(!is(typeof(UINT_LEAST32_MAX))) {
        private enum enumMixinStr_UINT_LEAST32_MAX = `enum UINT_LEAST32_MAX = ( 4294967295U );`;
        static if(is(typeof({ mixin(enumMixinStr_UINT_LEAST32_MAX); }))) {
            mixin(enumMixinStr_UINT_LEAST32_MAX);
        }
    }




    static if(!is(typeof(UINT_LEAST16_MAX))) {
        private enum enumMixinStr_UINT_LEAST16_MAX = `enum UINT_LEAST16_MAX = ( 65535 );`;
        static if(is(typeof({ mixin(enumMixinStr_UINT_LEAST16_MAX); }))) {
            mixin(enumMixinStr_UINT_LEAST16_MAX);
        }
    }




    static if(!is(typeof(UINT_LEAST8_MAX))) {
        private enum enumMixinStr_UINT_LEAST8_MAX = `enum UINT_LEAST8_MAX = ( 255 );`;
        static if(is(typeof({ mixin(enumMixinStr_UINT_LEAST8_MAX); }))) {
            mixin(enumMixinStr_UINT_LEAST8_MAX);
        }
    }




    static if(!is(typeof(INT_LEAST64_MAX))) {
        private enum enumMixinStr_INT_LEAST64_MAX = `enum INT_LEAST64_MAX = ( 9223372036854775807L );`;
        static if(is(typeof({ mixin(enumMixinStr_INT_LEAST64_MAX); }))) {
            mixin(enumMixinStr_INT_LEAST64_MAX);
        }
    }




    static if(!is(typeof(INT_LEAST32_MAX))) {
        private enum enumMixinStr_INT_LEAST32_MAX = `enum INT_LEAST32_MAX = ( 2147483647 );`;
        static if(is(typeof({ mixin(enumMixinStr_INT_LEAST32_MAX); }))) {
            mixin(enumMixinStr_INT_LEAST32_MAX);
        }
    }




    static if(!is(typeof(INT_LEAST16_MAX))) {
        private enum enumMixinStr_INT_LEAST16_MAX = `enum INT_LEAST16_MAX = ( 32767 );`;
        static if(is(typeof({ mixin(enumMixinStr_INT_LEAST16_MAX); }))) {
            mixin(enumMixinStr_INT_LEAST16_MAX);
        }
    }




    static if(!is(typeof(INT_LEAST8_MAX))) {
        private enum enumMixinStr_INT_LEAST8_MAX = `enum INT_LEAST8_MAX = ( 127 );`;
        static if(is(typeof({ mixin(enumMixinStr_INT_LEAST8_MAX); }))) {
            mixin(enumMixinStr_INT_LEAST8_MAX);
        }
    }




    static if(!is(typeof(INT_LEAST64_MIN))) {
        private enum enumMixinStr_INT_LEAST64_MIN = `enum INT_LEAST64_MIN = ( - 9223372036854775807L - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_INT_LEAST64_MIN); }))) {
            mixin(enumMixinStr_INT_LEAST64_MIN);
        }
    }




    static if(!is(typeof(INT_LEAST32_MIN))) {
        private enum enumMixinStr_INT_LEAST32_MIN = `enum INT_LEAST32_MIN = ( - 2147483647 - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_INT_LEAST32_MIN); }))) {
            mixin(enumMixinStr_INT_LEAST32_MIN);
        }
    }




    static if(!is(typeof(INT_LEAST16_MIN))) {
        private enum enumMixinStr_INT_LEAST16_MIN = `enum INT_LEAST16_MIN = ( - 32767 - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_INT_LEAST16_MIN); }))) {
            mixin(enumMixinStr_INT_LEAST16_MIN);
        }
    }




    static if(!is(typeof(INT_LEAST8_MIN))) {
        private enum enumMixinStr_INT_LEAST8_MIN = `enum INT_LEAST8_MIN = ( - 128 );`;
        static if(is(typeof({ mixin(enumMixinStr_INT_LEAST8_MIN); }))) {
            mixin(enumMixinStr_INT_LEAST8_MIN);
        }
    }




    static if(!is(typeof(UINT64_MAX))) {
        private enum enumMixinStr_UINT64_MAX = `enum UINT64_MAX = ( 18446744073709551615UL );`;
        static if(is(typeof({ mixin(enumMixinStr_UINT64_MAX); }))) {
            mixin(enumMixinStr_UINT64_MAX);
        }
    }




    static if(!is(typeof(UINT32_MAX))) {
        private enum enumMixinStr_UINT32_MAX = `enum UINT32_MAX = ( 4294967295U );`;
        static if(is(typeof({ mixin(enumMixinStr_UINT32_MAX); }))) {
            mixin(enumMixinStr_UINT32_MAX);
        }
    }




    static if(!is(typeof(UINT16_MAX))) {
        private enum enumMixinStr_UINT16_MAX = `enum UINT16_MAX = ( 65535 );`;
        static if(is(typeof({ mixin(enumMixinStr_UINT16_MAX); }))) {
            mixin(enumMixinStr_UINT16_MAX);
        }
    }




    static if(!is(typeof(UINT8_MAX))) {
        private enum enumMixinStr_UINT8_MAX = `enum UINT8_MAX = ( 255 );`;
        static if(is(typeof({ mixin(enumMixinStr_UINT8_MAX); }))) {
            mixin(enumMixinStr_UINT8_MAX);
        }
    }




    static if(!is(typeof(INT64_MAX))) {
        private enum enumMixinStr_INT64_MAX = `enum INT64_MAX = ( 9223372036854775807L );`;
        static if(is(typeof({ mixin(enumMixinStr_INT64_MAX); }))) {
            mixin(enumMixinStr_INT64_MAX);
        }
    }




    static if(!is(typeof(INT32_MAX))) {
        private enum enumMixinStr_INT32_MAX = `enum INT32_MAX = ( 2147483647 );`;
        static if(is(typeof({ mixin(enumMixinStr_INT32_MAX); }))) {
            mixin(enumMixinStr_INT32_MAX);
        }
    }




    static if(!is(typeof(INT16_MAX))) {
        private enum enumMixinStr_INT16_MAX = `enum INT16_MAX = ( 32767 );`;
        static if(is(typeof({ mixin(enumMixinStr_INT16_MAX); }))) {
            mixin(enumMixinStr_INT16_MAX);
        }
    }




    static if(!is(typeof(INT8_MAX))) {
        private enum enumMixinStr_INT8_MAX = `enum INT8_MAX = ( 127 );`;
        static if(is(typeof({ mixin(enumMixinStr_INT8_MAX); }))) {
            mixin(enumMixinStr_INT8_MAX);
        }
    }




    static if(!is(typeof(INT64_MIN))) {
        private enum enumMixinStr_INT64_MIN = `enum INT64_MIN = ( - 9223372036854775807L - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_INT64_MIN); }))) {
            mixin(enumMixinStr_INT64_MIN);
        }
    }




    static if(!is(typeof(INT32_MIN))) {
        private enum enumMixinStr_INT32_MIN = `enum INT32_MIN = ( - 2147483647 - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_INT32_MIN); }))) {
            mixin(enumMixinStr_INT32_MIN);
        }
    }




    static if(!is(typeof(_MKNOD_VER))) {
        private enum enumMixinStr__MKNOD_VER = `enum _MKNOD_VER = 0;`;
        static if(is(typeof({ mixin(enumMixinStr__MKNOD_VER); }))) {
            mixin(enumMixinStr__MKNOD_VER);
        }
    }




    static if(!is(typeof(INT16_MIN))) {
        private enum enumMixinStr_INT16_MIN = `enum INT16_MIN = ( - 32767 - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_INT16_MIN); }))) {
            mixin(enumMixinStr_INT16_MIN);
        }
    }




    static if(!is(typeof(INT8_MIN))) {
        private enum enumMixinStr_INT8_MIN = `enum INT8_MIN = ( - 128 );`;
        static if(is(typeof({ mixin(enumMixinStr_INT8_MIN); }))) {
            mixin(enumMixinStr_INT8_MIN);
        }
    }
    static if(!is(typeof(_STDINT_H))) {
        private enum enumMixinStr__STDINT_H = `enum _STDINT_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__STDINT_H); }))) {
            mixin(enumMixinStr__STDINT_H);
        }
    }




    static if(!is(typeof(_STDC_PREDEF_H))) {
        private enum enumMixinStr__STDC_PREDEF_H = `enum _STDC_PREDEF_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__STDC_PREDEF_H); }))) {
            mixin(enumMixinStr__STDC_PREDEF_H);
        }
    }




    static if(!is(typeof(SIGRTMAX))) {
        private enum enumMixinStr_SIGRTMAX = `enum SIGRTMAX = ( __libc_current_sigrtmax ( ) );`;
        static if(is(typeof({ mixin(enumMixinStr_SIGRTMAX); }))) {
            mixin(enumMixinStr_SIGRTMAX);
        }
    }




    static if(!is(typeof(SIGRTMIN))) {
        private enum enumMixinStr_SIGRTMIN = `enum SIGRTMIN = ( __libc_current_sigrtmin ( ) );`;
        static if(is(typeof({ mixin(enumMixinStr_SIGRTMIN); }))) {
            mixin(enumMixinStr_SIGRTMIN);
        }
    }




    static if(!is(typeof(NSIG))) {
        private enum enumMixinStr_NSIG = `enum NSIG = _NSIG;`;
        static if(is(typeof({ mixin(enumMixinStr_NSIG); }))) {
            mixin(enumMixinStr_NSIG);
        }
    }
    static if(!is(typeof(_SYS_SYSLOG_H))) {
        private enum enumMixinStr__SYS_SYSLOG_H = `enum _SYS_SYSLOG_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__SYS_SYSLOG_H); }))) {
            mixin(enumMixinStr__SYS_SYSLOG_H);
        }
    }




    static if(!is(typeof(_SETJMP_H))) {
        private enum enumMixinStr__SETJMP_H = `enum _SETJMP_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__SETJMP_H); }))) {
            mixin(enumMixinStr__SETJMP_H);
        }
    }




    static if(!is(typeof(__sched_priority))) {
        private enum enumMixinStr___sched_priority = `enum __sched_priority = sched_priority;`;
        static if(is(typeof({ mixin(enumMixinStr___sched_priority); }))) {
            mixin(enumMixinStr___sched_priority);
        }
    }




    static if(!is(typeof(sched_priority))) {
        private enum enumMixinStr_sched_priority = `enum sched_priority = sched_priority;`;
        static if(is(typeof({ mixin(enumMixinStr_sched_priority); }))) {
            mixin(enumMixinStr_sched_priority);
        }
    }




    static if(!is(typeof(LOG_EMERG))) {
        private enum enumMixinStr_LOG_EMERG = `enum LOG_EMERG = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_EMERG); }))) {
            mixin(enumMixinStr_LOG_EMERG);
        }
    }




    static if(!is(typeof(LOG_ALERT))) {
        private enum enumMixinStr_LOG_ALERT = `enum LOG_ALERT = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_ALERT); }))) {
            mixin(enumMixinStr_LOG_ALERT);
        }
    }




    static if(!is(typeof(LOG_CRIT))) {
        private enum enumMixinStr_LOG_CRIT = `enum LOG_CRIT = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_CRIT); }))) {
            mixin(enumMixinStr_LOG_CRIT);
        }
    }




    static if(!is(typeof(LOG_ERR))) {
        private enum enumMixinStr_LOG_ERR = `enum LOG_ERR = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_ERR); }))) {
            mixin(enumMixinStr_LOG_ERR);
        }
    }




    static if(!is(typeof(LOG_WARNING))) {
        private enum enumMixinStr_LOG_WARNING = `enum LOG_WARNING = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_WARNING); }))) {
            mixin(enumMixinStr_LOG_WARNING);
        }
    }




    static if(!is(typeof(LOG_NOTICE))) {
        private enum enumMixinStr_LOG_NOTICE = `enum LOG_NOTICE = 5;`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_NOTICE); }))) {
            mixin(enumMixinStr_LOG_NOTICE);
        }
    }




    static if(!is(typeof(LOG_INFO))) {
        private enum enumMixinStr_LOG_INFO = `enum LOG_INFO = 6;`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_INFO); }))) {
            mixin(enumMixinStr_LOG_INFO);
        }
    }




    static if(!is(typeof(LOG_DEBUG))) {
        private enum enumMixinStr_LOG_DEBUG = `enum LOG_DEBUG = 7;`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_DEBUG); }))) {
            mixin(enumMixinStr_LOG_DEBUG);
        }
    }




    static if(!is(typeof(LOG_PRIMASK))) {
        private enum enumMixinStr_LOG_PRIMASK = `enum LOG_PRIMASK = 0x07;`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_PRIMASK); }))) {
            mixin(enumMixinStr_LOG_PRIMASK);
        }
    }
    static if(!is(typeof(LOG_KERN))) {
        private enum enumMixinStr_LOG_KERN = `enum LOG_KERN = ( 0 << 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_KERN); }))) {
            mixin(enumMixinStr_LOG_KERN);
        }
    }




    static if(!is(typeof(LOG_USER))) {
        private enum enumMixinStr_LOG_USER = `enum LOG_USER = ( 1 << 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_USER); }))) {
            mixin(enumMixinStr_LOG_USER);
        }
    }




    static if(!is(typeof(LOG_MAIL))) {
        private enum enumMixinStr_LOG_MAIL = `enum LOG_MAIL = ( 2 << 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_MAIL); }))) {
            mixin(enumMixinStr_LOG_MAIL);
        }
    }




    static if(!is(typeof(LOG_DAEMON))) {
        private enum enumMixinStr_LOG_DAEMON = `enum LOG_DAEMON = ( 3 << 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_DAEMON); }))) {
            mixin(enumMixinStr_LOG_DAEMON);
        }
    }




    static if(!is(typeof(LOG_AUTH))) {
        private enum enumMixinStr_LOG_AUTH = `enum LOG_AUTH = ( 4 << 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_AUTH); }))) {
            mixin(enumMixinStr_LOG_AUTH);
        }
    }




    static if(!is(typeof(LOG_SYSLOG))) {
        private enum enumMixinStr_LOG_SYSLOG = `enum LOG_SYSLOG = ( 5 << 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_SYSLOG); }))) {
            mixin(enumMixinStr_LOG_SYSLOG);
        }
    }




    static if(!is(typeof(LOG_LPR))) {
        private enum enumMixinStr_LOG_LPR = `enum LOG_LPR = ( 6 << 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_LPR); }))) {
            mixin(enumMixinStr_LOG_LPR);
        }
    }




    static if(!is(typeof(LOG_NEWS))) {
        private enum enumMixinStr_LOG_NEWS = `enum LOG_NEWS = ( 7 << 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_NEWS); }))) {
            mixin(enumMixinStr_LOG_NEWS);
        }
    }




    static if(!is(typeof(LOG_UUCP))) {
        private enum enumMixinStr_LOG_UUCP = `enum LOG_UUCP = ( 8 << 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_UUCP); }))) {
            mixin(enumMixinStr_LOG_UUCP);
        }
    }




    static if(!is(typeof(LOG_CRON))) {
        private enum enumMixinStr_LOG_CRON = `enum LOG_CRON = ( 9 << 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_CRON); }))) {
            mixin(enumMixinStr_LOG_CRON);
        }
    }




    static if(!is(typeof(LOG_AUTHPRIV))) {
        private enum enumMixinStr_LOG_AUTHPRIV = `enum LOG_AUTHPRIV = ( 10 << 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_AUTHPRIV); }))) {
            mixin(enumMixinStr_LOG_AUTHPRIV);
        }
    }




    static if(!is(typeof(LOG_FTP))) {
        private enum enumMixinStr_LOG_FTP = `enum LOG_FTP = ( 11 << 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_FTP); }))) {
            mixin(enumMixinStr_LOG_FTP);
        }
    }




    static if(!is(typeof(LOG_LOCAL0))) {
        private enum enumMixinStr_LOG_LOCAL0 = `enum LOG_LOCAL0 = ( 16 << 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_LOCAL0); }))) {
            mixin(enumMixinStr_LOG_LOCAL0);
        }
    }




    static if(!is(typeof(LOG_LOCAL1))) {
        private enum enumMixinStr_LOG_LOCAL1 = `enum LOG_LOCAL1 = ( 17 << 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_LOCAL1); }))) {
            mixin(enumMixinStr_LOG_LOCAL1);
        }
    }




    static if(!is(typeof(LOG_LOCAL2))) {
        private enum enumMixinStr_LOG_LOCAL2 = `enum LOG_LOCAL2 = ( 18 << 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_LOCAL2); }))) {
            mixin(enumMixinStr_LOG_LOCAL2);
        }
    }




    static if(!is(typeof(LOG_LOCAL3))) {
        private enum enumMixinStr_LOG_LOCAL3 = `enum LOG_LOCAL3 = ( 19 << 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_LOCAL3); }))) {
            mixin(enumMixinStr_LOG_LOCAL3);
        }
    }




    static if(!is(typeof(LOG_LOCAL4))) {
        private enum enumMixinStr_LOG_LOCAL4 = `enum LOG_LOCAL4 = ( 20 << 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_LOCAL4); }))) {
            mixin(enumMixinStr_LOG_LOCAL4);
        }
    }




    static if(!is(typeof(LOG_LOCAL5))) {
        private enum enumMixinStr_LOG_LOCAL5 = `enum LOG_LOCAL5 = ( 21 << 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_LOCAL5); }))) {
            mixin(enumMixinStr_LOG_LOCAL5);
        }
    }




    static if(!is(typeof(LOG_LOCAL6))) {
        private enum enumMixinStr_LOG_LOCAL6 = `enum LOG_LOCAL6 = ( 22 << 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_LOCAL6); }))) {
            mixin(enumMixinStr_LOG_LOCAL6);
        }
    }




    static if(!is(typeof(LOG_LOCAL7))) {
        private enum enumMixinStr_LOG_LOCAL7 = `enum LOG_LOCAL7 = ( 23 << 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_LOCAL7); }))) {
            mixin(enumMixinStr_LOG_LOCAL7);
        }
    }




    static if(!is(typeof(LOG_NFACILITIES))) {
        private enum enumMixinStr_LOG_NFACILITIES = `enum LOG_NFACILITIES = 24;`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_NFACILITIES); }))) {
            mixin(enumMixinStr_LOG_NFACILITIES);
        }
    }




    static if(!is(typeof(LOG_FACMASK))) {
        private enum enumMixinStr_LOG_FACMASK = `enum LOG_FACMASK = 0x03f8;`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_FACMASK); }))) {
            mixin(enumMixinStr_LOG_FACMASK);
        }
    }
    static if(!is(typeof(LOG_PID))) {
        private enum enumMixinStr_LOG_PID = `enum LOG_PID = 0x01;`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_PID); }))) {
            mixin(enumMixinStr_LOG_PID);
        }
    }




    static if(!is(typeof(LOG_CONS))) {
        private enum enumMixinStr_LOG_CONS = `enum LOG_CONS = 0x02;`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_CONS); }))) {
            mixin(enumMixinStr_LOG_CONS);
        }
    }




    static if(!is(typeof(LOG_ODELAY))) {
        private enum enumMixinStr_LOG_ODELAY = `enum LOG_ODELAY = 0x04;`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_ODELAY); }))) {
            mixin(enumMixinStr_LOG_ODELAY);
        }
    }




    static if(!is(typeof(LOG_NDELAY))) {
        private enum enumMixinStr_LOG_NDELAY = `enum LOG_NDELAY = 0x08;`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_NDELAY); }))) {
            mixin(enumMixinStr_LOG_NDELAY);
        }
    }




    static if(!is(typeof(LOG_NOWAIT))) {
        private enum enumMixinStr_LOG_NOWAIT = `enum LOG_NOWAIT = 0x10;`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_NOWAIT); }))) {
            mixin(enumMixinStr_LOG_NOWAIT);
        }
    }




    static if(!is(typeof(LOG_PERROR))) {
        private enum enumMixinStr_LOG_PERROR = `enum LOG_PERROR = 0x20;`;
        static if(is(typeof({ mixin(enumMixinStr_LOG_PERROR); }))) {
            mixin(enumMixinStr_LOG_PERROR);
        }
    }




    static if(!is(typeof(_SCHED_H))) {
        private enum enumMixinStr__SCHED_H = `enum _SCHED_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__SCHED_H); }))) {
            mixin(enumMixinStr__SCHED_H);
        }
    }




    static if(!is(typeof(_RPC_NETDB_H))) {
        private enum enumMixinStr__RPC_NETDB_H = `enum _RPC_NETDB_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__RPC_NETDB_H); }))) {
            mixin(enumMixinStr__RPC_NETDB_H);
        }
    }




    static if(!is(typeof(NSS_BUFLEN_PASSWD))) {
        private enum enumMixinStr_NSS_BUFLEN_PASSWD = `enum NSS_BUFLEN_PASSWD = 1024;`;
        static if(is(typeof({ mixin(enumMixinStr_NSS_BUFLEN_PASSWD); }))) {
            mixin(enumMixinStr_NSS_BUFLEN_PASSWD);
        }
    }




    static if(!is(typeof(_PWD_H))) {
        private enum enumMixinStr__PWD_H = `enum _PWD_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__PWD_H); }))) {
            mixin(enumMixinStr__PWD_H);
        }
    }
    static if(!is(typeof(_SYS_TIME_H))) {
        private enum enumMixinStr__SYS_TIME_H = `enum _SYS_TIME_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__SYS_TIME_H); }))) {
            mixin(enumMixinStr__SYS_TIME_H);
        }
    }




    static if(!is(typeof(PTHREAD_BARRIER_SERIAL_THREAD))) {
        private enum enumMixinStr_PTHREAD_BARRIER_SERIAL_THREAD = `enum PTHREAD_BARRIER_SERIAL_THREAD = - 1;`;
        static if(is(typeof({ mixin(enumMixinStr_PTHREAD_BARRIER_SERIAL_THREAD); }))) {
            mixin(enumMixinStr_PTHREAD_BARRIER_SERIAL_THREAD);
        }
    }




    static if(!is(typeof(PTHREAD_ONCE_INIT))) {
        private enum enumMixinStr_PTHREAD_ONCE_INIT = `enum PTHREAD_ONCE_INIT = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_PTHREAD_ONCE_INIT); }))) {
            mixin(enumMixinStr_PTHREAD_ONCE_INIT);
        }
    }




    static if(!is(typeof(PTHREAD_CANCELED))) {
        private enum enumMixinStr_PTHREAD_CANCELED = `enum PTHREAD_CANCELED = ( cast( void * ) - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_PTHREAD_CANCELED); }))) {
            mixin(enumMixinStr_PTHREAD_CANCELED);
        }
    }




    static if(!is(typeof(PTHREAD_CANCEL_ASYNCHRONOUS))) {
        private enum enumMixinStr_PTHREAD_CANCEL_ASYNCHRONOUS = `enum PTHREAD_CANCEL_ASYNCHRONOUS = PTHREAD_CANCEL_ASYNCHRONOUS;`;
        static if(is(typeof({ mixin(enumMixinStr_PTHREAD_CANCEL_ASYNCHRONOUS); }))) {
            mixin(enumMixinStr_PTHREAD_CANCEL_ASYNCHRONOUS);
        }
    }




    static if(!is(typeof(PTHREAD_CANCEL_DEFERRED))) {
        private enum enumMixinStr_PTHREAD_CANCEL_DEFERRED = `enum PTHREAD_CANCEL_DEFERRED = PTHREAD_CANCEL_DEFERRED;`;
        static if(is(typeof({ mixin(enumMixinStr_PTHREAD_CANCEL_DEFERRED); }))) {
            mixin(enumMixinStr_PTHREAD_CANCEL_DEFERRED);
        }
    }




    static if(!is(typeof(PTHREAD_CANCEL_DISABLE))) {
        private enum enumMixinStr_PTHREAD_CANCEL_DISABLE = `enum PTHREAD_CANCEL_DISABLE = PTHREAD_CANCEL_DISABLE;`;
        static if(is(typeof({ mixin(enumMixinStr_PTHREAD_CANCEL_DISABLE); }))) {
            mixin(enumMixinStr_PTHREAD_CANCEL_DISABLE);
        }
    }




    static if(!is(typeof(PTHREAD_CANCEL_ENABLE))) {
        private enum enumMixinStr_PTHREAD_CANCEL_ENABLE = `enum PTHREAD_CANCEL_ENABLE = PTHREAD_CANCEL_ENABLE;`;
        static if(is(typeof({ mixin(enumMixinStr_PTHREAD_CANCEL_ENABLE); }))) {
            mixin(enumMixinStr_PTHREAD_CANCEL_ENABLE);
        }
    }




    static if(!is(typeof(PTHREAD_COND_INITIALIZER))) {
        private enum enumMixinStr_PTHREAD_COND_INITIALIZER = `enum PTHREAD_COND_INITIALIZER = { { { 0 } , { 0 } , { 0 , 0 } , { 0 , 0 } , 0 , 0 , { 0 , 0 } } };`;
        static if(is(typeof({ mixin(enumMixinStr_PTHREAD_COND_INITIALIZER); }))) {
            mixin(enumMixinStr_PTHREAD_COND_INITIALIZER);
        }
    }




    static if(!is(typeof(PTHREAD_PROCESS_SHARED))) {
        private enum enumMixinStr_PTHREAD_PROCESS_SHARED = `enum PTHREAD_PROCESS_SHARED = PTHREAD_PROCESS_SHARED;`;
        static if(is(typeof({ mixin(enumMixinStr_PTHREAD_PROCESS_SHARED); }))) {
            mixin(enumMixinStr_PTHREAD_PROCESS_SHARED);
        }
    }




    static if(!is(typeof(PTHREAD_PROCESS_PRIVATE))) {
        private enum enumMixinStr_PTHREAD_PROCESS_PRIVATE = `enum PTHREAD_PROCESS_PRIVATE = PTHREAD_PROCESS_PRIVATE;`;
        static if(is(typeof({ mixin(enumMixinStr_PTHREAD_PROCESS_PRIVATE); }))) {
            mixin(enumMixinStr_PTHREAD_PROCESS_PRIVATE);
        }
    }




    static if(!is(typeof(PTHREAD_SCOPE_PROCESS))) {
        private enum enumMixinStr_PTHREAD_SCOPE_PROCESS = `enum PTHREAD_SCOPE_PROCESS = PTHREAD_SCOPE_PROCESS;`;
        static if(is(typeof({ mixin(enumMixinStr_PTHREAD_SCOPE_PROCESS); }))) {
            mixin(enumMixinStr_PTHREAD_SCOPE_PROCESS);
        }
    }




    static if(!is(typeof(PTHREAD_SCOPE_SYSTEM))) {
        private enum enumMixinStr_PTHREAD_SCOPE_SYSTEM = `enum PTHREAD_SCOPE_SYSTEM = PTHREAD_SCOPE_SYSTEM;`;
        static if(is(typeof({ mixin(enumMixinStr_PTHREAD_SCOPE_SYSTEM); }))) {
            mixin(enumMixinStr_PTHREAD_SCOPE_SYSTEM);
        }
    }




    static if(!is(typeof(PTHREAD_EXPLICIT_SCHED))) {
        private enum enumMixinStr_PTHREAD_EXPLICIT_SCHED = `enum PTHREAD_EXPLICIT_SCHED = PTHREAD_EXPLICIT_SCHED;`;
        static if(is(typeof({ mixin(enumMixinStr_PTHREAD_EXPLICIT_SCHED); }))) {
            mixin(enumMixinStr_PTHREAD_EXPLICIT_SCHED);
        }
    }




    static if(!is(typeof(PTHREAD_INHERIT_SCHED))) {
        private enum enumMixinStr_PTHREAD_INHERIT_SCHED = `enum PTHREAD_INHERIT_SCHED = PTHREAD_INHERIT_SCHED;`;
        static if(is(typeof({ mixin(enumMixinStr_PTHREAD_INHERIT_SCHED); }))) {
            mixin(enumMixinStr_PTHREAD_INHERIT_SCHED);
        }
    }




    static if(!is(typeof(PTHREAD_RWLOCK_INITIALIZER))) {
        private enum enumMixinStr_PTHREAD_RWLOCK_INITIALIZER = `enum PTHREAD_RWLOCK_INITIALIZER = { { __PTHREAD_RWLOCK_INITIALIZER ( PTHREAD_RWLOCK_DEFAULT_NP ) } };`;
        static if(is(typeof({ mixin(enumMixinStr_PTHREAD_RWLOCK_INITIALIZER); }))) {
            mixin(enumMixinStr_PTHREAD_RWLOCK_INITIALIZER);
        }
    }




    static if(!is(typeof(PTHREAD_MUTEX_INITIALIZER))) {
        private enum enumMixinStr_PTHREAD_MUTEX_INITIALIZER = `enum PTHREAD_MUTEX_INITIALIZER = { { __PTHREAD_MUTEX_INITIALIZER ( PTHREAD_MUTEX_TIMED_NP ) } };`;
        static if(is(typeof({ mixin(enumMixinStr_PTHREAD_MUTEX_INITIALIZER); }))) {
            mixin(enumMixinStr_PTHREAD_MUTEX_INITIALIZER);
        }
    }




    static if(!is(typeof(PTHREAD_CREATE_DETACHED))) {
        private enum enumMixinStr_PTHREAD_CREATE_DETACHED = `enum PTHREAD_CREATE_DETACHED = PTHREAD_CREATE_DETACHED;`;
        static if(is(typeof({ mixin(enumMixinStr_PTHREAD_CREATE_DETACHED); }))) {
            mixin(enumMixinStr_PTHREAD_CREATE_DETACHED);
        }
    }




    static if(!is(typeof(PTHREAD_CREATE_JOINABLE))) {
        private enum enumMixinStr_PTHREAD_CREATE_JOINABLE = `enum PTHREAD_CREATE_JOINABLE = PTHREAD_CREATE_JOINABLE;`;
        static if(is(typeof({ mixin(enumMixinStr_PTHREAD_CREATE_JOINABLE); }))) {
            mixin(enumMixinStr_PTHREAD_CREATE_JOINABLE);
        }
    }




    static if(!is(typeof(ITIMER_REAL))) {
        private enum enumMixinStr_ITIMER_REAL = `enum ITIMER_REAL = ITIMER_REAL;`;
        static if(is(typeof({ mixin(enumMixinStr_ITIMER_REAL); }))) {
            mixin(enumMixinStr_ITIMER_REAL);
        }
    }




    static if(!is(typeof(ITIMER_VIRTUAL))) {
        private enum enumMixinStr_ITIMER_VIRTUAL = `enum ITIMER_VIRTUAL = ITIMER_VIRTUAL;`;
        static if(is(typeof({ mixin(enumMixinStr_ITIMER_VIRTUAL); }))) {
            mixin(enumMixinStr_ITIMER_VIRTUAL);
        }
    }




    static if(!is(typeof(ITIMER_PROF))) {
        private enum enumMixinStr_ITIMER_PROF = `enum ITIMER_PROF = ITIMER_PROF;`;
        static if(is(typeof({ mixin(enumMixinStr_ITIMER_PROF); }))) {
            mixin(enumMixinStr_ITIMER_PROF);
        }
    }




    static if(!is(typeof(_PTHREAD_H))) {
        private enum enumMixinStr__PTHREAD_H = `enum _PTHREAD_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__PTHREAD_H); }))) {
            mixin(enumMixinStr__PTHREAD_H);
        }
    }




    static if(!is(typeof(TCP_MSS_DESIRED))) {
        private enum enumMixinStr_TCP_MSS_DESIRED = `enum TCP_MSS_DESIRED = 1220U;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_MSS_DESIRED); }))) {
            mixin(enumMixinStr_TCP_MSS_DESIRED);
        }
    }




    static if(!is(typeof(TCP_MSS_DEFAULT))) {
        private enum enumMixinStr_TCP_MSS_DEFAULT = `enum TCP_MSS_DEFAULT = 536U;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_MSS_DEFAULT); }))) {
            mixin(enumMixinStr_TCP_MSS_DEFAULT);
        }
    }




    static if(!is(typeof(TCP_S_DATA_OUT))) {
        private enum enumMixinStr_TCP_S_DATA_OUT = `enum TCP_S_DATA_OUT = ( 1 << 3 );`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_S_DATA_OUT); }))) {
            mixin(enumMixinStr_TCP_S_DATA_OUT);
        }
    }




    static if(!is(typeof(TCP_S_DATA_IN))) {
        private enum enumMixinStr_TCP_S_DATA_IN = `enum TCP_S_DATA_IN = ( 1 << 2 );`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_S_DATA_IN); }))) {
            mixin(enumMixinStr_TCP_S_DATA_IN);
        }
    }




    static if(!is(typeof(TCP_COOKIE_OUT_NEVER))) {
        private enum enumMixinStr_TCP_COOKIE_OUT_NEVER = `enum TCP_COOKIE_OUT_NEVER = ( 1 << 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_COOKIE_OUT_NEVER); }))) {
            mixin(enumMixinStr_TCP_COOKIE_OUT_NEVER);
        }
    }




    static if(!is(typeof(TCP_COOKIE_IN_ALWAYS))) {
        private enum enumMixinStr_TCP_COOKIE_IN_ALWAYS = `enum TCP_COOKIE_IN_ALWAYS = ( 1 << 0 );`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_COOKIE_IN_ALWAYS); }))) {
            mixin(enumMixinStr_TCP_COOKIE_IN_ALWAYS);
        }
    }




    static if(!is(typeof(TCP_COOKIE_PAIR_SIZE))) {
        private enum enumMixinStr_TCP_COOKIE_PAIR_SIZE = `enum TCP_COOKIE_PAIR_SIZE = ( 2 * TCP_COOKIE_MAX );`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_COOKIE_PAIR_SIZE); }))) {
            mixin(enumMixinStr_TCP_COOKIE_PAIR_SIZE);
        }
    }




    static if(!is(typeof(TCP_COOKIE_MAX))) {
        private enum enumMixinStr_TCP_COOKIE_MAX = `enum TCP_COOKIE_MAX = 16;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_COOKIE_MAX); }))) {
            mixin(enumMixinStr_TCP_COOKIE_MAX);
        }
    }




    static if(!is(typeof(TCP_COOKIE_MIN))) {
        private enum enumMixinStr_TCP_COOKIE_MIN = `enum TCP_COOKIE_MIN = 8;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_COOKIE_MIN); }))) {
            mixin(enumMixinStr_TCP_COOKIE_MIN);
        }
    }




    static if(!is(typeof(TCP_MD5SIG_FLAG_PREFIX))) {
        private enum enumMixinStr_TCP_MD5SIG_FLAG_PREFIX = `enum TCP_MD5SIG_FLAG_PREFIX = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_MD5SIG_FLAG_PREFIX); }))) {
            mixin(enumMixinStr_TCP_MD5SIG_FLAG_PREFIX);
        }
    }




    static if(!is(typeof(TCP_MD5SIG_MAXKEYLEN))) {
        private enum enumMixinStr_TCP_MD5SIG_MAXKEYLEN = `enum TCP_MD5SIG_MAXKEYLEN = 80;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_MD5SIG_MAXKEYLEN); }))) {
            mixin(enumMixinStr_TCP_MD5SIG_MAXKEYLEN);
        }
    }




    static if(!is(typeof(TCPI_OPT_SYN_DATA))) {
        private enum enumMixinStr_TCPI_OPT_SYN_DATA = `enum TCPI_OPT_SYN_DATA = 32;`;
        static if(is(typeof({ mixin(enumMixinStr_TCPI_OPT_SYN_DATA); }))) {
            mixin(enumMixinStr_TCPI_OPT_SYN_DATA);
        }
    }




    static if(!is(typeof(TCPI_OPT_ECN_SEEN))) {
        private enum enumMixinStr_TCPI_OPT_ECN_SEEN = `enum TCPI_OPT_ECN_SEEN = 16;`;
        static if(is(typeof({ mixin(enumMixinStr_TCPI_OPT_ECN_SEEN); }))) {
            mixin(enumMixinStr_TCPI_OPT_ECN_SEEN);
        }
    }




    static if(!is(typeof(TCPI_OPT_ECN))) {
        private enum enumMixinStr_TCPI_OPT_ECN = `enum TCPI_OPT_ECN = 8;`;
        static if(is(typeof({ mixin(enumMixinStr_TCPI_OPT_ECN); }))) {
            mixin(enumMixinStr_TCPI_OPT_ECN);
        }
    }




    static if(!is(typeof(TCPI_OPT_WSCALE))) {
        private enum enumMixinStr_TCPI_OPT_WSCALE = `enum TCPI_OPT_WSCALE = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_TCPI_OPT_WSCALE); }))) {
            mixin(enumMixinStr_TCPI_OPT_WSCALE);
        }
    }
    static if(!is(typeof(TCPI_OPT_SACK))) {
        private enum enumMixinStr_TCPI_OPT_SACK = `enum TCPI_OPT_SACK = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_TCPI_OPT_SACK); }))) {
            mixin(enumMixinStr_TCPI_OPT_SACK);
        }
    }






    static if(!is(typeof(TTYDEF_IFLAG))) {
        private enum enumMixinStr_TTYDEF_IFLAG = `enum TTYDEF_IFLAG = ( BRKINT | ISTRIP | ICRNL | IMAXBEL | IXON | IXANY );`;
        static if(is(typeof({ mixin(enumMixinStr_TTYDEF_IFLAG); }))) {
            mixin(enumMixinStr_TTYDEF_IFLAG);
        }
    }




    static if(!is(typeof(TTYDEF_OFLAG))) {
        private enum enumMixinStr_TTYDEF_OFLAG = `enum TTYDEF_OFLAG = ( OPOST | ONLCR | XTABS );`;
        static if(is(typeof({ mixin(enumMixinStr_TTYDEF_OFLAG); }))) {
            mixin(enumMixinStr_TTYDEF_OFLAG);
        }
    }




    static if(!is(typeof(TTYDEF_LFLAG))) {
        private enum enumMixinStr_TTYDEF_LFLAG = `enum TTYDEF_LFLAG = ( ECHO | ICANON | ISIG | IEXTEN | ECHOE | ECHOKE | ECHOCTL );`;
        static if(is(typeof({ mixin(enumMixinStr_TTYDEF_LFLAG); }))) {
            mixin(enumMixinStr_TTYDEF_LFLAG);
        }
    }




    static if(!is(typeof(TTYDEF_CFLAG))) {
        private enum enumMixinStr_TTYDEF_CFLAG = `enum TTYDEF_CFLAG = ( CREAD | CS7 | PARENB | HUPCL );`;
        static if(is(typeof({ mixin(enumMixinStr_TTYDEF_CFLAG); }))) {
            mixin(enumMixinStr_TTYDEF_CFLAG);
        }
    }




    static if(!is(typeof(TTYDEF_SPEED))) {
        private enum enumMixinStr_TTYDEF_SPEED = `enum TTYDEF_SPEED = ( B9600 );`;
        static if(is(typeof({ mixin(enumMixinStr_TTYDEF_SPEED); }))) {
            mixin(enumMixinStr_TTYDEF_SPEED);
        }
    }






    static if(!is(typeof(CEOF))) {
        private enum enumMixinStr_CEOF = `enum CEOF = ( 'd' & 037 );`;
        static if(is(typeof({ mixin(enumMixinStr_CEOF); }))) {
            mixin(enumMixinStr_CEOF);
        }
    }




    static if(!is(typeof(TCPI_OPT_TIMESTAMPS))) {
        private enum enumMixinStr_TCPI_OPT_TIMESTAMPS = `enum TCPI_OPT_TIMESTAMPS = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_TCPI_OPT_TIMESTAMPS); }))) {
            mixin(enumMixinStr_TCPI_OPT_TIMESTAMPS);
        }
    }




    static if(!is(typeof(CEOL))) {
        private enum enumMixinStr_CEOL = `enum CEOL = _POSIX_VDISABLE;`;
        static if(is(typeof({ mixin(enumMixinStr_CEOL); }))) {
            mixin(enumMixinStr_CEOL);
        }
    }




    static if(!is(typeof(CERASE))) {
        private enum enumMixinStr_CERASE = `enum CERASE = std.conv.octal!177;`;
        static if(is(typeof({ mixin(enumMixinStr_CERASE); }))) {
            mixin(enumMixinStr_CERASE);
        }
    }




    static if(!is(typeof(CINTR))) {
        private enum enumMixinStr_CINTR = `enum CINTR = ( 'c' & 037 );`;
        static if(is(typeof({ mixin(enumMixinStr_CINTR); }))) {
            mixin(enumMixinStr_CINTR);
        }
    }




    static if(!is(typeof(SOL_TCP))) {
        private enum enumMixinStr_SOL_TCP = `enum SOL_TCP = 6;`;
        static if(is(typeof({ mixin(enumMixinStr_SOL_TCP); }))) {
            mixin(enumMixinStr_SOL_TCP);
        }
    }




    static if(!is(typeof(CSTATUS))) {
        private enum enumMixinStr_CSTATUS = `enum CSTATUS = _POSIX_VDISABLE;`;
        static if(is(typeof({ mixin(enumMixinStr_CSTATUS); }))) {
            mixin(enumMixinStr_CSTATUS);
        }
    }




    static if(!is(typeof(CKILL))) {
        private enum enumMixinStr_CKILL = `enum CKILL = ( 'u' & 037 );`;
        static if(is(typeof({ mixin(enumMixinStr_CKILL); }))) {
            mixin(enumMixinStr_CKILL);
        }
    }




    static if(!is(typeof(CMIN))) {
        private enum enumMixinStr_CMIN = `enum CMIN = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_CMIN); }))) {
            mixin(enumMixinStr_CMIN);
        }
    }




    static if(!is(typeof(CQUIT))) {
        private enum enumMixinStr_CQUIT = `enum CQUIT = std.conv.octal!34;`;
        static if(is(typeof({ mixin(enumMixinStr_CQUIT); }))) {
            mixin(enumMixinStr_CQUIT);
        }
    }




    static if(!is(typeof(CSUSP))) {
        private enum enumMixinStr_CSUSP = `enum CSUSP = ( 'z' & 037 );`;
        static if(is(typeof({ mixin(enumMixinStr_CSUSP); }))) {
            mixin(enumMixinStr_CSUSP);
        }
    }




    static if(!is(typeof(CTIME))) {
        private enum enumMixinStr_CTIME = `enum CTIME = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_CTIME); }))) {
            mixin(enumMixinStr_CTIME);
        }
    }




    static if(!is(typeof(CDSUSP))) {
        private enum enumMixinStr_CDSUSP = `enum CDSUSP = ( 'y' & 037 );`;
        static if(is(typeof({ mixin(enumMixinStr_CDSUSP); }))) {
            mixin(enumMixinStr_CDSUSP);
        }
    }




    static if(!is(typeof(CSTART))) {
        private enum enumMixinStr_CSTART = `enum CSTART = ( 'q' & 037 );`;
        static if(is(typeof({ mixin(enumMixinStr_CSTART); }))) {
            mixin(enumMixinStr_CSTART);
        }
    }




    static if(!is(typeof(CSTOP))) {
        private enum enumMixinStr_CSTOP = `enum CSTOP = ( 's' & 037 );`;
        static if(is(typeof({ mixin(enumMixinStr_CSTOP); }))) {
            mixin(enumMixinStr_CSTOP);
        }
    }




    static if(!is(typeof(CLNEXT))) {
        private enum enumMixinStr_CLNEXT = `enum CLNEXT = ( 'v' & 037 );`;
        static if(is(typeof({ mixin(enumMixinStr_CLNEXT); }))) {
            mixin(enumMixinStr_CLNEXT);
        }
    }




    static if(!is(typeof(CDISCARD))) {
        private enum enumMixinStr_CDISCARD = `enum CDISCARD = ( 'o' & 037 );`;
        static if(is(typeof({ mixin(enumMixinStr_CDISCARD); }))) {
            mixin(enumMixinStr_CDISCARD);
        }
    }




    static if(!is(typeof(CWERASE))) {
        private enum enumMixinStr_CWERASE = `enum CWERASE = ( 'w' & 037 );`;
        static if(is(typeof({ mixin(enumMixinStr_CWERASE); }))) {
            mixin(enumMixinStr_CWERASE);
        }
    }




    static if(!is(typeof(CREPRINT))) {
        private enum enumMixinStr_CREPRINT = `enum CREPRINT = ( 'r' & 037 );`;
        static if(is(typeof({ mixin(enumMixinStr_CREPRINT); }))) {
            mixin(enumMixinStr_CREPRINT);
        }
    }




    static if(!is(typeof(CEOT))) {
        private enum enumMixinStr_CEOT = `enum CEOT = ( 'd' & 037 );`;
        static if(is(typeof({ mixin(enumMixinStr_CEOT); }))) {
            mixin(enumMixinStr_CEOT);
        }
    }




    static if(!is(typeof(CBRK))) {
        private enum enumMixinStr_CBRK = `enum CBRK = _POSIX_VDISABLE;`;
        static if(is(typeof({ mixin(enumMixinStr_CBRK); }))) {
            mixin(enumMixinStr_CBRK);
        }
    }




    static if(!is(typeof(CRPRNT))) {
        private enum enumMixinStr_CRPRNT = `enum CRPRNT = ( 'r' & 037 );`;
        static if(is(typeof({ mixin(enumMixinStr_CRPRNT); }))) {
            mixin(enumMixinStr_CRPRNT);
        }
    }




    static if(!is(typeof(CFLUSH))) {
        private enum enumMixinStr_CFLUSH = `enum CFLUSH = ( 'o' & 037 );`;
        static if(is(typeof({ mixin(enumMixinStr_CFLUSH); }))) {
            mixin(enumMixinStr_CFLUSH);
        }
    }




    static if(!is(typeof(_SYS_TYPES_H))) {
        private enum enumMixinStr__SYS_TYPES_H = `enum _SYS_TYPES_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__SYS_TYPES_H); }))) {
            mixin(enumMixinStr__SYS_TYPES_H);
        }
    }




    static if(!is(typeof(TCP_MAX_WINSHIFT))) {
        private enum enumMixinStr_TCP_MAX_WINSHIFT = `enum TCP_MAX_WINSHIFT = 14;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_MAX_WINSHIFT); }))) {
            mixin(enumMixinStr_TCP_MAX_WINSHIFT);
        }
    }




    static if(!is(typeof(TCP_MAXWIN))) {
        private enum enumMixinStr_TCP_MAXWIN = `enum TCP_MAXWIN = 65535;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_MAXWIN); }))) {
            mixin(enumMixinStr_TCP_MAXWIN);
        }
    }




    static if(!is(typeof(TCP_MSS))) {
        private enum enumMixinStr_TCP_MSS = `enum TCP_MSS = 512;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_MSS); }))) {
            mixin(enumMixinStr_TCP_MSS);
        }
    }




    static if(!is(typeof(TCPOPT_TSTAMP_HDR))) {
        private enum enumMixinStr_TCPOPT_TSTAMP_HDR = `enum TCPOPT_TSTAMP_HDR = ( TCPOPT_NOP << 24 | TCPOPT_NOP << 16 | TCPOPT_TIMESTAMP << 8 | TCPOLEN_TIMESTAMP );`;
        static if(is(typeof({ mixin(enumMixinStr_TCPOPT_TSTAMP_HDR); }))) {
            mixin(enumMixinStr_TCPOPT_TSTAMP_HDR);
        }
    }




    static if(!is(typeof(TCPOLEN_TSTAMP_APPA))) {
        private enum enumMixinStr_TCPOLEN_TSTAMP_APPA = `enum TCPOLEN_TSTAMP_APPA = ( TCPOLEN_TIMESTAMP + 2 );`;
        static if(is(typeof({ mixin(enumMixinStr_TCPOLEN_TSTAMP_APPA); }))) {
            mixin(enumMixinStr_TCPOLEN_TSTAMP_APPA);
        }
    }




    static if(!is(typeof(TCPOLEN_TIMESTAMP))) {
        private enum enumMixinStr_TCPOLEN_TIMESTAMP = `enum TCPOLEN_TIMESTAMP = 10;`;
        static if(is(typeof({ mixin(enumMixinStr_TCPOLEN_TIMESTAMP); }))) {
            mixin(enumMixinStr_TCPOLEN_TIMESTAMP);
        }
    }




    static if(!is(typeof(TCPOPT_TIMESTAMP))) {
        private enum enumMixinStr_TCPOPT_TIMESTAMP = `enum TCPOPT_TIMESTAMP = 8;`;
        static if(is(typeof({ mixin(enumMixinStr_TCPOPT_TIMESTAMP); }))) {
            mixin(enumMixinStr_TCPOPT_TIMESTAMP);
        }
    }




    static if(!is(typeof(TCPOPT_SACK))) {
        private enum enumMixinStr_TCPOPT_SACK = `enum TCPOPT_SACK = 5;`;
        static if(is(typeof({ mixin(enumMixinStr_TCPOPT_SACK); }))) {
            mixin(enumMixinStr_TCPOPT_SACK);
        }
    }




    static if(!is(typeof(TCPOLEN_SACK_PERMITTED))) {
        private enum enumMixinStr_TCPOLEN_SACK_PERMITTED = `enum TCPOLEN_SACK_PERMITTED = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_TCPOLEN_SACK_PERMITTED); }))) {
            mixin(enumMixinStr_TCPOLEN_SACK_PERMITTED);
        }
    }




    static if(!is(typeof(TCPOPT_SACK_PERMITTED))) {
        private enum enumMixinStr_TCPOPT_SACK_PERMITTED = `enum TCPOPT_SACK_PERMITTED = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_TCPOPT_SACK_PERMITTED); }))) {
            mixin(enumMixinStr_TCPOPT_SACK_PERMITTED);
        }
    }




    static if(!is(typeof(TCPOLEN_WINDOW))) {
        private enum enumMixinStr_TCPOLEN_WINDOW = `enum TCPOLEN_WINDOW = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_TCPOLEN_WINDOW); }))) {
            mixin(enumMixinStr_TCPOLEN_WINDOW);
        }
    }






    static if(!is(typeof(TCPOPT_WINDOW))) {
        private enum enumMixinStr_TCPOPT_WINDOW = `enum TCPOPT_WINDOW = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_TCPOPT_WINDOW); }))) {
            mixin(enumMixinStr_TCPOPT_WINDOW);
        }
    }




    static if(!is(typeof(TCPOLEN_MAXSEG))) {
        private enum enumMixinStr_TCPOLEN_MAXSEG = `enum TCPOLEN_MAXSEG = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_TCPOLEN_MAXSEG); }))) {
            mixin(enumMixinStr_TCPOLEN_MAXSEG);
        }
    }






    static if(!is(typeof(TCPOPT_MAXSEG))) {
        private enum enumMixinStr_TCPOPT_MAXSEG = `enum TCPOPT_MAXSEG = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_TCPOPT_MAXSEG); }))) {
            mixin(enumMixinStr_TCPOPT_MAXSEG);
        }
    }






    static if(!is(typeof(TCPOPT_NOP))) {
        private enum enumMixinStr_TCPOPT_NOP = `enum TCPOPT_NOP = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_TCPOPT_NOP); }))) {
            mixin(enumMixinStr_TCPOPT_NOP);
        }
    }






    static if(!is(typeof(TCPOPT_EOL))) {
        private enum enumMixinStr_TCPOPT_EOL = `enum TCPOPT_EOL = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_TCPOPT_EOL); }))) {
            mixin(enumMixinStr_TCPOPT_EOL);
        }
    }






    static if(!is(typeof(TH_URG))) {
        private enum enumMixinStr_TH_URG = `enum TH_URG = 0x20;`;
        static if(is(typeof({ mixin(enumMixinStr_TH_URG); }))) {
            mixin(enumMixinStr_TH_URG);
        }
    }






    static if(!is(typeof(TH_ACK))) {
        private enum enumMixinStr_TH_ACK = `enum TH_ACK = 0x10;`;
        static if(is(typeof({ mixin(enumMixinStr_TH_ACK); }))) {
            mixin(enumMixinStr_TH_ACK);
        }
    }






    static if(!is(typeof(TH_PUSH))) {
        private enum enumMixinStr_TH_PUSH = `enum TH_PUSH = 0x08;`;
        static if(is(typeof({ mixin(enumMixinStr_TH_PUSH); }))) {
            mixin(enumMixinStr_TH_PUSH);
        }
    }




    static if(!is(typeof(TH_RST))) {
        private enum enumMixinStr_TH_RST = `enum TH_RST = 0x04;`;
        static if(is(typeof({ mixin(enumMixinStr_TH_RST); }))) {
            mixin(enumMixinStr_TH_RST);
        }
    }






    static if(!is(typeof(TH_SYN))) {
        private enum enumMixinStr_TH_SYN = `enum TH_SYN = 0x02;`;
        static if(is(typeof({ mixin(enumMixinStr_TH_SYN); }))) {
            mixin(enumMixinStr_TH_SYN);
        }
    }




    static if(!is(typeof(TH_FIN))) {
        private enum enumMixinStr_TH_FIN = `enum TH_FIN = 0x01;`;
        static if(is(typeof({ mixin(enumMixinStr_TH_FIN); }))) {
            mixin(enumMixinStr_TH_FIN);
        }
    }






    static if(!is(typeof(TCP_REPAIR_OFF_NO_WP))) {
        private enum enumMixinStr_TCP_REPAIR_OFF_NO_WP = `enum TCP_REPAIR_OFF_NO_WP = - 1;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_REPAIR_OFF_NO_WP); }))) {
            mixin(enumMixinStr_TCP_REPAIR_OFF_NO_WP);
        }
    }




    static if(!is(typeof(TCP_REPAIR_OFF))) {
        private enum enumMixinStr_TCP_REPAIR_OFF = `enum TCP_REPAIR_OFF = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_REPAIR_OFF); }))) {
            mixin(enumMixinStr_TCP_REPAIR_OFF);
        }
    }




    static if(!is(typeof(TCP_REPAIR_ON))) {
        private enum enumMixinStr_TCP_REPAIR_ON = `enum TCP_REPAIR_ON = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_REPAIR_ON); }))) {
            mixin(enumMixinStr_TCP_REPAIR_ON);
        }
    }




    static if(!is(typeof(TCP_TX_DELAY))) {
        private enum enumMixinStr_TCP_TX_DELAY = `enum TCP_TX_DELAY = 37;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_TX_DELAY); }))) {
            mixin(enumMixinStr_TCP_TX_DELAY);
        }
    }






    static if(!is(typeof(TCP_CM_INQ))) {
        private enum enumMixinStr_TCP_CM_INQ = `enum TCP_CM_INQ = TCP_INQ;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_CM_INQ); }))) {
            mixin(enumMixinStr_TCP_CM_INQ);
        }
    }




    static if(!is(typeof(TCP_INQ))) {
        private enum enumMixinStr_TCP_INQ = `enum TCP_INQ = 36;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_INQ); }))) {
            mixin(enumMixinStr_TCP_INQ);
        }
    }






    static if(!is(typeof(TCP_ZEROCOPY_RECEIVE))) {
        private enum enumMixinStr_TCP_ZEROCOPY_RECEIVE = `enum TCP_ZEROCOPY_RECEIVE = 35;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_ZEROCOPY_RECEIVE); }))) {
            mixin(enumMixinStr_TCP_ZEROCOPY_RECEIVE);
        }
    }




    static if(!is(typeof(TCP_FASTOPEN_NO_COOKIE))) {
        private enum enumMixinStr_TCP_FASTOPEN_NO_COOKIE = `enum TCP_FASTOPEN_NO_COOKIE = 34;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_FASTOPEN_NO_COOKIE); }))) {
            mixin(enumMixinStr_TCP_FASTOPEN_NO_COOKIE);
        }
    }




    static if(!is(typeof(TCP_FASTOPEN_KEY))) {
        private enum enumMixinStr_TCP_FASTOPEN_KEY = `enum TCP_FASTOPEN_KEY = 33;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_FASTOPEN_KEY); }))) {
            mixin(enumMixinStr_TCP_FASTOPEN_KEY);
        }
    }




    static if(!is(typeof(TCP_MD5SIG_EXT))) {
        private enum enumMixinStr_TCP_MD5SIG_EXT = `enum TCP_MD5SIG_EXT = 32;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_MD5SIG_EXT); }))) {
            mixin(enumMixinStr_TCP_MD5SIG_EXT);
        }
    }




    static if(!is(typeof(TCP_ULP))) {
        private enum enumMixinStr_TCP_ULP = `enum TCP_ULP = 31;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_ULP); }))) {
            mixin(enumMixinStr_TCP_ULP);
        }
    }




    static if(!is(typeof(TCP_FASTOPEN_CONNECT))) {
        private enum enumMixinStr_TCP_FASTOPEN_CONNECT = `enum TCP_FASTOPEN_CONNECT = 30;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_FASTOPEN_CONNECT); }))) {
            mixin(enumMixinStr_TCP_FASTOPEN_CONNECT);
        }
    }




    static if(!is(typeof(TCP_REPAIR_WINDOW))) {
        private enum enumMixinStr_TCP_REPAIR_WINDOW = `enum TCP_REPAIR_WINDOW = 29;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_REPAIR_WINDOW); }))) {
            mixin(enumMixinStr_TCP_REPAIR_WINDOW);
        }
    }




    static if(!is(typeof(TCP_SAVED_SYN))) {
        private enum enumMixinStr_TCP_SAVED_SYN = `enum TCP_SAVED_SYN = 28;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_SAVED_SYN); }))) {
            mixin(enumMixinStr_TCP_SAVED_SYN);
        }
    }




    static if(!is(typeof(TCP_SAVE_SYN))) {
        private enum enumMixinStr_TCP_SAVE_SYN = `enum TCP_SAVE_SYN = 27;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_SAVE_SYN); }))) {
            mixin(enumMixinStr_TCP_SAVE_SYN);
        }
    }




    static if(!is(typeof(TCP_CC_INFO))) {
        private enum enumMixinStr_TCP_CC_INFO = `enum TCP_CC_INFO = 26;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_CC_INFO); }))) {
            mixin(enumMixinStr_TCP_CC_INFO);
        }
    }




    static if(!is(typeof(TCP_NOTSENT_LOWAT))) {
        private enum enumMixinStr_TCP_NOTSENT_LOWAT = `enum TCP_NOTSENT_LOWAT = 25;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_NOTSENT_LOWAT); }))) {
            mixin(enumMixinStr_TCP_NOTSENT_LOWAT);
        }
    }




    static if(!is(typeof(TCP_TIMESTAMP))) {
        private enum enumMixinStr_TCP_TIMESTAMP = `enum TCP_TIMESTAMP = 24;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_TIMESTAMP); }))) {
            mixin(enumMixinStr_TCP_TIMESTAMP);
        }
    }




    static if(!is(typeof(TCP_FASTOPEN))) {
        private enum enumMixinStr_TCP_FASTOPEN = `enum TCP_FASTOPEN = 23;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_FASTOPEN); }))) {
            mixin(enumMixinStr_TCP_FASTOPEN);
        }
    }




    static if(!is(typeof(TCP_REPAIR_OPTIONS))) {
        private enum enumMixinStr_TCP_REPAIR_OPTIONS = `enum TCP_REPAIR_OPTIONS = 22;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_REPAIR_OPTIONS); }))) {
            mixin(enumMixinStr_TCP_REPAIR_OPTIONS);
        }
    }




    static if(!is(typeof(TCP_QUEUE_SEQ))) {
        private enum enumMixinStr_TCP_QUEUE_SEQ = `enum TCP_QUEUE_SEQ = 21;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_QUEUE_SEQ); }))) {
            mixin(enumMixinStr_TCP_QUEUE_SEQ);
        }
    }




    static if(!is(typeof(TCP_REPAIR_QUEUE))) {
        private enum enumMixinStr_TCP_REPAIR_QUEUE = `enum TCP_REPAIR_QUEUE = 20;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_REPAIR_QUEUE); }))) {
            mixin(enumMixinStr_TCP_REPAIR_QUEUE);
        }
    }




    static if(!is(typeof(TCP_REPAIR))) {
        private enum enumMixinStr_TCP_REPAIR = `enum TCP_REPAIR = 19;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_REPAIR); }))) {
            mixin(enumMixinStr_TCP_REPAIR);
        }
    }




    static if(!is(typeof(__BIT_TYPES_DEFINED__))) {
        private enum enumMixinStr___BIT_TYPES_DEFINED__ = `enum __BIT_TYPES_DEFINED__ = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___BIT_TYPES_DEFINED__); }))) {
            mixin(enumMixinStr___BIT_TYPES_DEFINED__);
        }
    }




    static if(!is(typeof(TCP_USER_TIMEOUT))) {
        private enum enumMixinStr_TCP_USER_TIMEOUT = `enum TCP_USER_TIMEOUT = 18;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_USER_TIMEOUT); }))) {
            mixin(enumMixinStr_TCP_USER_TIMEOUT);
        }
    }




    static if(!is(typeof(TCP_THIN_DUPACK))) {
        private enum enumMixinStr_TCP_THIN_DUPACK = `enum TCP_THIN_DUPACK = 17;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_THIN_DUPACK); }))) {
            mixin(enumMixinStr_TCP_THIN_DUPACK);
        }
    }




    static if(!is(typeof(TCP_THIN_LINEAR_TIMEOUTS))) {
        private enum enumMixinStr_TCP_THIN_LINEAR_TIMEOUTS = `enum TCP_THIN_LINEAR_TIMEOUTS = 16;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_THIN_LINEAR_TIMEOUTS); }))) {
            mixin(enumMixinStr_TCP_THIN_LINEAR_TIMEOUTS);
        }
    }




    static if(!is(typeof(TCP_COOKIE_TRANSACTIONS))) {
        private enum enumMixinStr_TCP_COOKIE_TRANSACTIONS = `enum TCP_COOKIE_TRANSACTIONS = 15;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_COOKIE_TRANSACTIONS); }))) {
            mixin(enumMixinStr_TCP_COOKIE_TRANSACTIONS);
        }
    }




    static if(!is(typeof(TCP_MD5SIG))) {
        private enum enumMixinStr_TCP_MD5SIG = `enum TCP_MD5SIG = 14;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_MD5SIG); }))) {
            mixin(enumMixinStr_TCP_MD5SIG);
        }
    }






    static if(!is(typeof(TCP_CONGESTION))) {
        private enum enumMixinStr_TCP_CONGESTION = `enum TCP_CONGESTION = 13;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_CONGESTION); }))) {
            mixin(enumMixinStr_TCP_CONGESTION);
        }
    }






    static if(!is(typeof(TCP_QUICKACK))) {
        private enum enumMixinStr_TCP_QUICKACK = `enum TCP_QUICKACK = 12;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_QUICKACK); }))) {
            mixin(enumMixinStr_TCP_QUICKACK);
        }
    }






    static if(!is(typeof(TCP_INFO))) {
        private enum enumMixinStr_TCP_INFO = `enum TCP_INFO = 11;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_INFO); }))) {
            mixin(enumMixinStr_TCP_INFO);
        }
    }






    static if(!is(typeof(TCP_WINDOW_CLAMP))) {
        private enum enumMixinStr_TCP_WINDOW_CLAMP = `enum TCP_WINDOW_CLAMP = 10;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_WINDOW_CLAMP); }))) {
            mixin(enumMixinStr_TCP_WINDOW_CLAMP);
        }
    }




    static if(!is(typeof(TCP_DEFER_ACCEPT))) {
        private enum enumMixinStr_TCP_DEFER_ACCEPT = `enum TCP_DEFER_ACCEPT = 9;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_DEFER_ACCEPT); }))) {
            mixin(enumMixinStr_TCP_DEFER_ACCEPT);
        }
    }




    static if(!is(typeof(TCP_LINGER2))) {
        private enum enumMixinStr_TCP_LINGER2 = `enum TCP_LINGER2 = 8;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_LINGER2); }))) {
            mixin(enumMixinStr_TCP_LINGER2);
        }
    }




    static if(!is(typeof(_SYS_UCONTEXT_H))) {
        private enum enumMixinStr__SYS_UCONTEXT_H = `enum _SYS_UCONTEXT_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__SYS_UCONTEXT_H); }))) {
            mixin(enumMixinStr__SYS_UCONTEXT_H);
        }
    }




    static if(!is(typeof(TCP_SYNCNT))) {
        private enum enumMixinStr_TCP_SYNCNT = `enum TCP_SYNCNT = 7;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_SYNCNT); }))) {
            mixin(enumMixinStr_TCP_SYNCNT);
        }
    }




    static if(!is(typeof(TCP_KEEPCNT))) {
        private enum enumMixinStr_TCP_KEEPCNT = `enum TCP_KEEPCNT = 6;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_KEEPCNT); }))) {
            mixin(enumMixinStr_TCP_KEEPCNT);
        }
    }




    static if(!is(typeof(TCP_KEEPINTVL))) {
        private enum enumMixinStr_TCP_KEEPINTVL = `enum TCP_KEEPINTVL = 5;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_KEEPINTVL); }))) {
            mixin(enumMixinStr_TCP_KEEPINTVL);
        }
    }




    static if(!is(typeof(TCP_KEEPIDLE))) {
        private enum enumMixinStr_TCP_KEEPIDLE = `enum TCP_KEEPIDLE = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_KEEPIDLE); }))) {
            mixin(enumMixinStr_TCP_KEEPIDLE);
        }
    }




    static if(!is(typeof(TCP_CORK))) {
        private enum enumMixinStr_TCP_CORK = `enum TCP_CORK = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_CORK); }))) {
            mixin(enumMixinStr_TCP_CORK);
        }
    }




    static if(!is(typeof(__ctx))) {
        private enum enumMixinStr___ctx = `enum __ctx = ( fld ) fld;`;
        static if(is(typeof({ mixin(enumMixinStr___ctx); }))) {
            mixin(enumMixinStr___ctx);
        }
    }




    static if(!is(typeof(TCP_MAXSEG))) {
        private enum enumMixinStr_TCP_MAXSEG = `enum TCP_MAXSEG = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_MAXSEG); }))) {
            mixin(enumMixinStr_TCP_MAXSEG);
        }
    }




    static if(!is(typeof(TCP_NODELAY))) {
        private enum enumMixinStr_TCP_NODELAY = `enum TCP_NODELAY = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_TCP_NODELAY); }))) {
            mixin(enumMixinStr_TCP_NODELAY);
        }
    }




    static if(!is(typeof(__NGREG))) {
        private enum enumMixinStr___NGREG = `enum __NGREG = 23;`;
        static if(is(typeof({ mixin(enumMixinStr___NGREG); }))) {
            mixin(enumMixinStr___NGREG);
        }
    }




    static if(!is(typeof(_NETINET_TCP_H))) {
        private enum enumMixinStr__NETINET_TCP_H = `enum _NETINET_TCP_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__NETINET_TCP_H); }))) {
            mixin(enumMixinStr__NETINET_TCP_H);
        }
    }




    static if(!is(typeof(NGREG))) {
        private enum enumMixinStr_NGREG = `enum NGREG = 23;`;
        static if(is(typeof({ mixin(enumMixinStr_NGREG); }))) {
            mixin(enumMixinStr_NGREG);
        }
    }
    static if(!is(typeof(INET6_ADDRSTRLEN))) {
        private enum enumMixinStr_INET6_ADDRSTRLEN = `enum INET6_ADDRSTRLEN = 46;`;
        static if(is(typeof({ mixin(enumMixinStr_INET6_ADDRSTRLEN); }))) {
            mixin(enumMixinStr_INET6_ADDRSTRLEN);
        }
    }




    static if(!is(typeof(INET_ADDRSTRLEN))) {
        private enum enumMixinStr_INET_ADDRSTRLEN = `enum INET_ADDRSTRLEN = 16;`;
        static if(is(typeof({ mixin(enumMixinStr_INET_ADDRSTRLEN); }))) {
            mixin(enumMixinStr_INET_ADDRSTRLEN);
        }
    }




    static if(!is(typeof(IN6ADDR_LOOPBACK_INIT))) {
        private enum enumMixinStr_IN6ADDR_LOOPBACK_INIT = `enum IN6ADDR_LOOPBACK_INIT = { { { 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 1 } } };`;
        static if(is(typeof({ mixin(enumMixinStr_IN6ADDR_LOOPBACK_INIT); }))) {
            mixin(enumMixinStr_IN6ADDR_LOOPBACK_INIT);
        }
    }




    static if(!is(typeof(IN6ADDR_ANY_INIT))) {
        private enum enumMixinStr_IN6ADDR_ANY_INIT = `enum IN6ADDR_ANY_INIT = { { { 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 } } };`;
        static if(is(typeof({ mixin(enumMixinStr_IN6ADDR_ANY_INIT); }))) {
            mixin(enumMixinStr_IN6ADDR_ANY_INIT);
        }
    }




    static if(!is(typeof(s6_addr32))) {
        private enum enumMixinStr_s6_addr32 = `enum s6_addr32 = __in6_u . __u6_addr32;`;
        static if(is(typeof({ mixin(enumMixinStr_s6_addr32); }))) {
            mixin(enumMixinStr_s6_addr32);
        }
    }




    static if(!is(typeof(s6_addr16))) {
        private enum enumMixinStr_s6_addr16 = `enum s6_addr16 = __in6_u . __u6_addr16;`;
        static if(is(typeof({ mixin(enumMixinStr_s6_addr16); }))) {
            mixin(enumMixinStr_s6_addr16);
        }
    }




    static if(!is(typeof(s6_addr))) {
        private enum enumMixinStr_s6_addr = `enum s6_addr = __in6_u . __u6_addr8;`;
        static if(is(typeof({ mixin(enumMixinStr_s6_addr); }))) {
            mixin(enumMixinStr_s6_addr);
        }
    }




    static if(!is(typeof(INADDR_MAX_LOCAL_GROUP))) {
        private enum enumMixinStr_INADDR_MAX_LOCAL_GROUP = `enum INADDR_MAX_LOCAL_GROUP = ( cast( in_addr_t ) 0xe00000ff );`;
        static if(is(typeof({ mixin(enumMixinStr_INADDR_MAX_LOCAL_GROUP); }))) {
            mixin(enumMixinStr_INADDR_MAX_LOCAL_GROUP);
        }
    }




    static if(!is(typeof(INADDR_ALLSNOOPERS_GROUP))) {
        private enum enumMixinStr_INADDR_ALLSNOOPERS_GROUP = `enum INADDR_ALLSNOOPERS_GROUP = ( cast( in_addr_t ) 0xe000006a );`;
        static if(is(typeof({ mixin(enumMixinStr_INADDR_ALLSNOOPERS_GROUP); }))) {
            mixin(enumMixinStr_INADDR_ALLSNOOPERS_GROUP);
        }
    }




    static if(!is(typeof(_SYS_UIO_H))) {
        private enum enumMixinStr__SYS_UIO_H = `enum _SYS_UIO_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__SYS_UIO_H); }))) {
            mixin(enumMixinStr__SYS_UIO_H);
        }
    }




    static if(!is(typeof(INADDR_ALLRTRS_GROUP))) {
        private enum enumMixinStr_INADDR_ALLRTRS_GROUP = `enum INADDR_ALLRTRS_GROUP = ( cast( in_addr_t ) 0xe0000002 );`;
        static if(is(typeof({ mixin(enumMixinStr_INADDR_ALLRTRS_GROUP); }))) {
            mixin(enumMixinStr_INADDR_ALLRTRS_GROUP);
        }
    }




    static if(!is(typeof(INADDR_ALLHOSTS_GROUP))) {
        private enum enumMixinStr_INADDR_ALLHOSTS_GROUP = `enum INADDR_ALLHOSTS_GROUP = ( cast( in_addr_t ) 0xe0000001 );`;
        static if(is(typeof({ mixin(enumMixinStr_INADDR_ALLHOSTS_GROUP); }))) {
            mixin(enumMixinStr_INADDR_ALLHOSTS_GROUP);
        }
    }




    static if(!is(typeof(INADDR_UNSPEC_GROUP))) {
        private enum enumMixinStr_INADDR_UNSPEC_GROUP = `enum INADDR_UNSPEC_GROUP = ( cast( in_addr_t ) 0xe0000000 );`;
        static if(is(typeof({ mixin(enumMixinStr_INADDR_UNSPEC_GROUP); }))) {
            mixin(enumMixinStr_INADDR_UNSPEC_GROUP);
        }
    }




    static if(!is(typeof(INADDR_LOOPBACK))) {
        private enum enumMixinStr_INADDR_LOOPBACK = `enum INADDR_LOOPBACK = ( cast( in_addr_t ) 0x7f000001 );`;
        static if(is(typeof({ mixin(enumMixinStr_INADDR_LOOPBACK); }))) {
            mixin(enumMixinStr_INADDR_LOOPBACK);
        }
    }




    static if(!is(typeof(IN_LOOPBACKNET))) {
        private enum enumMixinStr_IN_LOOPBACKNET = `enum IN_LOOPBACKNET = 127;`;
        static if(is(typeof({ mixin(enumMixinStr_IN_LOOPBACKNET); }))) {
            mixin(enumMixinStr_IN_LOOPBACKNET);
        }
    }




    static if(!is(typeof(UIO_MAXIOV))) {
        private enum enumMixinStr_UIO_MAXIOV = `enum UIO_MAXIOV = __IOV_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr_UIO_MAXIOV); }))) {
            mixin(enumMixinStr_UIO_MAXIOV);
        }
    }




    static if(!is(typeof(INADDR_NONE))) {
        private enum enumMixinStr_INADDR_NONE = `enum INADDR_NONE = ( cast( in_addr_t ) 0xffffffff );`;
        static if(is(typeof({ mixin(enumMixinStr_INADDR_NONE); }))) {
            mixin(enumMixinStr_INADDR_NONE);
        }
    }




    static if(!is(typeof(INADDR_BROADCAST))) {
        private enum enumMixinStr_INADDR_BROADCAST = `enum INADDR_BROADCAST = ( cast( in_addr_t ) 0xffffffff );`;
        static if(is(typeof({ mixin(enumMixinStr_INADDR_BROADCAST); }))) {
            mixin(enumMixinStr_INADDR_BROADCAST);
        }
    }




    static if(!is(typeof(INADDR_ANY))) {
        private enum enumMixinStr_INADDR_ANY = `enum INADDR_ANY = ( cast( in_addr_t ) 0x00000000 );`;
        static if(is(typeof({ mixin(enumMixinStr_INADDR_ANY); }))) {
            mixin(enumMixinStr_INADDR_ANY);
        }
    }
    static if(!is(typeof(IN_CLASSC_HOST))) {
        private enum enumMixinStr_IN_CLASSC_HOST = `enum IN_CLASSC_HOST = ( 0xffffffff & ~ IN_CLASSC_NET );`;
        static if(is(typeof({ mixin(enumMixinStr_IN_CLASSC_HOST); }))) {
            mixin(enumMixinStr_IN_CLASSC_HOST);
        }
    }




    static if(!is(typeof(IN_CLASSC_NSHIFT))) {
        private enum enumMixinStr_IN_CLASSC_NSHIFT = `enum IN_CLASSC_NSHIFT = 8;`;
        static if(is(typeof({ mixin(enumMixinStr_IN_CLASSC_NSHIFT); }))) {
            mixin(enumMixinStr_IN_CLASSC_NSHIFT);
        }
    }




    static if(!is(typeof(IN_CLASSC_NET))) {
        private enum enumMixinStr_IN_CLASSC_NET = `enum IN_CLASSC_NET = 0xffffff00;`;
        static if(is(typeof({ mixin(enumMixinStr_IN_CLASSC_NET); }))) {
            mixin(enumMixinStr_IN_CLASSC_NET);
        }
    }






    static if(!is(typeof(_SYS_UN_H))) {
        private enum enumMixinStr__SYS_UN_H = `enum _SYS_UN_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__SYS_UN_H); }))) {
            mixin(enumMixinStr__SYS_UN_H);
        }
    }




    static if(!is(typeof(IN_CLASSB_MAX))) {
        private enum enumMixinStr_IN_CLASSB_MAX = `enum IN_CLASSB_MAX = 65536;`;
        static if(is(typeof({ mixin(enumMixinStr_IN_CLASSB_MAX); }))) {
            mixin(enumMixinStr_IN_CLASSB_MAX);
        }
    }




    static if(!is(typeof(IN_CLASSB_HOST))) {
        private enum enumMixinStr_IN_CLASSB_HOST = `enum IN_CLASSB_HOST = ( 0xffffffff & ~ IN_CLASSB_NET );`;
        static if(is(typeof({ mixin(enumMixinStr_IN_CLASSB_HOST); }))) {
            mixin(enumMixinStr_IN_CLASSB_HOST);
        }
    }




    static if(!is(typeof(IN_CLASSB_NSHIFT))) {
        private enum enumMixinStr_IN_CLASSB_NSHIFT = `enum IN_CLASSB_NSHIFT = 16;`;
        static if(is(typeof({ mixin(enumMixinStr_IN_CLASSB_NSHIFT); }))) {
            mixin(enumMixinStr_IN_CLASSB_NSHIFT);
        }
    }




    static if(!is(typeof(IN_CLASSB_NET))) {
        private enum enumMixinStr_IN_CLASSB_NET = `enum IN_CLASSB_NET = 0xffff0000;`;
        static if(is(typeof({ mixin(enumMixinStr_IN_CLASSB_NET); }))) {
            mixin(enumMixinStr_IN_CLASSB_NET);
        }
    }






    static if(!is(typeof(IN_CLASSA_MAX))) {
        private enum enumMixinStr_IN_CLASSA_MAX = `enum IN_CLASSA_MAX = 128;`;
        static if(is(typeof({ mixin(enumMixinStr_IN_CLASSA_MAX); }))) {
            mixin(enumMixinStr_IN_CLASSA_MAX);
        }
    }




    static if(!is(typeof(IN_CLASSA_HOST))) {
        private enum enumMixinStr_IN_CLASSA_HOST = `enum IN_CLASSA_HOST = ( 0xffffffff & ~ IN_CLASSA_NET );`;
        static if(is(typeof({ mixin(enumMixinStr_IN_CLASSA_HOST); }))) {
            mixin(enumMixinStr_IN_CLASSA_HOST);
        }
    }






    static if(!is(typeof(IN_CLASSA_NSHIFT))) {
        private enum enumMixinStr_IN_CLASSA_NSHIFT = `enum IN_CLASSA_NSHIFT = 24;`;
        static if(is(typeof({ mixin(enumMixinStr_IN_CLASSA_NSHIFT); }))) {
            mixin(enumMixinStr_IN_CLASSA_NSHIFT);
        }
    }




    static if(!is(typeof(_SYS_WAIT_H))) {
        private enum enumMixinStr__SYS_WAIT_H = `enum _SYS_WAIT_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__SYS_WAIT_H); }))) {
            mixin(enumMixinStr__SYS_WAIT_H);
        }
    }




    static if(!is(typeof(IN_CLASSA_NET))) {
        private enum enumMixinStr_IN_CLASSA_NET = `enum IN_CLASSA_NET = 0xff000000;`;
        static if(is(typeof({ mixin(enumMixinStr_IN_CLASSA_NET); }))) {
            mixin(enumMixinStr_IN_CLASSA_NET);
        }
    }






    static if(!is(typeof(IPPROTO_MH))) {
        private enum enumMixinStr_IPPROTO_MH = `enum IPPROTO_MH = IPPROTO_MH;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_MH); }))) {
            mixin(enumMixinStr_IPPROTO_MH);
        }
    }




    static if(!is(typeof(IPPROTO_DSTOPTS))) {
        private enum enumMixinStr_IPPROTO_DSTOPTS = `enum IPPROTO_DSTOPTS = IPPROTO_DSTOPTS;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_DSTOPTS); }))) {
            mixin(enumMixinStr_IPPROTO_DSTOPTS);
        }
    }




    static if(!is(typeof(IPPROTO_NONE))) {
        private enum enumMixinStr_IPPROTO_NONE = `enum IPPROTO_NONE = IPPROTO_NONE;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_NONE); }))) {
            mixin(enumMixinStr_IPPROTO_NONE);
        }
    }




    static if(!is(typeof(IPPROTO_ICMPV6))) {
        private enum enumMixinStr_IPPROTO_ICMPV6 = `enum IPPROTO_ICMPV6 = IPPROTO_ICMPV6;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_ICMPV6); }))) {
            mixin(enumMixinStr_IPPROTO_ICMPV6);
        }
    }




    static if(!is(typeof(IPPROTO_FRAGMENT))) {
        private enum enumMixinStr_IPPROTO_FRAGMENT = `enum IPPROTO_FRAGMENT = IPPROTO_FRAGMENT;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_FRAGMENT); }))) {
            mixin(enumMixinStr_IPPROTO_FRAGMENT);
        }
    }




    static if(!is(typeof(IPPROTO_ROUTING))) {
        private enum enumMixinStr_IPPROTO_ROUTING = `enum IPPROTO_ROUTING = IPPROTO_ROUTING;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_ROUTING); }))) {
            mixin(enumMixinStr_IPPROTO_ROUTING);
        }
    }




    static if(!is(typeof(IPPROTO_HOPOPTS))) {
        private enum enumMixinStr_IPPROTO_HOPOPTS = `enum IPPROTO_HOPOPTS = IPPROTO_HOPOPTS;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_HOPOPTS); }))) {
            mixin(enumMixinStr_IPPROTO_HOPOPTS);
        }
    }




    static if(!is(typeof(IPPROTO_RAW))) {
        private enum enumMixinStr_IPPROTO_RAW = `enum IPPROTO_RAW = IPPROTO_RAW;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_RAW); }))) {
            mixin(enumMixinStr_IPPROTO_RAW);
        }
    }




    static if(!is(typeof(WCOREFLAG))) {
        private enum enumMixinStr_WCOREFLAG = `enum WCOREFLAG = __WCOREFLAG;`;
        static if(is(typeof({ mixin(enumMixinStr_WCOREFLAG); }))) {
            mixin(enumMixinStr_WCOREFLAG);
        }
    }
    static if(!is(typeof(IPPROTO_MPLS))) {
        private enum enumMixinStr_IPPROTO_MPLS = `enum IPPROTO_MPLS = IPPROTO_MPLS;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_MPLS); }))) {
            mixin(enumMixinStr_IPPROTO_MPLS);
        }
    }




    static if(!is(typeof(IPPROTO_UDPLITE))) {
        private enum enumMixinStr_IPPROTO_UDPLITE = `enum IPPROTO_UDPLITE = IPPROTO_UDPLITE;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_UDPLITE); }))) {
            mixin(enumMixinStr_IPPROTO_UDPLITE);
        }
    }




    static if(!is(typeof(IPPROTO_SCTP))) {
        private enum enumMixinStr_IPPROTO_SCTP = `enum IPPROTO_SCTP = IPPROTO_SCTP;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_SCTP); }))) {
            mixin(enumMixinStr_IPPROTO_SCTP);
        }
    }




    static if(!is(typeof(IPPROTO_COMP))) {
        private enum enumMixinStr_IPPROTO_COMP = `enum IPPROTO_COMP = IPPROTO_COMP;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_COMP); }))) {
            mixin(enumMixinStr_IPPROTO_COMP);
        }
    }




    static if(!is(typeof(IPPROTO_PIM))) {
        private enum enumMixinStr_IPPROTO_PIM = `enum IPPROTO_PIM = IPPROTO_PIM;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_PIM); }))) {
            mixin(enumMixinStr_IPPROTO_PIM);
        }
    }




    static if(!is(typeof(WAIT_ANY))) {
        private enum enumMixinStr_WAIT_ANY = `enum WAIT_ANY = ( - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_WAIT_ANY); }))) {
            mixin(enumMixinStr_WAIT_ANY);
        }
    }




    static if(!is(typeof(WAIT_MYPGRP))) {
        private enum enumMixinStr_WAIT_MYPGRP = `enum WAIT_MYPGRP = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_WAIT_MYPGRP); }))) {
            mixin(enumMixinStr_WAIT_MYPGRP);
        }
    }




    static if(!is(typeof(IPPROTO_ENCAP))) {
        private enum enumMixinStr_IPPROTO_ENCAP = `enum IPPROTO_ENCAP = IPPROTO_ENCAP;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_ENCAP); }))) {
            mixin(enumMixinStr_IPPROTO_ENCAP);
        }
    }




    static if(!is(typeof(IPPROTO_BEETPH))) {
        private enum enumMixinStr_IPPROTO_BEETPH = `enum IPPROTO_BEETPH = IPPROTO_BEETPH;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_BEETPH); }))) {
            mixin(enumMixinStr_IPPROTO_BEETPH);
        }
    }




    static if(!is(typeof(IPPROTO_MTP))) {
        private enum enumMixinStr_IPPROTO_MTP = `enum IPPROTO_MTP = IPPROTO_MTP;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_MTP); }))) {
            mixin(enumMixinStr_IPPROTO_MTP);
        }
    }




    static if(!is(typeof(IPPROTO_AH))) {
        private enum enumMixinStr_IPPROTO_AH = `enum IPPROTO_AH = IPPROTO_AH;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_AH); }))) {
            mixin(enumMixinStr_IPPROTO_AH);
        }
    }




    static if(!is(typeof(IPPROTO_ESP))) {
        private enum enumMixinStr_IPPROTO_ESP = `enum IPPROTO_ESP = IPPROTO_ESP;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_ESP); }))) {
            mixin(enumMixinStr_IPPROTO_ESP);
        }
    }




    static if(!is(typeof(IPPROTO_GRE))) {
        private enum enumMixinStr_IPPROTO_GRE = `enum IPPROTO_GRE = IPPROTO_GRE;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_GRE); }))) {
            mixin(enumMixinStr_IPPROTO_GRE);
        }
    }




    static if(!is(typeof(IPPROTO_RSVP))) {
        private enum enumMixinStr_IPPROTO_RSVP = `enum IPPROTO_RSVP = IPPROTO_RSVP;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_RSVP); }))) {
            mixin(enumMixinStr_IPPROTO_RSVP);
        }
    }




    static if(!is(typeof(IPPROTO_IPV6))) {
        private enum enumMixinStr_IPPROTO_IPV6 = `enum IPPROTO_IPV6 = IPPROTO_IPV6;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_IPV6); }))) {
            mixin(enumMixinStr_IPPROTO_IPV6);
        }
    }




    static if(!is(typeof(IPPROTO_DCCP))) {
        private enum enumMixinStr_IPPROTO_DCCP = `enum IPPROTO_DCCP = IPPROTO_DCCP;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_DCCP); }))) {
            mixin(enumMixinStr_IPPROTO_DCCP);
        }
    }




    static if(!is(typeof(IPPROTO_TP))) {
        private enum enumMixinStr_IPPROTO_TP = `enum IPPROTO_TP = IPPROTO_TP;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_TP); }))) {
            mixin(enumMixinStr_IPPROTO_TP);
        }
    }




    static if(!is(typeof(IPPROTO_IDP))) {
        private enum enumMixinStr_IPPROTO_IDP = `enum IPPROTO_IDP = IPPROTO_IDP;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_IDP); }))) {
            mixin(enumMixinStr_IPPROTO_IDP);
        }
    }




    static if(!is(typeof(IPPROTO_UDP))) {
        private enum enumMixinStr_IPPROTO_UDP = `enum IPPROTO_UDP = IPPROTO_UDP;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_UDP); }))) {
            mixin(enumMixinStr_IPPROTO_UDP);
        }
    }




    static if(!is(typeof(IPPROTO_PUP))) {
        private enum enumMixinStr_IPPROTO_PUP = `enum IPPROTO_PUP = IPPROTO_PUP;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_PUP); }))) {
            mixin(enumMixinStr_IPPROTO_PUP);
        }
    }




    static if(!is(typeof(IPPROTO_EGP))) {
        private enum enumMixinStr_IPPROTO_EGP = `enum IPPROTO_EGP = IPPROTO_EGP;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_EGP); }))) {
            mixin(enumMixinStr_IPPROTO_EGP);
        }
    }




    static if(!is(typeof(IPPROTO_TCP))) {
        private enum enumMixinStr_IPPROTO_TCP = `enum IPPROTO_TCP = IPPROTO_TCP;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_TCP); }))) {
            mixin(enumMixinStr_IPPROTO_TCP);
        }
    }




    static if(!is(typeof(_TIME_H))) {
        private enum enumMixinStr__TIME_H = `enum _TIME_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__TIME_H); }))) {
            mixin(enumMixinStr__TIME_H);
        }
    }




    static if(!is(typeof(IPPROTO_IPIP))) {
        private enum enumMixinStr_IPPROTO_IPIP = `enum IPPROTO_IPIP = IPPROTO_IPIP;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_IPIP); }))) {
            mixin(enumMixinStr_IPPROTO_IPIP);
        }
    }




    static if(!is(typeof(IPPROTO_IGMP))) {
        private enum enumMixinStr_IPPROTO_IGMP = `enum IPPROTO_IGMP = IPPROTO_IGMP;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_IGMP); }))) {
            mixin(enumMixinStr_IPPROTO_IGMP);
        }
    }




    static if(!is(typeof(IPPROTO_ICMP))) {
        private enum enumMixinStr_IPPROTO_ICMP = `enum IPPROTO_ICMP = IPPROTO_ICMP;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_ICMP); }))) {
            mixin(enumMixinStr_IPPROTO_ICMP);
        }
    }




    static if(!is(typeof(IPPROTO_IP))) {
        private enum enumMixinStr_IPPROTO_IP = `enum IPPROTO_IP = IPPROTO_IP;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPROTO_IP); }))) {
            mixin(enumMixinStr_IPPROTO_IP);
        }
    }




    static if(!is(typeof(_NETINET_IN_H))) {
        private enum enumMixinStr__NETINET_IN_H = `enum _NETINET_IN_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__NETINET_IN_H); }))) {
            mixin(enumMixinStr__NETINET_IN_H);
        }
    }




    static if(!is(typeof(NI_DGRAM))) {
        private enum enumMixinStr_NI_DGRAM = `enum NI_DGRAM = 16;`;
        static if(is(typeof({ mixin(enumMixinStr_NI_DGRAM); }))) {
            mixin(enumMixinStr_NI_DGRAM);
        }
    }




    static if(!is(typeof(NI_NAMEREQD))) {
        private enum enumMixinStr_NI_NAMEREQD = `enum NI_NAMEREQD = 8;`;
        static if(is(typeof({ mixin(enumMixinStr_NI_NAMEREQD); }))) {
            mixin(enumMixinStr_NI_NAMEREQD);
        }
    }




    static if(!is(typeof(NI_NOFQDN))) {
        private enum enumMixinStr_NI_NOFQDN = `enum NI_NOFQDN = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_NI_NOFQDN); }))) {
            mixin(enumMixinStr_NI_NOFQDN);
        }
    }




    static if(!is(typeof(NI_NUMERICSERV))) {
        private enum enumMixinStr_NI_NUMERICSERV = `enum NI_NUMERICSERV = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_NI_NUMERICSERV); }))) {
            mixin(enumMixinStr_NI_NUMERICSERV);
        }
    }




    static if(!is(typeof(NI_NUMERICHOST))) {
        private enum enumMixinStr_NI_NUMERICHOST = `enum NI_NUMERICHOST = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_NI_NUMERICHOST); }))) {
            mixin(enumMixinStr_NI_NUMERICHOST);
        }
    }




    static if(!is(typeof(NI_MAXSERV))) {
        private enum enumMixinStr_NI_MAXSERV = `enum NI_MAXSERV = 32;`;
        static if(is(typeof({ mixin(enumMixinStr_NI_MAXSERV); }))) {
            mixin(enumMixinStr_NI_MAXSERV);
        }
    }




    static if(!is(typeof(NI_MAXHOST))) {
        private enum enumMixinStr_NI_MAXHOST = `enum NI_MAXHOST = 1025;`;
        static if(is(typeof({ mixin(enumMixinStr_NI_MAXHOST); }))) {
            mixin(enumMixinStr_NI_MAXHOST);
        }
    }




    static if(!is(typeof(EAI_OVERFLOW))) {
        private enum enumMixinStr_EAI_OVERFLOW = `enum EAI_OVERFLOW = - 12;`;
        static if(is(typeof({ mixin(enumMixinStr_EAI_OVERFLOW); }))) {
            mixin(enumMixinStr_EAI_OVERFLOW);
        }
    }




    static if(!is(typeof(EAI_SYSTEM))) {
        private enum enumMixinStr_EAI_SYSTEM = `enum EAI_SYSTEM = - 11;`;
        static if(is(typeof({ mixin(enumMixinStr_EAI_SYSTEM); }))) {
            mixin(enumMixinStr_EAI_SYSTEM);
        }
    }




    static if(!is(typeof(EAI_MEMORY))) {
        private enum enumMixinStr_EAI_MEMORY = `enum EAI_MEMORY = - 10;`;
        static if(is(typeof({ mixin(enumMixinStr_EAI_MEMORY); }))) {
            mixin(enumMixinStr_EAI_MEMORY);
        }
    }




    static if(!is(typeof(EAI_SERVICE))) {
        private enum enumMixinStr_EAI_SERVICE = `enum EAI_SERVICE = - 8;`;
        static if(is(typeof({ mixin(enumMixinStr_EAI_SERVICE); }))) {
            mixin(enumMixinStr_EAI_SERVICE);
        }
    }




    static if(!is(typeof(EAI_SOCKTYPE))) {
        private enum enumMixinStr_EAI_SOCKTYPE = `enum EAI_SOCKTYPE = - 7;`;
        static if(is(typeof({ mixin(enumMixinStr_EAI_SOCKTYPE); }))) {
            mixin(enumMixinStr_EAI_SOCKTYPE);
        }
    }




    static if(!is(typeof(EAI_FAMILY))) {
        private enum enumMixinStr_EAI_FAMILY = `enum EAI_FAMILY = - 6;`;
        static if(is(typeof({ mixin(enumMixinStr_EAI_FAMILY); }))) {
            mixin(enumMixinStr_EAI_FAMILY);
        }
    }




    static if(!is(typeof(EAI_FAIL))) {
        private enum enumMixinStr_EAI_FAIL = `enum EAI_FAIL = - 4;`;
        static if(is(typeof({ mixin(enumMixinStr_EAI_FAIL); }))) {
            mixin(enumMixinStr_EAI_FAIL);
        }
    }




    static if(!is(typeof(TIME_UTC))) {
        private enum enumMixinStr_TIME_UTC = `enum TIME_UTC = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_TIME_UTC); }))) {
            mixin(enumMixinStr_TIME_UTC);
        }
    }




    static if(!is(typeof(EAI_AGAIN))) {
        private enum enumMixinStr_EAI_AGAIN = `enum EAI_AGAIN = - 3;`;
        static if(is(typeof({ mixin(enumMixinStr_EAI_AGAIN); }))) {
            mixin(enumMixinStr_EAI_AGAIN);
        }
    }




    static if(!is(typeof(EAI_NONAME))) {
        private enum enumMixinStr_EAI_NONAME = `enum EAI_NONAME = - 2;`;
        static if(is(typeof({ mixin(enumMixinStr_EAI_NONAME); }))) {
            mixin(enumMixinStr_EAI_NONAME);
        }
    }




    static if(!is(typeof(EAI_BADFLAGS))) {
        private enum enumMixinStr_EAI_BADFLAGS = `enum EAI_BADFLAGS = - 1;`;
        static if(is(typeof({ mixin(enumMixinStr_EAI_BADFLAGS); }))) {
            mixin(enumMixinStr_EAI_BADFLAGS);
        }
    }




    static if(!is(typeof(AI_NUMERICSERV))) {
        private enum enumMixinStr_AI_NUMERICSERV = `enum AI_NUMERICSERV = 0x0400;`;
        static if(is(typeof({ mixin(enumMixinStr_AI_NUMERICSERV); }))) {
            mixin(enumMixinStr_AI_NUMERICSERV);
        }
    }




    static if(!is(typeof(AI_ADDRCONFIG))) {
        private enum enumMixinStr_AI_ADDRCONFIG = `enum AI_ADDRCONFIG = 0x0020;`;
        static if(is(typeof({ mixin(enumMixinStr_AI_ADDRCONFIG); }))) {
            mixin(enumMixinStr_AI_ADDRCONFIG);
        }
    }




    static if(!is(typeof(AI_ALL))) {
        private enum enumMixinStr_AI_ALL = `enum AI_ALL = 0x0010;`;
        static if(is(typeof({ mixin(enumMixinStr_AI_ALL); }))) {
            mixin(enumMixinStr_AI_ALL);
        }
    }




    static if(!is(typeof(AI_V4MAPPED))) {
        private enum enumMixinStr_AI_V4MAPPED = `enum AI_V4MAPPED = 0x0008;`;
        static if(is(typeof({ mixin(enumMixinStr_AI_V4MAPPED); }))) {
            mixin(enumMixinStr_AI_V4MAPPED);
        }
    }




    static if(!is(typeof(AI_NUMERICHOST))) {
        private enum enumMixinStr_AI_NUMERICHOST = `enum AI_NUMERICHOST = 0x0004;`;
        static if(is(typeof({ mixin(enumMixinStr_AI_NUMERICHOST); }))) {
            mixin(enumMixinStr_AI_NUMERICHOST);
        }
    }




    static if(!is(typeof(AI_CANONNAME))) {
        private enum enumMixinStr_AI_CANONNAME = `enum AI_CANONNAME = 0x0002;`;
        static if(is(typeof({ mixin(enumMixinStr_AI_CANONNAME); }))) {
            mixin(enumMixinStr_AI_CANONNAME);
        }
    }




    static if(!is(typeof(AI_PASSIVE))) {
        private enum enumMixinStr_AI_PASSIVE = `enum AI_PASSIVE = 0x0001;`;
        static if(is(typeof({ mixin(enumMixinStr_AI_PASSIVE); }))) {
            mixin(enumMixinStr_AI_PASSIVE);
        }
    }




    static if(!is(typeof(h_addr))) {
        private enum enumMixinStr_h_addr = `enum h_addr = h_addr_list [ 0 ];`;
        static if(is(typeof({ mixin(enumMixinStr_h_addr); }))) {
            mixin(enumMixinStr_h_addr);
        }
    }




    static if(!is(typeof(IPPORT_RESERVED))) {
        private enum enumMixinStr_IPPORT_RESERVED = `enum IPPORT_RESERVED = 1024;`;
        static if(is(typeof({ mixin(enumMixinStr_IPPORT_RESERVED); }))) {
            mixin(enumMixinStr_IPPORT_RESERVED);
        }
    }




    static if(!is(typeof(NO_ADDRESS))) {
        private enum enumMixinStr_NO_ADDRESS = `enum NO_ADDRESS = NO_DATA;`;
        static if(is(typeof({ mixin(enumMixinStr_NO_ADDRESS); }))) {
            mixin(enumMixinStr_NO_ADDRESS);
        }
    }




    static if(!is(typeof(NETDB_SUCCESS))) {
        private enum enumMixinStr_NETDB_SUCCESS = `enum NETDB_SUCCESS = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_NETDB_SUCCESS); }))) {
            mixin(enumMixinStr_NETDB_SUCCESS);
        }
    }




    static if(!is(typeof(NETDB_INTERNAL))) {
        private enum enumMixinStr_NETDB_INTERNAL = `enum NETDB_INTERNAL = - 1;`;
        static if(is(typeof({ mixin(enumMixinStr_NETDB_INTERNAL); }))) {
            mixin(enumMixinStr_NETDB_INTERNAL);
        }
    }




    static if(!is(typeof(NO_DATA))) {
        private enum enumMixinStr_NO_DATA = `enum NO_DATA = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_NO_DATA); }))) {
            mixin(enumMixinStr_NO_DATA);
        }
    }




    static if(!is(typeof(NO_RECOVERY))) {
        private enum enumMixinStr_NO_RECOVERY = `enum NO_RECOVERY = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_NO_RECOVERY); }))) {
            mixin(enumMixinStr_NO_RECOVERY);
        }
    }




    static if(!is(typeof(TRY_AGAIN))) {
        private enum enumMixinStr_TRY_AGAIN = `enum TRY_AGAIN = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_TRY_AGAIN); }))) {
            mixin(enumMixinStr_TRY_AGAIN);
        }
    }




    static if(!is(typeof(HOST_NOT_FOUND))) {
        private enum enumMixinStr_HOST_NOT_FOUND = `enum HOST_NOT_FOUND = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_HOST_NOT_FOUND); }))) {
            mixin(enumMixinStr_HOST_NOT_FOUND);
        }
    }




    static if(!is(typeof(h_errno))) {
        private enum enumMixinStr_h_errno = `enum h_errno = ( * __h_errno_location ( ) );`;
        static if(is(typeof({ mixin(enumMixinStr_h_errno); }))) {
            mixin(enumMixinStr_h_errno);
        }
    }




    static if(!is(typeof(_PATH_SERVICES))) {
        private enum enumMixinStr__PATH_SERVICES = `enum _PATH_SERVICES = "/etc/services";`;
        static if(is(typeof({ mixin(enumMixinStr__PATH_SERVICES); }))) {
            mixin(enumMixinStr__PATH_SERVICES);
        }
    }




    static if(!is(typeof(_PATH_PROTOCOLS))) {
        private enum enumMixinStr__PATH_PROTOCOLS = `enum _PATH_PROTOCOLS = "/etc/protocols";`;
        static if(is(typeof({ mixin(enumMixinStr__PATH_PROTOCOLS); }))) {
            mixin(enumMixinStr__PATH_PROTOCOLS);
        }
    }




    static if(!is(typeof(_PATH_NSSWITCH_CONF))) {
        private enum enumMixinStr__PATH_NSSWITCH_CONF = `enum _PATH_NSSWITCH_CONF = "/etc/nsswitch.conf";`;
        static if(is(typeof({ mixin(enumMixinStr__PATH_NSSWITCH_CONF); }))) {
            mixin(enumMixinStr__PATH_NSSWITCH_CONF);
        }
    }




    static if(!is(typeof(_PATH_NETWORKS))) {
        private enum enumMixinStr__PATH_NETWORKS = `enum _PATH_NETWORKS = "/etc/networks";`;
        static if(is(typeof({ mixin(enumMixinStr__PATH_NETWORKS); }))) {
            mixin(enumMixinStr__PATH_NETWORKS);
        }
    }




    static if(!is(typeof(_PATH_HOSTS))) {
        private enum enumMixinStr__PATH_HOSTS = `enum _PATH_HOSTS = "/etc/hosts";`;
        static if(is(typeof({ mixin(enumMixinStr__PATH_HOSTS); }))) {
            mixin(enumMixinStr__PATH_HOSTS);
        }
    }




    static if(!is(typeof(_PATH_HEQUIV))) {
        private enum enumMixinStr__PATH_HEQUIV = `enum _PATH_HEQUIV = "/etc/hosts.equiv";`;
        static if(is(typeof({ mixin(enumMixinStr__PATH_HEQUIV); }))) {
            mixin(enumMixinStr__PATH_HEQUIV);
        }
    }




    static if(!is(typeof(_NETDB_H))) {
        private enum enumMixinStr__NETDB_H = `enum _NETDB_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__NETDB_H); }))) {
            mixin(enumMixinStr__NETDB_H);
        }
    }
    static if(!is(typeof(M_SQRT1_2))) {
        private enum enumMixinStr_M_SQRT1_2 = `enum M_SQRT1_2 = 0.70710678118654752440;`;
        static if(is(typeof({ mixin(enumMixinStr_M_SQRT1_2); }))) {
            mixin(enumMixinStr_M_SQRT1_2);
        }
    }




    static if(!is(typeof(M_SQRT2))) {
        private enum enumMixinStr_M_SQRT2 = `enum M_SQRT2 = 1.41421356237309504880;`;
        static if(is(typeof({ mixin(enumMixinStr_M_SQRT2); }))) {
            mixin(enumMixinStr_M_SQRT2);
        }
    }




    static if(!is(typeof(M_2_SQRTPI))) {
        private enum enumMixinStr_M_2_SQRTPI = `enum M_2_SQRTPI = 1.12837916709551257390;`;
        static if(is(typeof({ mixin(enumMixinStr_M_2_SQRTPI); }))) {
            mixin(enumMixinStr_M_2_SQRTPI);
        }
    }




    static if(!is(typeof(M_2_PI))) {
        private enum enumMixinStr_M_2_PI = `enum M_2_PI = 0.63661977236758134308;`;
        static if(is(typeof({ mixin(enumMixinStr_M_2_PI); }))) {
            mixin(enumMixinStr_M_2_PI);
        }
    }




    static if(!is(typeof(M_1_PI))) {
        private enum enumMixinStr_M_1_PI = `enum M_1_PI = 0.31830988618379067154;`;
        static if(is(typeof({ mixin(enumMixinStr_M_1_PI); }))) {
            mixin(enumMixinStr_M_1_PI);
        }
    }




    static if(!is(typeof(M_PI_4))) {
        private enum enumMixinStr_M_PI_4 = `enum M_PI_4 = 0.78539816339744830962;`;
        static if(is(typeof({ mixin(enumMixinStr_M_PI_4); }))) {
            mixin(enumMixinStr_M_PI_4);
        }
    }




    static if(!is(typeof(M_PI_2))) {
        private enum enumMixinStr_M_PI_2 = `enum M_PI_2 = 1.57079632679489661923;`;
        static if(is(typeof({ mixin(enumMixinStr_M_PI_2); }))) {
            mixin(enumMixinStr_M_PI_2);
        }
    }




    static if(!is(typeof(M_PI))) {
        private enum enumMixinStr_M_PI = `enum M_PI = 3.14159265358979323846;`;
        static if(is(typeof({ mixin(enumMixinStr_M_PI); }))) {
            mixin(enumMixinStr_M_PI);
        }
    }




    static if(!is(typeof(M_LN10))) {
        private enum enumMixinStr_M_LN10 = `enum M_LN10 = 2.30258509299404568402;`;
        static if(is(typeof({ mixin(enumMixinStr_M_LN10); }))) {
            mixin(enumMixinStr_M_LN10);
        }
    }




    static if(!is(typeof(M_LN2))) {
        private enum enumMixinStr_M_LN2 = `enum M_LN2 = 0.69314718055994530942;`;
        static if(is(typeof({ mixin(enumMixinStr_M_LN2); }))) {
            mixin(enumMixinStr_M_LN2);
        }
    }




    static if(!is(typeof(M_LOG10E))) {
        private enum enumMixinStr_M_LOG10E = `enum M_LOG10E = 0.43429448190325182765;`;
        static if(is(typeof({ mixin(enumMixinStr_M_LOG10E); }))) {
            mixin(enumMixinStr_M_LOG10E);
        }
    }






    static if(!is(typeof(M_LOG2E))) {
        private enum enumMixinStr_M_LOG2E = `enum M_LOG2E = 1.4426950408889634074;`;
        static if(is(typeof({ mixin(enumMixinStr_M_LOG2E); }))) {
            mixin(enumMixinStr_M_LOG2E);
        }
    }




    static if(!is(typeof(M_E))) {
        private enum enumMixinStr_M_E = `enum M_E = 2.7182818284590452354;`;
        static if(is(typeof({ mixin(enumMixinStr_M_E); }))) {
            mixin(enumMixinStr_M_E);
        }
    }




    static if(!is(typeof(math_errhandling))) {
        private enum enumMixinStr_math_errhandling = `enum math_errhandling = ( MATH_ERRNO | MATH_ERREXCEPT );`;
        static if(is(typeof({ mixin(enumMixinStr_math_errhandling); }))) {
            mixin(enumMixinStr_math_errhandling);
        }
    }




    static if(!is(typeof(MATH_ERREXCEPT))) {
        private enum enumMixinStr_MATH_ERREXCEPT = `enum MATH_ERREXCEPT = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_MATH_ERREXCEPT); }))) {
            mixin(enumMixinStr_MATH_ERREXCEPT);
        }
    }




    static if(!is(typeof(MATH_ERRNO))) {
        private enum enumMixinStr_MATH_ERRNO = `enum MATH_ERRNO = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_MATH_ERRNO); }))) {
            mixin(enumMixinStr_MATH_ERRNO);
        }
    }
    static if(!is(typeof(FP_NORMAL))) {
        private enum enumMixinStr_FP_NORMAL = `enum FP_NORMAL = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_FP_NORMAL); }))) {
            mixin(enumMixinStr_FP_NORMAL);
        }
    }




    static if(!is(typeof(FP_SUBNORMAL))) {
        private enum enumMixinStr_FP_SUBNORMAL = `enum FP_SUBNORMAL = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_FP_SUBNORMAL); }))) {
            mixin(enumMixinStr_FP_SUBNORMAL);
        }
    }




    static if(!is(typeof(FP_ZERO))) {
        private enum enumMixinStr_FP_ZERO = `enum FP_ZERO = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_FP_ZERO); }))) {
            mixin(enumMixinStr_FP_ZERO);
        }
    }




    static if(!is(typeof(FP_INFINITE))) {
        private enum enumMixinStr_FP_INFINITE = `enum FP_INFINITE = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_FP_INFINITE); }))) {
            mixin(enumMixinStr_FP_INFINITE);
        }
    }




    static if(!is(typeof(FP_NAN))) {
        private enum enumMixinStr_FP_NAN = `enum FP_NAN = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_FP_NAN); }))) {
            mixin(enumMixinStr_FP_NAN);
        }
    }






    static if(!is(typeof(__MATHCALL_NARROW))) {
        private enum enumMixinStr___MATHCALL_NARROW = `enum __MATHCALL_NARROW = ( func , redir , nargs ) __MATHCALL_NARROW_NORMAL ( func , nargs );`;
        static if(is(typeof({ mixin(enumMixinStr___MATHCALL_NARROW); }))) {
            mixin(enumMixinStr___MATHCALL_NARROW);
        }
    }




    static if(!is(typeof(__MATHCALL_NARROW_REDIR))) {
        private enum enumMixinStr___MATHCALL_NARROW_REDIR = `enum __MATHCALL_NARROW_REDIR = ( func , redir , nargs ) extern _Mret_ func __MATHCALL_NARROW_ARGS_ ## nargs __asm__ ( "" "redir" ) __attribute__ ( ( __nothrow__ ) );`;
        static if(is(typeof({ mixin(enumMixinStr___MATHCALL_NARROW_REDIR); }))) {
            mixin(enumMixinStr___MATHCALL_NARROW_REDIR);
        }
    }




    static if(!is(typeof(__MATHCALL_NARROW_NORMAL))) {
        private enum enumMixinStr___MATHCALL_NARROW_NORMAL = `enum __MATHCALL_NARROW_NORMAL = ( func , nargs ) extern _Mret_ func __MATHCALL_NARROW_ARGS_ ## nargs __attribute__ ( ( __nothrow__ ) );`;
        static if(is(typeof({ mixin(enumMixinStr___MATHCALL_NARROW_NORMAL); }))) {
            mixin(enumMixinStr___MATHCALL_NARROW_NORMAL);
        }
    }




    static if(!is(typeof(__MATHCALL_NARROW_ARGS_3))) {
        private enum enumMixinStr___MATHCALL_NARROW_ARGS_3 = `enum __MATHCALL_NARROW_ARGS_3 = ( _Marg_ __x , _Marg_ __y , _Marg_ __z );`;
        static if(is(typeof({ mixin(enumMixinStr___MATHCALL_NARROW_ARGS_3); }))) {
            mixin(enumMixinStr___MATHCALL_NARROW_ARGS_3);
        }
    }




    static if(!is(typeof(__MATHCALL_NARROW_ARGS_2))) {
        private enum enumMixinStr___MATHCALL_NARROW_ARGS_2 = `enum __MATHCALL_NARROW_ARGS_2 = ( _Marg_ __x , _Marg_ __y );`;
        static if(is(typeof({ mixin(enumMixinStr___MATHCALL_NARROW_ARGS_2); }))) {
            mixin(enumMixinStr___MATHCALL_NARROW_ARGS_2);
        }
    }




    static if(!is(typeof(__MATHCALL_NARROW_ARGS_1))) {
        private enum enumMixinStr___MATHCALL_NARROW_ARGS_1 = `enum __MATHCALL_NARROW_ARGS_1 = ( _Marg_ __x );`;
        static if(is(typeof({ mixin(enumMixinStr___MATHCALL_NARROW_ARGS_1); }))) {
            mixin(enumMixinStr___MATHCALL_NARROW_ARGS_1);
        }
    }




    static if(!is(typeof(__MATH_DECLARING_FLOATN))) {
        private enum enumMixinStr___MATH_DECLARING_FLOATN = `enum __MATH_DECLARING_FLOATN = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___MATH_DECLARING_FLOATN); }))) {
            mixin(enumMixinStr___MATH_DECLARING_FLOATN);
        }
    }




    static if(!is(typeof(__MATH_DECLARING_DOUBLE))) {
        private enum enumMixinStr___MATH_DECLARING_DOUBLE = `enum __MATH_DECLARING_DOUBLE = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___MATH_DECLARING_DOUBLE); }))) {
            mixin(enumMixinStr___MATH_DECLARING_DOUBLE);
        }
    }




    static if(!is(typeof(__MATH_PRECNAME))) {
        private enum enumMixinStr___MATH_PRECNAME = `enum __MATH_PRECNAME = ( name , r ) name ## f64x ## r;`;
        static if(is(typeof({ mixin(enumMixinStr___MATH_PRECNAME); }))) {
            mixin(enumMixinStr___MATH_PRECNAME);
        }
    }




    static if(!is(typeof(_Mdouble_))) {
        private enum enumMixinStr__Mdouble_ = `enum _Mdouble_ = _Float64x;`;
        static if(is(typeof({ mixin(enumMixinStr__Mdouble_); }))) {
            mixin(enumMixinStr__Mdouble_);
        }
    }




    static if(!is(typeof(_UNISTD_H))) {
        private enum enumMixinStr__UNISTD_H = `enum _UNISTD_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__UNISTD_H); }))) {
            mixin(enumMixinStr__UNISTD_H);
        }
    }




    static if(!is(typeof(_POSIX_VERSION))) {
        private enum enumMixinStr__POSIX_VERSION = `enum _POSIX_VERSION = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_VERSION); }))) {
            mixin(enumMixinStr__POSIX_VERSION);
        }
    }




    static if(!is(typeof(__POSIX2_THIS_VERSION))) {
        private enum enumMixinStr___POSIX2_THIS_VERSION = `enum __POSIX2_THIS_VERSION = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr___POSIX2_THIS_VERSION); }))) {
            mixin(enumMixinStr___POSIX2_THIS_VERSION);
        }
    }




    static if(!is(typeof(_POSIX2_VERSION))) {
        private enum enumMixinStr__POSIX2_VERSION = `enum _POSIX2_VERSION = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX2_VERSION); }))) {
            mixin(enumMixinStr__POSIX2_VERSION);
        }
    }




    static if(!is(typeof(_POSIX2_C_VERSION))) {
        private enum enumMixinStr__POSIX2_C_VERSION = `enum _POSIX2_C_VERSION = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX2_C_VERSION); }))) {
            mixin(enumMixinStr__POSIX2_C_VERSION);
        }
    }




    static if(!is(typeof(_POSIX2_C_BIND))) {
        private enum enumMixinStr__POSIX2_C_BIND = `enum _POSIX2_C_BIND = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX2_C_BIND); }))) {
            mixin(enumMixinStr__POSIX2_C_BIND);
        }
    }




    static if(!is(typeof(_POSIX2_C_DEV))) {
        private enum enumMixinStr__POSIX2_C_DEV = `enum _POSIX2_C_DEV = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX2_C_DEV); }))) {
            mixin(enumMixinStr__POSIX2_C_DEV);
        }
    }




    static if(!is(typeof(_POSIX2_SW_DEV))) {
        private enum enumMixinStr__POSIX2_SW_DEV = `enum _POSIX2_SW_DEV = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX2_SW_DEV); }))) {
            mixin(enumMixinStr__POSIX2_SW_DEV);
        }
    }




    static if(!is(typeof(_POSIX2_LOCALEDEF))) {
        private enum enumMixinStr__POSIX2_LOCALEDEF = `enum _POSIX2_LOCALEDEF = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX2_LOCALEDEF); }))) {
            mixin(enumMixinStr__POSIX2_LOCALEDEF);
        }
    }




    static if(!is(typeof(_XOPEN_VERSION))) {
        private enum enumMixinStr__XOPEN_VERSION = `enum _XOPEN_VERSION = 700;`;
        static if(is(typeof({ mixin(enumMixinStr__XOPEN_VERSION); }))) {
            mixin(enumMixinStr__XOPEN_VERSION);
        }
    }




    static if(!is(typeof(_XOPEN_XCU_VERSION))) {
        private enum enumMixinStr__XOPEN_XCU_VERSION = `enum _XOPEN_XCU_VERSION = 4;`;
        static if(is(typeof({ mixin(enumMixinStr__XOPEN_XCU_VERSION); }))) {
            mixin(enumMixinStr__XOPEN_XCU_VERSION);
        }
    }




    static if(!is(typeof(_XOPEN_XPG2))) {
        private enum enumMixinStr__XOPEN_XPG2 = `enum _XOPEN_XPG2 = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__XOPEN_XPG2); }))) {
            mixin(enumMixinStr__XOPEN_XPG2);
        }
    }




    static if(!is(typeof(_XOPEN_XPG3))) {
        private enum enumMixinStr__XOPEN_XPG3 = `enum _XOPEN_XPG3 = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__XOPEN_XPG3); }))) {
            mixin(enumMixinStr__XOPEN_XPG3);
        }
    }




    static if(!is(typeof(_XOPEN_XPG4))) {
        private enum enumMixinStr__XOPEN_XPG4 = `enum _XOPEN_XPG4 = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__XOPEN_XPG4); }))) {
            mixin(enumMixinStr__XOPEN_XPG4);
        }
    }




    static if(!is(typeof(_XOPEN_UNIX))) {
        private enum enumMixinStr__XOPEN_UNIX = `enum _XOPEN_UNIX = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__XOPEN_UNIX); }))) {
            mixin(enumMixinStr__XOPEN_UNIX);
        }
    }




    static if(!is(typeof(_XOPEN_ENH_I18N))) {
        private enum enumMixinStr__XOPEN_ENH_I18N = `enum _XOPEN_ENH_I18N = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__XOPEN_ENH_I18N); }))) {
            mixin(enumMixinStr__XOPEN_ENH_I18N);
        }
    }




    static if(!is(typeof(_XOPEN_LEGACY))) {
        private enum enumMixinStr__XOPEN_LEGACY = `enum _XOPEN_LEGACY = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__XOPEN_LEGACY); }))) {
            mixin(enumMixinStr__XOPEN_LEGACY);
        }
    }




    static if(!is(typeof(__MATH_DECLARE_LDOUBLE))) {
        private enum enumMixinStr___MATH_DECLARE_LDOUBLE = `enum __MATH_DECLARE_LDOUBLE = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___MATH_DECLARE_LDOUBLE); }))) {
            mixin(enumMixinStr___MATH_DECLARE_LDOUBLE);
        }
    }




    static if(!is(typeof(STDIN_FILENO))) {
        private enum enumMixinStr_STDIN_FILENO = `enum STDIN_FILENO = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_STDIN_FILENO); }))) {
            mixin(enumMixinStr_STDIN_FILENO);
        }
    }




    static if(!is(typeof(STDOUT_FILENO))) {
        private enum enumMixinStr_STDOUT_FILENO = `enum STDOUT_FILENO = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_STDOUT_FILENO); }))) {
            mixin(enumMixinStr_STDOUT_FILENO);
        }
    }




    static if(!is(typeof(STDERR_FILENO))) {
        private enum enumMixinStr_STDERR_FILENO = `enum STDERR_FILENO = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_STDERR_FILENO); }))) {
            mixin(enumMixinStr_STDERR_FILENO);
        }
    }






    static if(!is(typeof(__MATHDECL_1))) {
        private enum enumMixinStr___MATHDECL_1 = `enum __MATHDECL_1 = ( type , function , suffix , args ) extern type ( name , r ) namef64xr ( function , suffix ) args __attribute__ ( ( __nothrow__ ) );`;
        static if(is(typeof({ mixin(enumMixinStr___MATHDECL_1); }))) {
            mixin(enumMixinStr___MATHDECL_1);
        }
    }
    static if(!is(typeof(R_OK))) {
        private enum enumMixinStr_R_OK = `enum R_OK = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_R_OK); }))) {
            mixin(enumMixinStr_R_OK);
        }
    }




    static if(!is(typeof(W_OK))) {
        private enum enumMixinStr_W_OK = `enum W_OK = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_W_OK); }))) {
            mixin(enumMixinStr_W_OK);
        }
    }




    static if(!is(typeof(X_OK))) {
        private enum enumMixinStr_X_OK = `enum X_OK = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_X_OK); }))) {
            mixin(enumMixinStr_X_OK);
        }
    }




    static if(!is(typeof(F_OK))) {
        private enum enumMixinStr_F_OK = `enum F_OK = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_F_OK); }))) {
            mixin(enumMixinStr_F_OK);
        }
    }




    static if(!is(typeof(__MATHDECL))) {
        private enum enumMixinStr___MATHDECL = `enum __MATHDECL = ( type , function , suffix , args ) ( type , function , suffix , args ) extern type ( name , r ) namef64xr ( function , suffix ) args __attribute__ ( ( __nothrow__ ) ) ( type , function , suffix , args ) ; ( type , function , suffix , args ) extern type ( name , r ) namef64xr ( function , suffix ) args __attribute__ ( ( __nothrow__ ) ) ( type , __function , suffix , args );`;
        static if(is(typeof({ mixin(enumMixinStr___MATHDECL); }))) {
            mixin(enumMixinStr___MATHDECL);
        }
    }




    static if(!is(typeof(__MATHCALL))) {
        private enum enumMixinStr___MATHCALL = `enum __MATHCALL = ( function , suffix , args ) ( type , function , suffix , args ) ( type , function , suffix , args ) extern type ( name , r ) namef64xr ( function , suffix ) args __attribute__ ( ( __nothrow__ ) ) ( type , function , suffix , args ) ; ( type , function , suffix , args ) extern type ( name , r ) namef64xr ( function , suffix ) args __attribute__ ( ( __nothrow__ ) ) ( type , __function , suffix , args ) ( _Float64x , function , suffix , args );`;
        static if(is(typeof({ mixin(enumMixinStr___MATHCALL); }))) {
            mixin(enumMixinStr___MATHCALL);
        }
    }
    static if(!is(typeof(FP_ILOGBNAN))) {
        private enum enumMixinStr_FP_ILOGBNAN = `enum FP_ILOGBNAN = ( - 2147483647 - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_FP_ILOGBNAN); }))) {
            mixin(enumMixinStr_FP_ILOGBNAN);
        }
    }




    static if(!is(typeof(FP_ILOGB0))) {
        private enum enumMixinStr_FP_ILOGB0 = `enum FP_ILOGB0 = ( - 2147483647 - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_FP_ILOGB0); }))) {
            mixin(enumMixinStr_FP_ILOGB0);
        }
    }




    static if(!is(typeof(NAN))) {
        private enum enumMixinStr_NAN = `enum NAN = ( __builtin_nanf ( "" ) );`;
        static if(is(typeof({ mixin(enumMixinStr_NAN); }))) {
            mixin(enumMixinStr_NAN);
        }
    }




    static if(!is(typeof(INFINITY))) {
        private enum enumMixinStr_INFINITY = `enum INFINITY = ( __builtin_inff ( ) );`;
        static if(is(typeof({ mixin(enumMixinStr_INFINITY); }))) {
            mixin(enumMixinStr_INFINITY);
        }
    }




    static if(!is(typeof(HUGE_VALL))) {
        private enum enumMixinStr_HUGE_VALL = `enum HUGE_VALL = ( __builtin_huge_vall ( ) );`;
        static if(is(typeof({ mixin(enumMixinStr_HUGE_VALL); }))) {
            mixin(enumMixinStr_HUGE_VALL);
        }
    }




    static if(!is(typeof(L_SET))) {
        private enum enumMixinStr_L_SET = `enum L_SET = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_L_SET); }))) {
            mixin(enumMixinStr_L_SET);
        }
    }




    static if(!is(typeof(L_INCR))) {
        private enum enumMixinStr_L_INCR = `enum L_INCR = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_L_INCR); }))) {
            mixin(enumMixinStr_L_INCR);
        }
    }




    static if(!is(typeof(L_XTND))) {
        private enum enumMixinStr_L_XTND = `enum L_XTND = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_L_XTND); }))) {
            mixin(enumMixinStr_L_XTND);
        }
    }




    static if(!is(typeof(HUGE_VALF))) {
        private enum enumMixinStr_HUGE_VALF = `enum HUGE_VALF = ( __builtin_huge_valf ( ) );`;
        static if(is(typeof({ mixin(enumMixinStr_HUGE_VALF); }))) {
            mixin(enumMixinStr_HUGE_VALF);
        }
    }




    static if(!is(typeof(HUGE_VAL))) {
        private enum enumMixinStr_HUGE_VAL = `enum HUGE_VAL = ( __builtin_huge_val ( ) );`;
        static if(is(typeof({ mixin(enumMixinStr_HUGE_VAL); }))) {
            mixin(enumMixinStr_HUGE_VAL);
        }
    }




    static if(!is(typeof(_MATH_H))) {
        private enum enumMixinStr__MATH_H = `enum _MATH_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__MATH_H); }))) {
            mixin(enumMixinStr__MATH_H);
        }
    }




    static if(!is(typeof(__FD_SETSIZE))) {
        private enum enumMixinStr___FD_SETSIZE = `enum __FD_SETSIZE = 1024;`;
        static if(is(typeof({ mixin(enumMixinStr___FD_SETSIZE); }))) {
            mixin(enumMixinStr___FD_SETSIZE);
        }
    }
    static if(!is(typeof(RTSIG_MAX))) {
        private enum enumMixinStr_RTSIG_MAX = `enum RTSIG_MAX = 32;`;
        static if(is(typeof({ mixin(enumMixinStr_RTSIG_MAX); }))) {
            mixin(enumMixinStr_RTSIG_MAX);
        }
    }




    static if(!is(typeof(XATTR_LIST_MAX))) {
        private enum enumMixinStr_XATTR_LIST_MAX = `enum XATTR_LIST_MAX = 65536;`;
        static if(is(typeof({ mixin(enumMixinStr_XATTR_LIST_MAX); }))) {
            mixin(enumMixinStr_XATTR_LIST_MAX);
        }
    }




    static if(!is(typeof(XATTR_SIZE_MAX))) {
        private enum enumMixinStr_XATTR_SIZE_MAX = `enum XATTR_SIZE_MAX = 65536;`;
        static if(is(typeof({ mixin(enumMixinStr_XATTR_SIZE_MAX); }))) {
            mixin(enumMixinStr_XATTR_SIZE_MAX);
        }
    }




    static if(!is(typeof(XATTR_NAME_MAX))) {
        private enum enumMixinStr_XATTR_NAME_MAX = `enum XATTR_NAME_MAX = 255;`;
        static if(is(typeof({ mixin(enumMixinStr_XATTR_NAME_MAX); }))) {
            mixin(enumMixinStr_XATTR_NAME_MAX);
        }
    }




    static if(!is(typeof(PIPE_BUF))) {
        private enum enumMixinStr_PIPE_BUF = `enum PIPE_BUF = 4096;`;
        static if(is(typeof({ mixin(enumMixinStr_PIPE_BUF); }))) {
            mixin(enumMixinStr_PIPE_BUF);
        }
    }




    static if(!is(typeof(PATH_MAX))) {
        private enum enumMixinStr_PATH_MAX = `enum PATH_MAX = 4096;`;
        static if(is(typeof({ mixin(enumMixinStr_PATH_MAX); }))) {
            mixin(enumMixinStr_PATH_MAX);
        }
    }




    static if(!is(typeof(NAME_MAX))) {
        private enum enumMixinStr_NAME_MAX = `enum NAME_MAX = 255;`;
        static if(is(typeof({ mixin(enumMixinStr_NAME_MAX); }))) {
            mixin(enumMixinStr_NAME_MAX);
        }
    }




    static if(!is(typeof(MAX_INPUT))) {
        private enum enumMixinStr_MAX_INPUT = `enum MAX_INPUT = 255;`;
        static if(is(typeof({ mixin(enumMixinStr_MAX_INPUT); }))) {
            mixin(enumMixinStr_MAX_INPUT);
        }
    }




    static if(!is(typeof(MAX_CANON))) {
        private enum enumMixinStr_MAX_CANON = `enum MAX_CANON = 255;`;
        static if(is(typeof({ mixin(enumMixinStr_MAX_CANON); }))) {
            mixin(enumMixinStr_MAX_CANON);
        }
    }




    static if(!is(typeof(LINK_MAX))) {
        private enum enumMixinStr_LINK_MAX = `enum LINK_MAX = 127;`;
        static if(is(typeof({ mixin(enumMixinStr_LINK_MAX); }))) {
            mixin(enumMixinStr_LINK_MAX);
        }
    }




    static if(!is(typeof(ARG_MAX))) {
        private enum enumMixinStr_ARG_MAX = `enum ARG_MAX = 131072;`;
        static if(is(typeof({ mixin(enumMixinStr_ARG_MAX); }))) {
            mixin(enumMixinStr_ARG_MAX);
        }
    }




    static if(!is(typeof(NGROUPS_MAX))) {
        private enum enumMixinStr_NGROUPS_MAX = `enum NGROUPS_MAX = 65536;`;
        static if(is(typeof({ mixin(enumMixinStr_NGROUPS_MAX); }))) {
            mixin(enumMixinStr_NGROUPS_MAX);
        }
    }




    static if(!is(typeof(NR_OPEN))) {
        private enum enumMixinStr_NR_OPEN = `enum NR_OPEN = 1024;`;
        static if(is(typeof({ mixin(enumMixinStr_NR_OPEN); }))) {
            mixin(enumMixinStr_NR_OPEN);
        }
    }
    static if(!is(typeof(ULLONG_MAX))) {
        private enum enumMixinStr_ULLONG_MAX = `enum ULLONG_MAX = ( LLONG_MAX * 2ULL + 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_ULLONG_MAX); }))) {
            mixin(enumMixinStr_ULLONG_MAX);
        }
    }




    static if(!is(typeof(LLONG_MAX))) {
        private enum enumMixinStr_LLONG_MAX = `enum LLONG_MAX = 0x7fffffffffffffffLL;`;
        static if(is(typeof({ mixin(enumMixinStr_LLONG_MAX); }))) {
            mixin(enumMixinStr_LLONG_MAX);
        }
    }




    static if(!is(typeof(LLONG_MIN))) {
        private enum enumMixinStr_LLONG_MIN = `enum LLONG_MIN = ( - 0x7fffffffffffffffLL - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_LLONG_MIN); }))) {
            mixin(enumMixinStr_LLONG_MIN);
        }
    }




    static if(!is(typeof(MB_LEN_MAX))) {
        private enum enumMixinStr_MB_LEN_MAX = `enum MB_LEN_MAX = 16;`;
        static if(is(typeof({ mixin(enumMixinStr_MB_LEN_MAX); }))) {
            mixin(enumMixinStr_MB_LEN_MAX);
        }
    }




    static if(!is(typeof(_LIBC_LIMITS_H_))) {
        private enum enumMixinStr__LIBC_LIMITS_H_ = `enum _LIBC_LIMITS_H_ = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__LIBC_LIMITS_H_); }))) {
            mixin(enumMixinStr__LIBC_LIMITS_H_);
        }
    }




    static if(!is(typeof(SCNxPTR))) {
        private enum enumMixinStr_SCNxPTR = `enum SCNxPTR = __PRIPTR_PREFIX "x";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNxPTR); }))) {
            mixin(enumMixinStr_SCNxPTR);
        }
    }




    static if(!is(typeof(SCNuPTR))) {
        private enum enumMixinStr_SCNuPTR = `enum SCNuPTR = __PRIPTR_PREFIX "u";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNuPTR); }))) {
            mixin(enumMixinStr_SCNuPTR);
        }
    }




    static if(!is(typeof(SCNoPTR))) {
        private enum enumMixinStr_SCNoPTR = `enum SCNoPTR = __PRIPTR_PREFIX "o";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNoPTR); }))) {
            mixin(enumMixinStr_SCNoPTR);
        }
    }




    static if(!is(typeof(SCNiPTR))) {
        private enum enumMixinStr_SCNiPTR = `enum SCNiPTR = __PRIPTR_PREFIX "i";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNiPTR); }))) {
            mixin(enumMixinStr_SCNiPTR);
        }
    }




    static if(!is(typeof(SCNdPTR))) {
        private enum enumMixinStr_SCNdPTR = `enum SCNdPTR = __PRIPTR_PREFIX "d";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNdPTR); }))) {
            mixin(enumMixinStr_SCNdPTR);
        }
    }




    static if(!is(typeof(SCNxMAX))) {
        private enum enumMixinStr_SCNxMAX = `enum SCNxMAX = __PRI64_PREFIX "x";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNxMAX); }))) {
            mixin(enumMixinStr_SCNxMAX);
        }
    }




    static if(!is(typeof(SCNuMAX))) {
        private enum enumMixinStr_SCNuMAX = `enum SCNuMAX = __PRI64_PREFIX "u";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNuMAX); }))) {
            mixin(enumMixinStr_SCNuMAX);
        }
    }




    static if(!is(typeof(SCNoMAX))) {
        private enum enumMixinStr_SCNoMAX = `enum SCNoMAX = __PRI64_PREFIX "o";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNoMAX); }))) {
            mixin(enumMixinStr_SCNoMAX);
        }
    }




    static if(!is(typeof(SCNiMAX))) {
        private enum enumMixinStr_SCNiMAX = `enum SCNiMAX = __PRI64_PREFIX "i";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNiMAX); }))) {
            mixin(enumMixinStr_SCNiMAX);
        }
    }




    static if(!is(typeof(SCNdMAX))) {
        private enum enumMixinStr_SCNdMAX = `enum SCNdMAX = __PRI64_PREFIX "d";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNdMAX); }))) {
            mixin(enumMixinStr_SCNdMAX);
        }
    }




    static if(!is(typeof(SCNxFAST64))) {
        private enum enumMixinStr_SCNxFAST64 = `enum SCNxFAST64 = __PRI64_PREFIX "x";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNxFAST64); }))) {
            mixin(enumMixinStr_SCNxFAST64);
        }
    }




    static if(!is(typeof(SCNxFAST32))) {
        private enum enumMixinStr_SCNxFAST32 = `enum SCNxFAST32 = __PRIPTR_PREFIX "x";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNxFAST32); }))) {
            mixin(enumMixinStr_SCNxFAST32);
        }
    }




    static if(!is(typeof(SCNxFAST16))) {
        private enum enumMixinStr_SCNxFAST16 = `enum SCNxFAST16 = __PRIPTR_PREFIX "x";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNxFAST16); }))) {
            mixin(enumMixinStr_SCNxFAST16);
        }
    }




    static if(!is(typeof(SCNxFAST8))) {
        private enum enumMixinStr_SCNxFAST8 = `enum SCNxFAST8 = "hhx";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNxFAST8); }))) {
            mixin(enumMixinStr_SCNxFAST8);
        }
    }




    static if(!is(typeof(SCNxLEAST64))) {
        private enum enumMixinStr_SCNxLEAST64 = `enum SCNxLEAST64 = __PRI64_PREFIX "x";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNxLEAST64); }))) {
            mixin(enumMixinStr_SCNxLEAST64);
        }
    }




    static if(!is(typeof(SCNxLEAST32))) {
        private enum enumMixinStr_SCNxLEAST32 = `enum SCNxLEAST32 = "x";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNxLEAST32); }))) {
            mixin(enumMixinStr_SCNxLEAST32);
        }
    }




    static if(!is(typeof(SCNxLEAST16))) {
        private enum enumMixinStr_SCNxLEAST16 = `enum SCNxLEAST16 = "hx";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNxLEAST16); }))) {
            mixin(enumMixinStr_SCNxLEAST16);
        }
    }




    static if(!is(typeof(SCNxLEAST8))) {
        private enum enumMixinStr_SCNxLEAST8 = `enum SCNxLEAST8 = "hhx";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNxLEAST8); }))) {
            mixin(enumMixinStr_SCNxLEAST8);
        }
    }




    static if(!is(typeof(SCNx64))) {
        private enum enumMixinStr_SCNx64 = `enum SCNx64 = __PRI64_PREFIX "x";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNx64); }))) {
            mixin(enumMixinStr_SCNx64);
        }
    }




    static if(!is(typeof(SCNx32))) {
        private enum enumMixinStr_SCNx32 = `enum SCNx32 = "x";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNx32); }))) {
            mixin(enumMixinStr_SCNx32);
        }
    }




    static if(!is(typeof(SCNx16))) {
        private enum enumMixinStr_SCNx16 = `enum SCNx16 = "hx";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNx16); }))) {
            mixin(enumMixinStr_SCNx16);
        }
    }




    static if(!is(typeof(SCNx8))) {
        private enum enumMixinStr_SCNx8 = `enum SCNx8 = "hhx";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNx8); }))) {
            mixin(enumMixinStr_SCNx8);
        }
    }




    static if(!is(typeof(SCNoFAST64))) {
        private enum enumMixinStr_SCNoFAST64 = `enum SCNoFAST64 = __PRI64_PREFIX "o";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNoFAST64); }))) {
            mixin(enumMixinStr_SCNoFAST64);
        }
    }




    static if(!is(typeof(SCNoFAST32))) {
        private enum enumMixinStr_SCNoFAST32 = `enum SCNoFAST32 = __PRIPTR_PREFIX "o";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNoFAST32); }))) {
            mixin(enumMixinStr_SCNoFAST32);
        }
    }




    static if(!is(typeof(SCNoFAST16))) {
        private enum enumMixinStr_SCNoFAST16 = `enum SCNoFAST16 = __PRIPTR_PREFIX "o";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNoFAST16); }))) {
            mixin(enumMixinStr_SCNoFAST16);
        }
    }




    static if(!is(typeof(SCNoFAST8))) {
        private enum enumMixinStr_SCNoFAST8 = `enum SCNoFAST8 = "hho";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNoFAST8); }))) {
            mixin(enumMixinStr_SCNoFAST8);
        }
    }




    static if(!is(typeof(SCNoLEAST64))) {
        private enum enumMixinStr_SCNoLEAST64 = `enum SCNoLEAST64 = __PRI64_PREFIX "o";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNoLEAST64); }))) {
            mixin(enumMixinStr_SCNoLEAST64);
        }
    }




    static if(!is(typeof(SCNoLEAST32))) {
        private enum enumMixinStr_SCNoLEAST32 = `enum SCNoLEAST32 = "o";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNoLEAST32); }))) {
            mixin(enumMixinStr_SCNoLEAST32);
        }
    }




    static if(!is(typeof(SCNoLEAST16))) {
        private enum enumMixinStr_SCNoLEAST16 = `enum SCNoLEAST16 = "ho";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNoLEAST16); }))) {
            mixin(enumMixinStr_SCNoLEAST16);
        }
    }




    static if(!is(typeof(SCNoLEAST8))) {
        private enum enumMixinStr_SCNoLEAST8 = `enum SCNoLEAST8 = "hho";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNoLEAST8); }))) {
            mixin(enumMixinStr_SCNoLEAST8);
        }
    }




    static if(!is(typeof(SCNo64))) {
        private enum enumMixinStr_SCNo64 = `enum SCNo64 = __PRI64_PREFIX "o";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNo64); }))) {
            mixin(enumMixinStr_SCNo64);
        }
    }




    static if(!is(typeof(SCNo32))) {
        private enum enumMixinStr_SCNo32 = `enum SCNo32 = "o";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNo32); }))) {
            mixin(enumMixinStr_SCNo32);
        }
    }




    static if(!is(typeof(SCNo16))) {
        private enum enumMixinStr_SCNo16 = `enum SCNo16 = "ho";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNo16); }))) {
            mixin(enumMixinStr_SCNo16);
        }
    }




    static if(!is(typeof(SCNo8))) {
        private enum enumMixinStr_SCNo8 = `enum SCNo8 = "hho";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNo8); }))) {
            mixin(enumMixinStr_SCNo8);
        }
    }




    static if(!is(typeof(SCNuFAST64))) {
        private enum enumMixinStr_SCNuFAST64 = `enum SCNuFAST64 = __PRI64_PREFIX "u";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNuFAST64); }))) {
            mixin(enumMixinStr_SCNuFAST64);
        }
    }




    static if(!is(typeof(SCNuFAST32))) {
        private enum enumMixinStr_SCNuFAST32 = `enum SCNuFAST32 = __PRIPTR_PREFIX "u";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNuFAST32); }))) {
            mixin(enumMixinStr_SCNuFAST32);
        }
    }




    static if(!is(typeof(SCNuFAST16))) {
        private enum enumMixinStr_SCNuFAST16 = `enum SCNuFAST16 = __PRIPTR_PREFIX "u";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNuFAST16); }))) {
            mixin(enumMixinStr_SCNuFAST16);
        }
    }




    static if(!is(typeof(SCNuFAST8))) {
        private enum enumMixinStr_SCNuFAST8 = `enum SCNuFAST8 = "hhu";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNuFAST8); }))) {
            mixin(enumMixinStr_SCNuFAST8);
        }
    }




    static if(!is(typeof(SCNuLEAST64))) {
        private enum enumMixinStr_SCNuLEAST64 = `enum SCNuLEAST64 = __PRI64_PREFIX "u";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNuLEAST64); }))) {
            mixin(enumMixinStr_SCNuLEAST64);
        }
    }




    static if(!is(typeof(SCNuLEAST32))) {
        private enum enumMixinStr_SCNuLEAST32 = `enum SCNuLEAST32 = "u";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNuLEAST32); }))) {
            mixin(enumMixinStr_SCNuLEAST32);
        }
    }




    static if(!is(typeof(SCNuLEAST16))) {
        private enum enumMixinStr_SCNuLEAST16 = `enum SCNuLEAST16 = "hu";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNuLEAST16); }))) {
            mixin(enumMixinStr_SCNuLEAST16);
        }
    }




    static if(!is(typeof(SCNuLEAST8))) {
        private enum enumMixinStr_SCNuLEAST8 = `enum SCNuLEAST8 = "hhu";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNuLEAST8); }))) {
            mixin(enumMixinStr_SCNuLEAST8);
        }
    }




    static if(!is(typeof(SCNu64))) {
        private enum enumMixinStr_SCNu64 = `enum SCNu64 = __PRI64_PREFIX "u";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNu64); }))) {
            mixin(enumMixinStr_SCNu64);
        }
    }




    static if(!is(typeof(SCNu32))) {
        private enum enumMixinStr_SCNu32 = `enum SCNu32 = "u";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNu32); }))) {
            mixin(enumMixinStr_SCNu32);
        }
    }




    static if(!is(typeof(SCNu16))) {
        private enum enumMixinStr_SCNu16 = `enum SCNu16 = "hu";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNu16); }))) {
            mixin(enumMixinStr_SCNu16);
        }
    }




    static if(!is(typeof(SCNu8))) {
        private enum enumMixinStr_SCNu8 = `enum SCNu8 = "hhu";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNu8); }))) {
            mixin(enumMixinStr_SCNu8);
        }
    }




    static if(!is(typeof(SCNiFAST64))) {
        private enum enumMixinStr_SCNiFAST64 = `enum SCNiFAST64 = __PRI64_PREFIX "i";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNiFAST64); }))) {
            mixin(enumMixinStr_SCNiFAST64);
        }
    }




    static if(!is(typeof(SCNiFAST32))) {
        private enum enumMixinStr_SCNiFAST32 = `enum SCNiFAST32 = __PRIPTR_PREFIX "i";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNiFAST32); }))) {
            mixin(enumMixinStr_SCNiFAST32);
        }
    }




    static if(!is(typeof(SCNiFAST16))) {
        private enum enumMixinStr_SCNiFAST16 = `enum SCNiFAST16 = __PRIPTR_PREFIX "i";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNiFAST16); }))) {
            mixin(enumMixinStr_SCNiFAST16);
        }
    }




    static if(!is(typeof(SCNiFAST8))) {
        private enum enumMixinStr_SCNiFAST8 = `enum SCNiFAST8 = "hhi";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNiFAST8); }))) {
            mixin(enumMixinStr_SCNiFAST8);
        }
    }




    static if(!is(typeof(SCNiLEAST64))) {
        private enum enumMixinStr_SCNiLEAST64 = `enum SCNiLEAST64 = __PRI64_PREFIX "i";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNiLEAST64); }))) {
            mixin(enumMixinStr_SCNiLEAST64);
        }
    }




    static if(!is(typeof(SCNiLEAST32))) {
        private enum enumMixinStr_SCNiLEAST32 = `enum SCNiLEAST32 = "i";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNiLEAST32); }))) {
            mixin(enumMixinStr_SCNiLEAST32);
        }
    }




    static if(!is(typeof(SCNiLEAST16))) {
        private enum enumMixinStr_SCNiLEAST16 = `enum SCNiLEAST16 = "hi";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNiLEAST16); }))) {
            mixin(enumMixinStr_SCNiLEAST16);
        }
    }




    static if(!is(typeof(SCNiLEAST8))) {
        private enum enumMixinStr_SCNiLEAST8 = `enum SCNiLEAST8 = "hhi";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNiLEAST8); }))) {
            mixin(enumMixinStr_SCNiLEAST8);
        }
    }




    static if(!is(typeof(SCNi64))) {
        private enum enumMixinStr_SCNi64 = `enum SCNi64 = __PRI64_PREFIX "i";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNi64); }))) {
            mixin(enumMixinStr_SCNi64);
        }
    }




    static if(!is(typeof(SCNi32))) {
        private enum enumMixinStr_SCNi32 = `enum SCNi32 = "i";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNi32); }))) {
            mixin(enumMixinStr_SCNi32);
        }
    }




    static if(!is(typeof(SCNi16))) {
        private enum enumMixinStr_SCNi16 = `enum SCNi16 = "hi";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNi16); }))) {
            mixin(enumMixinStr_SCNi16);
        }
    }




    static if(!is(typeof(SCNi8))) {
        private enum enumMixinStr_SCNi8 = `enum SCNi8 = "hhi";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNi8); }))) {
            mixin(enumMixinStr_SCNi8);
        }
    }




    static if(!is(typeof(SCNdFAST64))) {
        private enum enumMixinStr_SCNdFAST64 = `enum SCNdFAST64 = __PRI64_PREFIX "d";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNdFAST64); }))) {
            mixin(enumMixinStr_SCNdFAST64);
        }
    }




    static if(!is(typeof(SCNdFAST32))) {
        private enum enumMixinStr_SCNdFAST32 = `enum SCNdFAST32 = __PRIPTR_PREFIX "d";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNdFAST32); }))) {
            mixin(enumMixinStr_SCNdFAST32);
        }
    }




    static if(!is(typeof(SCNdFAST16))) {
        private enum enumMixinStr_SCNdFAST16 = `enum SCNdFAST16 = __PRIPTR_PREFIX "d";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNdFAST16); }))) {
            mixin(enumMixinStr_SCNdFAST16);
        }
    }




    static if(!is(typeof(SCNdFAST8))) {
        private enum enumMixinStr_SCNdFAST8 = `enum SCNdFAST8 = "hhd";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNdFAST8); }))) {
            mixin(enumMixinStr_SCNdFAST8);
        }
    }




    static if(!is(typeof(SCNdLEAST64))) {
        private enum enumMixinStr_SCNdLEAST64 = `enum SCNdLEAST64 = __PRI64_PREFIX "d";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNdLEAST64); }))) {
            mixin(enumMixinStr_SCNdLEAST64);
        }
    }




    static if(!is(typeof(SCNdLEAST32))) {
        private enum enumMixinStr_SCNdLEAST32 = `enum SCNdLEAST32 = "d";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNdLEAST32); }))) {
            mixin(enumMixinStr_SCNdLEAST32);
        }
    }




    static if(!is(typeof(SCNdLEAST16))) {
        private enum enumMixinStr_SCNdLEAST16 = `enum SCNdLEAST16 = "hd";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNdLEAST16); }))) {
            mixin(enumMixinStr_SCNdLEAST16);
        }
    }




    static if(!is(typeof(SCNdLEAST8))) {
        private enum enumMixinStr_SCNdLEAST8 = `enum SCNdLEAST8 = "hhd";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNdLEAST8); }))) {
            mixin(enumMixinStr_SCNdLEAST8);
        }
    }




    static if(!is(typeof(SCNd64))) {
        private enum enumMixinStr_SCNd64 = `enum SCNd64 = __PRI64_PREFIX "d";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNd64); }))) {
            mixin(enumMixinStr_SCNd64);
        }
    }




    static if(!is(typeof(SCNd32))) {
        private enum enumMixinStr_SCNd32 = `enum SCNd32 = "d";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNd32); }))) {
            mixin(enumMixinStr_SCNd32);
        }
    }




    static if(!is(typeof(SCNd16))) {
        private enum enumMixinStr_SCNd16 = `enum SCNd16 = "hd";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNd16); }))) {
            mixin(enumMixinStr_SCNd16);
        }
    }




    static if(!is(typeof(SCNd8))) {
        private enum enumMixinStr_SCNd8 = `enum SCNd8 = "hhd";`;
        static if(is(typeof({ mixin(enumMixinStr_SCNd8); }))) {
            mixin(enumMixinStr_SCNd8);
        }
    }




    static if(!is(typeof(PRIXPTR))) {
        private enum enumMixinStr_PRIXPTR = `enum PRIXPTR = __PRIPTR_PREFIX "X";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIXPTR); }))) {
            mixin(enumMixinStr_PRIXPTR);
        }
    }




    static if(!is(typeof(PRIxPTR))) {
        private enum enumMixinStr_PRIxPTR = `enum PRIxPTR = __PRIPTR_PREFIX "x";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIxPTR); }))) {
            mixin(enumMixinStr_PRIxPTR);
        }
    }




    static if(!is(typeof(PRIuPTR))) {
        private enum enumMixinStr_PRIuPTR = `enum PRIuPTR = __PRIPTR_PREFIX "u";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIuPTR); }))) {
            mixin(enumMixinStr_PRIuPTR);
        }
    }




    static if(!is(typeof(PRIoPTR))) {
        private enum enumMixinStr_PRIoPTR = `enum PRIoPTR = __PRIPTR_PREFIX "o";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIoPTR); }))) {
            mixin(enumMixinStr_PRIoPTR);
        }
    }




    static if(!is(typeof(PRIiPTR))) {
        private enum enumMixinStr_PRIiPTR = `enum PRIiPTR = __PRIPTR_PREFIX "i";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIiPTR); }))) {
            mixin(enumMixinStr_PRIiPTR);
        }
    }




    static if(!is(typeof(PRIdPTR))) {
        private enum enumMixinStr_PRIdPTR = `enum PRIdPTR = __PRIPTR_PREFIX "d";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIdPTR); }))) {
            mixin(enumMixinStr_PRIdPTR);
        }
    }




    static if(!is(typeof(PRIXMAX))) {
        private enum enumMixinStr_PRIXMAX = `enum PRIXMAX = __PRI64_PREFIX "X";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIXMAX); }))) {
            mixin(enumMixinStr_PRIXMAX);
        }
    }




    static if(!is(typeof(PRIxMAX))) {
        private enum enumMixinStr_PRIxMAX = `enum PRIxMAX = __PRI64_PREFIX "x";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIxMAX); }))) {
            mixin(enumMixinStr_PRIxMAX);
        }
    }




    static if(!is(typeof(PRIuMAX))) {
        private enum enumMixinStr_PRIuMAX = `enum PRIuMAX = __PRI64_PREFIX "u";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIuMAX); }))) {
            mixin(enumMixinStr_PRIuMAX);
        }
    }




    static if(!is(typeof(PRIoMAX))) {
        private enum enumMixinStr_PRIoMAX = `enum PRIoMAX = __PRI64_PREFIX "o";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIoMAX); }))) {
            mixin(enumMixinStr_PRIoMAX);
        }
    }




    static if(!is(typeof(PRIiMAX))) {
        private enum enumMixinStr_PRIiMAX = `enum PRIiMAX = __PRI64_PREFIX "i";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIiMAX); }))) {
            mixin(enumMixinStr_PRIiMAX);
        }
    }




    static if(!is(typeof(PRIdMAX))) {
        private enum enumMixinStr_PRIdMAX = `enum PRIdMAX = __PRI64_PREFIX "d";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIdMAX); }))) {
            mixin(enumMixinStr_PRIdMAX);
        }
    }




    static if(!is(typeof(PRIXFAST64))) {
        private enum enumMixinStr_PRIXFAST64 = `enum PRIXFAST64 = __PRI64_PREFIX "X";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIXFAST64); }))) {
            mixin(enumMixinStr_PRIXFAST64);
        }
    }




    static if(!is(typeof(PRIXFAST32))) {
        private enum enumMixinStr_PRIXFAST32 = `enum PRIXFAST32 = __PRIPTR_PREFIX "X";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIXFAST32); }))) {
            mixin(enumMixinStr_PRIXFAST32);
        }
    }




    static if(!is(typeof(PRIXFAST16))) {
        private enum enumMixinStr_PRIXFAST16 = `enum PRIXFAST16 = __PRIPTR_PREFIX "X";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIXFAST16); }))) {
            mixin(enumMixinStr_PRIXFAST16);
        }
    }




    static if(!is(typeof(PRIXFAST8))) {
        private enum enumMixinStr_PRIXFAST8 = `enum PRIXFAST8 = "X";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIXFAST8); }))) {
            mixin(enumMixinStr_PRIXFAST8);
        }
    }




    static if(!is(typeof(PRIXLEAST64))) {
        private enum enumMixinStr_PRIXLEAST64 = `enum PRIXLEAST64 = __PRI64_PREFIX "X";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIXLEAST64); }))) {
            mixin(enumMixinStr_PRIXLEAST64);
        }
    }




    static if(!is(typeof(PRIXLEAST32))) {
        private enum enumMixinStr_PRIXLEAST32 = `enum PRIXLEAST32 = "X";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIXLEAST32); }))) {
            mixin(enumMixinStr_PRIXLEAST32);
        }
    }




    static if(!is(typeof(PRIXLEAST16))) {
        private enum enumMixinStr_PRIXLEAST16 = `enum PRIXLEAST16 = "X";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIXLEAST16); }))) {
            mixin(enumMixinStr_PRIXLEAST16);
        }
    }




    static if(!is(typeof(PRIXLEAST8))) {
        private enum enumMixinStr_PRIXLEAST8 = `enum PRIXLEAST8 = "X";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIXLEAST8); }))) {
            mixin(enumMixinStr_PRIXLEAST8);
        }
    }




    static if(!is(typeof(PRIX64))) {
        private enum enumMixinStr_PRIX64 = `enum PRIX64 = __PRI64_PREFIX "X";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIX64); }))) {
            mixin(enumMixinStr_PRIX64);
        }
    }




    static if(!is(typeof(PRIX32))) {
        private enum enumMixinStr_PRIX32 = `enum PRIX32 = "X";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIX32); }))) {
            mixin(enumMixinStr_PRIX32);
        }
    }




    static if(!is(typeof(PRIX16))) {
        private enum enumMixinStr_PRIX16 = `enum PRIX16 = "X";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIX16); }))) {
            mixin(enumMixinStr_PRIX16);
        }
    }




    static if(!is(typeof(PRIX8))) {
        private enum enumMixinStr_PRIX8 = `enum PRIX8 = "X";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIX8); }))) {
            mixin(enumMixinStr_PRIX8);
        }
    }




    static if(!is(typeof(PRIxFAST64))) {
        private enum enumMixinStr_PRIxFAST64 = `enum PRIxFAST64 = __PRI64_PREFIX "x";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIxFAST64); }))) {
            mixin(enumMixinStr_PRIxFAST64);
        }
    }




    static if(!is(typeof(PRIxFAST32))) {
        private enum enumMixinStr_PRIxFAST32 = `enum PRIxFAST32 = __PRIPTR_PREFIX "x";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIxFAST32); }))) {
            mixin(enumMixinStr_PRIxFAST32);
        }
    }




    static if(!is(typeof(PRIxFAST16))) {
        private enum enumMixinStr_PRIxFAST16 = `enum PRIxFAST16 = __PRIPTR_PREFIX "x";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIxFAST16); }))) {
            mixin(enumMixinStr_PRIxFAST16);
        }
    }




    static if(!is(typeof(PRIxFAST8))) {
        private enum enumMixinStr_PRIxFAST8 = `enum PRIxFAST8 = "x";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIxFAST8); }))) {
            mixin(enumMixinStr_PRIxFAST8);
        }
    }




    static if(!is(typeof(PRIxLEAST64))) {
        private enum enumMixinStr_PRIxLEAST64 = `enum PRIxLEAST64 = __PRI64_PREFIX "x";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIxLEAST64); }))) {
            mixin(enumMixinStr_PRIxLEAST64);
        }
    }




    static if(!is(typeof(PRIxLEAST32))) {
        private enum enumMixinStr_PRIxLEAST32 = `enum PRIxLEAST32 = "x";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIxLEAST32); }))) {
            mixin(enumMixinStr_PRIxLEAST32);
        }
    }




    static if(!is(typeof(PRIxLEAST16))) {
        private enum enumMixinStr_PRIxLEAST16 = `enum PRIxLEAST16 = "x";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIxLEAST16); }))) {
            mixin(enumMixinStr_PRIxLEAST16);
        }
    }




    static if(!is(typeof(PRIxLEAST8))) {
        private enum enumMixinStr_PRIxLEAST8 = `enum PRIxLEAST8 = "x";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIxLEAST8); }))) {
            mixin(enumMixinStr_PRIxLEAST8);
        }
    }




    static if(!is(typeof(PRIx64))) {
        private enum enumMixinStr_PRIx64 = `enum PRIx64 = __PRI64_PREFIX "x";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIx64); }))) {
            mixin(enumMixinStr_PRIx64);
        }
    }




    static if(!is(typeof(PRIx32))) {
        private enum enumMixinStr_PRIx32 = `enum PRIx32 = "x";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIx32); }))) {
            mixin(enumMixinStr_PRIx32);
        }
    }




    static if(!is(typeof(PRIx16))) {
        private enum enumMixinStr_PRIx16 = `enum PRIx16 = "x";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIx16); }))) {
            mixin(enumMixinStr_PRIx16);
        }
    }




    static if(!is(typeof(PRIx8))) {
        private enum enumMixinStr_PRIx8 = `enum PRIx8 = "x";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIx8); }))) {
            mixin(enumMixinStr_PRIx8);
        }
    }




    static if(!is(typeof(PRIuFAST64))) {
        private enum enumMixinStr_PRIuFAST64 = `enum PRIuFAST64 = __PRI64_PREFIX "u";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIuFAST64); }))) {
            mixin(enumMixinStr_PRIuFAST64);
        }
    }




    static if(!is(typeof(PRIuFAST32))) {
        private enum enumMixinStr_PRIuFAST32 = `enum PRIuFAST32 = __PRIPTR_PREFIX "u";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIuFAST32); }))) {
            mixin(enumMixinStr_PRIuFAST32);
        }
    }




    static if(!is(typeof(PRIuFAST16))) {
        private enum enumMixinStr_PRIuFAST16 = `enum PRIuFAST16 = __PRIPTR_PREFIX "u";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIuFAST16); }))) {
            mixin(enumMixinStr_PRIuFAST16);
        }
    }




    static if(!is(typeof(PRIuFAST8))) {
        private enum enumMixinStr_PRIuFAST8 = `enum PRIuFAST8 = "u";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIuFAST8); }))) {
            mixin(enumMixinStr_PRIuFAST8);
        }
    }




    static if(!is(typeof(PRIuLEAST64))) {
        private enum enumMixinStr_PRIuLEAST64 = `enum PRIuLEAST64 = __PRI64_PREFIX "u";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIuLEAST64); }))) {
            mixin(enumMixinStr_PRIuLEAST64);
        }
    }




    static if(!is(typeof(PRIuLEAST32))) {
        private enum enumMixinStr_PRIuLEAST32 = `enum PRIuLEAST32 = "u";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIuLEAST32); }))) {
            mixin(enumMixinStr_PRIuLEAST32);
        }
    }




    static if(!is(typeof(PRIuLEAST16))) {
        private enum enumMixinStr_PRIuLEAST16 = `enum PRIuLEAST16 = "u";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIuLEAST16); }))) {
            mixin(enumMixinStr_PRIuLEAST16);
        }
    }




    static if(!is(typeof(PRIuLEAST8))) {
        private enum enumMixinStr_PRIuLEAST8 = `enum PRIuLEAST8 = "u";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIuLEAST8); }))) {
            mixin(enumMixinStr_PRIuLEAST8);
        }
    }




    static if(!is(typeof(PRIu64))) {
        private enum enumMixinStr_PRIu64 = `enum PRIu64 = __PRI64_PREFIX "u";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIu64); }))) {
            mixin(enumMixinStr_PRIu64);
        }
    }




    static if(!is(typeof(PRIu32))) {
        private enum enumMixinStr_PRIu32 = `enum PRIu32 = "u";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIu32); }))) {
            mixin(enumMixinStr_PRIu32);
        }
    }




    static if(!is(typeof(PRIu16))) {
        private enum enumMixinStr_PRIu16 = `enum PRIu16 = "u";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIu16); }))) {
            mixin(enumMixinStr_PRIu16);
        }
    }




    static if(!is(typeof(PRIu8))) {
        private enum enumMixinStr_PRIu8 = `enum PRIu8 = "u";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIu8); }))) {
            mixin(enumMixinStr_PRIu8);
        }
    }




    static if(!is(typeof(PRIoFAST64))) {
        private enum enumMixinStr_PRIoFAST64 = `enum PRIoFAST64 = __PRI64_PREFIX "o";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIoFAST64); }))) {
            mixin(enumMixinStr_PRIoFAST64);
        }
    }




    static if(!is(typeof(PRIoFAST32))) {
        private enum enumMixinStr_PRIoFAST32 = `enum PRIoFAST32 = __PRIPTR_PREFIX "o";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIoFAST32); }))) {
            mixin(enumMixinStr_PRIoFAST32);
        }
    }




    static if(!is(typeof(PRIoFAST16))) {
        private enum enumMixinStr_PRIoFAST16 = `enum PRIoFAST16 = __PRIPTR_PREFIX "o";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIoFAST16); }))) {
            mixin(enumMixinStr_PRIoFAST16);
        }
    }




    static if(!is(typeof(PRIoFAST8))) {
        private enum enumMixinStr_PRIoFAST8 = `enum PRIoFAST8 = "o";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIoFAST8); }))) {
            mixin(enumMixinStr_PRIoFAST8);
        }
    }




    static if(!is(typeof(PRIoLEAST64))) {
        private enum enumMixinStr_PRIoLEAST64 = `enum PRIoLEAST64 = __PRI64_PREFIX "o";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIoLEAST64); }))) {
            mixin(enumMixinStr_PRIoLEAST64);
        }
    }




    static if(!is(typeof(PRIoLEAST32))) {
        private enum enumMixinStr_PRIoLEAST32 = `enum PRIoLEAST32 = "o";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIoLEAST32); }))) {
            mixin(enumMixinStr_PRIoLEAST32);
        }
    }




    static if(!is(typeof(PRIoLEAST16))) {
        private enum enumMixinStr_PRIoLEAST16 = `enum PRIoLEAST16 = "o";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIoLEAST16); }))) {
            mixin(enumMixinStr_PRIoLEAST16);
        }
    }




    static if(!is(typeof(PRIoLEAST8))) {
        private enum enumMixinStr_PRIoLEAST8 = `enum PRIoLEAST8 = "o";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIoLEAST8); }))) {
            mixin(enumMixinStr_PRIoLEAST8);
        }
    }




    static if(!is(typeof(PRIo64))) {
        private enum enumMixinStr_PRIo64 = `enum PRIo64 = __PRI64_PREFIX "o";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIo64); }))) {
            mixin(enumMixinStr_PRIo64);
        }
    }




    static if(!is(typeof(PRIo32))) {
        private enum enumMixinStr_PRIo32 = `enum PRIo32 = "o";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIo32); }))) {
            mixin(enumMixinStr_PRIo32);
        }
    }




    static if(!is(typeof(PRIo16))) {
        private enum enumMixinStr_PRIo16 = `enum PRIo16 = "o";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIo16); }))) {
            mixin(enumMixinStr_PRIo16);
        }
    }




    static if(!is(typeof(PRIo8))) {
        private enum enumMixinStr_PRIo8 = `enum PRIo8 = "o";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIo8); }))) {
            mixin(enumMixinStr_PRIo8);
        }
    }




    static if(!is(typeof(PRIiFAST64))) {
        private enum enumMixinStr_PRIiFAST64 = `enum PRIiFAST64 = __PRI64_PREFIX "i";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIiFAST64); }))) {
            mixin(enumMixinStr_PRIiFAST64);
        }
    }




    static if(!is(typeof(PRIiFAST32))) {
        private enum enumMixinStr_PRIiFAST32 = `enum PRIiFAST32 = __PRIPTR_PREFIX "i";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIiFAST32); }))) {
            mixin(enumMixinStr_PRIiFAST32);
        }
    }




    static if(!is(typeof(PRIiFAST16))) {
        private enum enumMixinStr_PRIiFAST16 = `enum PRIiFAST16 = __PRIPTR_PREFIX "i";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIiFAST16); }))) {
            mixin(enumMixinStr_PRIiFAST16);
        }
    }




    static if(!is(typeof(PRIiFAST8))) {
        private enum enumMixinStr_PRIiFAST8 = `enum PRIiFAST8 = "i";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIiFAST8); }))) {
            mixin(enumMixinStr_PRIiFAST8);
        }
    }




    static if(!is(typeof(PRIiLEAST64))) {
        private enum enumMixinStr_PRIiLEAST64 = `enum PRIiLEAST64 = __PRI64_PREFIX "i";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIiLEAST64); }))) {
            mixin(enumMixinStr_PRIiLEAST64);
        }
    }




    static if(!is(typeof(PRIiLEAST32))) {
        private enum enumMixinStr_PRIiLEAST32 = `enum PRIiLEAST32 = "i";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIiLEAST32); }))) {
            mixin(enumMixinStr_PRIiLEAST32);
        }
    }




    static if(!is(typeof(PRIiLEAST16))) {
        private enum enumMixinStr_PRIiLEAST16 = `enum PRIiLEAST16 = "i";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIiLEAST16); }))) {
            mixin(enumMixinStr_PRIiLEAST16);
        }
    }




    static if(!is(typeof(PRIiLEAST8))) {
        private enum enumMixinStr_PRIiLEAST8 = `enum PRIiLEAST8 = "i";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIiLEAST8); }))) {
            mixin(enumMixinStr_PRIiLEAST8);
        }
    }




    static if(!is(typeof(PRIi64))) {
        private enum enumMixinStr_PRIi64 = `enum PRIi64 = __PRI64_PREFIX "i";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIi64); }))) {
            mixin(enumMixinStr_PRIi64);
        }
    }




    static if(!is(typeof(PRIi32))) {
        private enum enumMixinStr_PRIi32 = `enum PRIi32 = "i";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIi32); }))) {
            mixin(enumMixinStr_PRIi32);
        }
    }




    static if(!is(typeof(PRIi16))) {
        private enum enumMixinStr_PRIi16 = `enum PRIi16 = "i";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIi16); }))) {
            mixin(enumMixinStr_PRIi16);
        }
    }




    static if(!is(typeof(PRIi8))) {
        private enum enumMixinStr_PRIi8 = `enum PRIi8 = "i";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIi8); }))) {
            mixin(enumMixinStr_PRIi8);
        }
    }




    static if(!is(typeof(PRIdFAST64))) {
        private enum enumMixinStr_PRIdFAST64 = `enum PRIdFAST64 = __PRI64_PREFIX "d";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIdFAST64); }))) {
            mixin(enumMixinStr_PRIdFAST64);
        }
    }




    static if(!is(typeof(PRIdFAST32))) {
        private enum enumMixinStr_PRIdFAST32 = `enum PRIdFAST32 = __PRIPTR_PREFIX "d";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIdFAST32); }))) {
            mixin(enumMixinStr_PRIdFAST32);
        }
    }




    static if(!is(typeof(PRIdFAST16))) {
        private enum enumMixinStr_PRIdFAST16 = `enum PRIdFAST16 = __PRIPTR_PREFIX "d";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIdFAST16); }))) {
            mixin(enumMixinStr_PRIdFAST16);
        }
    }




    static if(!is(typeof(PRIdFAST8))) {
        private enum enumMixinStr_PRIdFAST8 = `enum PRIdFAST8 = "d";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIdFAST8); }))) {
            mixin(enumMixinStr_PRIdFAST8);
        }
    }




    static if(!is(typeof(PRIdLEAST64))) {
        private enum enumMixinStr_PRIdLEAST64 = `enum PRIdLEAST64 = __PRI64_PREFIX "d";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIdLEAST64); }))) {
            mixin(enumMixinStr_PRIdLEAST64);
        }
    }




    static if(!is(typeof(PRIdLEAST32))) {
        private enum enumMixinStr_PRIdLEAST32 = `enum PRIdLEAST32 = "d";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIdLEAST32); }))) {
            mixin(enumMixinStr_PRIdLEAST32);
        }
    }




    static if(!is(typeof(PRIdLEAST16))) {
        private enum enumMixinStr_PRIdLEAST16 = `enum PRIdLEAST16 = "d";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIdLEAST16); }))) {
            mixin(enumMixinStr_PRIdLEAST16);
        }
    }




    static if(!is(typeof(PRIdLEAST8))) {
        private enum enumMixinStr_PRIdLEAST8 = `enum PRIdLEAST8 = "d";`;
        static if(is(typeof({ mixin(enumMixinStr_PRIdLEAST8); }))) {
            mixin(enumMixinStr_PRIdLEAST8);
        }
    }




    static if(!is(typeof(PRId64))) {
        private enum enumMixinStr_PRId64 = `enum PRId64 = __PRI64_PREFIX "d";`;
        static if(is(typeof({ mixin(enumMixinStr_PRId64); }))) {
            mixin(enumMixinStr_PRId64);
        }
    }




    static if(!is(typeof(PRId32))) {
        private enum enumMixinStr_PRId32 = `enum PRId32 = "d";`;
        static if(is(typeof({ mixin(enumMixinStr_PRId32); }))) {
            mixin(enumMixinStr_PRId32);
        }
    }




    static if(!is(typeof(PRId16))) {
        private enum enumMixinStr_PRId16 = `enum PRId16 = "d";`;
        static if(is(typeof({ mixin(enumMixinStr_PRId16); }))) {
            mixin(enumMixinStr_PRId16);
        }
    }




    static if(!is(typeof(PRId8))) {
        private enum enumMixinStr_PRId8 = `enum PRId8 = "d";`;
        static if(is(typeof({ mixin(enumMixinStr_PRId8); }))) {
            mixin(enumMixinStr_PRId8);
        }
    }




    static if(!is(typeof(__PRIPTR_PREFIX))) {
        private enum enumMixinStr___PRIPTR_PREFIX = `enum __PRIPTR_PREFIX = "l";`;
        static if(is(typeof({ mixin(enumMixinStr___PRIPTR_PREFIX); }))) {
            mixin(enumMixinStr___PRIPTR_PREFIX);
        }
    }




    static if(!is(typeof(__PRI64_PREFIX))) {
        private enum enumMixinStr___PRI64_PREFIX = `enum __PRI64_PREFIX = "l";`;
        static if(is(typeof({ mixin(enumMixinStr___PRI64_PREFIX); }))) {
            mixin(enumMixinStr___PRI64_PREFIX);
        }
    }




    static if(!is(typeof(____gwchar_t_defined))) {
        private enum enumMixinStr_____gwchar_t_defined = `enum ____gwchar_t_defined = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_____gwchar_t_defined); }))) {
            mixin(enumMixinStr_____gwchar_t_defined);
        }
    }




    static if(!is(typeof(_INTTYPES_H))) {
        private enum enumMixinStr__INTTYPES_H = `enum _INTTYPES_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__INTTYPES_H); }))) {
            mixin(enumMixinStr__INTTYPES_H);
        }
    }




    static if(!is(typeof(ifa_dstaddr))) {
        private enum enumMixinStr_ifa_dstaddr = `enum ifa_dstaddr = ifa_ifu . ifu_dstaddr;`;
        static if(is(typeof({ mixin(enumMixinStr_ifa_dstaddr); }))) {
            mixin(enumMixinStr_ifa_dstaddr);
        }
    }




    static if(!is(typeof(ifa_broadaddr))) {
        private enum enumMixinStr_ifa_broadaddr = `enum ifa_broadaddr = ifa_ifu . ifu_broadaddr;`;
        static if(is(typeof({ mixin(enumMixinStr_ifa_broadaddr); }))) {
            mixin(enumMixinStr_ifa_broadaddr);
        }
    }




    static if(!is(typeof(_IFADDRS_H))) {
        private enum enumMixinStr__IFADDRS_H = `enum _IFADDRS_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__IFADDRS_H); }))) {
            mixin(enumMixinStr__IFADDRS_H);
        }
    }




    static if(!is(typeof(NSS_BUFLEN_GROUP))) {
        private enum enumMixinStr_NSS_BUFLEN_GROUP = `enum NSS_BUFLEN_GROUP = 1024;`;
        static if(is(typeof({ mixin(enumMixinStr_NSS_BUFLEN_GROUP); }))) {
            mixin(enumMixinStr_NSS_BUFLEN_GROUP);
        }
    }




    static if(!is(typeof(_GRP_H))) {
        private enum enumMixinStr__GRP_H = `enum _GRP_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__GRP_H); }))) {
            mixin(enumMixinStr__GRP_H);
        }
    }
    static if(!is(typeof(__GLIBC_MINOR__))) {
        private enum enumMixinStr___GLIBC_MINOR__ = `enum __GLIBC_MINOR__ = 31;`;
        static if(is(typeof({ mixin(enumMixinStr___GLIBC_MINOR__); }))) {
            mixin(enumMixinStr___GLIBC_MINOR__);
        }
    }




    static if(!is(typeof(__GLIBC__))) {
        private enum enumMixinStr___GLIBC__ = `enum __GLIBC__ = 2;`;
        static if(is(typeof({ mixin(enumMixinStr___GLIBC__); }))) {
            mixin(enumMixinStr___GLIBC__);
        }
    }




    static if(!is(typeof(__GNU_LIBRARY__))) {
        private enum enumMixinStr___GNU_LIBRARY__ = `enum __GNU_LIBRARY__ = 6;`;
        static if(is(typeof({ mixin(enumMixinStr___GNU_LIBRARY__); }))) {
            mixin(enumMixinStr___GNU_LIBRARY__);
        }
    }




    static if(!is(typeof(__GLIBC_USE_DEPRECATED_SCANF))) {
        private enum enumMixinStr___GLIBC_USE_DEPRECATED_SCANF = `enum __GLIBC_USE_DEPRECATED_SCANF = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___GLIBC_USE_DEPRECATED_SCANF); }))) {
            mixin(enumMixinStr___GLIBC_USE_DEPRECATED_SCANF);
        }
    }




    static if(!is(typeof(__GLIBC_USE_DEPRECATED_GETS))) {
        private enum enumMixinStr___GLIBC_USE_DEPRECATED_GETS = `enum __GLIBC_USE_DEPRECATED_GETS = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___GLIBC_USE_DEPRECATED_GETS); }))) {
            mixin(enumMixinStr___GLIBC_USE_DEPRECATED_GETS);
        }
    }




    static if(!is(typeof(__USE_FORTIFY_LEVEL))) {
        private enum enumMixinStr___USE_FORTIFY_LEVEL = `enum __USE_FORTIFY_LEVEL = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___USE_FORTIFY_LEVEL); }))) {
            mixin(enumMixinStr___USE_FORTIFY_LEVEL);
        }
    }




    static if(!is(typeof(__USE_ATFILE))) {
        private enum enumMixinStr___USE_ATFILE = `enum __USE_ATFILE = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___USE_ATFILE); }))) {
            mixin(enumMixinStr___USE_ATFILE);
        }
    }




    static if(!is(typeof(__USE_MISC))) {
        private enum enumMixinStr___USE_MISC = `enum __USE_MISC = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___USE_MISC); }))) {
            mixin(enumMixinStr___USE_MISC);
        }
    }




    static if(!is(typeof(_ATFILE_SOURCE))) {
        private enum enumMixinStr__ATFILE_SOURCE = `enum _ATFILE_SOURCE = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__ATFILE_SOURCE); }))) {
            mixin(enumMixinStr__ATFILE_SOURCE);
        }
    }




    static if(!is(typeof(__USE_XOPEN2K8))) {
        private enum enumMixinStr___USE_XOPEN2K8 = `enum __USE_XOPEN2K8 = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___USE_XOPEN2K8); }))) {
            mixin(enumMixinStr___USE_XOPEN2K8);
        }
    }




    static if(!is(typeof(__USE_ISOC99))) {
        private enum enumMixinStr___USE_ISOC99 = `enum __USE_ISOC99 = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___USE_ISOC99); }))) {
            mixin(enumMixinStr___USE_ISOC99);
        }
    }




    static if(!is(typeof(__USE_ISOC95))) {
        private enum enumMixinStr___USE_ISOC95 = `enum __USE_ISOC95 = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___USE_ISOC95); }))) {
            mixin(enumMixinStr___USE_ISOC95);
        }
    }




    static if(!is(typeof(__USE_XOPEN2K))) {
        private enum enumMixinStr___USE_XOPEN2K = `enum __USE_XOPEN2K = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___USE_XOPEN2K); }))) {
            mixin(enumMixinStr___USE_XOPEN2K);
        }
    }




    static if(!is(typeof(__USE_POSIX199506))) {
        private enum enumMixinStr___USE_POSIX199506 = `enum __USE_POSIX199506 = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___USE_POSIX199506); }))) {
            mixin(enumMixinStr___USE_POSIX199506);
        }
    }




    static if(!is(typeof(__USE_POSIX199309))) {
        private enum enumMixinStr___USE_POSIX199309 = `enum __USE_POSIX199309 = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___USE_POSIX199309); }))) {
            mixin(enumMixinStr___USE_POSIX199309);
        }
    }




    static if(!is(typeof(__USE_POSIX2))) {
        private enum enumMixinStr___USE_POSIX2 = `enum __USE_POSIX2 = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___USE_POSIX2); }))) {
            mixin(enumMixinStr___USE_POSIX2);
        }
    }




    static if(!is(typeof(__USE_POSIX))) {
        private enum enumMixinStr___USE_POSIX = `enum __USE_POSIX = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___USE_POSIX); }))) {
            mixin(enumMixinStr___USE_POSIX);
        }
    }




    static if(!is(typeof(_POSIX_C_SOURCE))) {
        private enum enumMixinStr__POSIX_C_SOURCE = `enum _POSIX_C_SOURCE = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_C_SOURCE); }))) {
            mixin(enumMixinStr__POSIX_C_SOURCE);
        }
    }




    static if(!is(typeof(_POSIX_SOURCE))) {
        private enum enumMixinStr__POSIX_SOURCE = `enum _POSIX_SOURCE = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_SOURCE); }))) {
            mixin(enumMixinStr__POSIX_SOURCE);
        }
    }




    static if(!is(typeof(__USE_POSIX_IMPLICITLY))) {
        private enum enumMixinStr___USE_POSIX_IMPLICITLY = `enum __USE_POSIX_IMPLICITLY = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___USE_POSIX_IMPLICITLY); }))) {
            mixin(enumMixinStr___USE_POSIX_IMPLICITLY);
        }
    }




    static if(!is(typeof(__USE_ISOC11))) {
        private enum enumMixinStr___USE_ISOC11 = `enum __USE_ISOC11 = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___USE_ISOC11); }))) {
            mixin(enumMixinStr___USE_ISOC11);
        }
    }




    static if(!is(typeof(__GLIBC_USE_ISOC2X))) {
        private enum enumMixinStr___GLIBC_USE_ISOC2X = `enum __GLIBC_USE_ISOC2X = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___GLIBC_USE_ISOC2X); }))) {
            mixin(enumMixinStr___GLIBC_USE_ISOC2X);
        }
    }




    static if(!is(typeof(_DEFAULT_SOURCE))) {
        private enum enumMixinStr__DEFAULT_SOURCE = `enum _DEFAULT_SOURCE = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__DEFAULT_SOURCE); }))) {
            mixin(enumMixinStr__DEFAULT_SOURCE);
        }
    }
    static if(!is(typeof(_FEATURES_H))) {
        private enum enumMixinStr__FEATURES_H = `enum _FEATURES_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__FEATURES_H); }))) {
            mixin(enumMixinStr__FEATURES_H);
        }
    }




    static if(!is(typeof(F_TEST))) {
        private enum enumMixinStr_F_TEST = `enum F_TEST = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_F_TEST); }))) {
            mixin(enumMixinStr_F_TEST);
        }
    }




    static if(!is(typeof(F_TLOCK))) {
        private enum enumMixinStr_F_TLOCK = `enum F_TLOCK = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_F_TLOCK); }))) {
            mixin(enumMixinStr_F_TLOCK);
        }
    }




    static if(!is(typeof(F_LOCK))) {
        private enum enumMixinStr_F_LOCK = `enum F_LOCK = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_F_LOCK); }))) {
            mixin(enumMixinStr_F_LOCK);
        }
    }




    static if(!is(typeof(F_ULOCK))) {
        private enum enumMixinStr_F_ULOCK = `enum F_ULOCK = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_F_ULOCK); }))) {
            mixin(enumMixinStr_F_ULOCK);
        }
    }




    static if(!is(typeof(AT_EACCESS))) {
        private enum enumMixinStr_AT_EACCESS = `enum AT_EACCESS = 0x200;`;
        static if(is(typeof({ mixin(enumMixinStr_AT_EACCESS); }))) {
            mixin(enumMixinStr_AT_EACCESS);
        }
    }




    static if(!is(typeof(AT_SYMLINK_FOLLOW))) {
        private enum enumMixinStr_AT_SYMLINK_FOLLOW = `enum AT_SYMLINK_FOLLOW = 0x400;`;
        static if(is(typeof({ mixin(enumMixinStr_AT_SYMLINK_FOLLOW); }))) {
            mixin(enumMixinStr_AT_SYMLINK_FOLLOW);
        }
    }




    static if(!is(typeof(AT_REMOVEDIR))) {
        private enum enumMixinStr_AT_REMOVEDIR = `enum AT_REMOVEDIR = 0x200;`;
        static if(is(typeof({ mixin(enumMixinStr_AT_REMOVEDIR); }))) {
            mixin(enumMixinStr_AT_REMOVEDIR);
        }
    }




    static if(!is(typeof(AT_SYMLINK_NOFOLLOW))) {
        private enum enumMixinStr_AT_SYMLINK_NOFOLLOW = `enum AT_SYMLINK_NOFOLLOW = 0x100;`;
        static if(is(typeof({ mixin(enumMixinStr_AT_SYMLINK_NOFOLLOW); }))) {
            mixin(enumMixinStr_AT_SYMLINK_NOFOLLOW);
        }
    }




    static if(!is(typeof(AT_FDCWD))) {
        private enum enumMixinStr_AT_FDCWD = `enum AT_FDCWD = - 100;`;
        static if(is(typeof({ mixin(enumMixinStr_AT_FDCWD); }))) {
            mixin(enumMixinStr_AT_FDCWD);
        }
    }






    static if(!is(typeof(_FCNTL_H))) {
        private enum enumMixinStr__FCNTL_H = `enum _FCNTL_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__FCNTL_H); }))) {
            mixin(enumMixinStr__FCNTL_H);
        }
    }




    static if(!is(typeof(errno))) {
        private enum enumMixinStr_errno = `enum errno = ( * __errno_location ( ) );`;
        static if(is(typeof({ mixin(enumMixinStr_errno); }))) {
            mixin(enumMixinStr_errno);
        }
    }




    static if(!is(typeof(_ERRNO_H))) {
        private enum enumMixinStr__ERRNO_H = `enum _ERRNO_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__ERRNO_H); }))) {
            mixin(enumMixinStr__ERRNO_H);
        }
    }
    static if(!is(typeof(BYTE_ORDER))) {
        private enum enumMixinStr_BYTE_ORDER = `enum BYTE_ORDER = __BYTE_ORDER;`;
        static if(is(typeof({ mixin(enumMixinStr_BYTE_ORDER); }))) {
            mixin(enumMixinStr_BYTE_ORDER);
        }
    }




    static if(!is(typeof(PDP_ENDIAN))) {
        private enum enumMixinStr_PDP_ENDIAN = `enum PDP_ENDIAN = __PDP_ENDIAN;`;
        static if(is(typeof({ mixin(enumMixinStr_PDP_ENDIAN); }))) {
            mixin(enumMixinStr_PDP_ENDIAN);
        }
    }




    static if(!is(typeof(BIG_ENDIAN))) {
        private enum enumMixinStr_BIG_ENDIAN = `enum BIG_ENDIAN = __BIG_ENDIAN;`;
        static if(is(typeof({ mixin(enumMixinStr_BIG_ENDIAN); }))) {
            mixin(enumMixinStr_BIG_ENDIAN);
        }
    }




    static if(!is(typeof(LITTLE_ENDIAN))) {
        private enum enumMixinStr_LITTLE_ENDIAN = `enum LITTLE_ENDIAN = __LITTLE_ENDIAN;`;
        static if(is(typeof({ mixin(enumMixinStr_LITTLE_ENDIAN); }))) {
            mixin(enumMixinStr_LITTLE_ENDIAN);
        }
    }




    static if(!is(typeof(_ENDIAN_H))) {
        private enum enumMixinStr__ENDIAN_H = `enum _ENDIAN_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__ENDIAN_H); }))) {
            mixin(enumMixinStr__ENDIAN_H);
        }
    }




    static if(!is(typeof(MAXNAMLEN))) {
        private enum enumMixinStr_MAXNAMLEN = `enum MAXNAMLEN = 255;`;
        static if(is(typeof({ mixin(enumMixinStr_MAXNAMLEN); }))) {
            mixin(enumMixinStr_MAXNAMLEN);
        }
    }
    static if(!is(typeof(DT_WHT))) {
        private enum enumMixinStr_DT_WHT = `enum DT_WHT = DT_WHT;`;
        static if(is(typeof({ mixin(enumMixinStr_DT_WHT); }))) {
            mixin(enumMixinStr_DT_WHT);
        }
    }




    static if(!is(typeof(DT_SOCK))) {
        private enum enumMixinStr_DT_SOCK = `enum DT_SOCK = DT_SOCK;`;
        static if(is(typeof({ mixin(enumMixinStr_DT_SOCK); }))) {
            mixin(enumMixinStr_DT_SOCK);
        }
    }




    static if(!is(typeof(DT_LNK))) {
        private enum enumMixinStr_DT_LNK = `enum DT_LNK = DT_LNK;`;
        static if(is(typeof({ mixin(enumMixinStr_DT_LNK); }))) {
            mixin(enumMixinStr_DT_LNK);
        }
    }




    static if(!is(typeof(DT_REG))) {
        private enum enumMixinStr_DT_REG = `enum DT_REG = DT_REG;`;
        static if(is(typeof({ mixin(enumMixinStr_DT_REG); }))) {
            mixin(enumMixinStr_DT_REG);
        }
    }




    static if(!is(typeof(DT_BLK))) {
        private enum enumMixinStr_DT_BLK = `enum DT_BLK = DT_BLK;`;
        static if(is(typeof({ mixin(enumMixinStr_DT_BLK); }))) {
            mixin(enumMixinStr_DT_BLK);
        }
    }




    static if(!is(typeof(DT_DIR))) {
        private enum enumMixinStr_DT_DIR = `enum DT_DIR = DT_DIR;`;
        static if(is(typeof({ mixin(enumMixinStr_DT_DIR); }))) {
            mixin(enumMixinStr_DT_DIR);
        }
    }




    static if(!is(typeof(DT_CHR))) {
        private enum enumMixinStr_DT_CHR = `enum DT_CHR = DT_CHR;`;
        static if(is(typeof({ mixin(enumMixinStr_DT_CHR); }))) {
            mixin(enumMixinStr_DT_CHR);
        }
    }




    static if(!is(typeof(DT_FIFO))) {
        private enum enumMixinStr_DT_FIFO = `enum DT_FIFO = DT_FIFO;`;
        static if(is(typeof({ mixin(enumMixinStr_DT_FIFO); }))) {
            mixin(enumMixinStr_DT_FIFO);
        }
    }




    static if(!is(typeof(DT_UNKNOWN))) {
        private enum enumMixinStr_DT_UNKNOWN = `enum DT_UNKNOWN = DT_UNKNOWN;`;
        static if(is(typeof({ mixin(enumMixinStr_DT_UNKNOWN); }))) {
            mixin(enumMixinStr_DT_UNKNOWN);
        }
    }
    static if(!is(typeof(_DIRENT_H))) {
        private enum enumMixinStr__DIRENT_H = `enum _DIRENT_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__DIRENT_H); }))) {
            mixin(enumMixinStr__DIRENT_H);
        }
    }
    static if(!is(typeof(_CTYPE_H))) {
        private enum enumMixinStr__CTYPE_H = `enum _CTYPE_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__CTYPE_H); }))) {
            mixin(enumMixinStr__CTYPE_H);
        }
    }




    static if(!is(typeof(__SYSCALL_WORDSIZE))) {
        private enum enumMixinStr___SYSCALL_WORDSIZE = `enum __SYSCALL_WORDSIZE = 64;`;
        static if(is(typeof({ mixin(enumMixinStr___SYSCALL_WORDSIZE); }))) {
            mixin(enumMixinStr___SYSCALL_WORDSIZE);
        }
    }




    static if(!is(typeof(_UTIME_H))) {
        private enum enumMixinStr__UTIME_H = `enum _UTIME_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__UTIME_H); }))) {
            mixin(enumMixinStr__UTIME_H);
        }
    }




    static if(!is(typeof(__WORDSIZE_TIME64_COMPAT32))) {
        private enum enumMixinStr___WORDSIZE_TIME64_COMPAT32 = `enum __WORDSIZE_TIME64_COMPAT32 = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___WORDSIZE_TIME64_COMPAT32); }))) {
            mixin(enumMixinStr___WORDSIZE_TIME64_COMPAT32);
        }
    }






    static if(!is(typeof(ZMQ_VERSION_MAJOR))) {
        private enum enumMixinStr_ZMQ_VERSION_MAJOR = `enum ZMQ_VERSION_MAJOR = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_VERSION_MAJOR); }))) {
            mixin(enumMixinStr_ZMQ_VERSION_MAJOR);
        }
    }




    static if(!is(typeof(ZMQ_VERSION_MINOR))) {
        private enum enumMixinStr_ZMQ_VERSION_MINOR = `enum ZMQ_VERSION_MINOR = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_VERSION_MINOR); }))) {
            mixin(enumMixinStr_ZMQ_VERSION_MINOR);
        }
    }




    static if(!is(typeof(ZMQ_VERSION_PATCH))) {
        private enum enumMixinStr_ZMQ_VERSION_PATCH = `enum ZMQ_VERSION_PATCH = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_VERSION_PATCH); }))) {
            mixin(enumMixinStr_ZMQ_VERSION_PATCH);
        }
    }






    static if(!is(typeof(ZMQ_VERSION))) {
        private enum enumMixinStr_ZMQ_VERSION = `enum ZMQ_VERSION = ( ( 4 ) * 10000 + ( 3 ) * 100 + ( 2 ) );`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_VERSION); }))) {
            mixin(enumMixinStr_ZMQ_VERSION);
        }
    }




    static if(!is(typeof(ZMQ_EXPORT))) {
        private enum enumMixinStr_ZMQ_EXPORT = `enum ZMQ_EXPORT = __attribute__ ( ( visibility ( "default" ) ) );`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_EXPORT); }))) {
            mixin(enumMixinStr_ZMQ_EXPORT);
        }
    }




    static if(!is(typeof(ZMQ_DEFINED_STDINT))) {
        private enum enumMixinStr_ZMQ_DEFINED_STDINT = `enum ZMQ_DEFINED_STDINT = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_DEFINED_STDINT); }))) {
            mixin(enumMixinStr_ZMQ_DEFINED_STDINT);
        }
    }




    static if(!is(typeof(ZMQ_HAUSNUMERO))) {
        private enum enumMixinStr_ZMQ_HAUSNUMERO = `enum ZMQ_HAUSNUMERO = 156384712;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_HAUSNUMERO); }))) {
            mixin(enumMixinStr_ZMQ_HAUSNUMERO);
        }
    }




    static if(!is(typeof(__WORDSIZE))) {
        private enum enumMixinStr___WORDSIZE = `enum __WORDSIZE = 64;`;
        static if(is(typeof({ mixin(enumMixinStr___WORDSIZE); }))) {
            mixin(enumMixinStr___WORDSIZE);
        }
    }




    static if(!is(typeof(__WCHAR_MIN))) {
        private enum enumMixinStr___WCHAR_MIN = `enum __WCHAR_MIN = ( - __WCHAR_MAX - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr___WCHAR_MIN); }))) {
            mixin(enumMixinStr___WCHAR_MIN);
        }
    }




    static if(!is(typeof(__WCHAR_MAX))) {
        private enum enumMixinStr___WCHAR_MAX = `enum __WCHAR_MAX = 0x7fffffff;`;
        static if(is(typeof({ mixin(enumMixinStr___WCHAR_MAX); }))) {
            mixin(enumMixinStr___WCHAR_MAX);
        }
    }




    static if(!is(typeof(_BITS_WCHAR_H))) {
        private enum enumMixinStr__BITS_WCHAR_H = `enum _BITS_WCHAR_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_WCHAR_H); }))) {
            mixin(enumMixinStr__BITS_WCHAR_H);
        }
    }




    static if(!is(typeof(EFSM))) {
        private enum enumMixinStr_EFSM = `enum EFSM = ( 156384712 + 51 );`;
        static if(is(typeof({ mixin(enumMixinStr_EFSM); }))) {
            mixin(enumMixinStr_EFSM);
        }
    }




    static if(!is(typeof(ENOCOMPATPROTO))) {
        private enum enumMixinStr_ENOCOMPATPROTO = `enum ENOCOMPATPROTO = ( 156384712 + 52 );`;
        static if(is(typeof({ mixin(enumMixinStr_ENOCOMPATPROTO); }))) {
            mixin(enumMixinStr_ENOCOMPATPROTO);
        }
    }




    static if(!is(typeof(ETERM))) {
        private enum enumMixinStr_ETERM = `enum ETERM = ( 156384712 + 53 );`;
        static if(is(typeof({ mixin(enumMixinStr_ETERM); }))) {
            mixin(enumMixinStr_ETERM);
        }
    }




    static if(!is(typeof(EMTHREAD))) {
        private enum enumMixinStr_EMTHREAD = `enum EMTHREAD = ( 156384712 + 54 );`;
        static if(is(typeof({ mixin(enumMixinStr_EMTHREAD); }))) {
            mixin(enumMixinStr_EMTHREAD);
        }
    }




    static if(!is(typeof(__WCOREFLAG))) {
        private enum enumMixinStr___WCOREFLAG = `enum __WCOREFLAG = 0x80;`;
        static if(is(typeof({ mixin(enumMixinStr___WCOREFLAG); }))) {
            mixin(enumMixinStr___WCOREFLAG);
        }
    }




    static if(!is(typeof(__W_CONTINUED))) {
        private enum enumMixinStr___W_CONTINUED = `enum __W_CONTINUED = 0xffff;`;
        static if(is(typeof({ mixin(enumMixinStr___W_CONTINUED); }))) {
            mixin(enumMixinStr___W_CONTINUED);
        }
    }
    static if(!is(typeof(ZMQ_IO_THREADS))) {
        private enum enumMixinStr_ZMQ_IO_THREADS = `enum ZMQ_IO_THREADS = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_IO_THREADS); }))) {
            mixin(enumMixinStr_ZMQ_IO_THREADS);
        }
    }




    static if(!is(typeof(ZMQ_MAX_SOCKETS))) {
        private enum enumMixinStr_ZMQ_MAX_SOCKETS = `enum ZMQ_MAX_SOCKETS = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_MAX_SOCKETS); }))) {
            mixin(enumMixinStr_ZMQ_MAX_SOCKETS);
        }
    }




    static if(!is(typeof(ZMQ_SOCKET_LIMIT))) {
        private enum enumMixinStr_ZMQ_SOCKET_LIMIT = `enum ZMQ_SOCKET_LIMIT = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_SOCKET_LIMIT); }))) {
            mixin(enumMixinStr_ZMQ_SOCKET_LIMIT);
        }
    }




    static if(!is(typeof(ZMQ_THREAD_PRIORITY))) {
        private enum enumMixinStr_ZMQ_THREAD_PRIORITY = `enum ZMQ_THREAD_PRIORITY = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_THREAD_PRIORITY); }))) {
            mixin(enumMixinStr_ZMQ_THREAD_PRIORITY);
        }
    }




    static if(!is(typeof(ZMQ_THREAD_SCHED_POLICY))) {
        private enum enumMixinStr_ZMQ_THREAD_SCHED_POLICY = `enum ZMQ_THREAD_SCHED_POLICY = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_THREAD_SCHED_POLICY); }))) {
            mixin(enumMixinStr_ZMQ_THREAD_SCHED_POLICY);
        }
    }




    static if(!is(typeof(ZMQ_MAX_MSGSZ))) {
        private enum enumMixinStr_ZMQ_MAX_MSGSZ = `enum ZMQ_MAX_MSGSZ = 5;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_MAX_MSGSZ); }))) {
            mixin(enumMixinStr_ZMQ_MAX_MSGSZ);
        }
    }




    static if(!is(typeof(ZMQ_MSG_T_SIZE))) {
        private enum enumMixinStr_ZMQ_MSG_T_SIZE = `enum ZMQ_MSG_T_SIZE = 6;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_MSG_T_SIZE); }))) {
            mixin(enumMixinStr_ZMQ_MSG_T_SIZE);
        }
    }




    static if(!is(typeof(ZMQ_THREAD_AFFINITY_CPU_ADD))) {
        private enum enumMixinStr_ZMQ_THREAD_AFFINITY_CPU_ADD = `enum ZMQ_THREAD_AFFINITY_CPU_ADD = 7;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_THREAD_AFFINITY_CPU_ADD); }))) {
            mixin(enumMixinStr_ZMQ_THREAD_AFFINITY_CPU_ADD);
        }
    }




    static if(!is(typeof(ZMQ_THREAD_AFFINITY_CPU_REMOVE))) {
        private enum enumMixinStr_ZMQ_THREAD_AFFINITY_CPU_REMOVE = `enum ZMQ_THREAD_AFFINITY_CPU_REMOVE = 8;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_THREAD_AFFINITY_CPU_REMOVE); }))) {
            mixin(enumMixinStr_ZMQ_THREAD_AFFINITY_CPU_REMOVE);
        }
    }




    static if(!is(typeof(ZMQ_THREAD_NAME_PREFIX))) {
        private enum enumMixinStr_ZMQ_THREAD_NAME_PREFIX = `enum ZMQ_THREAD_NAME_PREFIX = 9;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_THREAD_NAME_PREFIX); }))) {
            mixin(enumMixinStr_ZMQ_THREAD_NAME_PREFIX);
        }
    }




    static if(!is(typeof(ZMQ_IO_THREADS_DFLT))) {
        private enum enumMixinStr_ZMQ_IO_THREADS_DFLT = `enum ZMQ_IO_THREADS_DFLT = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_IO_THREADS_DFLT); }))) {
            mixin(enumMixinStr_ZMQ_IO_THREADS_DFLT);
        }
    }




    static if(!is(typeof(ZMQ_MAX_SOCKETS_DFLT))) {
        private enum enumMixinStr_ZMQ_MAX_SOCKETS_DFLT = `enum ZMQ_MAX_SOCKETS_DFLT = 1023;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_MAX_SOCKETS_DFLT); }))) {
            mixin(enumMixinStr_ZMQ_MAX_SOCKETS_DFLT);
        }
    }




    static if(!is(typeof(ZMQ_THREAD_PRIORITY_DFLT))) {
        private enum enumMixinStr_ZMQ_THREAD_PRIORITY_DFLT = `enum ZMQ_THREAD_PRIORITY_DFLT = - 1;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_THREAD_PRIORITY_DFLT); }))) {
            mixin(enumMixinStr_ZMQ_THREAD_PRIORITY_DFLT);
        }
    }




    static if(!is(typeof(ZMQ_THREAD_SCHED_POLICY_DFLT))) {
        private enum enumMixinStr_ZMQ_THREAD_SCHED_POLICY_DFLT = `enum ZMQ_THREAD_SCHED_POLICY_DFLT = - 1;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_THREAD_SCHED_POLICY_DFLT); }))) {
            mixin(enumMixinStr_ZMQ_THREAD_SCHED_POLICY_DFLT);
        }
    }
    static if(!is(typeof(__WCLONE))) {
        private enum enumMixinStr___WCLONE = `enum __WCLONE = 0x80000000;`;
        static if(is(typeof({ mixin(enumMixinStr___WCLONE); }))) {
            mixin(enumMixinStr___WCLONE);
        }
    }




    static if(!is(typeof(__WALL))) {
        private enum enumMixinStr___WALL = `enum __WALL = 0x40000000;`;
        static if(is(typeof({ mixin(enumMixinStr___WALL); }))) {
            mixin(enumMixinStr___WALL);
        }
    }




    static if(!is(typeof(__WNOTHREAD))) {
        private enum enumMixinStr___WNOTHREAD = `enum __WNOTHREAD = 0x20000000;`;
        static if(is(typeof({ mixin(enumMixinStr___WNOTHREAD); }))) {
            mixin(enumMixinStr___WNOTHREAD);
        }
    }




    static if(!is(typeof(WNOWAIT))) {
        private enum enumMixinStr_WNOWAIT = `enum WNOWAIT = 0x01000000;`;
        static if(is(typeof({ mixin(enumMixinStr_WNOWAIT); }))) {
            mixin(enumMixinStr_WNOWAIT);
        }
    }




    static if(!is(typeof(WCONTINUED))) {
        private enum enumMixinStr_WCONTINUED = `enum WCONTINUED = 8;`;
        static if(is(typeof({ mixin(enumMixinStr_WCONTINUED); }))) {
            mixin(enumMixinStr_WCONTINUED);
        }
    }




    static if(!is(typeof(WEXITED))) {
        private enum enumMixinStr_WEXITED = `enum WEXITED = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_WEXITED); }))) {
            mixin(enumMixinStr_WEXITED);
        }
    }




    static if(!is(typeof(WSTOPPED))) {
        private enum enumMixinStr_WSTOPPED = `enum WSTOPPED = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_WSTOPPED); }))) {
            mixin(enumMixinStr_WSTOPPED);
        }
    }




    static if(!is(typeof(WUNTRACED))) {
        private enum enumMixinStr_WUNTRACED = `enum WUNTRACED = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_WUNTRACED); }))) {
            mixin(enumMixinStr_WUNTRACED);
        }
    }




    static if(!is(typeof(WNOHANG))) {
        private enum enumMixinStr_WNOHANG = `enum WNOHANG = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_WNOHANG); }))) {
            mixin(enumMixinStr_WNOHANG);
        }
    }




    static if(!is(typeof(__IOV_MAX))) {
        private enum enumMixinStr___IOV_MAX = `enum __IOV_MAX = 1024;`;
        static if(is(typeof({ mixin(enumMixinStr___IOV_MAX); }))) {
            mixin(enumMixinStr___IOV_MAX);
        }
    }




    static if(!is(typeof(_BITS_UIO_LIM_H))) {
        private enum enumMixinStr__BITS_UIO_LIM_H = `enum _BITS_UIO_LIM_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_UIO_LIM_H); }))) {
            mixin(enumMixinStr__BITS_UIO_LIM_H);
        }
    }




    static if(!is(typeof(_BITS_UINTN_IDENTITY_H))) {
        private enum enumMixinStr__BITS_UINTN_IDENTITY_H = `enum _BITS_UINTN_IDENTITY_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_UINTN_IDENTITY_H); }))) {
            mixin(enumMixinStr__BITS_UINTN_IDENTITY_H);
        }
    }




    static if(!is(typeof(__STATFS_MATCHES_STATFS64))) {
        private enum enumMixinStr___STATFS_MATCHES_STATFS64 = `enum __STATFS_MATCHES_STATFS64 = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___STATFS_MATCHES_STATFS64); }))) {
            mixin(enumMixinStr___STATFS_MATCHES_STATFS64);
        }
    }




    static if(!is(typeof(__RLIM_T_MATCHES_RLIM64_T))) {
        private enum enumMixinStr___RLIM_T_MATCHES_RLIM64_T = `enum __RLIM_T_MATCHES_RLIM64_T = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___RLIM_T_MATCHES_RLIM64_T); }))) {
            mixin(enumMixinStr___RLIM_T_MATCHES_RLIM64_T);
        }
    }




    static if(!is(typeof(__INO_T_MATCHES_INO64_T))) {
        private enum enumMixinStr___INO_T_MATCHES_INO64_T = `enum __INO_T_MATCHES_INO64_T = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___INO_T_MATCHES_INO64_T); }))) {
            mixin(enumMixinStr___INO_T_MATCHES_INO64_T);
        }
    }




    static if(!is(typeof(__OFF_T_MATCHES_OFF64_T))) {
        private enum enumMixinStr___OFF_T_MATCHES_OFF64_T = `enum __OFF_T_MATCHES_OFF64_T = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___OFF_T_MATCHES_OFF64_T); }))) {
            mixin(enumMixinStr___OFF_T_MATCHES_OFF64_T);
        }
    }




    static if(!is(typeof(__CPU_MASK_TYPE))) {
        private enum enumMixinStr___CPU_MASK_TYPE = `enum __CPU_MASK_TYPE = __SYSCALL_ULONG_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___CPU_MASK_TYPE); }))) {
            mixin(enumMixinStr___CPU_MASK_TYPE);
        }
    }




    static if(!is(typeof(__SSIZE_T_TYPE))) {
        private enum enumMixinStr___SSIZE_T_TYPE = `enum __SSIZE_T_TYPE = __SWORD_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___SSIZE_T_TYPE); }))) {
            mixin(enumMixinStr___SSIZE_T_TYPE);
        }
    }




    static if(!is(typeof(__FSID_T_TYPE))) {
        private enum enumMixinStr___FSID_T_TYPE = `enum __FSID_T_TYPE = { int __val [ 2 ] ; };`;
        static if(is(typeof({ mixin(enumMixinStr___FSID_T_TYPE); }))) {
            mixin(enumMixinStr___FSID_T_TYPE);
        }
    }




    static if(!is(typeof(__BLKSIZE_T_TYPE))) {
        private enum enumMixinStr___BLKSIZE_T_TYPE = `enum __BLKSIZE_T_TYPE = __SYSCALL_SLONG_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___BLKSIZE_T_TYPE); }))) {
            mixin(enumMixinStr___BLKSIZE_T_TYPE);
        }
    }




    static if(!is(typeof(__TIMER_T_TYPE))) {
        private enum enumMixinStr___TIMER_T_TYPE = `enum __TIMER_T_TYPE = void *;`;
        static if(is(typeof({ mixin(enumMixinStr___TIMER_T_TYPE); }))) {
            mixin(enumMixinStr___TIMER_T_TYPE);
        }
    }




    static if(!is(typeof(__CLOCKID_T_TYPE))) {
        private enum enumMixinStr___CLOCKID_T_TYPE = `enum __CLOCKID_T_TYPE = __S32_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___CLOCKID_T_TYPE); }))) {
            mixin(enumMixinStr___CLOCKID_T_TYPE);
        }
    }




    static if(!is(typeof(__KEY_T_TYPE))) {
        private enum enumMixinStr___KEY_T_TYPE = `enum __KEY_T_TYPE = __S32_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___KEY_T_TYPE); }))) {
            mixin(enumMixinStr___KEY_T_TYPE);
        }
    }




    static if(!is(typeof(__DADDR_T_TYPE))) {
        private enum enumMixinStr___DADDR_T_TYPE = `enum __DADDR_T_TYPE = __S32_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___DADDR_T_TYPE); }))) {
            mixin(enumMixinStr___DADDR_T_TYPE);
        }
    }




    static if(!is(typeof(__SUSECONDS_T_TYPE))) {
        private enum enumMixinStr___SUSECONDS_T_TYPE = `enum __SUSECONDS_T_TYPE = __SYSCALL_SLONG_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___SUSECONDS_T_TYPE); }))) {
            mixin(enumMixinStr___SUSECONDS_T_TYPE);
        }
    }




    static if(!is(typeof(__USECONDS_T_TYPE))) {
        private enum enumMixinStr___USECONDS_T_TYPE = `enum __USECONDS_T_TYPE = __U32_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___USECONDS_T_TYPE); }))) {
            mixin(enumMixinStr___USECONDS_T_TYPE);
        }
    }




    static if(!is(typeof(__TIME_T_TYPE))) {
        private enum enumMixinStr___TIME_T_TYPE = `enum __TIME_T_TYPE = __SYSCALL_SLONG_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___TIME_T_TYPE); }))) {
            mixin(enumMixinStr___TIME_T_TYPE);
        }
    }




    static if(!is(typeof(__CLOCK_T_TYPE))) {
        private enum enumMixinStr___CLOCK_T_TYPE = `enum __CLOCK_T_TYPE = __SYSCALL_SLONG_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___CLOCK_T_TYPE); }))) {
            mixin(enumMixinStr___CLOCK_T_TYPE);
        }
    }




    static if(!is(typeof(__ID_T_TYPE))) {
        private enum enumMixinStr___ID_T_TYPE = `enum __ID_T_TYPE = __U32_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___ID_T_TYPE); }))) {
            mixin(enumMixinStr___ID_T_TYPE);
        }
    }




    static if(!is(typeof(__FSFILCNT64_T_TYPE))) {
        private enum enumMixinStr___FSFILCNT64_T_TYPE = `enum __FSFILCNT64_T_TYPE = __UQUAD_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___FSFILCNT64_T_TYPE); }))) {
            mixin(enumMixinStr___FSFILCNT64_T_TYPE);
        }
    }




    static if(!is(typeof(__FSFILCNT_T_TYPE))) {
        private enum enumMixinStr___FSFILCNT_T_TYPE = `enum __FSFILCNT_T_TYPE = __SYSCALL_ULONG_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___FSFILCNT_T_TYPE); }))) {
            mixin(enumMixinStr___FSFILCNT_T_TYPE);
        }
    }




    static if(!is(typeof(__FSBLKCNT64_T_TYPE))) {
        private enum enumMixinStr___FSBLKCNT64_T_TYPE = `enum __FSBLKCNT64_T_TYPE = __UQUAD_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___FSBLKCNT64_T_TYPE); }))) {
            mixin(enumMixinStr___FSBLKCNT64_T_TYPE);
        }
    }




    static if(!is(typeof(__FSBLKCNT_T_TYPE))) {
        private enum enumMixinStr___FSBLKCNT_T_TYPE = `enum __FSBLKCNT_T_TYPE = __SYSCALL_ULONG_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___FSBLKCNT_T_TYPE); }))) {
            mixin(enumMixinStr___FSBLKCNT_T_TYPE);
        }
    }




    static if(!is(typeof(__BLKCNT64_T_TYPE))) {
        private enum enumMixinStr___BLKCNT64_T_TYPE = `enum __BLKCNT64_T_TYPE = __SQUAD_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___BLKCNT64_T_TYPE); }))) {
            mixin(enumMixinStr___BLKCNT64_T_TYPE);
        }
    }




    static if(!is(typeof(__BLKCNT_T_TYPE))) {
        private enum enumMixinStr___BLKCNT_T_TYPE = `enum __BLKCNT_T_TYPE = __SYSCALL_SLONG_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___BLKCNT_T_TYPE); }))) {
            mixin(enumMixinStr___BLKCNT_T_TYPE);
        }
    }




    static if(!is(typeof(__RLIM64_T_TYPE))) {
        private enum enumMixinStr___RLIM64_T_TYPE = `enum __RLIM64_T_TYPE = __UQUAD_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___RLIM64_T_TYPE); }))) {
            mixin(enumMixinStr___RLIM64_T_TYPE);
        }
    }




    static if(!is(typeof(__RLIM_T_TYPE))) {
        private enum enumMixinStr___RLIM_T_TYPE = `enum __RLIM_T_TYPE = __SYSCALL_ULONG_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___RLIM_T_TYPE); }))) {
            mixin(enumMixinStr___RLIM_T_TYPE);
        }
    }




    static if(!is(typeof(__PID_T_TYPE))) {
        private enum enumMixinStr___PID_T_TYPE = `enum __PID_T_TYPE = __S32_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___PID_T_TYPE); }))) {
            mixin(enumMixinStr___PID_T_TYPE);
        }
    }




    static if(!is(typeof(__OFF64_T_TYPE))) {
        private enum enumMixinStr___OFF64_T_TYPE = `enum __OFF64_T_TYPE = __SQUAD_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___OFF64_T_TYPE); }))) {
            mixin(enumMixinStr___OFF64_T_TYPE);
        }
    }




    static if(!is(typeof(__OFF_T_TYPE))) {
        private enum enumMixinStr___OFF_T_TYPE = `enum __OFF_T_TYPE = __SYSCALL_SLONG_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___OFF_T_TYPE); }))) {
            mixin(enumMixinStr___OFF_T_TYPE);
        }
    }




    static if(!is(typeof(__FSWORD_T_TYPE))) {
        private enum enumMixinStr___FSWORD_T_TYPE = `enum __FSWORD_T_TYPE = __SYSCALL_SLONG_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___FSWORD_T_TYPE); }))) {
            mixin(enumMixinStr___FSWORD_T_TYPE);
        }
    }




    static if(!is(typeof(ZMQ_PAIR))) {
        private enum enumMixinStr_ZMQ_PAIR = `enum ZMQ_PAIR = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_PAIR); }))) {
            mixin(enumMixinStr_ZMQ_PAIR);
        }
    }




    static if(!is(typeof(ZMQ_PUB))) {
        private enum enumMixinStr_ZMQ_PUB = `enum ZMQ_PUB = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_PUB); }))) {
            mixin(enumMixinStr_ZMQ_PUB);
        }
    }




    static if(!is(typeof(ZMQ_SUB))) {
        private enum enumMixinStr_ZMQ_SUB = `enum ZMQ_SUB = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_SUB); }))) {
            mixin(enumMixinStr_ZMQ_SUB);
        }
    }




    static if(!is(typeof(ZMQ_REQ))) {
        private enum enumMixinStr_ZMQ_REQ = `enum ZMQ_REQ = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_REQ); }))) {
            mixin(enumMixinStr_ZMQ_REQ);
        }
    }




    static if(!is(typeof(ZMQ_REP))) {
        private enum enumMixinStr_ZMQ_REP = `enum ZMQ_REP = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_REP); }))) {
            mixin(enumMixinStr_ZMQ_REP);
        }
    }




    static if(!is(typeof(ZMQ_DEALER))) {
        private enum enumMixinStr_ZMQ_DEALER = `enum ZMQ_DEALER = 5;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_DEALER); }))) {
            mixin(enumMixinStr_ZMQ_DEALER);
        }
    }




    static if(!is(typeof(ZMQ_ROUTER))) {
        private enum enumMixinStr_ZMQ_ROUTER = `enum ZMQ_ROUTER = 6;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_ROUTER); }))) {
            mixin(enumMixinStr_ZMQ_ROUTER);
        }
    }




    static if(!is(typeof(ZMQ_PULL))) {
        private enum enumMixinStr_ZMQ_PULL = `enum ZMQ_PULL = 7;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_PULL); }))) {
            mixin(enumMixinStr_ZMQ_PULL);
        }
    }




    static if(!is(typeof(ZMQ_PUSH))) {
        private enum enumMixinStr_ZMQ_PUSH = `enum ZMQ_PUSH = 8;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_PUSH); }))) {
            mixin(enumMixinStr_ZMQ_PUSH);
        }
    }




    static if(!is(typeof(ZMQ_XPUB))) {
        private enum enumMixinStr_ZMQ_XPUB = `enum ZMQ_XPUB = 9;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_XPUB); }))) {
            mixin(enumMixinStr_ZMQ_XPUB);
        }
    }




    static if(!is(typeof(ZMQ_XSUB))) {
        private enum enumMixinStr_ZMQ_XSUB = `enum ZMQ_XSUB = 10;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_XSUB); }))) {
            mixin(enumMixinStr_ZMQ_XSUB);
        }
    }




    static if(!is(typeof(ZMQ_STREAM))) {
        private enum enumMixinStr_ZMQ_STREAM = `enum ZMQ_STREAM = 11;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_STREAM); }))) {
            mixin(enumMixinStr_ZMQ_STREAM);
        }
    }




    static if(!is(typeof(ZMQ_XREQ))) {
        private enum enumMixinStr_ZMQ_XREQ = `enum ZMQ_XREQ = 5;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_XREQ); }))) {
            mixin(enumMixinStr_ZMQ_XREQ);
        }
    }




    static if(!is(typeof(ZMQ_XREP))) {
        private enum enumMixinStr_ZMQ_XREP = `enum ZMQ_XREP = 6;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_XREP); }))) {
            mixin(enumMixinStr_ZMQ_XREP);
        }
    }




    static if(!is(typeof(ZMQ_AFFINITY))) {
        private enum enumMixinStr_ZMQ_AFFINITY = `enum ZMQ_AFFINITY = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_AFFINITY); }))) {
            mixin(enumMixinStr_ZMQ_AFFINITY);
        }
    }




    static if(!is(typeof(ZMQ_ROUTING_ID))) {
        private enum enumMixinStr_ZMQ_ROUTING_ID = `enum ZMQ_ROUTING_ID = 5;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_ROUTING_ID); }))) {
            mixin(enumMixinStr_ZMQ_ROUTING_ID);
        }
    }




    static if(!is(typeof(ZMQ_SUBSCRIBE))) {
        private enum enumMixinStr_ZMQ_SUBSCRIBE = `enum ZMQ_SUBSCRIBE = 6;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_SUBSCRIBE); }))) {
            mixin(enumMixinStr_ZMQ_SUBSCRIBE);
        }
    }




    static if(!is(typeof(ZMQ_UNSUBSCRIBE))) {
        private enum enumMixinStr_ZMQ_UNSUBSCRIBE = `enum ZMQ_UNSUBSCRIBE = 7;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_UNSUBSCRIBE); }))) {
            mixin(enumMixinStr_ZMQ_UNSUBSCRIBE);
        }
    }




    static if(!is(typeof(ZMQ_RATE))) {
        private enum enumMixinStr_ZMQ_RATE = `enum ZMQ_RATE = 8;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_RATE); }))) {
            mixin(enumMixinStr_ZMQ_RATE);
        }
    }




    static if(!is(typeof(ZMQ_RECOVERY_IVL))) {
        private enum enumMixinStr_ZMQ_RECOVERY_IVL = `enum ZMQ_RECOVERY_IVL = 9;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_RECOVERY_IVL); }))) {
            mixin(enumMixinStr_ZMQ_RECOVERY_IVL);
        }
    }




    static if(!is(typeof(ZMQ_SNDBUF))) {
        private enum enumMixinStr_ZMQ_SNDBUF = `enum ZMQ_SNDBUF = 11;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_SNDBUF); }))) {
            mixin(enumMixinStr_ZMQ_SNDBUF);
        }
    }




    static if(!is(typeof(ZMQ_RCVBUF))) {
        private enum enumMixinStr_ZMQ_RCVBUF = `enum ZMQ_RCVBUF = 12;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_RCVBUF); }))) {
            mixin(enumMixinStr_ZMQ_RCVBUF);
        }
    }




    static if(!is(typeof(ZMQ_RCVMORE))) {
        private enum enumMixinStr_ZMQ_RCVMORE = `enum ZMQ_RCVMORE = 13;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_RCVMORE); }))) {
            mixin(enumMixinStr_ZMQ_RCVMORE);
        }
    }




    static if(!is(typeof(ZMQ_FD))) {
        private enum enumMixinStr_ZMQ_FD = `enum ZMQ_FD = 14;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_FD); }))) {
            mixin(enumMixinStr_ZMQ_FD);
        }
    }




    static if(!is(typeof(ZMQ_EVENTS))) {
        private enum enumMixinStr_ZMQ_EVENTS = `enum ZMQ_EVENTS = 15;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_EVENTS); }))) {
            mixin(enumMixinStr_ZMQ_EVENTS);
        }
    }




    static if(!is(typeof(ZMQ_TYPE))) {
        private enum enumMixinStr_ZMQ_TYPE = `enum ZMQ_TYPE = 16;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_TYPE); }))) {
            mixin(enumMixinStr_ZMQ_TYPE);
        }
    }




    static if(!is(typeof(ZMQ_LINGER))) {
        private enum enumMixinStr_ZMQ_LINGER = `enum ZMQ_LINGER = 17;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_LINGER); }))) {
            mixin(enumMixinStr_ZMQ_LINGER);
        }
    }




    static if(!is(typeof(ZMQ_RECONNECT_IVL))) {
        private enum enumMixinStr_ZMQ_RECONNECT_IVL = `enum ZMQ_RECONNECT_IVL = 18;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_RECONNECT_IVL); }))) {
            mixin(enumMixinStr_ZMQ_RECONNECT_IVL);
        }
    }




    static if(!is(typeof(ZMQ_BACKLOG))) {
        private enum enumMixinStr_ZMQ_BACKLOG = `enum ZMQ_BACKLOG = 19;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_BACKLOG); }))) {
            mixin(enumMixinStr_ZMQ_BACKLOG);
        }
    }




    static if(!is(typeof(ZMQ_RECONNECT_IVL_MAX))) {
        private enum enumMixinStr_ZMQ_RECONNECT_IVL_MAX = `enum ZMQ_RECONNECT_IVL_MAX = 21;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_RECONNECT_IVL_MAX); }))) {
            mixin(enumMixinStr_ZMQ_RECONNECT_IVL_MAX);
        }
    }




    static if(!is(typeof(ZMQ_MAXMSGSIZE))) {
        private enum enumMixinStr_ZMQ_MAXMSGSIZE = `enum ZMQ_MAXMSGSIZE = 22;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_MAXMSGSIZE); }))) {
            mixin(enumMixinStr_ZMQ_MAXMSGSIZE);
        }
    }




    static if(!is(typeof(ZMQ_SNDHWM))) {
        private enum enumMixinStr_ZMQ_SNDHWM = `enum ZMQ_SNDHWM = 23;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_SNDHWM); }))) {
            mixin(enumMixinStr_ZMQ_SNDHWM);
        }
    }




    static if(!is(typeof(ZMQ_RCVHWM))) {
        private enum enumMixinStr_ZMQ_RCVHWM = `enum ZMQ_RCVHWM = 24;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_RCVHWM); }))) {
            mixin(enumMixinStr_ZMQ_RCVHWM);
        }
    }




    static if(!is(typeof(ZMQ_MULTICAST_HOPS))) {
        private enum enumMixinStr_ZMQ_MULTICAST_HOPS = `enum ZMQ_MULTICAST_HOPS = 25;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_MULTICAST_HOPS); }))) {
            mixin(enumMixinStr_ZMQ_MULTICAST_HOPS);
        }
    }




    static if(!is(typeof(ZMQ_RCVTIMEO))) {
        private enum enumMixinStr_ZMQ_RCVTIMEO = `enum ZMQ_RCVTIMEO = 27;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_RCVTIMEO); }))) {
            mixin(enumMixinStr_ZMQ_RCVTIMEO);
        }
    }




    static if(!is(typeof(ZMQ_SNDTIMEO))) {
        private enum enumMixinStr_ZMQ_SNDTIMEO = `enum ZMQ_SNDTIMEO = 28;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_SNDTIMEO); }))) {
            mixin(enumMixinStr_ZMQ_SNDTIMEO);
        }
    }




    static if(!is(typeof(ZMQ_LAST_ENDPOINT))) {
        private enum enumMixinStr_ZMQ_LAST_ENDPOINT = `enum ZMQ_LAST_ENDPOINT = 32;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_LAST_ENDPOINT); }))) {
            mixin(enumMixinStr_ZMQ_LAST_ENDPOINT);
        }
    }




    static if(!is(typeof(ZMQ_ROUTER_MANDATORY))) {
        private enum enumMixinStr_ZMQ_ROUTER_MANDATORY = `enum ZMQ_ROUTER_MANDATORY = 33;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_ROUTER_MANDATORY); }))) {
            mixin(enumMixinStr_ZMQ_ROUTER_MANDATORY);
        }
    }




    static if(!is(typeof(ZMQ_TCP_KEEPALIVE))) {
        private enum enumMixinStr_ZMQ_TCP_KEEPALIVE = `enum ZMQ_TCP_KEEPALIVE = 34;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_TCP_KEEPALIVE); }))) {
            mixin(enumMixinStr_ZMQ_TCP_KEEPALIVE);
        }
    }




    static if(!is(typeof(ZMQ_TCP_KEEPALIVE_CNT))) {
        private enum enumMixinStr_ZMQ_TCP_KEEPALIVE_CNT = `enum ZMQ_TCP_KEEPALIVE_CNT = 35;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_TCP_KEEPALIVE_CNT); }))) {
            mixin(enumMixinStr_ZMQ_TCP_KEEPALIVE_CNT);
        }
    }




    static if(!is(typeof(ZMQ_TCP_KEEPALIVE_IDLE))) {
        private enum enumMixinStr_ZMQ_TCP_KEEPALIVE_IDLE = `enum ZMQ_TCP_KEEPALIVE_IDLE = 36;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_TCP_KEEPALIVE_IDLE); }))) {
            mixin(enumMixinStr_ZMQ_TCP_KEEPALIVE_IDLE);
        }
    }




    static if(!is(typeof(ZMQ_TCP_KEEPALIVE_INTVL))) {
        private enum enumMixinStr_ZMQ_TCP_KEEPALIVE_INTVL = `enum ZMQ_TCP_KEEPALIVE_INTVL = 37;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_TCP_KEEPALIVE_INTVL); }))) {
            mixin(enumMixinStr_ZMQ_TCP_KEEPALIVE_INTVL);
        }
    }




    static if(!is(typeof(ZMQ_IMMEDIATE))) {
        private enum enumMixinStr_ZMQ_IMMEDIATE = `enum ZMQ_IMMEDIATE = 39;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_IMMEDIATE); }))) {
            mixin(enumMixinStr_ZMQ_IMMEDIATE);
        }
    }




    static if(!is(typeof(ZMQ_XPUB_VERBOSE))) {
        private enum enumMixinStr_ZMQ_XPUB_VERBOSE = `enum ZMQ_XPUB_VERBOSE = 40;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_XPUB_VERBOSE); }))) {
            mixin(enumMixinStr_ZMQ_XPUB_VERBOSE);
        }
    }




    static if(!is(typeof(ZMQ_ROUTER_RAW))) {
        private enum enumMixinStr_ZMQ_ROUTER_RAW = `enum ZMQ_ROUTER_RAW = 41;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_ROUTER_RAW); }))) {
            mixin(enumMixinStr_ZMQ_ROUTER_RAW);
        }
    }




    static if(!is(typeof(ZMQ_IPV6))) {
        private enum enumMixinStr_ZMQ_IPV6 = `enum ZMQ_IPV6 = 42;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_IPV6); }))) {
            mixin(enumMixinStr_ZMQ_IPV6);
        }
    }




    static if(!is(typeof(ZMQ_MECHANISM))) {
        private enum enumMixinStr_ZMQ_MECHANISM = `enum ZMQ_MECHANISM = 43;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_MECHANISM); }))) {
            mixin(enumMixinStr_ZMQ_MECHANISM);
        }
    }




    static if(!is(typeof(ZMQ_PLAIN_SERVER))) {
        private enum enumMixinStr_ZMQ_PLAIN_SERVER = `enum ZMQ_PLAIN_SERVER = 44;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_PLAIN_SERVER); }))) {
            mixin(enumMixinStr_ZMQ_PLAIN_SERVER);
        }
    }




    static if(!is(typeof(ZMQ_PLAIN_USERNAME))) {
        private enum enumMixinStr_ZMQ_PLAIN_USERNAME = `enum ZMQ_PLAIN_USERNAME = 45;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_PLAIN_USERNAME); }))) {
            mixin(enumMixinStr_ZMQ_PLAIN_USERNAME);
        }
    }




    static if(!is(typeof(ZMQ_PLAIN_PASSWORD))) {
        private enum enumMixinStr_ZMQ_PLAIN_PASSWORD = `enum ZMQ_PLAIN_PASSWORD = 46;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_PLAIN_PASSWORD); }))) {
            mixin(enumMixinStr_ZMQ_PLAIN_PASSWORD);
        }
    }




    static if(!is(typeof(ZMQ_CURVE_SERVER))) {
        private enum enumMixinStr_ZMQ_CURVE_SERVER = `enum ZMQ_CURVE_SERVER = 47;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_CURVE_SERVER); }))) {
            mixin(enumMixinStr_ZMQ_CURVE_SERVER);
        }
    }




    static if(!is(typeof(ZMQ_CURVE_PUBLICKEY))) {
        private enum enumMixinStr_ZMQ_CURVE_PUBLICKEY = `enum ZMQ_CURVE_PUBLICKEY = 48;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_CURVE_PUBLICKEY); }))) {
            mixin(enumMixinStr_ZMQ_CURVE_PUBLICKEY);
        }
    }




    static if(!is(typeof(ZMQ_CURVE_SECRETKEY))) {
        private enum enumMixinStr_ZMQ_CURVE_SECRETKEY = `enum ZMQ_CURVE_SECRETKEY = 49;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_CURVE_SECRETKEY); }))) {
            mixin(enumMixinStr_ZMQ_CURVE_SECRETKEY);
        }
    }




    static if(!is(typeof(ZMQ_CURVE_SERVERKEY))) {
        private enum enumMixinStr_ZMQ_CURVE_SERVERKEY = `enum ZMQ_CURVE_SERVERKEY = 50;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_CURVE_SERVERKEY); }))) {
            mixin(enumMixinStr_ZMQ_CURVE_SERVERKEY);
        }
    }




    static if(!is(typeof(ZMQ_PROBE_ROUTER))) {
        private enum enumMixinStr_ZMQ_PROBE_ROUTER = `enum ZMQ_PROBE_ROUTER = 51;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_PROBE_ROUTER); }))) {
            mixin(enumMixinStr_ZMQ_PROBE_ROUTER);
        }
    }




    static if(!is(typeof(ZMQ_REQ_CORRELATE))) {
        private enum enumMixinStr_ZMQ_REQ_CORRELATE = `enum ZMQ_REQ_CORRELATE = 52;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_REQ_CORRELATE); }))) {
            mixin(enumMixinStr_ZMQ_REQ_CORRELATE);
        }
    }




    static if(!is(typeof(ZMQ_REQ_RELAXED))) {
        private enum enumMixinStr_ZMQ_REQ_RELAXED = `enum ZMQ_REQ_RELAXED = 53;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_REQ_RELAXED); }))) {
            mixin(enumMixinStr_ZMQ_REQ_RELAXED);
        }
    }




    static if(!is(typeof(ZMQ_CONFLATE))) {
        private enum enumMixinStr_ZMQ_CONFLATE = `enum ZMQ_CONFLATE = 54;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_CONFLATE); }))) {
            mixin(enumMixinStr_ZMQ_CONFLATE);
        }
    }




    static if(!is(typeof(ZMQ_ZAP_DOMAIN))) {
        private enum enumMixinStr_ZMQ_ZAP_DOMAIN = `enum ZMQ_ZAP_DOMAIN = 55;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_ZAP_DOMAIN); }))) {
            mixin(enumMixinStr_ZMQ_ZAP_DOMAIN);
        }
    }




    static if(!is(typeof(ZMQ_ROUTER_HANDOVER))) {
        private enum enumMixinStr_ZMQ_ROUTER_HANDOVER = `enum ZMQ_ROUTER_HANDOVER = 56;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_ROUTER_HANDOVER); }))) {
            mixin(enumMixinStr_ZMQ_ROUTER_HANDOVER);
        }
    }




    static if(!is(typeof(ZMQ_TOS))) {
        private enum enumMixinStr_ZMQ_TOS = `enum ZMQ_TOS = 57;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_TOS); }))) {
            mixin(enumMixinStr_ZMQ_TOS);
        }
    }




    static if(!is(typeof(ZMQ_CONNECT_ROUTING_ID))) {
        private enum enumMixinStr_ZMQ_CONNECT_ROUTING_ID = `enum ZMQ_CONNECT_ROUTING_ID = 61;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_CONNECT_ROUTING_ID); }))) {
            mixin(enumMixinStr_ZMQ_CONNECT_ROUTING_ID);
        }
    }




    static if(!is(typeof(ZMQ_GSSAPI_SERVER))) {
        private enum enumMixinStr_ZMQ_GSSAPI_SERVER = `enum ZMQ_GSSAPI_SERVER = 62;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_GSSAPI_SERVER); }))) {
            mixin(enumMixinStr_ZMQ_GSSAPI_SERVER);
        }
    }




    static if(!is(typeof(ZMQ_GSSAPI_PRINCIPAL))) {
        private enum enumMixinStr_ZMQ_GSSAPI_PRINCIPAL = `enum ZMQ_GSSAPI_PRINCIPAL = 63;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_GSSAPI_PRINCIPAL); }))) {
            mixin(enumMixinStr_ZMQ_GSSAPI_PRINCIPAL);
        }
    }




    static if(!is(typeof(ZMQ_GSSAPI_SERVICE_PRINCIPAL))) {
        private enum enumMixinStr_ZMQ_GSSAPI_SERVICE_PRINCIPAL = `enum ZMQ_GSSAPI_SERVICE_PRINCIPAL = 64;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_GSSAPI_SERVICE_PRINCIPAL); }))) {
            mixin(enumMixinStr_ZMQ_GSSAPI_SERVICE_PRINCIPAL);
        }
    }




    static if(!is(typeof(ZMQ_GSSAPI_PLAINTEXT))) {
        private enum enumMixinStr_ZMQ_GSSAPI_PLAINTEXT = `enum ZMQ_GSSAPI_PLAINTEXT = 65;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_GSSAPI_PLAINTEXT); }))) {
            mixin(enumMixinStr_ZMQ_GSSAPI_PLAINTEXT);
        }
    }




    static if(!is(typeof(ZMQ_HANDSHAKE_IVL))) {
        private enum enumMixinStr_ZMQ_HANDSHAKE_IVL = `enum ZMQ_HANDSHAKE_IVL = 66;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_HANDSHAKE_IVL); }))) {
            mixin(enumMixinStr_ZMQ_HANDSHAKE_IVL);
        }
    }




    static if(!is(typeof(ZMQ_SOCKS_PROXY))) {
        private enum enumMixinStr_ZMQ_SOCKS_PROXY = `enum ZMQ_SOCKS_PROXY = 68;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_SOCKS_PROXY); }))) {
            mixin(enumMixinStr_ZMQ_SOCKS_PROXY);
        }
    }




    static if(!is(typeof(ZMQ_XPUB_NODROP))) {
        private enum enumMixinStr_ZMQ_XPUB_NODROP = `enum ZMQ_XPUB_NODROP = 69;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_XPUB_NODROP); }))) {
            mixin(enumMixinStr_ZMQ_XPUB_NODROP);
        }
    }




    static if(!is(typeof(ZMQ_BLOCKY))) {
        private enum enumMixinStr_ZMQ_BLOCKY = `enum ZMQ_BLOCKY = 70;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_BLOCKY); }))) {
            mixin(enumMixinStr_ZMQ_BLOCKY);
        }
    }




    static if(!is(typeof(ZMQ_XPUB_MANUAL))) {
        private enum enumMixinStr_ZMQ_XPUB_MANUAL = `enum ZMQ_XPUB_MANUAL = 71;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_XPUB_MANUAL); }))) {
            mixin(enumMixinStr_ZMQ_XPUB_MANUAL);
        }
    }




    static if(!is(typeof(ZMQ_XPUB_WELCOME_MSG))) {
        private enum enumMixinStr_ZMQ_XPUB_WELCOME_MSG = `enum ZMQ_XPUB_WELCOME_MSG = 72;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_XPUB_WELCOME_MSG); }))) {
            mixin(enumMixinStr_ZMQ_XPUB_WELCOME_MSG);
        }
    }




    static if(!is(typeof(ZMQ_STREAM_NOTIFY))) {
        private enum enumMixinStr_ZMQ_STREAM_NOTIFY = `enum ZMQ_STREAM_NOTIFY = 73;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_STREAM_NOTIFY); }))) {
            mixin(enumMixinStr_ZMQ_STREAM_NOTIFY);
        }
    }




    static if(!is(typeof(ZMQ_INVERT_MATCHING))) {
        private enum enumMixinStr_ZMQ_INVERT_MATCHING = `enum ZMQ_INVERT_MATCHING = 74;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_INVERT_MATCHING); }))) {
            mixin(enumMixinStr_ZMQ_INVERT_MATCHING);
        }
    }




    static if(!is(typeof(ZMQ_HEARTBEAT_IVL))) {
        private enum enumMixinStr_ZMQ_HEARTBEAT_IVL = `enum ZMQ_HEARTBEAT_IVL = 75;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_HEARTBEAT_IVL); }))) {
            mixin(enumMixinStr_ZMQ_HEARTBEAT_IVL);
        }
    }




    static if(!is(typeof(ZMQ_HEARTBEAT_TTL))) {
        private enum enumMixinStr_ZMQ_HEARTBEAT_TTL = `enum ZMQ_HEARTBEAT_TTL = 76;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_HEARTBEAT_TTL); }))) {
            mixin(enumMixinStr_ZMQ_HEARTBEAT_TTL);
        }
    }




    static if(!is(typeof(ZMQ_HEARTBEAT_TIMEOUT))) {
        private enum enumMixinStr_ZMQ_HEARTBEAT_TIMEOUT = `enum ZMQ_HEARTBEAT_TIMEOUT = 77;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_HEARTBEAT_TIMEOUT); }))) {
            mixin(enumMixinStr_ZMQ_HEARTBEAT_TIMEOUT);
        }
    }




    static if(!is(typeof(ZMQ_XPUB_VERBOSER))) {
        private enum enumMixinStr_ZMQ_XPUB_VERBOSER = `enum ZMQ_XPUB_VERBOSER = 78;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_XPUB_VERBOSER); }))) {
            mixin(enumMixinStr_ZMQ_XPUB_VERBOSER);
        }
    }




    static if(!is(typeof(ZMQ_CONNECT_TIMEOUT))) {
        private enum enumMixinStr_ZMQ_CONNECT_TIMEOUT = `enum ZMQ_CONNECT_TIMEOUT = 79;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_CONNECT_TIMEOUT); }))) {
            mixin(enumMixinStr_ZMQ_CONNECT_TIMEOUT);
        }
    }




    static if(!is(typeof(ZMQ_TCP_MAXRT))) {
        private enum enumMixinStr_ZMQ_TCP_MAXRT = `enum ZMQ_TCP_MAXRT = 80;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_TCP_MAXRT); }))) {
            mixin(enumMixinStr_ZMQ_TCP_MAXRT);
        }
    }




    static if(!is(typeof(ZMQ_THREAD_SAFE))) {
        private enum enumMixinStr_ZMQ_THREAD_SAFE = `enum ZMQ_THREAD_SAFE = 81;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_THREAD_SAFE); }))) {
            mixin(enumMixinStr_ZMQ_THREAD_SAFE);
        }
    }




    static if(!is(typeof(ZMQ_MULTICAST_MAXTPDU))) {
        private enum enumMixinStr_ZMQ_MULTICAST_MAXTPDU = `enum ZMQ_MULTICAST_MAXTPDU = 84;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_MULTICAST_MAXTPDU); }))) {
            mixin(enumMixinStr_ZMQ_MULTICAST_MAXTPDU);
        }
    }




    static if(!is(typeof(ZMQ_VMCI_BUFFER_SIZE))) {
        private enum enumMixinStr_ZMQ_VMCI_BUFFER_SIZE = `enum ZMQ_VMCI_BUFFER_SIZE = 85;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_VMCI_BUFFER_SIZE); }))) {
            mixin(enumMixinStr_ZMQ_VMCI_BUFFER_SIZE);
        }
    }




    static if(!is(typeof(ZMQ_VMCI_BUFFER_MIN_SIZE))) {
        private enum enumMixinStr_ZMQ_VMCI_BUFFER_MIN_SIZE = `enum ZMQ_VMCI_BUFFER_MIN_SIZE = 86;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_VMCI_BUFFER_MIN_SIZE); }))) {
            mixin(enumMixinStr_ZMQ_VMCI_BUFFER_MIN_SIZE);
        }
    }




    static if(!is(typeof(ZMQ_VMCI_BUFFER_MAX_SIZE))) {
        private enum enumMixinStr_ZMQ_VMCI_BUFFER_MAX_SIZE = `enum ZMQ_VMCI_BUFFER_MAX_SIZE = 87;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_VMCI_BUFFER_MAX_SIZE); }))) {
            mixin(enumMixinStr_ZMQ_VMCI_BUFFER_MAX_SIZE);
        }
    }




    static if(!is(typeof(ZMQ_VMCI_CONNECT_TIMEOUT))) {
        private enum enumMixinStr_ZMQ_VMCI_CONNECT_TIMEOUT = `enum ZMQ_VMCI_CONNECT_TIMEOUT = 88;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_VMCI_CONNECT_TIMEOUT); }))) {
            mixin(enumMixinStr_ZMQ_VMCI_CONNECT_TIMEOUT);
        }
    }




    static if(!is(typeof(ZMQ_USE_FD))) {
        private enum enumMixinStr_ZMQ_USE_FD = `enum ZMQ_USE_FD = 89;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_USE_FD); }))) {
            mixin(enumMixinStr_ZMQ_USE_FD);
        }
    }




    static if(!is(typeof(ZMQ_GSSAPI_PRINCIPAL_NAMETYPE))) {
        private enum enumMixinStr_ZMQ_GSSAPI_PRINCIPAL_NAMETYPE = `enum ZMQ_GSSAPI_PRINCIPAL_NAMETYPE = 90;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_GSSAPI_PRINCIPAL_NAMETYPE); }))) {
            mixin(enumMixinStr_ZMQ_GSSAPI_PRINCIPAL_NAMETYPE);
        }
    }




    static if(!is(typeof(ZMQ_GSSAPI_SERVICE_PRINCIPAL_NAMETYPE))) {
        private enum enumMixinStr_ZMQ_GSSAPI_SERVICE_PRINCIPAL_NAMETYPE = `enum ZMQ_GSSAPI_SERVICE_PRINCIPAL_NAMETYPE = 91;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_GSSAPI_SERVICE_PRINCIPAL_NAMETYPE); }))) {
            mixin(enumMixinStr_ZMQ_GSSAPI_SERVICE_PRINCIPAL_NAMETYPE);
        }
    }




    static if(!is(typeof(ZMQ_BINDTODEVICE))) {
        private enum enumMixinStr_ZMQ_BINDTODEVICE = `enum ZMQ_BINDTODEVICE = 92;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_BINDTODEVICE); }))) {
            mixin(enumMixinStr_ZMQ_BINDTODEVICE);
        }
    }




    static if(!is(typeof(ZMQ_MORE))) {
        private enum enumMixinStr_ZMQ_MORE = `enum ZMQ_MORE = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_MORE); }))) {
            mixin(enumMixinStr_ZMQ_MORE);
        }
    }




    static if(!is(typeof(ZMQ_SHARED))) {
        private enum enumMixinStr_ZMQ_SHARED = `enum ZMQ_SHARED = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_SHARED); }))) {
            mixin(enumMixinStr_ZMQ_SHARED);
        }
    }




    static if(!is(typeof(ZMQ_DONTWAIT))) {
        private enum enumMixinStr_ZMQ_DONTWAIT = `enum ZMQ_DONTWAIT = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_DONTWAIT); }))) {
            mixin(enumMixinStr_ZMQ_DONTWAIT);
        }
    }




    static if(!is(typeof(ZMQ_SNDMORE))) {
        private enum enumMixinStr_ZMQ_SNDMORE = `enum ZMQ_SNDMORE = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_SNDMORE); }))) {
            mixin(enumMixinStr_ZMQ_SNDMORE);
        }
    }




    static if(!is(typeof(ZMQ_NULL))) {
        private enum enumMixinStr_ZMQ_NULL = `enum ZMQ_NULL = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_NULL); }))) {
            mixin(enumMixinStr_ZMQ_NULL);
        }
    }




    static if(!is(typeof(ZMQ_PLAIN))) {
        private enum enumMixinStr_ZMQ_PLAIN = `enum ZMQ_PLAIN = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_PLAIN); }))) {
            mixin(enumMixinStr_ZMQ_PLAIN);
        }
    }




    static if(!is(typeof(ZMQ_CURVE))) {
        private enum enumMixinStr_ZMQ_CURVE = `enum ZMQ_CURVE = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_CURVE); }))) {
            mixin(enumMixinStr_ZMQ_CURVE);
        }
    }




    static if(!is(typeof(ZMQ_GSSAPI))) {
        private enum enumMixinStr_ZMQ_GSSAPI = `enum ZMQ_GSSAPI = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_GSSAPI); }))) {
            mixin(enumMixinStr_ZMQ_GSSAPI);
        }
    }




    static if(!is(typeof(ZMQ_GROUP_MAX_LENGTH))) {
        private enum enumMixinStr_ZMQ_GROUP_MAX_LENGTH = `enum ZMQ_GROUP_MAX_LENGTH = 15;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_GROUP_MAX_LENGTH); }))) {
            mixin(enumMixinStr_ZMQ_GROUP_MAX_LENGTH);
        }
    }




    static if(!is(typeof(ZMQ_IDENTITY))) {
        private enum enumMixinStr_ZMQ_IDENTITY = `enum ZMQ_IDENTITY = 5;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_IDENTITY); }))) {
            mixin(enumMixinStr_ZMQ_IDENTITY);
        }
    }




    static if(!is(typeof(ZMQ_CONNECT_RID))) {
        private enum enumMixinStr_ZMQ_CONNECT_RID = `enum ZMQ_CONNECT_RID = 61;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_CONNECT_RID); }))) {
            mixin(enumMixinStr_ZMQ_CONNECT_RID);
        }
    }




    static if(!is(typeof(ZMQ_TCP_ACCEPT_FILTER))) {
        private enum enumMixinStr_ZMQ_TCP_ACCEPT_FILTER = `enum ZMQ_TCP_ACCEPT_FILTER = 38;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_TCP_ACCEPT_FILTER); }))) {
            mixin(enumMixinStr_ZMQ_TCP_ACCEPT_FILTER);
        }
    }




    static if(!is(typeof(ZMQ_IPC_FILTER_PID))) {
        private enum enumMixinStr_ZMQ_IPC_FILTER_PID = `enum ZMQ_IPC_FILTER_PID = 58;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_IPC_FILTER_PID); }))) {
            mixin(enumMixinStr_ZMQ_IPC_FILTER_PID);
        }
    }




    static if(!is(typeof(ZMQ_IPC_FILTER_UID))) {
        private enum enumMixinStr_ZMQ_IPC_FILTER_UID = `enum ZMQ_IPC_FILTER_UID = 59;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_IPC_FILTER_UID); }))) {
            mixin(enumMixinStr_ZMQ_IPC_FILTER_UID);
        }
    }




    static if(!is(typeof(ZMQ_IPC_FILTER_GID))) {
        private enum enumMixinStr_ZMQ_IPC_FILTER_GID = `enum ZMQ_IPC_FILTER_GID = 60;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_IPC_FILTER_GID); }))) {
            mixin(enumMixinStr_ZMQ_IPC_FILTER_GID);
        }
    }




    static if(!is(typeof(ZMQ_IPV4ONLY))) {
        private enum enumMixinStr_ZMQ_IPV4ONLY = `enum ZMQ_IPV4ONLY = 31;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_IPV4ONLY); }))) {
            mixin(enumMixinStr_ZMQ_IPV4ONLY);
        }
    }




    static if(!is(typeof(ZMQ_DELAY_ATTACH_ON_CONNECT))) {
        private enum enumMixinStr_ZMQ_DELAY_ATTACH_ON_CONNECT = `enum ZMQ_DELAY_ATTACH_ON_CONNECT = 39;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_DELAY_ATTACH_ON_CONNECT); }))) {
            mixin(enumMixinStr_ZMQ_DELAY_ATTACH_ON_CONNECT);
        }
    }




    static if(!is(typeof(ZMQ_NOBLOCK))) {
        private enum enumMixinStr_ZMQ_NOBLOCK = `enum ZMQ_NOBLOCK = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_NOBLOCK); }))) {
            mixin(enumMixinStr_ZMQ_NOBLOCK);
        }
    }




    static if(!is(typeof(ZMQ_FAIL_UNROUTABLE))) {
        private enum enumMixinStr_ZMQ_FAIL_UNROUTABLE = `enum ZMQ_FAIL_UNROUTABLE = 33;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_FAIL_UNROUTABLE); }))) {
            mixin(enumMixinStr_ZMQ_FAIL_UNROUTABLE);
        }
    }




    static if(!is(typeof(ZMQ_ROUTER_BEHAVIOR))) {
        private enum enumMixinStr_ZMQ_ROUTER_BEHAVIOR = `enum ZMQ_ROUTER_BEHAVIOR = 33;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_ROUTER_BEHAVIOR); }))) {
            mixin(enumMixinStr_ZMQ_ROUTER_BEHAVIOR);
        }
    }




    static if(!is(typeof(ZMQ_SRCFD))) {
        private enum enumMixinStr_ZMQ_SRCFD = `enum ZMQ_SRCFD = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_SRCFD); }))) {
            mixin(enumMixinStr_ZMQ_SRCFD);
        }
    }




    static if(!is(typeof(ZMQ_GSSAPI_NT_HOSTBASED))) {
        private enum enumMixinStr_ZMQ_GSSAPI_NT_HOSTBASED = `enum ZMQ_GSSAPI_NT_HOSTBASED = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_GSSAPI_NT_HOSTBASED); }))) {
            mixin(enumMixinStr_ZMQ_GSSAPI_NT_HOSTBASED);
        }
    }




    static if(!is(typeof(ZMQ_GSSAPI_NT_USER_NAME))) {
        private enum enumMixinStr_ZMQ_GSSAPI_NT_USER_NAME = `enum ZMQ_GSSAPI_NT_USER_NAME = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_GSSAPI_NT_USER_NAME); }))) {
            mixin(enumMixinStr_ZMQ_GSSAPI_NT_USER_NAME);
        }
    }




    static if(!is(typeof(ZMQ_GSSAPI_NT_KRB5_PRINCIPAL))) {
        private enum enumMixinStr_ZMQ_GSSAPI_NT_KRB5_PRINCIPAL = `enum ZMQ_GSSAPI_NT_KRB5_PRINCIPAL = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_GSSAPI_NT_KRB5_PRINCIPAL); }))) {
            mixin(enumMixinStr_ZMQ_GSSAPI_NT_KRB5_PRINCIPAL);
        }
    }




    static if(!is(typeof(ZMQ_EVENT_CONNECTED))) {
        private enum enumMixinStr_ZMQ_EVENT_CONNECTED = `enum ZMQ_EVENT_CONNECTED = 0x0001;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_EVENT_CONNECTED); }))) {
            mixin(enumMixinStr_ZMQ_EVENT_CONNECTED);
        }
    }




    static if(!is(typeof(ZMQ_EVENT_CONNECT_DELAYED))) {
        private enum enumMixinStr_ZMQ_EVENT_CONNECT_DELAYED = `enum ZMQ_EVENT_CONNECT_DELAYED = 0x0002;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_EVENT_CONNECT_DELAYED); }))) {
            mixin(enumMixinStr_ZMQ_EVENT_CONNECT_DELAYED);
        }
    }




    static if(!is(typeof(ZMQ_EVENT_CONNECT_RETRIED))) {
        private enum enumMixinStr_ZMQ_EVENT_CONNECT_RETRIED = `enum ZMQ_EVENT_CONNECT_RETRIED = 0x0004;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_EVENT_CONNECT_RETRIED); }))) {
            mixin(enumMixinStr_ZMQ_EVENT_CONNECT_RETRIED);
        }
    }




    static if(!is(typeof(ZMQ_EVENT_LISTENING))) {
        private enum enumMixinStr_ZMQ_EVENT_LISTENING = `enum ZMQ_EVENT_LISTENING = 0x0008;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_EVENT_LISTENING); }))) {
            mixin(enumMixinStr_ZMQ_EVENT_LISTENING);
        }
    }




    static if(!is(typeof(ZMQ_EVENT_BIND_FAILED))) {
        private enum enumMixinStr_ZMQ_EVENT_BIND_FAILED = `enum ZMQ_EVENT_BIND_FAILED = 0x0010;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_EVENT_BIND_FAILED); }))) {
            mixin(enumMixinStr_ZMQ_EVENT_BIND_FAILED);
        }
    }




    static if(!is(typeof(ZMQ_EVENT_ACCEPTED))) {
        private enum enumMixinStr_ZMQ_EVENT_ACCEPTED = `enum ZMQ_EVENT_ACCEPTED = 0x0020;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_EVENT_ACCEPTED); }))) {
            mixin(enumMixinStr_ZMQ_EVENT_ACCEPTED);
        }
    }




    static if(!is(typeof(ZMQ_EVENT_ACCEPT_FAILED))) {
        private enum enumMixinStr_ZMQ_EVENT_ACCEPT_FAILED = `enum ZMQ_EVENT_ACCEPT_FAILED = 0x0040;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_EVENT_ACCEPT_FAILED); }))) {
            mixin(enumMixinStr_ZMQ_EVENT_ACCEPT_FAILED);
        }
    }




    static if(!is(typeof(ZMQ_EVENT_CLOSED))) {
        private enum enumMixinStr_ZMQ_EVENT_CLOSED = `enum ZMQ_EVENT_CLOSED = 0x0080;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_EVENT_CLOSED); }))) {
            mixin(enumMixinStr_ZMQ_EVENT_CLOSED);
        }
    }




    static if(!is(typeof(ZMQ_EVENT_CLOSE_FAILED))) {
        private enum enumMixinStr_ZMQ_EVENT_CLOSE_FAILED = `enum ZMQ_EVENT_CLOSE_FAILED = 0x0100;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_EVENT_CLOSE_FAILED); }))) {
            mixin(enumMixinStr_ZMQ_EVENT_CLOSE_FAILED);
        }
    }




    static if(!is(typeof(ZMQ_EVENT_DISCONNECTED))) {
        private enum enumMixinStr_ZMQ_EVENT_DISCONNECTED = `enum ZMQ_EVENT_DISCONNECTED = 0x0200;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_EVENT_DISCONNECTED); }))) {
            mixin(enumMixinStr_ZMQ_EVENT_DISCONNECTED);
        }
    }




    static if(!is(typeof(ZMQ_EVENT_MONITOR_STOPPED))) {
        private enum enumMixinStr_ZMQ_EVENT_MONITOR_STOPPED = `enum ZMQ_EVENT_MONITOR_STOPPED = 0x0400;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_EVENT_MONITOR_STOPPED); }))) {
            mixin(enumMixinStr_ZMQ_EVENT_MONITOR_STOPPED);
        }
    }




    static if(!is(typeof(ZMQ_EVENT_ALL))) {
        private enum enumMixinStr_ZMQ_EVENT_ALL = `enum ZMQ_EVENT_ALL = 0xFFFF;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_EVENT_ALL); }))) {
            mixin(enumMixinStr_ZMQ_EVENT_ALL);
        }
    }




    static if(!is(typeof(ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL))) {
        private enum enumMixinStr_ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL = `enum ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL = 0x0800;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL); }))) {
            mixin(enumMixinStr_ZMQ_EVENT_HANDSHAKE_FAILED_NO_DETAIL);
        }
    }




    static if(!is(typeof(ZMQ_EVENT_HANDSHAKE_SUCCEEDED))) {
        private enum enumMixinStr_ZMQ_EVENT_HANDSHAKE_SUCCEEDED = `enum ZMQ_EVENT_HANDSHAKE_SUCCEEDED = 0x1000;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_EVENT_HANDSHAKE_SUCCEEDED); }))) {
            mixin(enumMixinStr_ZMQ_EVENT_HANDSHAKE_SUCCEEDED);
        }
    }




    static if(!is(typeof(ZMQ_EVENT_HANDSHAKE_FAILED_PROTOCOL))) {
        private enum enumMixinStr_ZMQ_EVENT_HANDSHAKE_FAILED_PROTOCOL = `enum ZMQ_EVENT_HANDSHAKE_FAILED_PROTOCOL = 0x2000;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_EVENT_HANDSHAKE_FAILED_PROTOCOL); }))) {
            mixin(enumMixinStr_ZMQ_EVENT_HANDSHAKE_FAILED_PROTOCOL);
        }
    }




    static if(!is(typeof(ZMQ_EVENT_HANDSHAKE_FAILED_AUTH))) {
        private enum enumMixinStr_ZMQ_EVENT_HANDSHAKE_FAILED_AUTH = `enum ZMQ_EVENT_HANDSHAKE_FAILED_AUTH = 0x4000;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_EVENT_HANDSHAKE_FAILED_AUTH); }))) {
            mixin(enumMixinStr_ZMQ_EVENT_HANDSHAKE_FAILED_AUTH);
        }
    }




    static if(!is(typeof(ZMQ_PROTOCOL_ERROR_ZMTP_UNSPECIFIED))) {
        private enum enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_UNSPECIFIED = `enum ZMQ_PROTOCOL_ERROR_ZMTP_UNSPECIFIED = 0x10000000;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_UNSPECIFIED); }))) {
            mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_UNSPECIFIED);
        }
    }




    static if(!is(typeof(ZMQ_PROTOCOL_ERROR_ZMTP_UNEXPECTED_COMMAND))) {
        private enum enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_UNEXPECTED_COMMAND = `enum ZMQ_PROTOCOL_ERROR_ZMTP_UNEXPECTED_COMMAND = 0x10000001;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_UNEXPECTED_COMMAND); }))) {
            mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_UNEXPECTED_COMMAND);
        }
    }




    static if(!is(typeof(ZMQ_PROTOCOL_ERROR_ZMTP_INVALID_SEQUENCE))) {
        private enum enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_INVALID_SEQUENCE = `enum ZMQ_PROTOCOL_ERROR_ZMTP_INVALID_SEQUENCE = 0x10000002;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_INVALID_SEQUENCE); }))) {
            mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_INVALID_SEQUENCE);
        }
    }




    static if(!is(typeof(ZMQ_PROTOCOL_ERROR_ZMTP_KEY_EXCHANGE))) {
        private enum enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_KEY_EXCHANGE = `enum ZMQ_PROTOCOL_ERROR_ZMTP_KEY_EXCHANGE = 0x10000003;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_KEY_EXCHANGE); }))) {
            mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_KEY_EXCHANGE);
        }
    }




    static if(!is(typeof(ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_UNSPECIFIED))) {
        private enum enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_UNSPECIFIED = `enum ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_UNSPECIFIED = 0x10000011;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_UNSPECIFIED); }))) {
            mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_UNSPECIFIED);
        }
    }




    static if(!is(typeof(ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_MESSAGE))) {
        private enum enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_MESSAGE = `enum ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_MESSAGE = 0x10000012;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_MESSAGE); }))) {
            mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_MESSAGE);
        }
    }




    static if(!is(typeof(ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_HELLO))) {
        private enum enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_HELLO = `enum ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_HELLO = 0x10000013;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_HELLO); }))) {
            mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_HELLO);
        }
    }




    static if(!is(typeof(ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_INITIATE))) {
        private enum enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_INITIATE = `enum ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_INITIATE = 0x10000014;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_INITIATE); }))) {
            mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_INITIATE);
        }
    }




    static if(!is(typeof(ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_ERROR))) {
        private enum enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_ERROR = `enum ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_ERROR = 0x10000015;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_ERROR); }))) {
            mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_ERROR);
        }
    }




    static if(!is(typeof(ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_READY))) {
        private enum enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_READY = `enum ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_READY = 0x10000016;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_READY); }))) {
            mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_READY);
        }
    }




    static if(!is(typeof(ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_WELCOME))) {
        private enum enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_WELCOME = `enum ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_WELCOME = 0x10000017;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_WELCOME); }))) {
            mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_MALFORMED_COMMAND_WELCOME);
        }
    }




    static if(!is(typeof(ZMQ_PROTOCOL_ERROR_ZMTP_INVALID_METADATA))) {
        private enum enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_INVALID_METADATA = `enum ZMQ_PROTOCOL_ERROR_ZMTP_INVALID_METADATA = 0x10000018;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_INVALID_METADATA); }))) {
            mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_INVALID_METADATA);
        }
    }




    static if(!is(typeof(ZMQ_PROTOCOL_ERROR_ZMTP_CRYPTOGRAPHIC))) {
        private enum enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_CRYPTOGRAPHIC = `enum ZMQ_PROTOCOL_ERROR_ZMTP_CRYPTOGRAPHIC = 0x11000001;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_CRYPTOGRAPHIC); }))) {
            mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_CRYPTOGRAPHIC);
        }
    }




    static if(!is(typeof(ZMQ_PROTOCOL_ERROR_ZMTP_MECHANISM_MISMATCH))) {
        private enum enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_MECHANISM_MISMATCH = `enum ZMQ_PROTOCOL_ERROR_ZMTP_MECHANISM_MISMATCH = 0x11000002;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_MECHANISM_MISMATCH); }))) {
            mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZMTP_MECHANISM_MISMATCH);
        }
    }




    static if(!is(typeof(ZMQ_PROTOCOL_ERROR_ZAP_UNSPECIFIED))) {
        private enum enumMixinStr_ZMQ_PROTOCOL_ERROR_ZAP_UNSPECIFIED = `enum ZMQ_PROTOCOL_ERROR_ZAP_UNSPECIFIED = 0x20000000;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZAP_UNSPECIFIED); }))) {
            mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZAP_UNSPECIFIED);
        }
    }




    static if(!is(typeof(ZMQ_PROTOCOL_ERROR_ZAP_MALFORMED_REPLY))) {
        private enum enumMixinStr_ZMQ_PROTOCOL_ERROR_ZAP_MALFORMED_REPLY = `enum ZMQ_PROTOCOL_ERROR_ZAP_MALFORMED_REPLY = 0x20000001;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZAP_MALFORMED_REPLY); }))) {
            mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZAP_MALFORMED_REPLY);
        }
    }




    static if(!is(typeof(ZMQ_PROTOCOL_ERROR_ZAP_BAD_REQUEST_ID))) {
        private enum enumMixinStr_ZMQ_PROTOCOL_ERROR_ZAP_BAD_REQUEST_ID = `enum ZMQ_PROTOCOL_ERROR_ZAP_BAD_REQUEST_ID = 0x20000002;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZAP_BAD_REQUEST_ID); }))) {
            mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZAP_BAD_REQUEST_ID);
        }
    }




    static if(!is(typeof(ZMQ_PROTOCOL_ERROR_ZAP_BAD_VERSION))) {
        private enum enumMixinStr_ZMQ_PROTOCOL_ERROR_ZAP_BAD_VERSION = `enum ZMQ_PROTOCOL_ERROR_ZAP_BAD_VERSION = 0x20000003;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZAP_BAD_VERSION); }))) {
            mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZAP_BAD_VERSION);
        }
    }




    static if(!is(typeof(ZMQ_PROTOCOL_ERROR_ZAP_INVALID_STATUS_CODE))) {
        private enum enumMixinStr_ZMQ_PROTOCOL_ERROR_ZAP_INVALID_STATUS_CODE = `enum ZMQ_PROTOCOL_ERROR_ZAP_INVALID_STATUS_CODE = 0x20000004;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZAP_INVALID_STATUS_CODE); }))) {
            mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZAP_INVALID_STATUS_CODE);
        }
    }




    static if(!is(typeof(ZMQ_PROTOCOL_ERROR_ZAP_INVALID_METADATA))) {
        private enum enumMixinStr_ZMQ_PROTOCOL_ERROR_ZAP_INVALID_METADATA = `enum ZMQ_PROTOCOL_ERROR_ZAP_INVALID_METADATA = 0x20000005;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZAP_INVALID_METADATA); }))) {
            mixin(enumMixinStr_ZMQ_PROTOCOL_ERROR_ZAP_INVALID_METADATA);
        }
    }




    static if(!is(typeof(__NLINK_T_TYPE))) {
        private enum enumMixinStr___NLINK_T_TYPE = `enum __NLINK_T_TYPE = __SYSCALL_ULONG_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___NLINK_T_TYPE); }))) {
            mixin(enumMixinStr___NLINK_T_TYPE);
        }
    }




    static if(!is(typeof(__MODE_T_TYPE))) {
        private enum enumMixinStr___MODE_T_TYPE = `enum __MODE_T_TYPE = __U32_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___MODE_T_TYPE); }))) {
            mixin(enumMixinStr___MODE_T_TYPE);
        }
    }




    static if(!is(typeof(__INO64_T_TYPE))) {
        private enum enumMixinStr___INO64_T_TYPE = `enum __INO64_T_TYPE = __UQUAD_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___INO64_T_TYPE); }))) {
            mixin(enumMixinStr___INO64_T_TYPE);
        }
    }




    static if(!is(typeof(__INO_T_TYPE))) {
        private enum enumMixinStr___INO_T_TYPE = `enum __INO_T_TYPE = __SYSCALL_ULONG_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___INO_T_TYPE); }))) {
            mixin(enumMixinStr___INO_T_TYPE);
        }
    }




    static if(!is(typeof(__GID_T_TYPE))) {
        private enum enumMixinStr___GID_T_TYPE = `enum __GID_T_TYPE = __U32_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___GID_T_TYPE); }))) {
            mixin(enumMixinStr___GID_T_TYPE);
        }
    }




    static if(!is(typeof(__UID_T_TYPE))) {
        private enum enumMixinStr___UID_T_TYPE = `enum __UID_T_TYPE = __U32_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___UID_T_TYPE); }))) {
            mixin(enumMixinStr___UID_T_TYPE);
        }
    }




    static if(!is(typeof(__DEV_T_TYPE))) {
        private enum enumMixinStr___DEV_T_TYPE = `enum __DEV_T_TYPE = __UQUAD_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___DEV_T_TYPE); }))) {
            mixin(enumMixinStr___DEV_T_TYPE);
        }
    }




    static if(!is(typeof(__SYSCALL_ULONG_TYPE))) {
        private enum enumMixinStr___SYSCALL_ULONG_TYPE = `enum __SYSCALL_ULONG_TYPE = __ULONGWORD_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___SYSCALL_ULONG_TYPE); }))) {
            mixin(enumMixinStr___SYSCALL_ULONG_TYPE);
        }
    }




    static if(!is(typeof(__SYSCALL_SLONG_TYPE))) {
        private enum enumMixinStr___SYSCALL_SLONG_TYPE = `enum __SYSCALL_SLONG_TYPE = __SLONGWORD_TYPE;`;
        static if(is(typeof({ mixin(enumMixinStr___SYSCALL_SLONG_TYPE); }))) {
            mixin(enumMixinStr___SYSCALL_SLONG_TYPE);
        }
    }




    static if(!is(typeof(_BITS_TYPESIZES_H))) {
        private enum enumMixinStr__BITS_TYPESIZES_H = `enum _BITS_TYPESIZES_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_TYPESIZES_H); }))) {
            mixin(enumMixinStr__BITS_TYPESIZES_H);
        }
    }




    static if(!is(typeof(__timer_t_defined))) {
        private enum enumMixinStr___timer_t_defined = `enum __timer_t_defined = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___timer_t_defined); }))) {
            mixin(enumMixinStr___timer_t_defined);
        }
    }




    static if(!is(typeof(__time_t_defined))) {
        private enum enumMixinStr___time_t_defined = `enum __time_t_defined = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___time_t_defined); }))) {
            mixin(enumMixinStr___time_t_defined);
        }
    }




    static if(!is(typeof(__struct_tm_defined))) {
        private enum enumMixinStr___struct_tm_defined = `enum __struct_tm_defined = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___struct_tm_defined); }))) {
            mixin(enumMixinStr___struct_tm_defined);
        }
    }




    static if(!is(typeof(__timeval_defined))) {
        private enum enumMixinStr___timeval_defined = `enum __timeval_defined = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___timeval_defined); }))) {
            mixin(enumMixinStr___timeval_defined);
        }
    }




    static if(!is(typeof(_STRUCT_TIMESPEC))) {
        private enum enumMixinStr__STRUCT_TIMESPEC = `enum _STRUCT_TIMESPEC = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__STRUCT_TIMESPEC); }))) {
            mixin(enumMixinStr__STRUCT_TIMESPEC);
        }
    }




    static if(!is(typeof(__sigstack_defined))) {
        private enum enumMixinStr___sigstack_defined = `enum __sigstack_defined = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___sigstack_defined); }))) {
            mixin(enumMixinStr___sigstack_defined);
        }
    }




    static if(!is(typeof(_BITS_TYPES_STRUCT_SCHED_PARAM))) {
        private enum enumMixinStr__BITS_TYPES_STRUCT_SCHED_PARAM = `enum _BITS_TYPES_STRUCT_SCHED_PARAM = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_TYPES_STRUCT_SCHED_PARAM); }))) {
            mixin(enumMixinStr__BITS_TYPES_STRUCT_SCHED_PARAM);
        }
    }




    static if(!is(typeof(__osockaddr_defined))) {
        private enum enumMixinStr___osockaddr_defined = `enum __osockaddr_defined = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___osockaddr_defined); }))) {
            mixin(enumMixinStr___osockaddr_defined);
        }
    }




    static if(!is(typeof(__itimerspec_defined))) {
        private enum enumMixinStr___itimerspec_defined = `enum __itimerspec_defined = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___itimerspec_defined); }))) {
            mixin(enumMixinStr___itimerspec_defined);
        }
    }




    static if(!is(typeof(__iovec_defined))) {
        private enum enumMixinStr___iovec_defined = `enum __iovec_defined = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___iovec_defined); }))) {
            mixin(enumMixinStr___iovec_defined);
        }
    }




    static if(!is(typeof(_IO_USER_LOCK))) {
        private enum enumMixinStr__IO_USER_LOCK = `enum _IO_USER_LOCK = 0x8000;`;
        static if(is(typeof({ mixin(enumMixinStr__IO_USER_LOCK); }))) {
            mixin(enumMixinStr__IO_USER_LOCK);
        }
    }






    static if(!is(typeof(_IO_ERR_SEEN))) {
        private enum enumMixinStr__IO_ERR_SEEN = `enum _IO_ERR_SEEN = 0x0020;`;
        static if(is(typeof({ mixin(enumMixinStr__IO_ERR_SEEN); }))) {
            mixin(enumMixinStr__IO_ERR_SEEN);
        }
    }




    static if(!is(typeof(ZMQ_POLLIN))) {
        private enum enumMixinStr_ZMQ_POLLIN = `enum ZMQ_POLLIN = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_POLLIN); }))) {
            mixin(enumMixinStr_ZMQ_POLLIN);
        }
    }




    static if(!is(typeof(ZMQ_POLLOUT))) {
        private enum enumMixinStr_ZMQ_POLLOUT = `enum ZMQ_POLLOUT = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_POLLOUT); }))) {
            mixin(enumMixinStr_ZMQ_POLLOUT);
        }
    }




    static if(!is(typeof(ZMQ_POLLERR))) {
        private enum enumMixinStr_ZMQ_POLLERR = `enum ZMQ_POLLERR = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_POLLERR); }))) {
            mixin(enumMixinStr_ZMQ_POLLERR);
        }
    }




    static if(!is(typeof(ZMQ_POLLPRI))) {
        private enum enumMixinStr_ZMQ_POLLPRI = `enum ZMQ_POLLPRI = 8;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_POLLPRI); }))) {
            mixin(enumMixinStr_ZMQ_POLLPRI);
        }
    }






    static if(!is(typeof(_IO_EOF_SEEN))) {
        private enum enumMixinStr__IO_EOF_SEEN = `enum _IO_EOF_SEEN = 0x0010;`;
        static if(is(typeof({ mixin(enumMixinStr__IO_EOF_SEEN); }))) {
            mixin(enumMixinStr__IO_EOF_SEEN);
        }
    }




    static if(!is(typeof(ZMQ_POLLITEMS_DFLT))) {
        private enum enumMixinStr_ZMQ_POLLITEMS_DFLT = `enum ZMQ_POLLITEMS_DFLT = 16;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_POLLITEMS_DFLT); }))) {
            mixin(enumMixinStr_ZMQ_POLLITEMS_DFLT);
        }
    }
    static if(!is(typeof(__struct_FILE_defined))) {
        private enum enumMixinStr___struct_FILE_defined = `enum __struct_FILE_defined = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___struct_FILE_defined); }))) {
            mixin(enumMixinStr___struct_FILE_defined);
        }
    }




    static if(!is(typeof(__stack_t_defined))) {
        private enum enumMixinStr___stack_t_defined = `enum __stack_t_defined = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___stack_t_defined); }))) {
            mixin(enumMixinStr___stack_t_defined);
        }
    }






    static if(!is(typeof(ZMQ_HAS_CAPABILITIES))) {
        private enum enumMixinStr_ZMQ_HAS_CAPABILITIES = `enum ZMQ_HAS_CAPABILITIES = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_HAS_CAPABILITIES); }))) {
            mixin(enumMixinStr_ZMQ_HAS_CAPABILITIES);
        }
    }




    static if(!is(typeof(__sigset_t_defined))) {
        private enum enumMixinStr___sigset_t_defined = `enum __sigset_t_defined = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___sigset_t_defined); }))) {
            mixin(enumMixinStr___sigset_t_defined);
        }
    }




    static if(!is(typeof(si_arch))) {
        private enum enumMixinStr_si_arch = `enum si_arch = _sifields . _sigsys . _arch;`;
        static if(is(typeof({ mixin(enumMixinStr_si_arch); }))) {
            mixin(enumMixinStr_si_arch);
        }
    }




    static if(!is(typeof(ZMQ_STREAMER))) {
        private enum enumMixinStr_ZMQ_STREAMER = `enum ZMQ_STREAMER = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_STREAMER); }))) {
            mixin(enumMixinStr_ZMQ_STREAMER);
        }
    }




    static if(!is(typeof(ZMQ_FORWARDER))) {
        private enum enumMixinStr_ZMQ_FORWARDER = `enum ZMQ_FORWARDER = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_FORWARDER); }))) {
            mixin(enumMixinStr_ZMQ_FORWARDER);
        }
    }




    static if(!is(typeof(ZMQ_QUEUE))) {
        private enum enumMixinStr_ZMQ_QUEUE = `enum ZMQ_QUEUE = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_QUEUE); }))) {
            mixin(enumMixinStr_ZMQ_QUEUE);
        }
    }




    static if(!is(typeof(si_syscall))) {
        private enum enumMixinStr_si_syscall = `enum si_syscall = _sifields . _sigsys . _syscall;`;
        static if(is(typeof({ mixin(enumMixinStr_si_syscall); }))) {
            mixin(enumMixinStr_si_syscall);
        }
    }




    static if(!is(typeof(si_call_addr))) {
        private enum enumMixinStr_si_call_addr = `enum si_call_addr = _sifields . _sigsys . _call_addr;`;
        static if(is(typeof({ mixin(enumMixinStr_si_call_addr); }))) {
            mixin(enumMixinStr_si_call_addr);
        }
    }




    static if(!is(typeof(si_fd))) {
        private enum enumMixinStr_si_fd = `enum si_fd = _sifields . _sigpoll . si_fd;`;
        static if(is(typeof({ mixin(enumMixinStr_si_fd); }))) {
            mixin(enumMixinStr_si_fd);
        }
    }




    static if(!is(typeof(si_band))) {
        private enum enumMixinStr_si_band = `enum si_band = _sifields . _sigpoll . si_band;`;
        static if(is(typeof({ mixin(enumMixinStr_si_band); }))) {
            mixin(enumMixinStr_si_band);
        }
    }




    static if(!is(typeof(si_pkey))) {
        private enum enumMixinStr_si_pkey = `enum si_pkey = _sifields . _sigfault . _bounds . _pkey;`;
        static if(is(typeof({ mixin(enumMixinStr_si_pkey); }))) {
            mixin(enumMixinStr_si_pkey);
        }
    }




    static if(!is(typeof(si_upper))) {
        private enum enumMixinStr_si_upper = `enum si_upper = _sifields . _sigfault . _bounds . _addr_bnd . _upper;`;
        static if(is(typeof({ mixin(enumMixinStr_si_upper); }))) {
            mixin(enumMixinStr_si_upper);
        }
    }




    static if(!is(typeof(si_lower))) {
        private enum enumMixinStr_si_lower = `enum si_lower = _sifields . _sigfault . _bounds . _addr_bnd . _lower;`;
        static if(is(typeof({ mixin(enumMixinStr_si_lower); }))) {
            mixin(enumMixinStr_si_lower);
        }
    }




    static if(!is(typeof(si_addr_lsb))) {
        private enum enumMixinStr_si_addr_lsb = `enum si_addr_lsb = _sifields . _sigfault . si_addr_lsb;`;
        static if(is(typeof({ mixin(enumMixinStr_si_addr_lsb); }))) {
            mixin(enumMixinStr_si_addr_lsb);
        }
    }




    static if(!is(typeof(si_addr))) {
        private enum enumMixinStr_si_addr = `enum si_addr = _sifields . _sigfault . si_addr;`;
        static if(is(typeof({ mixin(enumMixinStr_si_addr); }))) {
            mixin(enumMixinStr_si_addr);
        }
    }




    static if(!is(typeof(si_ptr))) {
        private enum enumMixinStr_si_ptr = `enum si_ptr = _sifields . _rt . si_sigval . sival_ptr;`;
        static if(is(typeof({ mixin(enumMixinStr_si_ptr); }))) {
            mixin(enumMixinStr_si_ptr);
        }
    }




    static if(!is(typeof(si_int))) {
        private enum enumMixinStr_si_int = `enum si_int = _sifields . _rt . si_sigval . sival_int;`;
        static if(is(typeof({ mixin(enumMixinStr_si_int); }))) {
            mixin(enumMixinStr_si_int);
        }
    }




    static if(!is(typeof(si_value))) {
        private enum enumMixinStr_si_value = `enum si_value = _sifields . _rt . si_sigval;`;
        static if(is(typeof({ mixin(enumMixinStr_si_value); }))) {
            mixin(enumMixinStr_si_value);
        }
    }




    static if(!is(typeof(si_stime))) {
        private enum enumMixinStr_si_stime = `enum si_stime = _sifields . _sigchld . si_stime;`;
        static if(is(typeof({ mixin(enumMixinStr_si_stime); }))) {
            mixin(enumMixinStr_si_stime);
        }
    }




    static if(!is(typeof(si_utime))) {
        private enum enumMixinStr_si_utime = `enum si_utime = _sifields . _sigchld . si_utime;`;
        static if(is(typeof({ mixin(enumMixinStr_si_utime); }))) {
            mixin(enumMixinStr_si_utime);
        }
    }




    static if(!is(typeof(si_status))) {
        private enum enumMixinStr_si_status = `enum si_status = _sifields . _sigchld . si_status;`;
        static if(is(typeof({ mixin(enumMixinStr_si_status); }))) {
            mixin(enumMixinStr_si_status);
        }
    }




    static if(!is(typeof(si_overrun))) {
        private enum enumMixinStr_si_overrun = `enum si_overrun = _sifields . _timer . si_overrun;`;
        static if(is(typeof({ mixin(enumMixinStr_si_overrun); }))) {
            mixin(enumMixinStr_si_overrun);
        }
    }




    static if(!is(typeof(si_timerid))) {
        private enum enumMixinStr_si_timerid = `enum si_timerid = _sifields . _timer . si_tid;`;
        static if(is(typeof({ mixin(enumMixinStr_si_timerid); }))) {
            mixin(enumMixinStr_si_timerid);
        }
    }




    static if(!is(typeof(si_uid))) {
        private enum enumMixinStr_si_uid = `enum si_uid = _sifields . _kill . si_uid;`;
        static if(is(typeof({ mixin(enumMixinStr_si_uid); }))) {
            mixin(enumMixinStr_si_uid);
        }
    }




    static if(!is(typeof(si_pid))) {
        private enum enumMixinStr_si_pid = `enum si_pid = _sifields . _kill . si_pid;`;
        static if(is(typeof({ mixin(enumMixinStr_si_pid); }))) {
            mixin(enumMixinStr_si_pid);
        }
    }






    static if(!is(typeof(__SI_HAVE_SIGSYS))) {
        private enum enumMixinStr___SI_HAVE_SIGSYS = `enum __SI_HAVE_SIGSYS = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___SI_HAVE_SIGSYS); }))) {
            mixin(enumMixinStr___SI_HAVE_SIGSYS);
        }
    }




    static if(!is(typeof(__SI_ERRNO_THEN_CODE))) {
        private enum enumMixinStr___SI_ERRNO_THEN_CODE = `enum __SI_ERRNO_THEN_CODE = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___SI_ERRNO_THEN_CODE); }))) {
            mixin(enumMixinStr___SI_ERRNO_THEN_CODE);
        }
    }




    static if(!is(typeof(__SI_CLOCK_T))) {
        private enum enumMixinStr___SI_CLOCK_T = `enum __SI_CLOCK_T = __clock_t;`;
        static if(is(typeof({ mixin(enumMixinStr___SI_CLOCK_T); }))) {
            mixin(enumMixinStr___SI_CLOCK_T);
        }
    }




    static if(!is(typeof(__SI_BAND_TYPE))) {
        private enum enumMixinStr___SI_BAND_TYPE = `enum __SI_BAND_TYPE = long int;`;
        static if(is(typeof({ mixin(enumMixinStr___SI_BAND_TYPE); }))) {
            mixin(enumMixinStr___SI_BAND_TYPE);
        }
    }






    static if(!is(typeof(__SI_PAD_SIZE))) {
        private enum enumMixinStr___SI_PAD_SIZE = `enum __SI_PAD_SIZE = ( ( __SI_MAX_SIZE / ( int ) .sizeof ) - 4 );`;
        static if(is(typeof({ mixin(enumMixinStr___SI_PAD_SIZE); }))) {
            mixin(enumMixinStr___SI_PAD_SIZE);
        }
    }




    static if(!is(typeof(__SI_MAX_SIZE))) {
        private enum enumMixinStr___SI_MAX_SIZE = `enum __SI_MAX_SIZE = 128;`;
        static if(is(typeof({ mixin(enumMixinStr___SI_MAX_SIZE); }))) {
            mixin(enumMixinStr___SI_MAX_SIZE);
        }
    }




    static if(!is(typeof(__siginfo_t_defined))) {
        private enum enumMixinStr___siginfo_t_defined = `enum __siginfo_t_defined = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___siginfo_t_defined); }))) {
            mixin(enumMixinStr___siginfo_t_defined);
        }
    }




    static if(!is(typeof(sigev_notify_attributes))) {
        private enum enumMixinStr_sigev_notify_attributes = `enum sigev_notify_attributes = _sigev_un . _sigev_thread . _attribute;`;
        static if(is(typeof({ mixin(enumMixinStr_sigev_notify_attributes); }))) {
            mixin(enumMixinStr_sigev_notify_attributes);
        }
    }




    static if(!is(typeof(sigev_notify_function))) {
        private enum enumMixinStr_sigev_notify_function = `enum sigev_notify_function = _sigev_un . _sigev_thread . _function;`;
        static if(is(typeof({ mixin(enumMixinStr_sigev_notify_function); }))) {
            mixin(enumMixinStr_sigev_notify_function);
        }
    }




    static if(!is(typeof(__SIGEV_PAD_SIZE))) {
        private enum enumMixinStr___SIGEV_PAD_SIZE = `enum __SIGEV_PAD_SIZE = ( ( __SIGEV_MAX_SIZE / ( int ) .sizeof ) - 4 );`;
        static if(is(typeof({ mixin(enumMixinStr___SIGEV_PAD_SIZE); }))) {
            mixin(enumMixinStr___SIGEV_PAD_SIZE);
        }
    }






    static if(!is(typeof(__SIGEV_MAX_SIZE))) {
        private enum enumMixinStr___SIGEV_MAX_SIZE = `enum __SIGEV_MAX_SIZE = 64;`;
        static if(is(typeof({ mixin(enumMixinStr___SIGEV_MAX_SIZE); }))) {
            mixin(enumMixinStr___SIGEV_MAX_SIZE);
        }
    }




    static if(!is(typeof(__sigevent_t_defined))) {
        private enum enumMixinStr___sigevent_t_defined = `enum __sigevent_t_defined = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___sigevent_t_defined); }))) {
            mixin(enumMixinStr___sigevent_t_defined);
        }
    }




    static if(!is(typeof(__sig_atomic_t_defined))) {
        private enum enumMixinStr___sig_atomic_t_defined = `enum __sig_atomic_t_defined = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___sig_atomic_t_defined); }))) {
            mixin(enumMixinStr___sig_atomic_t_defined);
        }
    }




    static if(!is(typeof(_BITS_TYPES_LOCALE_T_H))) {
        private enum enumMixinStr__BITS_TYPES_LOCALE_T_H = `enum _BITS_TYPES_LOCALE_T_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_TYPES_LOCALE_T_H); }))) {
            mixin(enumMixinStr__BITS_TYPES_LOCALE_T_H);
        }
    }




    static if(!is(typeof(__clockid_t_defined))) {
        private enum enumMixinStr___clockid_t_defined = `enum __clockid_t_defined = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___clockid_t_defined); }))) {
            mixin(enumMixinStr___clockid_t_defined);
        }
    }




    static if(!is(typeof(__clock_t_defined))) {
        private enum enumMixinStr___clock_t_defined = `enum __clock_t_defined = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___clock_t_defined); }))) {
            mixin(enumMixinStr___clock_t_defined);
        }
    }






    static if(!is(typeof(_SIGSET_NWORDS))) {
        private enum enumMixinStr__SIGSET_NWORDS = `enum _SIGSET_NWORDS = ( 1024 / ( 8 * ( unsigned long int ) .sizeof ) );`;
        static if(is(typeof({ mixin(enumMixinStr__SIGSET_NWORDS); }))) {
            mixin(enumMixinStr__SIGSET_NWORDS);
        }
    }






    static if(!is(typeof(____mbstate_t_defined))) {
        private enum enumMixinStr_____mbstate_t_defined = `enum ____mbstate_t_defined = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_____mbstate_t_defined); }))) {
            mixin(enumMixinStr_____mbstate_t_defined);
        }
    }




    static if(!is(typeof(_BITS_TYPES___LOCALE_T_H))) {
        private enum enumMixinStr__BITS_TYPES___LOCALE_T_H = `enum _BITS_TYPES___LOCALE_T_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_TYPES___LOCALE_T_H); }))) {
            mixin(enumMixinStr__BITS_TYPES___LOCALE_T_H);
        }
    }




    static if(!is(typeof(_____fpos_t_defined))) {
        private enum enumMixinStr______fpos_t_defined = `enum _____fpos_t_defined = 1;`;
        static if(is(typeof({ mixin(enumMixinStr______fpos_t_defined); }))) {
            mixin(enumMixinStr______fpos_t_defined);
        }
    }




    static if(!is(typeof(_____fpos64_t_defined))) {
        private enum enumMixinStr______fpos64_t_defined = `enum _____fpos64_t_defined = 1;`;
        static if(is(typeof({ mixin(enumMixinStr______fpos64_t_defined); }))) {
            mixin(enumMixinStr______fpos64_t_defined);
        }
    }




    static if(!is(typeof(____FILE_defined))) {
        private enum enumMixinStr_____FILE_defined = `enum ____FILE_defined = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_____FILE_defined); }))) {
            mixin(enumMixinStr_____FILE_defined);
        }
    }




    static if(!is(typeof(__FILE_defined))) {
        private enum enumMixinStr___FILE_defined = `enum __FILE_defined = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___FILE_defined); }))) {
            mixin(enumMixinStr___FILE_defined);
        }
    }




    static if(!is(typeof(__STD_TYPE))) {
        private enum enumMixinStr___STD_TYPE = `enum __STD_TYPE = typedef;`;
        static if(is(typeof({ mixin(enumMixinStr___STD_TYPE); }))) {
            mixin(enumMixinStr___STD_TYPE);
        }
    }




    static if(!is(typeof(__U64_TYPE))) {
        private enum enumMixinStr___U64_TYPE = `enum __U64_TYPE = unsigned long int;`;
        static if(is(typeof({ mixin(enumMixinStr___U64_TYPE); }))) {
            mixin(enumMixinStr___U64_TYPE);
        }
    }




    static if(!is(typeof(__S64_TYPE))) {
        private enum enumMixinStr___S64_TYPE = `enum __S64_TYPE = long int;`;
        static if(is(typeof({ mixin(enumMixinStr___S64_TYPE); }))) {
            mixin(enumMixinStr___S64_TYPE);
        }
    }




    static if(!is(typeof(__ULONG32_TYPE))) {
        private enum enumMixinStr___ULONG32_TYPE = `enum __ULONG32_TYPE = unsigned int;`;
        static if(is(typeof({ mixin(enumMixinStr___ULONG32_TYPE); }))) {
            mixin(enumMixinStr___ULONG32_TYPE);
        }
    }




    static if(!is(typeof(__SLONG32_TYPE))) {
        private enum enumMixinStr___SLONG32_TYPE = `enum __SLONG32_TYPE = int;`;
        static if(is(typeof({ mixin(enumMixinStr___SLONG32_TYPE); }))) {
            mixin(enumMixinStr___SLONG32_TYPE);
        }
    }




    static if(!is(typeof(__UWORD_TYPE))) {
        private enum enumMixinStr___UWORD_TYPE = `enum __UWORD_TYPE = unsigned long int;`;
        static if(is(typeof({ mixin(enumMixinStr___UWORD_TYPE); }))) {
            mixin(enumMixinStr___UWORD_TYPE);
        }
    }




    static if(!is(typeof(__SWORD_TYPE))) {
        private enum enumMixinStr___SWORD_TYPE = `enum __SWORD_TYPE = long int;`;
        static if(is(typeof({ mixin(enumMixinStr___SWORD_TYPE); }))) {
            mixin(enumMixinStr___SWORD_TYPE);
        }
    }




    static if(!is(typeof(__UQUAD_TYPE))) {
        private enum enumMixinStr___UQUAD_TYPE = `enum __UQUAD_TYPE = unsigned long int;`;
        static if(is(typeof({ mixin(enumMixinStr___UQUAD_TYPE); }))) {
            mixin(enumMixinStr___UQUAD_TYPE);
        }
    }




    static if(!is(typeof(__SQUAD_TYPE))) {
        private enum enumMixinStr___SQUAD_TYPE = `enum __SQUAD_TYPE = long int;`;
        static if(is(typeof({ mixin(enumMixinStr___SQUAD_TYPE); }))) {
            mixin(enumMixinStr___SQUAD_TYPE);
        }
    }




    static if(!is(typeof(__ULONGWORD_TYPE))) {
        private enum enumMixinStr___ULONGWORD_TYPE = `enum __ULONGWORD_TYPE = unsigned long int;`;
        static if(is(typeof({ mixin(enumMixinStr___ULONGWORD_TYPE); }))) {
            mixin(enumMixinStr___ULONGWORD_TYPE);
        }
    }




    static if(!is(typeof(__SLONGWORD_TYPE))) {
        private enum enumMixinStr___SLONGWORD_TYPE = `enum __SLONGWORD_TYPE = long int;`;
        static if(is(typeof({ mixin(enumMixinStr___SLONGWORD_TYPE); }))) {
            mixin(enumMixinStr___SLONGWORD_TYPE);
        }
    }




    static if(!is(typeof(__U32_TYPE))) {
        private enum enumMixinStr___U32_TYPE = `enum __U32_TYPE = unsigned int;`;
        static if(is(typeof({ mixin(enumMixinStr___U32_TYPE); }))) {
            mixin(enumMixinStr___U32_TYPE);
        }
    }




    static if(!is(typeof(__S32_TYPE))) {
        private enum enumMixinStr___S32_TYPE = `enum __S32_TYPE = int;`;
        static if(is(typeof({ mixin(enumMixinStr___S32_TYPE); }))) {
            mixin(enumMixinStr___S32_TYPE);
        }
    }




    static if(!is(typeof(__U16_TYPE))) {
        private enum enumMixinStr___U16_TYPE = `enum __U16_TYPE = unsigned short int;`;
        static if(is(typeof({ mixin(enumMixinStr___U16_TYPE); }))) {
            mixin(enumMixinStr___U16_TYPE);
        }
    }




    static if(!is(typeof(__S16_TYPE))) {
        private enum enumMixinStr___S16_TYPE = `enum __S16_TYPE = short int;`;
        static if(is(typeof({ mixin(enumMixinStr___S16_TYPE); }))) {
            mixin(enumMixinStr___S16_TYPE);
        }
    }






    static if(!is(typeof(_BITS_TYPES_H))) {
        private enum enumMixinStr__BITS_TYPES_H = `enum _BITS_TYPES_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_TYPES_H); }))) {
            mixin(enumMixinStr__BITS_TYPES_H);
        }
    }




    static if(!is(typeof(__TIMESIZE))) {
        private enum enumMixinStr___TIMESIZE = `enum __TIMESIZE = 64;`;
        static if(is(typeof({ mixin(enumMixinStr___TIMESIZE); }))) {
            mixin(enumMixinStr___TIMESIZE);
        }
    }




    static if(!is(typeof(__TIME64_T_TYPE))) {
        private enum enumMixinStr___TIME64_T_TYPE = `enum __TIME64_T_TYPE = long int;`;
        static if(is(typeof({ mixin(enumMixinStr___TIME64_T_TYPE); }))) {
            mixin(enumMixinStr___TIME64_T_TYPE);
        }
    }




    static if(!is(typeof(_BITS_TIME64_H))) {
        private enum enumMixinStr__BITS_TIME64_H = `enum _BITS_TIME64_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_TIME64_H); }))) {
            mixin(enumMixinStr__BITS_TIME64_H);
        }
    }




    static if(!is(typeof(TIMER_ABSTIME))) {
        private enum enumMixinStr_TIMER_ABSTIME = `enum TIMER_ABSTIME = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_TIMER_ABSTIME); }))) {
            mixin(enumMixinStr_TIMER_ABSTIME);
        }
    }




    static if(!is(typeof(CLOCK_TAI))) {
        private enum enumMixinStr_CLOCK_TAI = `enum CLOCK_TAI = 11;`;
        static if(is(typeof({ mixin(enumMixinStr_CLOCK_TAI); }))) {
            mixin(enumMixinStr_CLOCK_TAI);
        }
    }




    static if(!is(typeof(CLOCK_BOOTTIME_ALARM))) {
        private enum enumMixinStr_CLOCK_BOOTTIME_ALARM = `enum CLOCK_BOOTTIME_ALARM = 9;`;
        static if(is(typeof({ mixin(enumMixinStr_CLOCK_BOOTTIME_ALARM); }))) {
            mixin(enumMixinStr_CLOCK_BOOTTIME_ALARM);
        }
    }




    static if(!is(typeof(CLOCK_REALTIME_ALARM))) {
        private enum enumMixinStr_CLOCK_REALTIME_ALARM = `enum CLOCK_REALTIME_ALARM = 8;`;
        static if(is(typeof({ mixin(enumMixinStr_CLOCK_REALTIME_ALARM); }))) {
            mixin(enumMixinStr_CLOCK_REALTIME_ALARM);
        }
    }




    static if(!is(typeof(CLOCK_BOOTTIME))) {
        private enum enumMixinStr_CLOCK_BOOTTIME = `enum CLOCK_BOOTTIME = 7;`;
        static if(is(typeof({ mixin(enumMixinStr_CLOCK_BOOTTIME); }))) {
            mixin(enumMixinStr_CLOCK_BOOTTIME);
        }
    }




    static if(!is(typeof(CLOCK_MONOTONIC_COARSE))) {
        private enum enumMixinStr_CLOCK_MONOTONIC_COARSE = `enum CLOCK_MONOTONIC_COARSE = 6;`;
        static if(is(typeof({ mixin(enumMixinStr_CLOCK_MONOTONIC_COARSE); }))) {
            mixin(enumMixinStr_CLOCK_MONOTONIC_COARSE);
        }
    }




    static if(!is(typeof(CLOCK_REALTIME_COARSE))) {
        private enum enumMixinStr_CLOCK_REALTIME_COARSE = `enum CLOCK_REALTIME_COARSE = 5;`;
        static if(is(typeof({ mixin(enumMixinStr_CLOCK_REALTIME_COARSE); }))) {
            mixin(enumMixinStr_CLOCK_REALTIME_COARSE);
        }
    }




    static if(!is(typeof(CLOCK_MONOTONIC_RAW))) {
        private enum enumMixinStr_CLOCK_MONOTONIC_RAW = `enum CLOCK_MONOTONIC_RAW = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_CLOCK_MONOTONIC_RAW); }))) {
            mixin(enumMixinStr_CLOCK_MONOTONIC_RAW);
        }
    }




    static if(!is(typeof(CLOCK_THREAD_CPUTIME_ID))) {
        private enum enumMixinStr_CLOCK_THREAD_CPUTIME_ID = `enum CLOCK_THREAD_CPUTIME_ID = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_CLOCK_THREAD_CPUTIME_ID); }))) {
            mixin(enumMixinStr_CLOCK_THREAD_CPUTIME_ID);
        }
    }




    static if(!is(typeof(CLOCK_PROCESS_CPUTIME_ID))) {
        private enum enumMixinStr_CLOCK_PROCESS_CPUTIME_ID = `enum CLOCK_PROCESS_CPUTIME_ID = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_CLOCK_PROCESS_CPUTIME_ID); }))) {
            mixin(enumMixinStr_CLOCK_PROCESS_CPUTIME_ID);
        }
    }




    static if(!is(typeof(CLOCK_MONOTONIC))) {
        private enum enumMixinStr_CLOCK_MONOTONIC = `enum CLOCK_MONOTONIC = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_CLOCK_MONOTONIC); }))) {
            mixin(enumMixinStr_CLOCK_MONOTONIC);
        }
    }




    static if(!is(typeof(CLOCK_REALTIME))) {
        private enum enumMixinStr_CLOCK_REALTIME = `enum CLOCK_REALTIME = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_CLOCK_REALTIME); }))) {
            mixin(enumMixinStr_CLOCK_REALTIME);
        }
    }




    static if(!is(typeof(CLOCKS_PER_SEC))) {
        private enum enumMixinStr_CLOCKS_PER_SEC = `enum CLOCKS_PER_SEC = ( cast( __clock_t ) 1000000 );`;
        static if(is(typeof({ mixin(enumMixinStr_CLOCKS_PER_SEC); }))) {
            mixin(enumMixinStr_CLOCKS_PER_SEC);
        }
    }




    static if(!is(typeof(_BITS_TIME_H))) {
        private enum enumMixinStr__BITS_TIME_H = `enum _BITS_TIME_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_TIME_H); }))) {
            mixin(enumMixinStr__BITS_TIME_H);
        }
    }




    static if(!is(typeof(_THREAD_SHARED_TYPES_H))) {
        private enum enumMixinStr__THREAD_SHARED_TYPES_H = `enum _THREAD_SHARED_TYPES_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__THREAD_SHARED_TYPES_H); }))) {
            mixin(enumMixinStr__THREAD_SHARED_TYPES_H);
        }
    }




    static if(!is(typeof(_PATH_LOG))) {
        private enum enumMixinStr__PATH_LOG = `enum _PATH_LOG = "/dev/log";`;
        static if(is(typeof({ mixin(enumMixinStr__PATH_LOG); }))) {
            mixin(enumMixinStr__PATH_LOG);
        }
    }




    static if(!is(typeof(_BITS_SYSLOG_PATH_H))) {
        private enum enumMixinStr__BITS_SYSLOG_PATH_H = `enum _BITS_SYSLOG_PATH_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_SYSLOG_PATH_H); }))) {
            mixin(enumMixinStr__BITS_SYSLOG_PATH_H);
        }
    }






    static if(!is(typeof(__PTHREAD_RWLOCK_ELISION_EXTRA))) {
        private enum enumMixinStr___PTHREAD_RWLOCK_ELISION_EXTRA = `enum __PTHREAD_RWLOCK_ELISION_EXTRA = 0 , { 0 , 0 , 0 , 0 , 0 , 0 , 0 };`;
        static if(is(typeof({ mixin(enumMixinStr___PTHREAD_RWLOCK_ELISION_EXTRA); }))) {
            mixin(enumMixinStr___PTHREAD_RWLOCK_ELISION_EXTRA);
        }
    }
    static if(!is(typeof(__PTHREAD_MUTEX_HAVE_PREV))) {
        private enum enumMixinStr___PTHREAD_MUTEX_HAVE_PREV = `enum __PTHREAD_MUTEX_HAVE_PREV = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___PTHREAD_MUTEX_HAVE_PREV); }))) {
            mixin(enumMixinStr___PTHREAD_MUTEX_HAVE_PREV);
        }
    }




    static if(!is(typeof(_THREAD_MUTEX_INTERNAL_H))) {
        private enum enumMixinStr__THREAD_MUTEX_INTERNAL_H = `enum _THREAD_MUTEX_INTERNAL_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__THREAD_MUTEX_INTERNAL_H); }))) {
            mixin(enumMixinStr__THREAD_MUTEX_INTERNAL_H);
        }
    }




    static if(!is(typeof(FOPEN_MAX))) {
        private enum enumMixinStr_FOPEN_MAX = `enum FOPEN_MAX = 16;`;
        static if(is(typeof({ mixin(enumMixinStr_FOPEN_MAX); }))) {
            mixin(enumMixinStr_FOPEN_MAX);
        }
    }




    static if(!is(typeof(L_ctermid))) {
        private enum enumMixinStr_L_ctermid = `enum L_ctermid = 9;`;
        static if(is(typeof({ mixin(enumMixinStr_L_ctermid); }))) {
            mixin(enumMixinStr_L_ctermid);
        }
    }




    static if(!is(typeof(FILENAME_MAX))) {
        private enum enumMixinStr_FILENAME_MAX = `enum FILENAME_MAX = 4096;`;
        static if(is(typeof({ mixin(enumMixinStr_FILENAME_MAX); }))) {
            mixin(enumMixinStr_FILENAME_MAX);
        }
    }




    static if(!is(typeof(TMP_MAX))) {
        private enum enumMixinStr_TMP_MAX = `enum TMP_MAX = 238328;`;
        static if(is(typeof({ mixin(enumMixinStr_TMP_MAX); }))) {
            mixin(enumMixinStr_TMP_MAX);
        }
    }




    static if(!is(typeof(L_tmpnam))) {
        private enum enumMixinStr_L_tmpnam = `enum L_tmpnam = 20;`;
        static if(is(typeof({ mixin(enumMixinStr_L_tmpnam); }))) {
            mixin(enumMixinStr_L_tmpnam);
        }
    }




    static if(!is(typeof(_BITS_STDIO_LIM_H))) {
        private enum enumMixinStr__BITS_STDIO_LIM_H = `enum _BITS_STDIO_LIM_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_STDIO_LIM_H); }))) {
            mixin(enumMixinStr__BITS_STDIO_LIM_H);
        }
    }




    static if(!is(typeof(_BITS_STDINT_UINTN_H))) {
        private enum enumMixinStr__BITS_STDINT_UINTN_H = `enum _BITS_STDINT_UINTN_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_STDINT_UINTN_H); }))) {
            mixin(enumMixinStr__BITS_STDINT_UINTN_H);
        }
    }




    static if(!is(typeof(_BITS_STDINT_INTN_H))) {
        private enum enumMixinStr__BITS_STDINT_INTN_H = `enum _BITS_STDINT_INTN_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_STDINT_INTN_H); }))) {
            mixin(enumMixinStr__BITS_STDINT_INTN_H);
        }
    }




    static if(!is(typeof(UTIME_OMIT))) {
        private enum enumMixinStr_UTIME_OMIT = `enum UTIME_OMIT = ( ( 1l << 30 ) - 2l );`;
        static if(is(typeof({ mixin(enumMixinStr_UTIME_OMIT); }))) {
            mixin(enumMixinStr_UTIME_OMIT);
        }
    }




    static if(!is(typeof(UTIME_NOW))) {
        private enum enumMixinStr_UTIME_NOW = `enum UTIME_NOW = ( ( 1l << 30 ) - 1l );`;
        static if(is(typeof({ mixin(enumMixinStr_UTIME_NOW); }))) {
            mixin(enumMixinStr_UTIME_NOW);
        }
    }




    static if(!is(typeof(__S_IEXEC))) {
        private enum enumMixinStr___S_IEXEC = `enum __S_IEXEC = std.conv.octal!100;`;
        static if(is(typeof({ mixin(enumMixinStr___S_IEXEC); }))) {
            mixin(enumMixinStr___S_IEXEC);
        }
    }




    static if(!is(typeof(__S_IWRITE))) {
        private enum enumMixinStr___S_IWRITE = `enum __S_IWRITE = std.conv.octal!200;`;
        static if(is(typeof({ mixin(enumMixinStr___S_IWRITE); }))) {
            mixin(enumMixinStr___S_IWRITE);
        }
    }




    static if(!is(typeof(__S_IREAD))) {
        private enum enumMixinStr___S_IREAD = `enum __S_IREAD = std.conv.octal!400;`;
        static if(is(typeof({ mixin(enumMixinStr___S_IREAD); }))) {
            mixin(enumMixinStr___S_IREAD);
        }
    }




    static if(!is(typeof(__S_ISVTX))) {
        private enum enumMixinStr___S_ISVTX = `enum __S_ISVTX = std.conv.octal!1000;`;
        static if(is(typeof({ mixin(enumMixinStr___S_ISVTX); }))) {
            mixin(enumMixinStr___S_ISVTX);
        }
    }




    static if(!is(typeof(__S_ISGID))) {
        private enum enumMixinStr___S_ISGID = `enum __S_ISGID = std.conv.octal!2000;`;
        static if(is(typeof({ mixin(enumMixinStr___S_ISGID); }))) {
            mixin(enumMixinStr___S_ISGID);
        }
    }




    static if(!is(typeof(__S_ISUID))) {
        private enum enumMixinStr___S_ISUID = `enum __S_ISUID = std.conv.octal!4000;`;
        static if(is(typeof({ mixin(enumMixinStr___S_ISUID); }))) {
            mixin(enumMixinStr___S_ISUID);
        }
    }
    static if(!is(typeof(__S_IFSOCK))) {
        private enum enumMixinStr___S_IFSOCK = `enum __S_IFSOCK = std.conv.octal!140000;`;
        static if(is(typeof({ mixin(enumMixinStr___S_IFSOCK); }))) {
            mixin(enumMixinStr___S_IFSOCK);
        }
    }




    static if(!is(typeof(__S_IFLNK))) {
        private enum enumMixinStr___S_IFLNK = `enum __S_IFLNK = std.conv.octal!120000;`;
        static if(is(typeof({ mixin(enumMixinStr___S_IFLNK); }))) {
            mixin(enumMixinStr___S_IFLNK);
        }
    }




    static if(!is(typeof(__S_IFIFO))) {
        private enum enumMixinStr___S_IFIFO = `enum __S_IFIFO = std.conv.octal!10000;`;
        static if(is(typeof({ mixin(enumMixinStr___S_IFIFO); }))) {
            mixin(enumMixinStr___S_IFIFO);
        }
    }




    static if(!is(typeof(__S_IFREG))) {
        private enum enumMixinStr___S_IFREG = `enum __S_IFREG = std.conv.octal!100000;`;
        static if(is(typeof({ mixin(enumMixinStr___S_IFREG); }))) {
            mixin(enumMixinStr___S_IFREG);
        }
    }




    static if(!is(typeof(__S_IFBLK))) {
        private enum enumMixinStr___S_IFBLK = `enum __S_IFBLK = std.conv.octal!60000;`;
        static if(is(typeof({ mixin(enumMixinStr___S_IFBLK); }))) {
            mixin(enumMixinStr___S_IFBLK);
        }
    }




    static if(!is(typeof(__S_IFCHR))) {
        private enum enumMixinStr___S_IFCHR = `enum __S_IFCHR = std.conv.octal!20000;`;
        static if(is(typeof({ mixin(enumMixinStr___S_IFCHR); }))) {
            mixin(enumMixinStr___S_IFCHR);
        }
    }




    static if(!is(typeof(__S_IFDIR))) {
        private enum enumMixinStr___S_IFDIR = `enum __S_IFDIR = std.conv.octal!40000;`;
        static if(is(typeof({ mixin(enumMixinStr___S_IFDIR); }))) {
            mixin(enumMixinStr___S_IFDIR);
        }
    }




    static if(!is(typeof(__S_IFMT))) {
        private enum enumMixinStr___S_IFMT = `enum __S_IFMT = std.conv.octal!170000;`;
        static if(is(typeof({ mixin(enumMixinStr___S_IFMT); }))) {
            mixin(enumMixinStr___S_IFMT);
        }
    }
    static if(!is(typeof(st_ctime))) {
        private enum enumMixinStr_st_ctime = `enum st_ctime = st_ctim . tv_sec;`;
        static if(is(typeof({ mixin(enumMixinStr_st_ctime); }))) {
            mixin(enumMixinStr_st_ctime);
        }
    }




    static if(!is(typeof(st_mtime))) {
        private enum enumMixinStr_st_mtime = `enum st_mtime = st_mtim . tv_sec;`;
        static if(is(typeof({ mixin(enumMixinStr_st_mtime); }))) {
            mixin(enumMixinStr_st_mtime);
        }
    }




    static if(!is(typeof(st_atime))) {
        private enum enumMixinStr_st_atime = `enum st_atime = st_atim . tv_sec;`;
        static if(is(typeof({ mixin(enumMixinStr_st_atime); }))) {
            mixin(enumMixinStr_st_atime);
        }
    }




    static if(!is(typeof(_STAT_VER))) {
        private enum enumMixinStr__STAT_VER = `enum _STAT_VER = _STAT_VER_LINUX;`;
        static if(is(typeof({ mixin(enumMixinStr__STAT_VER); }))) {
            mixin(enumMixinStr__STAT_VER);
        }
    }




    static if(!is(typeof(_MKNOD_VER_LINUX))) {
        private enum enumMixinStr__MKNOD_VER_LINUX = `enum _MKNOD_VER_LINUX = 0;`;
        static if(is(typeof({ mixin(enumMixinStr__MKNOD_VER_LINUX); }))) {
            mixin(enumMixinStr__MKNOD_VER_LINUX);
        }
    }




    static if(!is(typeof(_STAT_VER_LINUX))) {
        private enum enumMixinStr__STAT_VER_LINUX = `enum _STAT_VER_LINUX = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__STAT_VER_LINUX); }))) {
            mixin(enumMixinStr__STAT_VER_LINUX);
        }
    }




    static if(!is(typeof(_STAT_VER_KERNEL))) {
        private enum enumMixinStr__STAT_VER_KERNEL = `enum _STAT_VER_KERNEL = 0;`;
        static if(is(typeof({ mixin(enumMixinStr__STAT_VER_KERNEL); }))) {
            mixin(enumMixinStr__STAT_VER_KERNEL);
        }
    }




    static if(!is(typeof(_BITS_STAT_H))) {
        private enum enumMixinStr__BITS_STAT_H = `enum _BITS_STAT_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_STAT_H); }))) {
            mixin(enumMixinStr__BITS_STAT_H);
        }
    }




    static if(!is(typeof(SS_DISABLE))) {
        private enum enumMixinStr_SS_DISABLE = `enum SS_DISABLE = SS_DISABLE;`;
        static if(is(typeof({ mixin(enumMixinStr_SS_DISABLE); }))) {
            mixin(enumMixinStr_SS_DISABLE);
        }
    }




    static if(!is(typeof(SS_ONSTACK))) {
        private enum enumMixinStr_SS_ONSTACK = `enum SS_ONSTACK = SS_ONSTACK;`;
        static if(is(typeof({ mixin(enumMixinStr_SS_ONSTACK); }))) {
            mixin(enumMixinStr_SS_ONSTACK);
        }
    }




    static if(!is(typeof(_BITS_SS_FLAGS_H))) {
        private enum enumMixinStr__BITS_SS_FLAGS_H = `enum _BITS_SS_FLAGS_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_SS_FLAGS_H); }))) {
            mixin(enumMixinStr__BITS_SS_FLAGS_H);
        }
    }




    static if(!is(typeof(SOCK_NONBLOCK))) {
        private enum enumMixinStr_SOCK_NONBLOCK = `enum SOCK_NONBLOCK = SOCK_NONBLOCK;`;
        static if(is(typeof({ mixin(enumMixinStr_SOCK_NONBLOCK); }))) {
            mixin(enumMixinStr_SOCK_NONBLOCK);
        }
    }




    static if(!is(typeof(SOCK_CLOEXEC))) {
        private enum enumMixinStr_SOCK_CLOEXEC = `enum SOCK_CLOEXEC = SOCK_CLOEXEC;`;
        static if(is(typeof({ mixin(enumMixinStr_SOCK_CLOEXEC); }))) {
            mixin(enumMixinStr_SOCK_CLOEXEC);
        }
    }




    static if(!is(typeof(SOCK_PACKET))) {
        private enum enumMixinStr_SOCK_PACKET = `enum SOCK_PACKET = SOCK_PACKET;`;
        static if(is(typeof({ mixin(enumMixinStr_SOCK_PACKET); }))) {
            mixin(enumMixinStr_SOCK_PACKET);
        }
    }




    static if(!is(typeof(SOCK_DCCP))) {
        private enum enumMixinStr_SOCK_DCCP = `enum SOCK_DCCP = SOCK_DCCP;`;
        static if(is(typeof({ mixin(enumMixinStr_SOCK_DCCP); }))) {
            mixin(enumMixinStr_SOCK_DCCP);
        }
    }




    static if(!is(typeof(SOCK_SEQPACKET))) {
        private enum enumMixinStr_SOCK_SEQPACKET = `enum SOCK_SEQPACKET = SOCK_SEQPACKET;`;
        static if(is(typeof({ mixin(enumMixinStr_SOCK_SEQPACKET); }))) {
            mixin(enumMixinStr_SOCK_SEQPACKET);
        }
    }




    static if(!is(typeof(SOCK_RDM))) {
        private enum enumMixinStr_SOCK_RDM = `enum SOCK_RDM = SOCK_RDM;`;
        static if(is(typeof({ mixin(enumMixinStr_SOCK_RDM); }))) {
            mixin(enumMixinStr_SOCK_RDM);
        }
    }




    static if(!is(typeof(SOCK_RAW))) {
        private enum enumMixinStr_SOCK_RAW = `enum SOCK_RAW = SOCK_RAW;`;
        static if(is(typeof({ mixin(enumMixinStr_SOCK_RAW); }))) {
            mixin(enumMixinStr_SOCK_RAW);
        }
    }




    static if(!is(typeof(SOCK_DGRAM))) {
        private enum enumMixinStr_SOCK_DGRAM = `enum SOCK_DGRAM = SOCK_DGRAM;`;
        static if(is(typeof({ mixin(enumMixinStr_SOCK_DGRAM); }))) {
            mixin(enumMixinStr_SOCK_DGRAM);
        }
    }




    static if(!is(typeof(SOCK_STREAM))) {
        private enum enumMixinStr_SOCK_STREAM = `enum SOCK_STREAM = SOCK_STREAM;`;
        static if(is(typeof({ mixin(enumMixinStr_SOCK_STREAM); }))) {
            mixin(enumMixinStr_SOCK_STREAM);
        }
    }




    static if(!is(typeof(SCM_RIGHTS))) {
        private enum enumMixinStr_SCM_RIGHTS = `enum SCM_RIGHTS = SCM_RIGHTS;`;
        static if(is(typeof({ mixin(enumMixinStr_SCM_RIGHTS); }))) {
            mixin(enumMixinStr_SCM_RIGHTS);
        }
    }
    static if(!is(typeof(MSG_CMSG_CLOEXEC))) {
        private enum enumMixinStr_MSG_CMSG_CLOEXEC = `enum MSG_CMSG_CLOEXEC = MSG_CMSG_CLOEXEC;`;
        static if(is(typeof({ mixin(enumMixinStr_MSG_CMSG_CLOEXEC); }))) {
            mixin(enumMixinStr_MSG_CMSG_CLOEXEC);
        }
    }




    static if(!is(typeof(MSG_FASTOPEN))) {
        private enum enumMixinStr_MSG_FASTOPEN = `enum MSG_FASTOPEN = MSG_FASTOPEN;`;
        static if(is(typeof({ mixin(enumMixinStr_MSG_FASTOPEN); }))) {
            mixin(enumMixinStr_MSG_FASTOPEN);
        }
    }




    static if(!is(typeof(MSG_ZEROCOPY))) {
        private enum enumMixinStr_MSG_ZEROCOPY = `enum MSG_ZEROCOPY = MSG_ZEROCOPY;`;
        static if(is(typeof({ mixin(enumMixinStr_MSG_ZEROCOPY); }))) {
            mixin(enumMixinStr_MSG_ZEROCOPY);
        }
    }




    static if(!is(typeof(MSG_BATCH))) {
        private enum enumMixinStr_MSG_BATCH = `enum MSG_BATCH = MSG_BATCH;`;
        static if(is(typeof({ mixin(enumMixinStr_MSG_BATCH); }))) {
            mixin(enumMixinStr_MSG_BATCH);
        }
    }




    static if(!is(typeof(MSG_WAITFORONE))) {
        private enum enumMixinStr_MSG_WAITFORONE = `enum MSG_WAITFORONE = MSG_WAITFORONE;`;
        static if(is(typeof({ mixin(enumMixinStr_MSG_WAITFORONE); }))) {
            mixin(enumMixinStr_MSG_WAITFORONE);
        }
    }




    static if(!is(typeof(MSG_MORE))) {
        private enum enumMixinStr_MSG_MORE = `enum MSG_MORE = MSG_MORE;`;
        static if(is(typeof({ mixin(enumMixinStr_MSG_MORE); }))) {
            mixin(enumMixinStr_MSG_MORE);
        }
    }




    static if(!is(typeof(MSG_NOSIGNAL))) {
        private enum enumMixinStr_MSG_NOSIGNAL = `enum MSG_NOSIGNAL = MSG_NOSIGNAL;`;
        static if(is(typeof({ mixin(enumMixinStr_MSG_NOSIGNAL); }))) {
            mixin(enumMixinStr_MSG_NOSIGNAL);
        }
    }




    static if(!is(typeof(MSG_ERRQUEUE))) {
        private enum enumMixinStr_MSG_ERRQUEUE = `enum MSG_ERRQUEUE = MSG_ERRQUEUE;`;
        static if(is(typeof({ mixin(enumMixinStr_MSG_ERRQUEUE); }))) {
            mixin(enumMixinStr_MSG_ERRQUEUE);
        }
    }




    static if(!is(typeof(MSG_RST))) {
        private enum enumMixinStr_MSG_RST = `enum MSG_RST = MSG_RST;`;
        static if(is(typeof({ mixin(enumMixinStr_MSG_RST); }))) {
            mixin(enumMixinStr_MSG_RST);
        }
    }




    static if(!is(typeof(MSG_CONFIRM))) {
        private enum enumMixinStr_MSG_CONFIRM = `enum MSG_CONFIRM = MSG_CONFIRM;`;
        static if(is(typeof({ mixin(enumMixinStr_MSG_CONFIRM); }))) {
            mixin(enumMixinStr_MSG_CONFIRM);
        }
    }




    static if(!is(typeof(MSG_SYN))) {
        private enum enumMixinStr_MSG_SYN = `enum MSG_SYN = MSG_SYN;`;
        static if(is(typeof({ mixin(enumMixinStr_MSG_SYN); }))) {
            mixin(enumMixinStr_MSG_SYN);
        }
    }




    static if(!is(typeof(MSG_FIN))) {
        private enum enumMixinStr_MSG_FIN = `enum MSG_FIN = MSG_FIN;`;
        static if(is(typeof({ mixin(enumMixinStr_MSG_FIN); }))) {
            mixin(enumMixinStr_MSG_FIN);
        }
    }




    static if(!is(typeof(MSG_WAITALL))) {
        private enum enumMixinStr_MSG_WAITALL = `enum MSG_WAITALL = MSG_WAITALL;`;
        static if(is(typeof({ mixin(enumMixinStr_MSG_WAITALL); }))) {
            mixin(enumMixinStr_MSG_WAITALL);
        }
    }




    static if(!is(typeof(MSG_EOR))) {
        private enum enumMixinStr_MSG_EOR = `enum MSG_EOR = MSG_EOR;`;
        static if(is(typeof({ mixin(enumMixinStr_MSG_EOR); }))) {
            mixin(enumMixinStr_MSG_EOR);
        }
    }




    static if(!is(typeof(MSG_DONTWAIT))) {
        private enum enumMixinStr_MSG_DONTWAIT = `enum MSG_DONTWAIT = MSG_DONTWAIT;`;
        static if(is(typeof({ mixin(enumMixinStr_MSG_DONTWAIT); }))) {
            mixin(enumMixinStr_MSG_DONTWAIT);
        }
    }




    static if(!is(typeof(MSG_TRUNC))) {
        private enum enumMixinStr_MSG_TRUNC = `enum MSG_TRUNC = MSG_TRUNC;`;
        static if(is(typeof({ mixin(enumMixinStr_MSG_TRUNC); }))) {
            mixin(enumMixinStr_MSG_TRUNC);
        }
    }




    static if(!is(typeof(MSG_PROXY))) {
        private enum enumMixinStr_MSG_PROXY = `enum MSG_PROXY = MSG_PROXY;`;
        static if(is(typeof({ mixin(enumMixinStr_MSG_PROXY); }))) {
            mixin(enumMixinStr_MSG_PROXY);
        }
    }




    static if(!is(typeof(MSG_CTRUNC))) {
        private enum enumMixinStr_MSG_CTRUNC = `enum MSG_CTRUNC = MSG_CTRUNC;`;
        static if(is(typeof({ mixin(enumMixinStr_MSG_CTRUNC); }))) {
            mixin(enumMixinStr_MSG_CTRUNC);
        }
    }




    static if(!is(typeof(MSG_DONTROUTE))) {
        private enum enumMixinStr_MSG_DONTROUTE = `enum MSG_DONTROUTE = MSG_DONTROUTE;`;
        static if(is(typeof({ mixin(enumMixinStr_MSG_DONTROUTE); }))) {
            mixin(enumMixinStr_MSG_DONTROUTE);
        }
    }




    static if(!is(typeof(MSG_PEEK))) {
        private enum enumMixinStr_MSG_PEEK = `enum MSG_PEEK = MSG_PEEK;`;
        static if(is(typeof({ mixin(enumMixinStr_MSG_PEEK); }))) {
            mixin(enumMixinStr_MSG_PEEK);
        }
    }




    static if(!is(typeof(MSG_OOB))) {
        private enum enumMixinStr_MSG_OOB = `enum MSG_OOB = MSG_OOB;`;
        static if(is(typeof({ mixin(enumMixinStr_MSG_OOB); }))) {
            mixin(enumMixinStr_MSG_OOB);
        }
    }






    static if(!is(typeof(_SS_PADSIZE))) {
        private enum enumMixinStr__SS_PADSIZE = `enum _SS_PADSIZE = ( _SS_SIZE - __SOCKADDR_COMMON_SIZE - ( __ss_aligntype ) .sizeof );`;
        static if(is(typeof({ mixin(enumMixinStr__SS_PADSIZE); }))) {
            mixin(enumMixinStr__SS_PADSIZE);
        }
    }




    static if(!is(typeof(ZYRE_VERSION_MAJOR))) {
        private enum enumMixinStr_ZYRE_VERSION_MAJOR = `enum ZYRE_VERSION_MAJOR = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_ZYRE_VERSION_MAJOR); }))) {
            mixin(enumMixinStr_ZYRE_VERSION_MAJOR);
        }
    }




    static if(!is(typeof(ZYRE_VERSION_MINOR))) {
        private enum enumMixinStr_ZYRE_VERSION_MINOR = `enum ZYRE_VERSION_MINOR = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_ZYRE_VERSION_MINOR); }))) {
            mixin(enumMixinStr_ZYRE_VERSION_MINOR);
        }
    }




    static if(!is(typeof(ZYRE_VERSION_PATCH))) {
        private enum enumMixinStr_ZYRE_VERSION_PATCH = `enum ZYRE_VERSION_PATCH = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_ZYRE_VERSION_PATCH); }))) {
            mixin(enumMixinStr_ZYRE_VERSION_PATCH);
        }
    }






    static if(!is(typeof(ZYRE_VERSION))) {
        private enum enumMixinStr_ZYRE_VERSION = `enum ZYRE_VERSION = ( ( 2 ) * 10000 + ( 0 ) * 100 + ( 1 ) );`;
        static if(is(typeof({ mixin(enumMixinStr_ZYRE_VERSION); }))) {
            mixin(enumMixinStr_ZYRE_VERSION);
        }
    }




    static if(!is(typeof(__ss_aligntype))) {
        private enum enumMixinStr___ss_aligntype = `enum __ss_aligntype = unsigned long int;`;
        static if(is(typeof({ mixin(enumMixinStr___ss_aligntype); }))) {
            mixin(enumMixinStr___ss_aligntype);
        }
    }




    static if(!is(typeof(SOMAXCONN))) {
        private enum enumMixinStr_SOMAXCONN = `enum SOMAXCONN = 4096;`;
        static if(is(typeof({ mixin(enumMixinStr_SOMAXCONN); }))) {
            mixin(enumMixinStr_SOMAXCONN);
        }
    }




    static if(!is(typeof(ZYRE_PRIVATE))) {
        private enum enumMixinStr_ZYRE_PRIVATE = `enum ZYRE_PRIVATE = __attribute__ ( ( visibility ( "hidden" ) ) );`;
        static if(is(typeof({ mixin(enumMixinStr_ZYRE_PRIVATE); }))) {
            mixin(enumMixinStr_ZYRE_PRIVATE);
        }
    }




    static if(!is(typeof(ZYRE_EXPORT))) {
        private enum enumMixinStr_ZYRE_EXPORT = `enum ZYRE_EXPORT = __attribute__ ( ( visibility ( "default" ) ) );`;
        static if(is(typeof({ mixin(enumMixinStr_ZYRE_EXPORT); }))) {
            mixin(enumMixinStr_ZYRE_EXPORT);
        }
    }




    static if(!is(typeof(SOL_XDP))) {
        private enum enumMixinStr_SOL_XDP = `enum SOL_XDP = 283;`;
        static if(is(typeof({ mixin(enumMixinStr_SOL_XDP); }))) {
            mixin(enumMixinStr_SOL_XDP);
        }
    }




    static if(!is(typeof(SOL_TLS))) {
        private enum enumMixinStr_SOL_TLS = `enum SOL_TLS = 282;`;
        static if(is(typeof({ mixin(enumMixinStr_SOL_TLS); }))) {
            mixin(enumMixinStr_SOL_TLS);
        }
    }






    static if(!is(typeof(SOL_KCM))) {
        private enum enumMixinStr_SOL_KCM = `enum SOL_KCM = 281;`;
        static if(is(typeof({ mixin(enumMixinStr_SOL_KCM); }))) {
            mixin(enumMixinStr_SOL_KCM);
        }
    }




    static if(!is(typeof(SOL_NFC))) {
        private enum enumMixinStr_SOL_NFC = `enum SOL_NFC = 280;`;
        static if(is(typeof({ mixin(enumMixinStr_SOL_NFC); }))) {
            mixin(enumMixinStr_SOL_NFC);
        }
    }






    static if(!is(typeof(ZRE_DISCOVERY_PORT))) {
        private enum enumMixinStr_ZRE_DISCOVERY_PORT = `enum ZRE_DISCOVERY_PORT = 5670;`;
        static if(is(typeof({ mixin(enumMixinStr_ZRE_DISCOVERY_PORT); }))) {
            mixin(enumMixinStr_ZRE_DISCOVERY_PORT);
        }
    }




    static if(!is(typeof(SOL_ALG))) {
        private enum enumMixinStr_SOL_ALG = `enum SOL_ALG = 279;`;
        static if(is(typeof({ mixin(enumMixinStr_SOL_ALG); }))) {
            mixin(enumMixinStr_SOL_ALG);
        }
    }






    static if(!is(typeof(SOL_CAIF))) {
        private enum enumMixinStr_SOL_CAIF = `enum SOL_CAIF = 278;`;
        static if(is(typeof({ mixin(enumMixinStr_SOL_CAIF); }))) {
            mixin(enumMixinStr_SOL_CAIF);
        }
    }




    static if(!is(typeof(SOL_IUCV))) {
        private enum enumMixinStr_SOL_IUCV = `enum SOL_IUCV = 277;`;
        static if(is(typeof({ mixin(enumMixinStr_SOL_IUCV); }))) {
            mixin(enumMixinStr_SOL_IUCV);
        }
    }






    static if(!is(typeof(SOL_RDS))) {
        private enum enumMixinStr_SOL_RDS = `enum SOL_RDS = 276;`;
        static if(is(typeof({ mixin(enumMixinStr_SOL_RDS); }))) {
            mixin(enumMixinStr_SOL_RDS);
        }
    }




    static if(!is(typeof(SOL_PNPIPE))) {
        private enum enumMixinStr_SOL_PNPIPE = `enum SOL_PNPIPE = 275;`;
        static if(is(typeof({ mixin(enumMixinStr_SOL_PNPIPE); }))) {
            mixin(enumMixinStr_SOL_PNPIPE);
        }
    }




    static if(!is(typeof(FLT_EVAL_METHOD))) {
        private enum enumMixinStr_FLT_EVAL_METHOD = `enum FLT_EVAL_METHOD = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_FLT_EVAL_METHOD); }))) {
            mixin(enumMixinStr_FLT_EVAL_METHOD);
        }
    }




    static if(!is(typeof(FLT_ROUNDS))) {
        private enum enumMixinStr_FLT_ROUNDS = `enum FLT_ROUNDS = ( __builtin_flt_rounds ( ) );`;
        static if(is(typeof({ mixin(enumMixinStr_FLT_ROUNDS); }))) {
            mixin(enumMixinStr_FLT_ROUNDS);
        }
    }




    static if(!is(typeof(FLT_RADIX))) {
        private enum enumMixinStr_FLT_RADIX = `enum FLT_RADIX = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_FLT_RADIX); }))) {
            mixin(enumMixinStr_FLT_RADIX);
        }
    }




    static if(!is(typeof(FLT_MANT_DIG))) {
        private enum enumMixinStr_FLT_MANT_DIG = `enum FLT_MANT_DIG = 24;`;
        static if(is(typeof({ mixin(enumMixinStr_FLT_MANT_DIG); }))) {
            mixin(enumMixinStr_FLT_MANT_DIG);
        }
    }




    static if(!is(typeof(DBL_MANT_DIG))) {
        private enum enumMixinStr_DBL_MANT_DIG = `enum DBL_MANT_DIG = 53;`;
        static if(is(typeof({ mixin(enumMixinStr_DBL_MANT_DIG); }))) {
            mixin(enumMixinStr_DBL_MANT_DIG);
        }
    }




    static if(!is(typeof(LDBL_MANT_DIG))) {
        private enum enumMixinStr_LDBL_MANT_DIG = `enum LDBL_MANT_DIG = 64;`;
        static if(is(typeof({ mixin(enumMixinStr_LDBL_MANT_DIG); }))) {
            mixin(enumMixinStr_LDBL_MANT_DIG);
        }
    }




    static if(!is(typeof(SOL_BLUETOOTH))) {
        private enum enumMixinStr_SOL_BLUETOOTH = `enum SOL_BLUETOOTH = 274;`;
        static if(is(typeof({ mixin(enumMixinStr_SOL_BLUETOOTH); }))) {
            mixin(enumMixinStr_SOL_BLUETOOTH);
        }
    }




    static if(!is(typeof(DECIMAL_DIG))) {
        private enum enumMixinStr_DECIMAL_DIG = `enum DECIMAL_DIG = 21;`;
        static if(is(typeof({ mixin(enumMixinStr_DECIMAL_DIG); }))) {
            mixin(enumMixinStr_DECIMAL_DIG);
        }
    }




    static if(!is(typeof(FLT_DIG))) {
        private enum enumMixinStr_FLT_DIG = `enum FLT_DIG = 6;`;
        static if(is(typeof({ mixin(enumMixinStr_FLT_DIG); }))) {
            mixin(enumMixinStr_FLT_DIG);
        }
    }




    static if(!is(typeof(DBL_DIG))) {
        private enum enumMixinStr_DBL_DIG = `enum DBL_DIG = 15;`;
        static if(is(typeof({ mixin(enumMixinStr_DBL_DIG); }))) {
            mixin(enumMixinStr_DBL_DIG);
        }
    }




    static if(!is(typeof(LDBL_DIG))) {
        private enum enumMixinStr_LDBL_DIG = `enum LDBL_DIG = 18;`;
        static if(is(typeof({ mixin(enumMixinStr_LDBL_DIG); }))) {
            mixin(enumMixinStr_LDBL_DIG);
        }
    }




    static if(!is(typeof(FLT_MIN_EXP))) {
        private enum enumMixinStr_FLT_MIN_EXP = `enum FLT_MIN_EXP = (-125);`;
        static if(is(typeof({ mixin(enumMixinStr_FLT_MIN_EXP); }))) {
            mixin(enumMixinStr_FLT_MIN_EXP);
        }
    }




    static if(!is(typeof(DBL_MIN_EXP))) {
        private enum enumMixinStr_DBL_MIN_EXP = `enum DBL_MIN_EXP = (-1021);`;
        static if(is(typeof({ mixin(enumMixinStr_DBL_MIN_EXP); }))) {
            mixin(enumMixinStr_DBL_MIN_EXP);
        }
    }




    static if(!is(typeof(LDBL_MIN_EXP))) {
        private enum enumMixinStr_LDBL_MIN_EXP = `enum LDBL_MIN_EXP = (-16381);`;
        static if(is(typeof({ mixin(enumMixinStr_LDBL_MIN_EXP); }))) {
            mixin(enumMixinStr_LDBL_MIN_EXP);
        }
    }




    static if(!is(typeof(FLT_MIN_10_EXP))) {
        private enum enumMixinStr_FLT_MIN_10_EXP = `enum FLT_MIN_10_EXP = (-37);`;
        static if(is(typeof({ mixin(enumMixinStr_FLT_MIN_10_EXP); }))) {
            mixin(enumMixinStr_FLT_MIN_10_EXP);
        }
    }




    static if(!is(typeof(DBL_MIN_10_EXP))) {
        private enum enumMixinStr_DBL_MIN_10_EXP = `enum DBL_MIN_10_EXP = (-307);`;
        static if(is(typeof({ mixin(enumMixinStr_DBL_MIN_10_EXP); }))) {
            mixin(enumMixinStr_DBL_MIN_10_EXP);
        }
    }




    static if(!is(typeof(LDBL_MIN_10_EXP))) {
        private enum enumMixinStr_LDBL_MIN_10_EXP = `enum LDBL_MIN_10_EXP = (-4931);`;
        static if(is(typeof({ mixin(enumMixinStr_LDBL_MIN_10_EXP); }))) {
            mixin(enumMixinStr_LDBL_MIN_10_EXP);
        }
    }




    static if(!is(typeof(FLT_MAX_EXP))) {
        private enum enumMixinStr_FLT_MAX_EXP = `enum FLT_MAX_EXP = 128;`;
        static if(is(typeof({ mixin(enumMixinStr_FLT_MAX_EXP); }))) {
            mixin(enumMixinStr_FLT_MAX_EXP);
        }
    }




    static if(!is(typeof(DBL_MAX_EXP))) {
        private enum enumMixinStr_DBL_MAX_EXP = `enum DBL_MAX_EXP = 1024;`;
        static if(is(typeof({ mixin(enumMixinStr_DBL_MAX_EXP); }))) {
            mixin(enumMixinStr_DBL_MAX_EXP);
        }
    }




    static if(!is(typeof(LDBL_MAX_EXP))) {
        private enum enumMixinStr_LDBL_MAX_EXP = `enum LDBL_MAX_EXP = 16384;`;
        static if(is(typeof({ mixin(enumMixinStr_LDBL_MAX_EXP); }))) {
            mixin(enumMixinStr_LDBL_MAX_EXP);
        }
    }




    static if(!is(typeof(FLT_MAX_10_EXP))) {
        private enum enumMixinStr_FLT_MAX_10_EXP = `enum FLT_MAX_10_EXP = 38;`;
        static if(is(typeof({ mixin(enumMixinStr_FLT_MAX_10_EXP); }))) {
            mixin(enumMixinStr_FLT_MAX_10_EXP);
        }
    }




    static if(!is(typeof(DBL_MAX_10_EXP))) {
        private enum enumMixinStr_DBL_MAX_10_EXP = `enum DBL_MAX_10_EXP = 308;`;
        static if(is(typeof({ mixin(enumMixinStr_DBL_MAX_10_EXP); }))) {
            mixin(enumMixinStr_DBL_MAX_10_EXP);
        }
    }




    static if(!is(typeof(LDBL_MAX_10_EXP))) {
        private enum enumMixinStr_LDBL_MAX_10_EXP = `enum LDBL_MAX_10_EXP = 4932;`;
        static if(is(typeof({ mixin(enumMixinStr_LDBL_MAX_10_EXP); }))) {
            mixin(enumMixinStr_LDBL_MAX_10_EXP);
        }
    }




    static if(!is(typeof(FLT_MAX))) {
        private enum enumMixinStr_FLT_MAX = `enum FLT_MAX = 3.40282346638528859811704183484516925e+38F;`;
        static if(is(typeof({ mixin(enumMixinStr_FLT_MAX); }))) {
            mixin(enumMixinStr_FLT_MAX);
        }
    }




    static if(!is(typeof(DBL_MAX))) {
        private enum enumMixinStr_DBL_MAX = `enum DBL_MAX = ((double)1.79769313486231570814527423731704357e+308L);`;
        static if(is(typeof({ mixin(enumMixinStr_DBL_MAX); }))) {
            mixin(enumMixinStr_DBL_MAX);
        }
    }




    static if(!is(typeof(LDBL_MAX))) {
        private enum enumMixinStr_LDBL_MAX = `enum LDBL_MAX = 1.18973149535723176502126385303097021e+4932L;`;
        static if(is(typeof({ mixin(enumMixinStr_LDBL_MAX); }))) {
            mixin(enumMixinStr_LDBL_MAX);
        }
    }




    static if(!is(typeof(FLT_EPSILON))) {
        private enum enumMixinStr_FLT_EPSILON = `enum FLT_EPSILON = 1.19209289550781250000000000000000000e-7F;`;
        static if(is(typeof({ mixin(enumMixinStr_FLT_EPSILON); }))) {
            mixin(enumMixinStr_FLT_EPSILON);
        }
    }




    static if(!is(typeof(DBL_EPSILON))) {
        private enum enumMixinStr_DBL_EPSILON = `enum DBL_EPSILON = ((double)2.22044604925031308084726333618164062e-16L);`;
        static if(is(typeof({ mixin(enumMixinStr_DBL_EPSILON); }))) {
            mixin(enumMixinStr_DBL_EPSILON);
        }
    }




    static if(!is(typeof(LDBL_EPSILON))) {
        private enum enumMixinStr_LDBL_EPSILON = `enum LDBL_EPSILON = 1.08420217248550443400745280086994171e-19L;`;
        static if(is(typeof({ mixin(enumMixinStr_LDBL_EPSILON); }))) {
            mixin(enumMixinStr_LDBL_EPSILON);
        }
    }




    static if(!is(typeof(FLT_MIN))) {
        private enum enumMixinStr_FLT_MIN = `enum FLT_MIN = 1.17549435082228750796873653722224568e-38F;`;
        static if(is(typeof({ mixin(enumMixinStr_FLT_MIN); }))) {
            mixin(enumMixinStr_FLT_MIN);
        }
    }




    static if(!is(typeof(DBL_MIN))) {
        private enum enumMixinStr_DBL_MIN = `enum DBL_MIN = ((double)2.22507385850720138309023271733240406e-308L);`;
        static if(is(typeof({ mixin(enumMixinStr_DBL_MIN); }))) {
            mixin(enumMixinStr_DBL_MIN);
        }
    }




    static if(!is(typeof(LDBL_MIN))) {
        private enum enumMixinStr_LDBL_MIN = `enum LDBL_MIN = 3.36210314311209350626267781732175260e-4932L;`;
        static if(is(typeof({ mixin(enumMixinStr_LDBL_MIN); }))) {
            mixin(enumMixinStr_LDBL_MIN);
        }
    }




    static if(!is(typeof(SOL_PPPOL2TP))) {
        private enum enumMixinStr_SOL_PPPOL2TP = `enum SOL_PPPOL2TP = 273;`;
        static if(is(typeof({ mixin(enumMixinStr_SOL_PPPOL2TP); }))) {
            mixin(enumMixinStr_SOL_PPPOL2TP);
        }
    }




    static if(!is(typeof(FLT_TRUE_MIN))) {
        private enum enumMixinStr_FLT_TRUE_MIN = `enum FLT_TRUE_MIN = 1.40129846432481707092372958328991613e-45F;`;
        static if(is(typeof({ mixin(enumMixinStr_FLT_TRUE_MIN); }))) {
            mixin(enumMixinStr_FLT_TRUE_MIN);
        }
    }




    static if(!is(typeof(DBL_TRUE_MIN))) {
        private enum enumMixinStr_DBL_TRUE_MIN = `enum DBL_TRUE_MIN = ((double)4.94065645841246544176568792868221372e-324L);`;
        static if(is(typeof({ mixin(enumMixinStr_DBL_TRUE_MIN); }))) {
            mixin(enumMixinStr_DBL_TRUE_MIN);
        }
    }




    static if(!is(typeof(LDBL_TRUE_MIN))) {
        private enum enumMixinStr_LDBL_TRUE_MIN = `enum LDBL_TRUE_MIN = 3.64519953188247460252840593361941982e-4951L;`;
        static if(is(typeof({ mixin(enumMixinStr_LDBL_TRUE_MIN); }))) {
            mixin(enumMixinStr_LDBL_TRUE_MIN);
        }
    }




    static if(!is(typeof(FLT_DECIMAL_DIG))) {
        private enum enumMixinStr_FLT_DECIMAL_DIG = `enum FLT_DECIMAL_DIG = 9;`;
        static if(is(typeof({ mixin(enumMixinStr_FLT_DECIMAL_DIG); }))) {
            mixin(enumMixinStr_FLT_DECIMAL_DIG);
        }
    }




    static if(!is(typeof(DBL_DECIMAL_DIG))) {
        private enum enumMixinStr_DBL_DECIMAL_DIG = `enum DBL_DECIMAL_DIG = 17;`;
        static if(is(typeof({ mixin(enumMixinStr_DBL_DECIMAL_DIG); }))) {
            mixin(enumMixinStr_DBL_DECIMAL_DIG);
        }
    }




    static if(!is(typeof(LDBL_DECIMAL_DIG))) {
        private enum enumMixinStr_LDBL_DECIMAL_DIG = `enum LDBL_DECIMAL_DIG = 21;`;
        static if(is(typeof({ mixin(enumMixinStr_LDBL_DECIMAL_DIG); }))) {
            mixin(enumMixinStr_LDBL_DECIMAL_DIG);
        }
    }




    static if(!is(typeof(FLT_HAS_SUBNORM))) {
        private enum enumMixinStr_FLT_HAS_SUBNORM = `enum FLT_HAS_SUBNORM = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_FLT_HAS_SUBNORM); }))) {
            mixin(enumMixinStr_FLT_HAS_SUBNORM);
        }
    }




    static if(!is(typeof(DBL_HAS_SUBNORM))) {
        private enum enumMixinStr_DBL_HAS_SUBNORM = `enum DBL_HAS_SUBNORM = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_DBL_HAS_SUBNORM); }))) {
            mixin(enumMixinStr_DBL_HAS_SUBNORM);
        }
    }




    static if(!is(typeof(LDBL_HAS_SUBNORM))) {
        private enum enumMixinStr_LDBL_HAS_SUBNORM = `enum LDBL_HAS_SUBNORM = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_LDBL_HAS_SUBNORM); }))) {
            mixin(enumMixinStr_LDBL_HAS_SUBNORM);
        }
    }






    static if(!is(typeof(SOL_RXRPC))) {
        private enum enumMixinStr_SOL_RXRPC = `enum SOL_RXRPC = 272;`;
        static if(is(typeof({ mixin(enumMixinStr_SOL_RXRPC); }))) {
            mixin(enumMixinStr_SOL_RXRPC);
        }
    }






    static if(!is(typeof(SOL_TIPC))) {
        private enum enumMixinStr_SOL_TIPC = `enum SOL_TIPC = 271;`;
        static if(is(typeof({ mixin(enumMixinStr_SOL_TIPC); }))) {
            mixin(enumMixinStr_SOL_TIPC);
        }
    }






    static if(!is(typeof(SOL_NETLINK))) {
        private enum enumMixinStr_SOL_NETLINK = `enum SOL_NETLINK = 270;`;
        static if(is(typeof({ mixin(enumMixinStr_SOL_NETLINK); }))) {
            mixin(enumMixinStr_SOL_NETLINK);
        }
    }




    static if(!is(typeof(SOL_DCCP))) {
        private enum enumMixinStr_SOL_DCCP = `enum SOL_DCCP = 269;`;
        static if(is(typeof({ mixin(enumMixinStr_SOL_DCCP); }))) {
            mixin(enumMixinStr_SOL_DCCP);
        }
    }




    static if(!is(typeof(SOL_LLC))) {
        private enum enumMixinStr_SOL_LLC = `enum SOL_LLC = 268;`;
        static if(is(typeof({ mixin(enumMixinStr_SOL_LLC); }))) {
            mixin(enumMixinStr_SOL_LLC);
        }
    }




    static if(!is(typeof(SCHAR_MAX))) {
        private enum enumMixinStr_SCHAR_MAX = `enum SCHAR_MAX = 0x7f;`;
        static if(is(typeof({ mixin(enumMixinStr_SCHAR_MAX); }))) {
            mixin(enumMixinStr_SCHAR_MAX);
        }
    }




    static if(!is(typeof(SHRT_MAX))) {
        private enum enumMixinStr_SHRT_MAX = `enum SHRT_MAX = 0x7fff;`;
        static if(is(typeof({ mixin(enumMixinStr_SHRT_MAX); }))) {
            mixin(enumMixinStr_SHRT_MAX);
        }
    }




    static if(!is(typeof(INT_MAX))) {
        private enum enumMixinStr_INT_MAX = `enum INT_MAX = 0x7fffffff;`;
        static if(is(typeof({ mixin(enumMixinStr_INT_MAX); }))) {
            mixin(enumMixinStr_INT_MAX);
        }
    }




    static if(!is(typeof(LONG_MAX))) {
        private enum enumMixinStr_LONG_MAX = `enum LONG_MAX = 0x7fffffffffffffffL;`;
        static if(is(typeof({ mixin(enumMixinStr_LONG_MAX); }))) {
            mixin(enumMixinStr_LONG_MAX);
        }
    }




    static if(!is(typeof(SCHAR_MIN))) {
        private enum enumMixinStr_SCHAR_MIN = `enum SCHAR_MIN = ( - 0x7f - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_SCHAR_MIN); }))) {
            mixin(enumMixinStr_SCHAR_MIN);
        }
    }




    static if(!is(typeof(SHRT_MIN))) {
        private enum enumMixinStr_SHRT_MIN = `enum SHRT_MIN = ( - 0x7fff - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_SHRT_MIN); }))) {
            mixin(enumMixinStr_SHRT_MIN);
        }
    }




    static if(!is(typeof(INT_MIN))) {
        private enum enumMixinStr_INT_MIN = `enum INT_MIN = ( - 0x7fffffff - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_INT_MIN); }))) {
            mixin(enumMixinStr_INT_MIN);
        }
    }




    static if(!is(typeof(LONG_MIN))) {
        private enum enumMixinStr_LONG_MIN = `enum LONG_MIN = ( - 0x7fffffffffffffffL - 1L );`;
        static if(is(typeof({ mixin(enumMixinStr_LONG_MIN); }))) {
            mixin(enumMixinStr_LONG_MIN);
        }
    }




    static if(!is(typeof(UCHAR_MAX))) {
        private enum enumMixinStr_UCHAR_MAX = `enum UCHAR_MAX = ( 0x7f * 2 + 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_UCHAR_MAX); }))) {
            mixin(enumMixinStr_UCHAR_MAX);
        }
    }




    static if(!is(typeof(USHRT_MAX))) {
        private enum enumMixinStr_USHRT_MAX = `enum USHRT_MAX = ( 0x7fff * 2 + 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_USHRT_MAX); }))) {
            mixin(enumMixinStr_USHRT_MAX);
        }
    }




    static if(!is(typeof(UINT_MAX))) {
        private enum enumMixinStr_UINT_MAX = `enum UINT_MAX = ( 0x7fffffff * 2U + 1U );`;
        static if(is(typeof({ mixin(enumMixinStr_UINT_MAX); }))) {
            mixin(enumMixinStr_UINT_MAX);
        }
    }




    static if(!is(typeof(ULONG_MAX))) {
        private enum enumMixinStr_ULONG_MAX = `enum ULONG_MAX = ( 0x7fffffffffffffffL * 2UL + 1UL );`;
        static if(is(typeof({ mixin(enumMixinStr_ULONG_MAX); }))) {
            mixin(enumMixinStr_ULONG_MAX);
        }
    }




    static if(!is(typeof(SOL_NETBEUI))) {
        private enum enumMixinStr_SOL_NETBEUI = `enum SOL_NETBEUI = 267;`;
        static if(is(typeof({ mixin(enumMixinStr_SOL_NETBEUI); }))) {
            mixin(enumMixinStr_SOL_NETBEUI);
        }
    }




    static if(!is(typeof(CHAR_BIT))) {
        private enum enumMixinStr_CHAR_BIT = `enum CHAR_BIT = 8;`;
        static if(is(typeof({ mixin(enumMixinStr_CHAR_BIT); }))) {
            mixin(enumMixinStr_CHAR_BIT);
        }
    }




    static if(!is(typeof(CHAR_MIN))) {
        private enum enumMixinStr_CHAR_MIN = `enum CHAR_MIN = ( - 0x7f - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_CHAR_MIN); }))) {
            mixin(enumMixinStr_CHAR_MIN);
        }
    }




    static if(!is(typeof(CHAR_MAX))) {
        private enum enumMixinStr_CHAR_MAX = `enum CHAR_MAX = 0x7f;`;
        static if(is(typeof({ mixin(enumMixinStr_CHAR_MAX); }))) {
            mixin(enumMixinStr_CHAR_MAX);
        }
    }




    static if(!is(typeof(SOL_IRDA))) {
        private enum enumMixinStr_SOL_IRDA = `enum SOL_IRDA = 266;`;
        static if(is(typeof({ mixin(enumMixinStr_SOL_IRDA); }))) {
            mixin(enumMixinStr_SOL_IRDA);
        }
    }




    static if(!is(typeof(SOL_AAL))) {
        private enum enumMixinStr_SOL_AAL = `enum SOL_AAL = 265;`;
        static if(is(typeof({ mixin(enumMixinStr_SOL_AAL); }))) {
            mixin(enumMixinStr_SOL_AAL);
        }
    }






    static if(!is(typeof(SOL_ATM))) {
        private enum enumMixinStr_SOL_ATM = `enum SOL_ATM = 264;`;
        static if(is(typeof({ mixin(enumMixinStr_SOL_ATM); }))) {
            mixin(enumMixinStr_SOL_ATM);
        }
    }
    static if(!is(typeof(SOL_PACKET))) {
        private enum enumMixinStr_SOL_PACKET = `enum SOL_PACKET = 263;`;
        static if(is(typeof({ mixin(enumMixinStr_SOL_PACKET); }))) {
            mixin(enumMixinStr_SOL_PACKET);
        }
    }






    static if(!is(typeof(__GNUC_VA_LIST))) {
        private enum enumMixinStr___GNUC_VA_LIST = `enum __GNUC_VA_LIST = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___GNUC_VA_LIST); }))) {
            mixin(enumMixinStr___GNUC_VA_LIST);
        }
    }




    static if(!is(typeof(SOL_X25))) {
        private enum enumMixinStr_SOL_X25 = `enum SOL_X25 = 262;`;
        static if(is(typeof({ mixin(enumMixinStr_SOL_X25); }))) {
            mixin(enumMixinStr_SOL_X25);
        }
    }






    static if(!is(typeof(bool_))) {
        private enum enumMixinStr_bool_ = `enum bool_ = _Bool;`;
        static if(is(typeof({ mixin(enumMixinStr_bool_); }))) {
            mixin(enumMixinStr_bool_);
        }
    }




    static if(!is(typeof(true_))) {
        private enum enumMixinStr_true_ = `enum true_ = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_true_); }))) {
            mixin(enumMixinStr_true_);
        }
    }




    static if(!is(typeof(false_))) {
        private enum enumMixinStr_false_ = `enum false_ = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_false_); }))) {
            mixin(enumMixinStr_false_);
        }
    }




    static if(!is(typeof(__bool_true_false_are_defined))) {
        private enum enumMixinStr___bool_true_false_are_defined = `enum __bool_true_false_are_defined = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___bool_true_false_are_defined); }))) {
            mixin(enumMixinStr___bool_true_false_are_defined);
        }
    }




    static if(!is(typeof(SOL_DECNET))) {
        private enum enumMixinStr_SOL_DECNET = `enum SOL_DECNET = 261;`;
        static if(is(typeof({ mixin(enumMixinStr_SOL_DECNET); }))) {
            mixin(enumMixinStr_SOL_DECNET);
        }
    }




    static if(!is(typeof(SOL_RAW))) {
        private enum enumMixinStr_SOL_RAW = `enum SOL_RAW = 255;`;
        static if(is(typeof({ mixin(enumMixinStr_SOL_RAW); }))) {
            mixin(enumMixinStr_SOL_RAW);
        }
    }




    static if(!is(typeof(AF_MAX))) {
        private enum enumMixinStr_AF_MAX = `enum AF_MAX = PF_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_MAX); }))) {
            mixin(enumMixinStr_AF_MAX);
        }
    }




    static if(!is(typeof(AF_XDP))) {
        private enum enumMixinStr_AF_XDP = `enum AF_XDP = PF_XDP;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_XDP); }))) {
            mixin(enumMixinStr_AF_XDP);
        }
    }




    static if(!is(typeof(AF_SMC))) {
        private enum enumMixinStr_AF_SMC = `enum AF_SMC = PF_SMC;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_SMC); }))) {
            mixin(enumMixinStr_AF_SMC);
        }
    }




    static if(!is(typeof(AF_QIPCRTR))) {
        private enum enumMixinStr_AF_QIPCRTR = `enum AF_QIPCRTR = PF_QIPCRTR;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_QIPCRTR); }))) {
            mixin(enumMixinStr_AF_QIPCRTR);
        }
    }




    static if(!is(typeof(AF_KCM))) {
        private enum enumMixinStr_AF_KCM = `enum AF_KCM = PF_KCM;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_KCM); }))) {
            mixin(enumMixinStr_AF_KCM);
        }
    }




    static if(!is(typeof(AF_VSOCK))) {
        private enum enumMixinStr_AF_VSOCK = `enum AF_VSOCK = PF_VSOCK;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_VSOCK); }))) {
            mixin(enumMixinStr_AF_VSOCK);
        }
    }




    static if(!is(typeof(AF_NFC))) {
        private enum enumMixinStr_AF_NFC = `enum AF_NFC = PF_NFC;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_NFC); }))) {
            mixin(enumMixinStr_AF_NFC);
        }
    }




    static if(!is(typeof(AF_ALG))) {
        private enum enumMixinStr_AF_ALG = `enum AF_ALG = PF_ALG;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_ALG); }))) {
            mixin(enumMixinStr_AF_ALG);
        }
    }




    static if(!is(typeof(AF_CAIF))) {
        private enum enumMixinStr_AF_CAIF = `enum AF_CAIF = PF_CAIF;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_CAIF); }))) {
            mixin(enumMixinStr_AF_CAIF);
        }
    }




    static if(!is(typeof(AF_IEEE802154))) {
        private enum enumMixinStr_AF_IEEE802154 = `enum AF_IEEE802154 = PF_IEEE802154;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_IEEE802154); }))) {
            mixin(enumMixinStr_AF_IEEE802154);
        }
    }




    static if(!is(typeof(AF_PHONET))) {
        private enum enumMixinStr_AF_PHONET = `enum AF_PHONET = PF_PHONET;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_PHONET); }))) {
            mixin(enumMixinStr_AF_PHONET);
        }
    }




    static if(!is(typeof(AF_ISDN))) {
        private enum enumMixinStr_AF_ISDN = `enum AF_ISDN = PF_ISDN;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_ISDN); }))) {
            mixin(enumMixinStr_AF_ISDN);
        }
    }




    static if(!is(typeof(AF_RXRPC))) {
        private enum enumMixinStr_AF_RXRPC = `enum AF_RXRPC = PF_RXRPC;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_RXRPC); }))) {
            mixin(enumMixinStr_AF_RXRPC);
        }
    }




    static if(!is(typeof(AF_IUCV))) {
        private enum enumMixinStr_AF_IUCV = `enum AF_IUCV = PF_IUCV;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_IUCV); }))) {
            mixin(enumMixinStr_AF_IUCV);
        }
    }




    static if(!is(typeof(AF_BLUETOOTH))) {
        private enum enumMixinStr_AF_BLUETOOTH = `enum AF_BLUETOOTH = PF_BLUETOOTH;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_BLUETOOTH); }))) {
            mixin(enumMixinStr_AF_BLUETOOTH);
        }
    }




    static if(!is(typeof(AF_TIPC))) {
        private enum enumMixinStr_AF_TIPC = `enum AF_TIPC = PF_TIPC;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_TIPC); }))) {
            mixin(enumMixinStr_AF_TIPC);
        }
    }




    static if(!is(typeof(AF_CAN))) {
        private enum enumMixinStr_AF_CAN = `enum AF_CAN = PF_CAN;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_CAN); }))) {
            mixin(enumMixinStr_AF_CAN);
        }
    }




    static if(!is(typeof(AF_MPLS))) {
        private enum enumMixinStr_AF_MPLS = `enum AF_MPLS = PF_MPLS;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_MPLS); }))) {
            mixin(enumMixinStr_AF_MPLS);
        }
    }




    static if(!is(typeof(AF_IB))) {
        private enum enumMixinStr_AF_IB = `enum AF_IB = PF_IB;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_IB); }))) {
            mixin(enumMixinStr_AF_IB);
        }
    }




    static if(!is(typeof(AF_LLC))) {
        private enum enumMixinStr_AF_LLC = `enum AF_LLC = PF_LLC;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_LLC); }))) {
            mixin(enumMixinStr_AF_LLC);
        }
    }




    static if(!is(typeof(AF_WANPIPE))) {
        private enum enumMixinStr_AF_WANPIPE = `enum AF_WANPIPE = PF_WANPIPE;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_WANPIPE); }))) {
            mixin(enumMixinStr_AF_WANPIPE);
        }
    }




    static if(!is(typeof(AF_PPPOX))) {
        private enum enumMixinStr_AF_PPPOX = `enum AF_PPPOX = PF_PPPOX;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_PPPOX); }))) {
            mixin(enumMixinStr_AF_PPPOX);
        }
    }




    static if(!is(typeof(AF_IRDA))) {
        private enum enumMixinStr_AF_IRDA = `enum AF_IRDA = PF_IRDA;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_IRDA); }))) {
            mixin(enumMixinStr_AF_IRDA);
        }
    }




    static if(!is(typeof(AF_SNA))) {
        private enum enumMixinStr_AF_SNA = `enum AF_SNA = PF_SNA;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_SNA); }))) {
            mixin(enumMixinStr_AF_SNA);
        }
    }




    static if(!is(typeof(AF_RDS))) {
        private enum enumMixinStr_AF_RDS = `enum AF_RDS = PF_RDS;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_RDS); }))) {
            mixin(enumMixinStr_AF_RDS);
        }
    }




    static if(!is(typeof(AF_ATMSVC))) {
        private enum enumMixinStr_AF_ATMSVC = `enum AF_ATMSVC = PF_ATMSVC;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_ATMSVC); }))) {
            mixin(enumMixinStr_AF_ATMSVC);
        }
    }




    static if(!is(typeof(AF_ECONET))) {
        private enum enumMixinStr_AF_ECONET = `enum AF_ECONET = PF_ECONET;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_ECONET); }))) {
            mixin(enumMixinStr_AF_ECONET);
        }
    }




    static if(!is(typeof(AF_ASH))) {
        private enum enumMixinStr_AF_ASH = `enum AF_ASH = PF_ASH;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_ASH); }))) {
            mixin(enumMixinStr_AF_ASH);
        }
    }




    static if(!is(typeof(AF_PACKET))) {
        private enum enumMixinStr_AF_PACKET = `enum AF_PACKET = PF_PACKET;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_PACKET); }))) {
            mixin(enumMixinStr_AF_PACKET);
        }
    }




    static if(!is(typeof(AF_ROUTE))) {
        private enum enumMixinStr_AF_ROUTE = `enum AF_ROUTE = PF_ROUTE;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_ROUTE); }))) {
            mixin(enumMixinStr_AF_ROUTE);
        }
    }




    static if(!is(typeof(AF_NETLINK))) {
        private enum enumMixinStr_AF_NETLINK = `enum AF_NETLINK = PF_NETLINK;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_NETLINK); }))) {
            mixin(enumMixinStr_AF_NETLINK);
        }
    }




    static if(!is(typeof(AF_KEY))) {
        private enum enumMixinStr_AF_KEY = `enum AF_KEY = PF_KEY;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_KEY); }))) {
            mixin(enumMixinStr_AF_KEY);
        }
    }




    static if(!is(typeof(AF_SECURITY))) {
        private enum enumMixinStr_AF_SECURITY = `enum AF_SECURITY = PF_SECURITY;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_SECURITY); }))) {
            mixin(enumMixinStr_AF_SECURITY);
        }
    }




    static if(!is(typeof(AF_NETBEUI))) {
        private enum enumMixinStr_AF_NETBEUI = `enum AF_NETBEUI = PF_NETBEUI;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_NETBEUI); }))) {
            mixin(enumMixinStr_AF_NETBEUI);
        }
    }




    static if(!is(typeof(AF_DECnet))) {
        private enum enumMixinStr_AF_DECnet = `enum AF_DECnet = PF_DECnet;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_DECnet); }))) {
            mixin(enumMixinStr_AF_DECnet);
        }
    }




    static if(!is(typeof(AF_ROSE))) {
        private enum enumMixinStr_AF_ROSE = `enum AF_ROSE = PF_ROSE;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_ROSE); }))) {
            mixin(enumMixinStr_AF_ROSE);
        }
    }




    static if(!is(typeof(AF_INET6))) {
        private enum enumMixinStr_AF_INET6 = `enum AF_INET6 = PF_INET6;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_INET6); }))) {
            mixin(enumMixinStr_AF_INET6);
        }
    }




    static if(!is(typeof(AF_X25))) {
        private enum enumMixinStr_AF_X25 = `enum AF_X25 = PF_X25;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_X25); }))) {
            mixin(enumMixinStr_AF_X25);
        }
    }




    static if(!is(typeof(AF_ATMPVC))) {
        private enum enumMixinStr_AF_ATMPVC = `enum AF_ATMPVC = PF_ATMPVC;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_ATMPVC); }))) {
            mixin(enumMixinStr_AF_ATMPVC);
        }
    }




    static if(!is(typeof(AF_BRIDGE))) {
        private enum enumMixinStr_AF_BRIDGE = `enum AF_BRIDGE = PF_BRIDGE;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_BRIDGE); }))) {
            mixin(enumMixinStr_AF_BRIDGE);
        }
    }




    static if(!is(typeof(AF_NETROM))) {
        private enum enumMixinStr_AF_NETROM = `enum AF_NETROM = PF_NETROM;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_NETROM); }))) {
            mixin(enumMixinStr_AF_NETROM);
        }
    }




    static if(!is(typeof(AF_APPLETALK))) {
        private enum enumMixinStr_AF_APPLETALK = `enum AF_APPLETALK = PF_APPLETALK;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_APPLETALK); }))) {
            mixin(enumMixinStr_AF_APPLETALK);
        }
    }




    static if(!is(typeof(AF_IPX))) {
        private enum enumMixinStr_AF_IPX = `enum AF_IPX = PF_IPX;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_IPX); }))) {
            mixin(enumMixinStr_AF_IPX);
        }
    }




    static if(!is(typeof(AF_AX25))) {
        private enum enumMixinStr_AF_AX25 = `enum AF_AX25 = PF_AX25;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_AX25); }))) {
            mixin(enumMixinStr_AF_AX25);
        }
    }




    static if(!is(typeof(AF_INET))) {
        private enum enumMixinStr_AF_INET = `enum AF_INET = PF_INET;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_INET); }))) {
            mixin(enumMixinStr_AF_INET);
        }
    }




    static if(!is(typeof(AF_FILE))) {
        private enum enumMixinStr_AF_FILE = `enum AF_FILE = PF_FILE;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_FILE); }))) {
            mixin(enumMixinStr_AF_FILE);
        }
    }




    static if(!is(typeof(AF_UNIX))) {
        private enum enumMixinStr_AF_UNIX = `enum AF_UNIX = PF_UNIX;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_UNIX); }))) {
            mixin(enumMixinStr_AF_UNIX);
        }
    }




    static if(!is(typeof(AF_LOCAL))) {
        private enum enumMixinStr_AF_LOCAL = `enum AF_LOCAL = PF_LOCAL;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_LOCAL); }))) {
            mixin(enumMixinStr_AF_LOCAL);
        }
    }




    static if(!is(typeof(AF_UNSPEC))) {
        private enum enumMixinStr_AF_UNSPEC = `enum AF_UNSPEC = PF_UNSPEC;`;
        static if(is(typeof({ mixin(enumMixinStr_AF_UNSPEC); }))) {
            mixin(enumMixinStr_AF_UNSPEC);
        }
    }




    static if(!is(typeof(PF_MAX))) {
        private enum enumMixinStr_PF_MAX = `enum PF_MAX = 45;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_MAX); }))) {
            mixin(enumMixinStr_PF_MAX);
        }
    }




    static if(!is(typeof(PF_XDP))) {
        private enum enumMixinStr_PF_XDP = `enum PF_XDP = 44;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_XDP); }))) {
            mixin(enumMixinStr_PF_XDP);
        }
    }




    static if(!is(typeof(PF_SMC))) {
        private enum enumMixinStr_PF_SMC = `enum PF_SMC = 43;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_SMC); }))) {
            mixin(enumMixinStr_PF_SMC);
        }
    }




    static if(!is(typeof(PF_QIPCRTR))) {
        private enum enumMixinStr_PF_QIPCRTR = `enum PF_QIPCRTR = 42;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_QIPCRTR); }))) {
            mixin(enumMixinStr_PF_QIPCRTR);
        }
    }




    static if(!is(typeof(PF_KCM))) {
        private enum enumMixinStr_PF_KCM = `enum PF_KCM = 41;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_KCM); }))) {
            mixin(enumMixinStr_PF_KCM);
        }
    }




    static if(!is(typeof(PF_VSOCK))) {
        private enum enumMixinStr_PF_VSOCK = `enum PF_VSOCK = 40;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_VSOCK); }))) {
            mixin(enumMixinStr_PF_VSOCK);
        }
    }




    static if(!is(typeof(PF_NFC))) {
        private enum enumMixinStr_PF_NFC = `enum PF_NFC = 39;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_NFC); }))) {
            mixin(enumMixinStr_PF_NFC);
        }
    }




    static if(!is(typeof(PF_ALG))) {
        private enum enumMixinStr_PF_ALG = `enum PF_ALG = 38;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_ALG); }))) {
            mixin(enumMixinStr_PF_ALG);
        }
    }




    static if(!is(typeof(PF_CAIF))) {
        private enum enumMixinStr_PF_CAIF = `enum PF_CAIF = 37;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_CAIF); }))) {
            mixin(enumMixinStr_PF_CAIF);
        }
    }




    static if(!is(typeof(PF_IEEE802154))) {
        private enum enumMixinStr_PF_IEEE802154 = `enum PF_IEEE802154 = 36;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_IEEE802154); }))) {
            mixin(enumMixinStr_PF_IEEE802154);
        }
    }




    static if(!is(typeof(PF_PHONET))) {
        private enum enumMixinStr_PF_PHONET = `enum PF_PHONET = 35;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_PHONET); }))) {
            mixin(enumMixinStr_PF_PHONET);
        }
    }




    static if(!is(typeof(PF_ISDN))) {
        private enum enumMixinStr_PF_ISDN = `enum PF_ISDN = 34;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_ISDN); }))) {
            mixin(enumMixinStr_PF_ISDN);
        }
    }




    static if(!is(typeof(PF_RXRPC))) {
        private enum enumMixinStr_PF_RXRPC = `enum PF_RXRPC = 33;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_RXRPC); }))) {
            mixin(enumMixinStr_PF_RXRPC);
        }
    }




    static if(!is(typeof(PF_IUCV))) {
        private enum enumMixinStr_PF_IUCV = `enum PF_IUCV = 32;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_IUCV); }))) {
            mixin(enumMixinStr_PF_IUCV);
        }
    }




    static if(!is(typeof(PF_BLUETOOTH))) {
        private enum enumMixinStr_PF_BLUETOOTH = `enum PF_BLUETOOTH = 31;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_BLUETOOTH); }))) {
            mixin(enumMixinStr_PF_BLUETOOTH);
        }
    }




    static if(!is(typeof(PF_TIPC))) {
        private enum enumMixinStr_PF_TIPC = `enum PF_TIPC = 30;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_TIPC); }))) {
            mixin(enumMixinStr_PF_TIPC);
        }
    }




    static if(!is(typeof(PF_CAN))) {
        private enum enumMixinStr_PF_CAN = `enum PF_CAN = 29;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_CAN); }))) {
            mixin(enumMixinStr_PF_CAN);
        }
    }




    static if(!is(typeof(PF_MPLS))) {
        private enum enumMixinStr_PF_MPLS = `enum PF_MPLS = 28;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_MPLS); }))) {
            mixin(enumMixinStr_PF_MPLS);
        }
    }




    static if(!is(typeof(PF_IB))) {
        private enum enumMixinStr_PF_IB = `enum PF_IB = 27;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_IB); }))) {
            mixin(enumMixinStr_PF_IB);
        }
    }




    static if(!is(typeof(PF_LLC))) {
        private enum enumMixinStr_PF_LLC = `enum PF_LLC = 26;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_LLC); }))) {
            mixin(enumMixinStr_PF_LLC);
        }
    }




    static if(!is(typeof(PF_WANPIPE))) {
        private enum enumMixinStr_PF_WANPIPE = `enum PF_WANPIPE = 25;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_WANPIPE); }))) {
            mixin(enumMixinStr_PF_WANPIPE);
        }
    }




    static if(!is(typeof(PF_PPPOX))) {
        private enum enumMixinStr_PF_PPPOX = `enum PF_PPPOX = 24;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_PPPOX); }))) {
            mixin(enumMixinStr_PF_PPPOX);
        }
    }




    static if(!is(typeof(PF_IRDA))) {
        private enum enumMixinStr_PF_IRDA = `enum PF_IRDA = 23;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_IRDA); }))) {
            mixin(enumMixinStr_PF_IRDA);
        }
    }




    static if(!is(typeof(PF_SNA))) {
        private enum enumMixinStr_PF_SNA = `enum PF_SNA = 22;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_SNA); }))) {
            mixin(enumMixinStr_PF_SNA);
        }
    }




    static if(!is(typeof(PF_RDS))) {
        private enum enumMixinStr_PF_RDS = `enum PF_RDS = 21;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_RDS); }))) {
            mixin(enumMixinStr_PF_RDS);
        }
    }
    static if(!is(typeof(PF_ATMSVC))) {
        private enum enumMixinStr_PF_ATMSVC = `enum PF_ATMSVC = 20;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_ATMSVC); }))) {
            mixin(enumMixinStr_PF_ATMSVC);
        }
    }




    static if(!is(typeof(PF_ECONET))) {
        private enum enumMixinStr_PF_ECONET = `enum PF_ECONET = 19;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_ECONET); }))) {
            mixin(enumMixinStr_PF_ECONET);
        }
    }




    static if(!is(typeof(PF_ASH))) {
        private enum enumMixinStr_PF_ASH = `enum PF_ASH = 18;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_ASH); }))) {
            mixin(enumMixinStr_PF_ASH);
        }
    }






    static if(!is(typeof(PF_PACKET))) {
        private enum enumMixinStr_PF_PACKET = `enum PF_PACKET = 17;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_PACKET); }))) {
            mixin(enumMixinStr_PF_PACKET);
        }
    }




    static if(!is(typeof(PF_ROUTE))) {
        private enum enumMixinStr_PF_ROUTE = `enum PF_ROUTE = PF_NETLINK;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_ROUTE); }))) {
            mixin(enumMixinStr_PF_ROUTE);
        }
    }




    static if(!is(typeof(PF_NETLINK))) {
        private enum enumMixinStr_PF_NETLINK = `enum PF_NETLINK = 16;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_NETLINK); }))) {
            mixin(enumMixinStr_PF_NETLINK);
        }
    }




    static if(!is(typeof(PF_KEY))) {
        private enum enumMixinStr_PF_KEY = `enum PF_KEY = 15;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_KEY); }))) {
            mixin(enumMixinStr_PF_KEY);
        }
    }




    static if(!is(typeof(PF_SECURITY))) {
        private enum enumMixinStr_PF_SECURITY = `enum PF_SECURITY = 14;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_SECURITY); }))) {
            mixin(enumMixinStr_PF_SECURITY);
        }
    }




    static if(!is(typeof(PF_NETBEUI))) {
        private enum enumMixinStr_PF_NETBEUI = `enum PF_NETBEUI = 13;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_NETBEUI); }))) {
            mixin(enumMixinStr_PF_NETBEUI);
        }
    }




    static if(!is(typeof(PF_DECnet))) {
        private enum enumMixinStr_PF_DECnet = `enum PF_DECnet = 12;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_DECnet); }))) {
            mixin(enumMixinStr_PF_DECnet);
        }
    }




    static if(!is(typeof(PF_ROSE))) {
        private enum enumMixinStr_PF_ROSE = `enum PF_ROSE = 11;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_ROSE); }))) {
            mixin(enumMixinStr_PF_ROSE);
        }
    }




    static if(!is(typeof(PF_INET6))) {
        private enum enumMixinStr_PF_INET6 = `enum PF_INET6 = 10;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_INET6); }))) {
            mixin(enumMixinStr_PF_INET6);
        }
    }




    static if(!is(typeof(PF_X25))) {
        private enum enumMixinStr_PF_X25 = `enum PF_X25 = 9;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_X25); }))) {
            mixin(enumMixinStr_PF_X25);
        }
    }




    static if(!is(typeof(PF_ATMPVC))) {
        private enum enumMixinStr_PF_ATMPVC = `enum PF_ATMPVC = 8;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_ATMPVC); }))) {
            mixin(enumMixinStr_PF_ATMPVC);
        }
    }




    static if(!is(typeof(PF_BRIDGE))) {
        private enum enumMixinStr_PF_BRIDGE = `enum PF_BRIDGE = 7;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_BRIDGE); }))) {
            mixin(enumMixinStr_PF_BRIDGE);
        }
    }




    static if(!is(typeof(PF_NETROM))) {
        private enum enumMixinStr_PF_NETROM = `enum PF_NETROM = 6;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_NETROM); }))) {
            mixin(enumMixinStr_PF_NETROM);
        }
    }




    static if(!is(typeof(PF_APPLETALK))) {
        private enum enumMixinStr_PF_APPLETALK = `enum PF_APPLETALK = 5;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_APPLETALK); }))) {
            mixin(enumMixinStr_PF_APPLETALK);
        }
    }




    static if(!is(typeof(PF_IPX))) {
        private enum enumMixinStr_PF_IPX = `enum PF_IPX = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_IPX); }))) {
            mixin(enumMixinStr_PF_IPX);
        }
    }




    static if(!is(typeof(PF_AX25))) {
        private enum enumMixinStr_PF_AX25 = `enum PF_AX25 = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_AX25); }))) {
            mixin(enumMixinStr_PF_AX25);
        }
    }




    static if(!is(typeof(PF_INET))) {
        private enum enumMixinStr_PF_INET = `enum PF_INET = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_INET); }))) {
            mixin(enumMixinStr_PF_INET);
        }
    }




    static if(!is(typeof(PF_FILE))) {
        private enum enumMixinStr_PF_FILE = `enum PF_FILE = PF_LOCAL;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_FILE); }))) {
            mixin(enumMixinStr_PF_FILE);
        }
    }




    static if(!is(typeof(PF_UNIX))) {
        private enum enumMixinStr_PF_UNIX = `enum PF_UNIX = PF_LOCAL;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_UNIX); }))) {
            mixin(enumMixinStr_PF_UNIX);
        }
    }




    static if(!is(typeof(PF_LOCAL))) {
        private enum enumMixinStr_PF_LOCAL = `enum PF_LOCAL = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_LOCAL); }))) {
            mixin(enumMixinStr_PF_LOCAL);
        }
    }




    static if(!is(typeof(PF_UNSPEC))) {
        private enum enumMixinStr_PF_UNSPEC = `enum PF_UNSPEC = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_PF_UNSPEC); }))) {
            mixin(enumMixinStr_PF_UNSPEC);
        }
    }
    static if(!is(typeof(_SS_SIZE))) {
        private enum enumMixinStr__SS_SIZE = `enum _SS_SIZE = 128;`;
        static if(is(typeof({ mixin(enumMixinStr__SS_SIZE); }))) {
            mixin(enumMixinStr__SS_SIZE);
        }
    }




    static if(!is(typeof(__SOCKADDR_COMMON_SIZE))) {
        private enum enumMixinStr___SOCKADDR_COMMON_SIZE = `enum __SOCKADDR_COMMON_SIZE = ( ( unsigned short int ) .sizeof );`;
        static if(is(typeof({ mixin(enumMixinStr___SOCKADDR_COMMON_SIZE); }))) {
            mixin(enumMixinStr___SOCKADDR_COMMON_SIZE);
        }
    }






    static if(!is(typeof(_BITS_SOCKADDR_H))) {
        private enum enumMixinStr__BITS_SOCKADDR_H = `enum _BITS_SOCKADDR_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_SOCKADDR_H); }))) {
            mixin(enumMixinStr__BITS_SOCKADDR_H);
        }
    }




    static if(!is(typeof(_BITS_SIGTHREAD_H))) {
        private enum enumMixinStr__BITS_SIGTHREAD_H = `enum _BITS_SIGTHREAD_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_SIGTHREAD_H); }))) {
            mixin(enumMixinStr__BITS_SIGTHREAD_H);
        }
    }




    static if(!is(typeof(SIGSTKSZ))) {
        private enum enumMixinStr_SIGSTKSZ = `enum SIGSTKSZ = 8192;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGSTKSZ); }))) {
            mixin(enumMixinStr_SIGSTKSZ);
        }
    }




    static if(!is(typeof(MINSIGSTKSZ))) {
        private enum enumMixinStr_MINSIGSTKSZ = `enum MINSIGSTKSZ = 2048;`;
        static if(is(typeof({ mixin(enumMixinStr_MINSIGSTKSZ); }))) {
            mixin(enumMixinStr_MINSIGSTKSZ);
        }
    }




    static if(!is(typeof(_BITS_SIGSTACK_H))) {
        private enum enumMixinStr__BITS_SIGSTACK_H = `enum _BITS_SIGSTACK_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_SIGSTACK_H); }))) {
            mixin(enumMixinStr__BITS_SIGSTACK_H);
        }
    }




    static if(!is(typeof(__SIGRTMAX))) {
        private enum enumMixinStr___SIGRTMAX = `enum __SIGRTMAX = 64;`;
        static if(is(typeof({ mixin(enumMixinStr___SIGRTMAX); }))) {
            mixin(enumMixinStr___SIGRTMAX);
        }
    }




    static if(!is(typeof(SIGSYS))) {
        private enum enumMixinStr_SIGSYS = `enum SIGSYS = 31;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGSYS); }))) {
            mixin(enumMixinStr_SIGSYS);
        }
    }




    static if(!is(typeof(SIGPOLL))) {
        private enum enumMixinStr_SIGPOLL = `enum SIGPOLL = 29;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGPOLL); }))) {
            mixin(enumMixinStr_SIGPOLL);
        }
    }




    static if(!is(typeof(SIGURG))) {
        private enum enumMixinStr_SIGURG = `enum SIGURG = 23;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGURG); }))) {
            mixin(enumMixinStr_SIGURG);
        }
    }




    static if(!is(typeof(SIGTSTP))) {
        private enum enumMixinStr_SIGTSTP = `enum SIGTSTP = 20;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGTSTP); }))) {
            mixin(enumMixinStr_SIGTSTP);
        }
    }




    static if(!is(typeof(SIGSTOP))) {
        private enum enumMixinStr_SIGSTOP = `enum SIGSTOP = 19;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGSTOP); }))) {
            mixin(enumMixinStr_SIGSTOP);
        }
    }




    static if(!is(typeof(SIGCONT))) {
        private enum enumMixinStr_SIGCONT = `enum SIGCONT = 18;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGCONT); }))) {
            mixin(enumMixinStr_SIGCONT);
        }
    }




    static if(!is(typeof(SIGCHLD))) {
        private enum enumMixinStr_SIGCHLD = `enum SIGCHLD = 17;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGCHLD); }))) {
            mixin(enumMixinStr_SIGCHLD);
        }
    }




    static if(!is(typeof(SIGUSR2))) {
        private enum enumMixinStr_SIGUSR2 = `enum SIGUSR2 = 12;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGUSR2); }))) {
            mixin(enumMixinStr_SIGUSR2);
        }
    }




    static if(!is(typeof(SIGUSR1))) {
        private enum enumMixinStr_SIGUSR1 = `enum SIGUSR1 = 10;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGUSR1); }))) {
            mixin(enumMixinStr_SIGUSR1);
        }
    }




    static if(!is(typeof(SIGBUS))) {
        private enum enumMixinStr_SIGBUS = `enum SIGBUS = 7;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGBUS); }))) {
            mixin(enumMixinStr_SIGBUS);
        }
    }




    static if(!is(typeof(SIGPWR))) {
        private enum enumMixinStr_SIGPWR = `enum SIGPWR = 30;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGPWR); }))) {
            mixin(enumMixinStr_SIGPWR);
        }
    }




    static if(!is(typeof(SIGSTKFLT))) {
        private enum enumMixinStr_SIGSTKFLT = `enum SIGSTKFLT = 16;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGSTKFLT); }))) {
            mixin(enumMixinStr_SIGSTKFLT);
        }
    }




    static if(!is(typeof(_BITS_SIGNUM_H))) {
        private enum enumMixinStr__BITS_SIGNUM_H = `enum _BITS_SIGNUM_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_SIGNUM_H); }))) {
            mixin(enumMixinStr__BITS_SIGNUM_H);
        }
    }




    static if(!is(typeof(_NSIG))) {
        private enum enumMixinStr__NSIG = `enum _NSIG = ( 64 + 1 );`;
        static if(is(typeof({ mixin(enumMixinStr__NSIG); }))) {
            mixin(enumMixinStr__NSIG);
        }
    }




    static if(!is(typeof(__SIGRTMIN))) {
        private enum enumMixinStr___SIGRTMIN = `enum __SIGRTMIN = 32;`;
        static if(is(typeof({ mixin(enumMixinStr___SIGRTMIN); }))) {
            mixin(enumMixinStr___SIGRTMIN);
        }
    }




    static if(!is(typeof(SIGCLD))) {
        private enum enumMixinStr_SIGCLD = `enum SIGCLD = 17;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGCLD); }))) {
            mixin(enumMixinStr_SIGCLD);
        }
    }




    static if(!is(typeof(SIGIOT))) {
        private enum enumMixinStr_SIGIOT = `enum SIGIOT = SIGABRT;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGIOT); }))) {
            mixin(enumMixinStr_SIGIOT);
        }
    }




    static if(!is(typeof(SIGIO))) {
        private enum enumMixinStr_SIGIO = `enum SIGIO = 29;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGIO); }))) {
            mixin(enumMixinStr_SIGIO);
        }
    }




    static if(!is(typeof(SIGWINCH))) {
        private enum enumMixinStr_SIGWINCH = `enum SIGWINCH = 28;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGWINCH); }))) {
            mixin(enumMixinStr_SIGWINCH);
        }
    }




    static if(!is(typeof(SIGPROF))) {
        private enum enumMixinStr_SIGPROF = `enum SIGPROF = 27;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGPROF); }))) {
            mixin(enumMixinStr_SIGPROF);
        }
    }




    static if(!is(typeof(SIGVTALRM))) {
        private enum enumMixinStr_SIGVTALRM = `enum SIGVTALRM = 26;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGVTALRM); }))) {
            mixin(enumMixinStr_SIGVTALRM);
        }
    }




    static if(!is(typeof(SIGXFSZ))) {
        private enum enumMixinStr_SIGXFSZ = `enum SIGXFSZ = 25;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGXFSZ); }))) {
            mixin(enumMixinStr_SIGXFSZ);
        }
    }




    static if(!is(typeof(SIGXCPU))) {
        private enum enumMixinStr_SIGXCPU = `enum SIGXCPU = 24;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGXCPU); }))) {
            mixin(enumMixinStr_SIGXCPU);
        }
    }




    static if(!is(typeof(SIGTTOU))) {
        private enum enumMixinStr_SIGTTOU = `enum SIGTTOU = 22;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGTTOU); }))) {
            mixin(enumMixinStr_SIGTTOU);
        }
    }




    static if(!is(typeof(SIGTTIN))) {
        private enum enumMixinStr_SIGTTIN = `enum SIGTTIN = 21;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGTTIN); }))) {
            mixin(enumMixinStr_SIGTTIN);
        }
    }






    static if(!is(typeof(SIGALRM))) {
        private enum enumMixinStr_SIGALRM = `enum SIGALRM = 14;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGALRM); }))) {
            mixin(enumMixinStr_SIGALRM);
        }
    }




    static if(!is(typeof(SIGPIPE))) {
        private enum enumMixinStr_SIGPIPE = `enum SIGPIPE = 13;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGPIPE); }))) {
            mixin(enumMixinStr_SIGPIPE);
        }
    }




    static if(!is(typeof(SIGKILL))) {
        private enum enumMixinStr_SIGKILL = `enum SIGKILL = 9;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGKILL); }))) {
            mixin(enumMixinStr_SIGKILL);
        }
    }






    static if(!is(typeof(SIGTRAP))) {
        private enum enumMixinStr_SIGTRAP = `enum SIGTRAP = 5;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGTRAP); }))) {
            mixin(enumMixinStr_SIGTRAP);
        }
    }




    static if(!is(typeof(SIGQUIT))) {
        private enum enumMixinStr_SIGQUIT = `enum SIGQUIT = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGQUIT); }))) {
            mixin(enumMixinStr_SIGQUIT);
        }
    }




    static if(!is(typeof(SIGHUP))) {
        private enum enumMixinStr_SIGHUP = `enum SIGHUP = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGHUP); }))) {
            mixin(enumMixinStr_SIGHUP);
        }
    }




    static if(!is(typeof(SIGTERM))) {
        private enum enumMixinStr_SIGTERM = `enum SIGTERM = 15;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGTERM); }))) {
            mixin(enumMixinStr_SIGTERM);
        }
    }




    static if(!is(typeof(SIGSEGV))) {
        private enum enumMixinStr_SIGSEGV = `enum SIGSEGV = 11;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGSEGV); }))) {
            mixin(enumMixinStr_SIGSEGV);
        }
    }




    static if(!is(typeof(SIGFPE))) {
        private enum enumMixinStr_SIGFPE = `enum SIGFPE = 8;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGFPE); }))) {
            mixin(enumMixinStr_SIGFPE);
        }
    }




    static if(!is(typeof(SIGABRT))) {
        private enum enumMixinStr_SIGABRT = `enum SIGABRT = 6;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGABRT); }))) {
            mixin(enumMixinStr_SIGABRT);
        }
    }




    static if(!is(typeof(SIGILL))) {
        private enum enumMixinStr_SIGILL = `enum SIGILL = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGILL); }))) {
            mixin(enumMixinStr_SIGILL);
        }
    }




    static if(!is(typeof(SIGINT))) {
        private enum enumMixinStr_SIGINT = `enum SIGINT = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGINT); }))) {
            mixin(enumMixinStr_SIGINT);
        }
    }




    static if(!is(typeof(SIG_IGN))) {
        private enum enumMixinStr_SIG_IGN = `enum SIG_IGN = ( ( __sighandler_t ) 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_SIG_IGN); }))) {
            mixin(enumMixinStr_SIG_IGN);
        }
    }




    static if(!is(typeof(NULL))) {
        private enum enumMixinStr_NULL = `enum NULL = ( cast( void * ) 0 );`;
        static if(is(typeof({ mixin(enumMixinStr_NULL); }))) {
            mixin(enumMixinStr_NULL);
        }
    }




    static if(!is(typeof(SIG_DFL))) {
        private enum enumMixinStr_SIG_DFL = `enum SIG_DFL = ( ( __sighandler_t ) 0 );`;
        static if(is(typeof({ mixin(enumMixinStr_SIG_DFL); }))) {
            mixin(enumMixinStr_SIG_DFL);
        }
    }




    static if(!is(typeof(SIG_ERR))) {
        private enum enumMixinStr_SIG_ERR = `enum SIG_ERR = ( ( __sighandler_t ) - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_SIG_ERR); }))) {
            mixin(enumMixinStr_SIG_ERR);
        }
    }




    static if(!is(typeof(_BITS_SIGNUM_GENERIC_H))) {
        private enum enumMixinStr__BITS_SIGNUM_GENERIC_H = `enum _BITS_SIGNUM_GENERIC_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_SIGNUM_GENERIC_H); }))) {
            mixin(enumMixinStr__BITS_SIGNUM_GENERIC_H);
        }
    }






    static if(!is(typeof(POLL_HUP))) {
        private enum enumMixinStr_POLL_HUP = `enum POLL_HUP = POLL_HUP;`;
        static if(is(typeof({ mixin(enumMixinStr_POLL_HUP); }))) {
            mixin(enumMixinStr_POLL_HUP);
        }
    }






    static if(!is(typeof(POLL_PRI))) {
        private enum enumMixinStr_POLL_PRI = `enum POLL_PRI = POLL_PRI;`;
        static if(is(typeof({ mixin(enumMixinStr_POLL_PRI); }))) {
            mixin(enumMixinStr_POLL_PRI);
        }
    }




    static if(!is(typeof(POLL_ERR))) {
        private enum enumMixinStr_POLL_ERR = `enum POLL_ERR = POLL_ERR;`;
        static if(is(typeof({ mixin(enumMixinStr_POLL_ERR); }))) {
            mixin(enumMixinStr_POLL_ERR);
        }
    }




    static if(!is(typeof(POLL_MSG))) {
        private enum enumMixinStr_POLL_MSG = `enum POLL_MSG = POLL_MSG;`;
        static if(is(typeof({ mixin(enumMixinStr_POLL_MSG); }))) {
            mixin(enumMixinStr_POLL_MSG);
        }
    }




    static if(!is(typeof(POLL_OUT))) {
        private enum enumMixinStr_POLL_OUT = `enum POLL_OUT = POLL_OUT;`;
        static if(is(typeof({ mixin(enumMixinStr_POLL_OUT); }))) {
            mixin(enumMixinStr_POLL_OUT);
        }
    }






    static if(!is(typeof(POLL_IN))) {
        private enum enumMixinStr_POLL_IN = `enum POLL_IN = POLL_IN;`;
        static if(is(typeof({ mixin(enumMixinStr_POLL_IN); }))) {
            mixin(enumMixinStr_POLL_IN);
        }
    }




    static if(!is(typeof(CLD_CONTINUED))) {
        private enum enumMixinStr_CLD_CONTINUED = `enum CLD_CONTINUED = CLD_CONTINUED;`;
        static if(is(typeof({ mixin(enumMixinStr_CLD_CONTINUED); }))) {
            mixin(enumMixinStr_CLD_CONTINUED);
        }
    }




    static if(!is(typeof(CLD_STOPPED))) {
        private enum enumMixinStr_CLD_STOPPED = `enum CLD_STOPPED = CLD_STOPPED;`;
        static if(is(typeof({ mixin(enumMixinStr_CLD_STOPPED); }))) {
            mixin(enumMixinStr_CLD_STOPPED);
        }
    }




    static if(!is(typeof(CLD_TRAPPED))) {
        private enum enumMixinStr_CLD_TRAPPED = `enum CLD_TRAPPED = CLD_TRAPPED;`;
        static if(is(typeof({ mixin(enumMixinStr_CLD_TRAPPED); }))) {
            mixin(enumMixinStr_CLD_TRAPPED);
        }
    }






    static if(!is(typeof(CLD_DUMPED))) {
        private enum enumMixinStr_CLD_DUMPED = `enum CLD_DUMPED = CLD_DUMPED;`;
        static if(is(typeof({ mixin(enumMixinStr_CLD_DUMPED); }))) {
            mixin(enumMixinStr_CLD_DUMPED);
        }
    }




    static if(!is(typeof(CLD_KILLED))) {
        private enum enumMixinStr_CLD_KILLED = `enum CLD_KILLED = CLD_KILLED;`;
        static if(is(typeof({ mixin(enumMixinStr_CLD_KILLED); }))) {
            mixin(enumMixinStr_CLD_KILLED);
        }
    }




    static if(!is(typeof(CZMQ_VERSION_MAJOR))) {
        private enum enumMixinStr_CZMQ_VERSION_MAJOR = `enum CZMQ_VERSION_MAJOR = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_CZMQ_VERSION_MAJOR); }))) {
            mixin(enumMixinStr_CZMQ_VERSION_MAJOR);
        }
    }




    static if(!is(typeof(CZMQ_VERSION_MINOR))) {
        private enum enumMixinStr_CZMQ_VERSION_MINOR = `enum CZMQ_VERSION_MINOR = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_CZMQ_VERSION_MINOR); }))) {
            mixin(enumMixinStr_CZMQ_VERSION_MINOR);
        }
    }




    static if(!is(typeof(CZMQ_VERSION_PATCH))) {
        private enum enumMixinStr_CZMQ_VERSION_PATCH = `enum CZMQ_VERSION_PATCH = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_CZMQ_VERSION_PATCH); }))) {
            mixin(enumMixinStr_CZMQ_VERSION_PATCH);
        }
    }






    static if(!is(typeof(CZMQ_VERSION))) {
        private enum enumMixinStr_CZMQ_VERSION = `enum CZMQ_VERSION = ( ( 4 ) * 10000 + ( 2 ) * 100 + ( 1 ) );`;
        static if(is(typeof({ mixin(enumMixinStr_CZMQ_VERSION); }))) {
            mixin(enumMixinStr_CZMQ_VERSION);
        }
    }




    static if(!is(typeof(CLD_EXITED))) {
        private enum enumMixinStr_CLD_EXITED = `enum CLD_EXITED = CLD_EXITED;`;
        static if(is(typeof({ mixin(enumMixinStr_CLD_EXITED); }))) {
            mixin(enumMixinStr_CLD_EXITED);
        }
    }




    static if(!is(typeof(BUS_MCEERR_AO))) {
        private enum enumMixinStr_BUS_MCEERR_AO = `enum BUS_MCEERR_AO = BUS_MCEERR_AO;`;
        static if(is(typeof({ mixin(enumMixinStr_BUS_MCEERR_AO); }))) {
            mixin(enumMixinStr_BUS_MCEERR_AO);
        }
    }




    static if(!is(typeof(CZMQ_PRIVATE))) {
        private enum enumMixinStr_CZMQ_PRIVATE = `enum CZMQ_PRIVATE = __attribute__ ( ( visibility ( "hidden" ) ) );`;
        static if(is(typeof({ mixin(enumMixinStr_CZMQ_PRIVATE); }))) {
            mixin(enumMixinStr_CZMQ_PRIVATE);
        }
    }




    static if(!is(typeof(CZMQ_EXPORT))) {
        private enum enumMixinStr_CZMQ_EXPORT = `enum CZMQ_EXPORT = __attribute__ ( ( visibility ( "default" ) ) );`;
        static if(is(typeof({ mixin(enumMixinStr_CZMQ_EXPORT); }))) {
            mixin(enumMixinStr_CZMQ_EXPORT);
        }
    }




    static if(!is(typeof(BUS_MCEERR_AR))) {
        private enum enumMixinStr_BUS_MCEERR_AR = `enum BUS_MCEERR_AR = BUS_MCEERR_AR;`;
        static if(is(typeof({ mixin(enumMixinStr_BUS_MCEERR_AR); }))) {
            mixin(enumMixinStr_BUS_MCEERR_AR);
        }
    }




    static if(!is(typeof(BUS_OBJERR))) {
        private enum enumMixinStr_BUS_OBJERR = `enum BUS_OBJERR = BUS_OBJERR;`;
        static if(is(typeof({ mixin(enumMixinStr_BUS_OBJERR); }))) {
            mixin(enumMixinStr_BUS_OBJERR);
        }
    }






    static if(!is(typeof(BUS_ADRERR))) {
        private enum enumMixinStr_BUS_ADRERR = `enum BUS_ADRERR = BUS_ADRERR;`;
        static if(is(typeof({ mixin(enumMixinStr_BUS_ADRERR); }))) {
            mixin(enumMixinStr_BUS_ADRERR);
        }
    }




    static if(!is(typeof(BUS_ADRALN))) {
        private enum enumMixinStr_BUS_ADRALN = `enum BUS_ADRALN = BUS_ADRALN;`;
        static if(is(typeof({ mixin(enumMixinStr_BUS_ADRALN); }))) {
            mixin(enumMixinStr_BUS_ADRALN);
        }
    }






    static if(!is(typeof(SEGV_ADIPERR))) {
        private enum enumMixinStr_SEGV_ADIPERR = `enum SEGV_ADIPERR = SEGV_ADIPERR;`;
        static if(is(typeof({ mixin(enumMixinStr_SEGV_ADIPERR); }))) {
            mixin(enumMixinStr_SEGV_ADIPERR);
        }
    }




    static if(!is(typeof(SEGV_ADIDERR))) {
        private enum enumMixinStr_SEGV_ADIDERR = `enum SEGV_ADIDERR = SEGV_ADIDERR;`;
        static if(is(typeof({ mixin(enumMixinStr_SEGV_ADIDERR); }))) {
            mixin(enumMixinStr_SEGV_ADIDERR);
        }
    }






    static if(!is(typeof(SEGV_ACCADI))) {
        private enum enumMixinStr_SEGV_ACCADI = `enum SEGV_ACCADI = SEGV_ACCADI;`;
        static if(is(typeof({ mixin(enumMixinStr_SEGV_ACCADI); }))) {
            mixin(enumMixinStr_SEGV_ACCADI);
        }
    }




    static if(!is(typeof(SEGV_PKUERR))) {
        private enum enumMixinStr_SEGV_PKUERR = `enum SEGV_PKUERR = SEGV_PKUERR;`;
        static if(is(typeof({ mixin(enumMixinStr_SEGV_PKUERR); }))) {
            mixin(enumMixinStr_SEGV_PKUERR);
        }
    }






    static if(!is(typeof(SEGV_BNDERR))) {
        private enum enumMixinStr_SEGV_BNDERR = `enum SEGV_BNDERR = SEGV_BNDERR;`;
        static if(is(typeof({ mixin(enumMixinStr_SEGV_BNDERR); }))) {
            mixin(enumMixinStr_SEGV_BNDERR);
        }
    }




    static if(!is(typeof(SEGV_ACCERR))) {
        private enum enumMixinStr_SEGV_ACCERR = `enum SEGV_ACCERR = SEGV_ACCERR;`;
        static if(is(typeof({ mixin(enumMixinStr_SEGV_ACCERR); }))) {
            mixin(enumMixinStr_SEGV_ACCERR);
        }
    }






    static if(!is(typeof(SEGV_MAPERR))) {
        private enum enumMixinStr_SEGV_MAPERR = `enum SEGV_MAPERR = SEGV_MAPERR;`;
        static if(is(typeof({ mixin(enumMixinStr_SEGV_MAPERR); }))) {
            mixin(enumMixinStr_SEGV_MAPERR);
        }
    }




    static if(!is(typeof(FPE_CONDTRAP))) {
        private enum enumMixinStr_FPE_CONDTRAP = `enum FPE_CONDTRAP = FPE_CONDTRAP;`;
        static if(is(typeof({ mixin(enumMixinStr_FPE_CONDTRAP); }))) {
            mixin(enumMixinStr_FPE_CONDTRAP);
        }
    }






    static if(!is(typeof(FPE_FLTUNK))) {
        private enum enumMixinStr_FPE_FLTUNK = `enum FPE_FLTUNK = FPE_FLTUNK;`;
        static if(is(typeof({ mixin(enumMixinStr_FPE_FLTUNK); }))) {
            mixin(enumMixinStr_FPE_FLTUNK);
        }
    }




    static if(!is(typeof(FPE_FLTSUB))) {
        private enum enumMixinStr_FPE_FLTSUB = `enum FPE_FLTSUB = FPE_FLTSUB;`;
        static if(is(typeof({ mixin(enumMixinStr_FPE_FLTSUB); }))) {
            mixin(enumMixinStr_FPE_FLTSUB);
        }
    }






    static if(!is(typeof(FPE_FLTINV))) {
        private enum enumMixinStr_FPE_FLTINV = `enum FPE_FLTINV = FPE_FLTINV;`;
        static if(is(typeof({ mixin(enumMixinStr_FPE_FLTINV); }))) {
            mixin(enumMixinStr_FPE_FLTINV);
        }
    }




    static if(!is(typeof(FPE_FLTRES))) {
        private enum enumMixinStr_FPE_FLTRES = `enum FPE_FLTRES = FPE_FLTRES;`;
        static if(is(typeof({ mixin(enumMixinStr_FPE_FLTRES); }))) {
            mixin(enumMixinStr_FPE_FLTRES);
        }
    }






    static if(!is(typeof(FPE_FLTUND))) {
        private enum enumMixinStr_FPE_FLTUND = `enum FPE_FLTUND = FPE_FLTUND;`;
        static if(is(typeof({ mixin(enumMixinStr_FPE_FLTUND); }))) {
            mixin(enumMixinStr_FPE_FLTUND);
        }
    }




    static if(!is(typeof(FPE_FLTOVF))) {
        private enum enumMixinStr_FPE_FLTOVF = `enum FPE_FLTOVF = FPE_FLTOVF;`;
        static if(is(typeof({ mixin(enumMixinStr_FPE_FLTOVF); }))) {
            mixin(enumMixinStr_FPE_FLTOVF);
        }
    }






    static if(!is(typeof(FPE_FLTDIV))) {
        private enum enumMixinStr_FPE_FLTDIV = `enum FPE_FLTDIV = FPE_FLTDIV;`;
        static if(is(typeof({ mixin(enumMixinStr_FPE_FLTDIV); }))) {
            mixin(enumMixinStr_FPE_FLTDIV);
        }
    }




    static if(!is(typeof(FPE_INTOVF))) {
        private enum enumMixinStr_FPE_INTOVF = `enum FPE_INTOVF = FPE_INTOVF;`;
        static if(is(typeof({ mixin(enumMixinStr_FPE_INTOVF); }))) {
            mixin(enumMixinStr_FPE_INTOVF);
        }
    }






    static if(!is(typeof(FPE_INTDIV))) {
        private enum enumMixinStr_FPE_INTDIV = `enum FPE_INTDIV = FPE_INTDIV;`;
        static if(is(typeof({ mixin(enumMixinStr_FPE_INTDIV); }))) {
            mixin(enumMixinStr_FPE_INTDIV);
        }
    }




    static if(!is(typeof(ILL_BADIADDR))) {
        private enum enumMixinStr_ILL_BADIADDR = `enum ILL_BADIADDR = ILL_BADIADDR;`;
        static if(is(typeof({ mixin(enumMixinStr_ILL_BADIADDR); }))) {
            mixin(enumMixinStr_ILL_BADIADDR);
        }
    }






    static if(!is(typeof(ILL_BADSTK))) {
        private enum enumMixinStr_ILL_BADSTK = `enum ILL_BADSTK = ILL_BADSTK;`;
        static if(is(typeof({ mixin(enumMixinStr_ILL_BADSTK); }))) {
            mixin(enumMixinStr_ILL_BADSTK);
        }
    }




    static if(!is(typeof(ILL_COPROC))) {
        private enum enumMixinStr_ILL_COPROC = `enum ILL_COPROC = ILL_COPROC;`;
        static if(is(typeof({ mixin(enumMixinStr_ILL_COPROC); }))) {
            mixin(enumMixinStr_ILL_COPROC);
        }
    }






    static if(!is(typeof(ILL_PRVREG))) {
        private enum enumMixinStr_ILL_PRVREG = `enum ILL_PRVREG = ILL_PRVREG;`;
        static if(is(typeof({ mixin(enumMixinStr_ILL_PRVREG); }))) {
            mixin(enumMixinStr_ILL_PRVREG);
        }
    }




    static if(!is(typeof(ILL_PRVOPC))) {
        private enum enumMixinStr_ILL_PRVOPC = `enum ILL_PRVOPC = ILL_PRVOPC;`;
        static if(is(typeof({ mixin(enumMixinStr_ILL_PRVOPC); }))) {
            mixin(enumMixinStr_ILL_PRVOPC);
        }
    }






    static if(!is(typeof(ILL_ILLTRP))) {
        private enum enumMixinStr_ILL_ILLTRP = `enum ILL_ILLTRP = ILL_ILLTRP;`;
        static if(is(typeof({ mixin(enumMixinStr_ILL_ILLTRP); }))) {
            mixin(enumMixinStr_ILL_ILLTRP);
        }
    }




    static if(!is(typeof(ILL_ILLADR))) {
        private enum enumMixinStr_ILL_ILLADR = `enum ILL_ILLADR = ILL_ILLADR;`;
        static if(is(typeof({ mixin(enumMixinStr_ILL_ILLADR); }))) {
            mixin(enumMixinStr_ILL_ILLADR);
        }
    }






    static if(!is(typeof(ILL_ILLOPN))) {
        private enum enumMixinStr_ILL_ILLOPN = `enum ILL_ILLOPN = ILL_ILLOPN;`;
        static if(is(typeof({ mixin(enumMixinStr_ILL_ILLOPN); }))) {
            mixin(enumMixinStr_ILL_ILLOPN);
        }
    }




    static if(!is(typeof(ILL_ILLOPC))) {
        private enum enumMixinStr_ILL_ILLOPC = `enum ILL_ILLOPC = ILL_ILLOPC;`;
        static if(is(typeof({ mixin(enumMixinStr_ILL_ILLOPC); }))) {
            mixin(enumMixinStr_ILL_ILLOPC);
        }
    }






    static if(!is(typeof(SI_KERNEL))) {
        private enum enumMixinStr_SI_KERNEL = `enum SI_KERNEL = SI_KERNEL;`;
        static if(is(typeof({ mixin(enumMixinStr_SI_KERNEL); }))) {
            mixin(enumMixinStr_SI_KERNEL);
        }
    }




    static if(!is(typeof(SI_USER))) {
        private enum enumMixinStr_SI_USER = `enum SI_USER = SI_USER;`;
        static if(is(typeof({ mixin(enumMixinStr_SI_USER); }))) {
            mixin(enumMixinStr_SI_USER);
        }
    }






    static if(!is(typeof(SI_QUEUE))) {
        private enum enumMixinStr_SI_QUEUE = `enum SI_QUEUE = SI_QUEUE;`;
        static if(is(typeof({ mixin(enumMixinStr_SI_QUEUE); }))) {
            mixin(enumMixinStr_SI_QUEUE);
        }
    }




    static if(!is(typeof(SI_ASYNCIO))) {
        private enum enumMixinStr_SI_ASYNCIO = `enum SI_ASYNCIO = SI_ASYNCIO;`;
        static if(is(typeof({ mixin(enumMixinStr_SI_ASYNCIO); }))) {
            mixin(enumMixinStr_SI_ASYNCIO);
        }
    }






    static if(!is(typeof(SI_TIMER))) {
        private enum enumMixinStr_SI_TIMER = `enum SI_TIMER = SI_TIMER;`;
        static if(is(typeof({ mixin(enumMixinStr_SI_TIMER); }))) {
            mixin(enumMixinStr_SI_TIMER);
        }
    }




    static if(!is(typeof(SI_MESGQ))) {
        private enum enumMixinStr_SI_MESGQ = `enum SI_MESGQ = SI_MESGQ;`;
        static if(is(typeof({ mixin(enumMixinStr_SI_MESGQ); }))) {
            mixin(enumMixinStr_SI_MESGQ);
        }
    }






    static if(!is(typeof(SI_SIGIO))) {
        private enum enumMixinStr_SI_SIGIO = `enum SI_SIGIO = SI_SIGIO;`;
        static if(is(typeof({ mixin(enumMixinStr_SI_SIGIO); }))) {
            mixin(enumMixinStr_SI_SIGIO);
        }
    }






    static if(!is(typeof(SI_TKILL))) {
        private enum enumMixinStr_SI_TKILL = `enum SI_TKILL = SI_TKILL;`;
        static if(is(typeof({ mixin(enumMixinStr_SI_TKILL); }))) {
            mixin(enumMixinStr_SI_TKILL);
        }
    }




    static if(!is(typeof(SI_DETHREAD))) {
        private enum enumMixinStr_SI_DETHREAD = `enum SI_DETHREAD = SI_DETHREAD;`;
        static if(is(typeof({ mixin(enumMixinStr_SI_DETHREAD); }))) {
            mixin(enumMixinStr_SI_DETHREAD);
        }
    }






    static if(!is(typeof(SI_ASYNCNL))) {
        private enum enumMixinStr_SI_ASYNCNL = `enum SI_ASYNCNL = SI_ASYNCNL;`;
        static if(is(typeof({ mixin(enumMixinStr_SI_ASYNCNL); }))) {
            mixin(enumMixinStr_SI_ASYNCNL);
        }
    }




    static if(!is(typeof(__SI_ASYNCIO_AFTER_SIGIO))) {
        private enum enumMixinStr___SI_ASYNCIO_AFTER_SIGIO = `enum __SI_ASYNCIO_AFTER_SIGIO = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___SI_ASYNCIO_AFTER_SIGIO); }))) {
            mixin(enumMixinStr___SI_ASYNCIO_AFTER_SIGIO);
        }
    }






    static if(!is(typeof(_BITS_SIGINFO_CONSTS_H))) {
        private enum enumMixinStr__BITS_SIGINFO_CONSTS_H = `enum _BITS_SIGINFO_CONSTS_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_SIGINFO_CONSTS_H); }))) {
            mixin(enumMixinStr__BITS_SIGINFO_CONSTS_H);
        }
    }




    static if(!is(typeof(_BITS_SIGINFO_ARCH_H))) {
        private enum enumMixinStr__BITS_SIGINFO_ARCH_H = `enum _BITS_SIGINFO_ARCH_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_SIGINFO_ARCH_H); }))) {
            mixin(enumMixinStr__BITS_SIGINFO_ARCH_H);
        }
    }






    static if(!is(typeof(SIGEV_THREAD_ID))) {
        private enum enumMixinStr_SIGEV_THREAD_ID = `enum SIGEV_THREAD_ID = SIGEV_THREAD_ID;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGEV_THREAD_ID); }))) {
            mixin(enumMixinStr_SIGEV_THREAD_ID);
        }
    }




    static if(!is(typeof(SIGEV_THREAD))) {
        private enum enumMixinStr_SIGEV_THREAD = `enum SIGEV_THREAD = SIGEV_THREAD;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGEV_THREAD); }))) {
            mixin(enumMixinStr_SIGEV_THREAD);
        }
    }






    static if(!is(typeof(SIGEV_NONE))) {
        private enum enumMixinStr_SIGEV_NONE = `enum SIGEV_NONE = SIGEV_NONE;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGEV_NONE); }))) {
            mixin(enumMixinStr_SIGEV_NONE);
        }
    }




    static if(!is(typeof(SIGEV_SIGNAL))) {
        private enum enumMixinStr_SIGEV_SIGNAL = `enum SIGEV_SIGNAL = SIGEV_SIGNAL;`;
        static if(is(typeof({ mixin(enumMixinStr_SIGEV_SIGNAL); }))) {
            mixin(enumMixinStr_SIGEV_SIGNAL);
        }
    }






    static if(!is(typeof(_BITS_SIGEVENT_CONSTS_H))) {
        private enum enumMixinStr__BITS_SIGEVENT_CONSTS_H = `enum _BITS_SIGEVENT_CONSTS_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_SIGEVENT_CONSTS_H); }))) {
            mixin(enumMixinStr__BITS_SIGEVENT_CONSTS_H);
        }
    }




    static if(!is(typeof(FP_XSTATE_MAGIC2_SIZE))) {
        private enum enumMixinStr_FP_XSTATE_MAGIC2_SIZE = `enum FP_XSTATE_MAGIC2_SIZE = ( FP_XSTATE_MAGIC2 ) .sizeof;`;
        static if(is(typeof({ mixin(enumMixinStr_FP_XSTATE_MAGIC2_SIZE); }))) {
            mixin(enumMixinStr_FP_XSTATE_MAGIC2_SIZE);
        }
    }






    static if(!is(typeof(FP_XSTATE_MAGIC2))) {
        private enum enumMixinStr_FP_XSTATE_MAGIC2 = `enum FP_XSTATE_MAGIC2 = 0x46505845U;`;
        static if(is(typeof({ mixin(enumMixinStr_FP_XSTATE_MAGIC2); }))) {
            mixin(enumMixinStr_FP_XSTATE_MAGIC2);
        }
    }




    static if(!is(typeof(FP_XSTATE_MAGIC1))) {
        private enum enumMixinStr_FP_XSTATE_MAGIC1 = `enum FP_XSTATE_MAGIC1 = 0x46505853U;`;
        static if(is(typeof({ mixin(enumMixinStr_FP_XSTATE_MAGIC1); }))) {
            mixin(enumMixinStr_FP_XSTATE_MAGIC1);
        }
    }






    static if(!is(typeof(_BITS_SIGCONTEXT_H))) {
        private enum enumMixinStr__BITS_SIGCONTEXT_H = `enum _BITS_SIGCONTEXT_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_SIGCONTEXT_H); }))) {
            mixin(enumMixinStr__BITS_SIGCONTEXT_H);
        }
    }




    static if(!is(typeof(SIG_SETMASK))) {
        private enum enumMixinStr_SIG_SETMASK = `enum SIG_SETMASK = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_SIG_SETMASK); }))) {
            mixin(enumMixinStr_SIG_SETMASK);
        }
    }






    static if(!is(typeof(SIG_UNBLOCK))) {
        private enum enumMixinStr_SIG_UNBLOCK = `enum SIG_UNBLOCK = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_SIG_UNBLOCK); }))) {
            mixin(enumMixinStr_SIG_UNBLOCK);
        }
    }




    static if(!is(typeof(SIG_BLOCK))) {
        private enum enumMixinStr_SIG_BLOCK = `enum SIG_BLOCK = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_SIG_BLOCK); }))) {
            mixin(enumMixinStr_SIG_BLOCK);
        }
    }






    static if(!is(typeof(SA_STACK))) {
        private enum enumMixinStr_SA_STACK = `enum SA_STACK = SA_ONSTACK;`;
        static if(is(typeof({ mixin(enumMixinStr_SA_STACK); }))) {
            mixin(enumMixinStr_SA_STACK);
        }
    }




    static if(!is(typeof(SA_ONESHOT))) {
        private enum enumMixinStr_SA_ONESHOT = `enum SA_ONESHOT = SA_RESETHAND;`;
        static if(is(typeof({ mixin(enumMixinStr_SA_ONESHOT); }))) {
            mixin(enumMixinStr_SA_ONESHOT);
        }
    }






    static if(!is(typeof(SA_NOMASK))) {
        private enum enumMixinStr_SA_NOMASK = `enum SA_NOMASK = SA_NODEFER;`;
        static if(is(typeof({ mixin(enumMixinStr_SA_NOMASK); }))) {
            mixin(enumMixinStr_SA_NOMASK);
        }
    }




    static if(!is(typeof(SA_INTERRUPT))) {
        private enum enumMixinStr_SA_INTERRUPT = `enum SA_INTERRUPT = 0x20000000;`;
        static if(is(typeof({ mixin(enumMixinStr_SA_INTERRUPT); }))) {
            mixin(enumMixinStr_SA_INTERRUPT);
        }
    }






    static if(!is(typeof(SA_RESETHAND))) {
        private enum enumMixinStr_SA_RESETHAND = `enum SA_RESETHAND = 0x80000000;`;
        static if(is(typeof({ mixin(enumMixinStr_SA_RESETHAND); }))) {
            mixin(enumMixinStr_SA_RESETHAND);
        }
    }




    static if(!is(typeof(SA_NODEFER))) {
        private enum enumMixinStr_SA_NODEFER = `enum SA_NODEFER = 0x40000000;`;
        static if(is(typeof({ mixin(enumMixinStr_SA_NODEFER); }))) {
            mixin(enumMixinStr_SA_NODEFER);
        }
    }




    static if(!is(typeof(SA_RESTART))) {
        private enum enumMixinStr_SA_RESTART = `enum SA_RESTART = 0x10000000;`;
        static if(is(typeof({ mixin(enumMixinStr_SA_RESTART); }))) {
            mixin(enumMixinStr_SA_RESTART);
        }
    }




    static if(!is(typeof(SA_ONSTACK))) {
        private enum enumMixinStr_SA_ONSTACK = `enum SA_ONSTACK = 0x08000000;`;
        static if(is(typeof({ mixin(enumMixinStr_SA_ONSTACK); }))) {
            mixin(enumMixinStr_SA_ONSTACK);
        }
    }




    static if(!is(typeof(SA_SIGINFO))) {
        private enum enumMixinStr_SA_SIGINFO = `enum SA_SIGINFO = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_SA_SIGINFO); }))) {
            mixin(enumMixinStr_SA_SIGINFO);
        }
    }




    static if(!is(typeof(SA_NOCLDWAIT))) {
        private enum enumMixinStr_SA_NOCLDWAIT = `enum SA_NOCLDWAIT = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_SA_NOCLDWAIT); }))) {
            mixin(enumMixinStr_SA_NOCLDWAIT);
        }
    }




    static if(!is(typeof(SA_NOCLDSTOP))) {
        private enum enumMixinStr_SA_NOCLDSTOP = `enum SA_NOCLDSTOP = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_SA_NOCLDSTOP); }))) {
            mixin(enumMixinStr_SA_NOCLDSTOP);
        }
    }




    static if(!is(typeof(sa_sigaction))) {
        private enum enumMixinStr_sa_sigaction = `enum sa_sigaction = __sigaction_handler . sa_sigaction;`;
        static if(is(typeof({ mixin(enumMixinStr_sa_sigaction); }))) {
            mixin(enumMixinStr_sa_sigaction);
        }
    }




    static if(!is(typeof(sa_handler))) {
        private enum enumMixinStr_sa_handler = `enum sa_handler = __sigaction_handler . sa_handler;`;
        static if(is(typeof({ mixin(enumMixinStr_sa_handler); }))) {
            mixin(enumMixinStr_sa_handler);
        }
    }




    static if(!is(typeof(_BITS_SIGACTION_H))) {
        private enum enumMixinStr__BITS_SIGACTION_H = `enum _BITS_SIGACTION_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_SIGACTION_H); }))) {
            mixin(enumMixinStr__BITS_SIGACTION_H);
        }
    }




    static if(!is(typeof(_BITS_SETJMP_H))) {
        private enum enumMixinStr__BITS_SETJMP_H = `enum _BITS_SETJMP_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_SETJMP_H); }))) {
            mixin(enumMixinStr__BITS_SETJMP_H);
        }
    }
    static if(!is(typeof(__FD_ZERO_STOS))) {
        private enum enumMixinStr___FD_ZERO_STOS = `enum __FD_ZERO_STOS = "stosq";`;
        static if(is(typeof({ mixin(enumMixinStr___FD_ZERO_STOS); }))) {
            mixin(enumMixinStr___FD_ZERO_STOS);
        }
    }




    static if(!is(typeof(SCHED_RR))) {
        private enum enumMixinStr_SCHED_RR = `enum SCHED_RR = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_SCHED_RR); }))) {
            mixin(enumMixinStr_SCHED_RR);
        }
    }




    static if(!is(typeof(SCHED_FIFO))) {
        private enum enumMixinStr_SCHED_FIFO = `enum SCHED_FIFO = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_SCHED_FIFO); }))) {
            mixin(enumMixinStr_SCHED_FIFO);
        }
    }




    static if(!is(typeof(SCHED_OTHER))) {
        private enum enumMixinStr_SCHED_OTHER = `enum SCHED_OTHER = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_SCHED_OTHER); }))) {
            mixin(enumMixinStr_SCHED_OTHER);
        }
    }




    static if(!is(typeof(_BITS_SCHED_H))) {
        private enum enumMixinStr__BITS_SCHED_H = `enum _BITS_SCHED_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_SCHED_H); }))) {
            mixin(enumMixinStr__BITS_SCHED_H);
        }
    }




    static if(!is(typeof(__have_pthread_attr_t))) {
        private enum enumMixinStr___have_pthread_attr_t = `enum __have_pthread_attr_t = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___have_pthread_attr_t); }))) {
            mixin(enumMixinStr___have_pthread_attr_t);
        }
    }




    static if(!is(typeof(_BITS_PTHREADTYPES_COMMON_H))) {
        private enum enumMixinStr__BITS_PTHREADTYPES_COMMON_H = `enum _BITS_PTHREADTYPES_COMMON_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_PTHREADTYPES_COMMON_H); }))) {
            mixin(enumMixinStr__BITS_PTHREADTYPES_COMMON_H);
        }
    }
    static if(!is(typeof(__SIZEOF_PTHREAD_BARRIERATTR_T))) {
        private enum enumMixinStr___SIZEOF_PTHREAD_BARRIERATTR_T = `enum __SIZEOF_PTHREAD_BARRIERATTR_T = 4;`;
        static if(is(typeof({ mixin(enumMixinStr___SIZEOF_PTHREAD_BARRIERATTR_T); }))) {
            mixin(enumMixinStr___SIZEOF_PTHREAD_BARRIERATTR_T);
        }
    }




    static if(!is(typeof(__SIZEOF_PTHREAD_RWLOCKATTR_T))) {
        private enum enumMixinStr___SIZEOF_PTHREAD_RWLOCKATTR_T = `enum __SIZEOF_PTHREAD_RWLOCKATTR_T = 8;`;
        static if(is(typeof({ mixin(enumMixinStr___SIZEOF_PTHREAD_RWLOCKATTR_T); }))) {
            mixin(enumMixinStr___SIZEOF_PTHREAD_RWLOCKATTR_T);
        }
    }




    static if(!is(typeof(__SIZEOF_PTHREAD_CONDATTR_T))) {
        private enum enumMixinStr___SIZEOF_PTHREAD_CONDATTR_T = `enum __SIZEOF_PTHREAD_CONDATTR_T = 4;`;
        static if(is(typeof({ mixin(enumMixinStr___SIZEOF_PTHREAD_CONDATTR_T); }))) {
            mixin(enumMixinStr___SIZEOF_PTHREAD_CONDATTR_T);
        }
    }




    static if(!is(typeof(__SIZEOF_PTHREAD_COND_T))) {
        private enum enumMixinStr___SIZEOF_PTHREAD_COND_T = `enum __SIZEOF_PTHREAD_COND_T = 48;`;
        static if(is(typeof({ mixin(enumMixinStr___SIZEOF_PTHREAD_COND_T); }))) {
            mixin(enumMixinStr___SIZEOF_PTHREAD_COND_T);
        }
    }




    static if(!is(typeof(__SIZEOF_PTHREAD_MUTEXATTR_T))) {
        private enum enumMixinStr___SIZEOF_PTHREAD_MUTEXATTR_T = `enum __SIZEOF_PTHREAD_MUTEXATTR_T = 4;`;
        static if(is(typeof({ mixin(enumMixinStr___SIZEOF_PTHREAD_MUTEXATTR_T); }))) {
            mixin(enumMixinStr___SIZEOF_PTHREAD_MUTEXATTR_T);
        }
    }




    static if(!is(typeof(__SIZEOF_PTHREAD_BARRIER_T))) {
        private enum enumMixinStr___SIZEOF_PTHREAD_BARRIER_T = `enum __SIZEOF_PTHREAD_BARRIER_T = 32;`;
        static if(is(typeof({ mixin(enumMixinStr___SIZEOF_PTHREAD_BARRIER_T); }))) {
            mixin(enumMixinStr___SIZEOF_PTHREAD_BARRIER_T);
        }
    }






    static if(!is(typeof(__SIZEOF_PTHREAD_RWLOCK_T))) {
        private enum enumMixinStr___SIZEOF_PTHREAD_RWLOCK_T = `enum __SIZEOF_PTHREAD_RWLOCK_T = 56;`;
        static if(is(typeof({ mixin(enumMixinStr___SIZEOF_PTHREAD_RWLOCK_T); }))) {
            mixin(enumMixinStr___SIZEOF_PTHREAD_RWLOCK_T);
        }
    }






    static if(!is(typeof(__SIZEOF_PTHREAD_ATTR_T))) {
        private enum enumMixinStr___SIZEOF_PTHREAD_ATTR_T = `enum __SIZEOF_PTHREAD_ATTR_T = 56;`;
        static if(is(typeof({ mixin(enumMixinStr___SIZEOF_PTHREAD_ATTR_T); }))) {
            mixin(enumMixinStr___SIZEOF_PTHREAD_ATTR_T);
        }
    }




    static if(!is(typeof(__SIZEOF_PTHREAD_MUTEX_T))) {
        private enum enumMixinStr___SIZEOF_PTHREAD_MUTEX_T = `enum __SIZEOF_PTHREAD_MUTEX_T = 40;`;
        static if(is(typeof({ mixin(enumMixinStr___SIZEOF_PTHREAD_MUTEX_T); }))) {
            mixin(enumMixinStr___SIZEOF_PTHREAD_MUTEX_T);
        }
    }






    static if(!is(typeof(_BITS_PTHREADTYPES_ARCH_H))) {
        private enum enumMixinStr__BITS_PTHREADTYPES_ARCH_H = `enum _BITS_PTHREADTYPES_ARCH_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_PTHREADTYPES_ARCH_H); }))) {
            mixin(enumMixinStr__BITS_PTHREADTYPES_ARCH_H);
        }
    }




    static if(!is(typeof(_POSIX_TYPED_MEMORY_OBJECTS))) {
        private enum enumMixinStr__POSIX_TYPED_MEMORY_OBJECTS = `enum _POSIX_TYPED_MEMORY_OBJECTS = - 1;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_TYPED_MEMORY_OBJECTS); }))) {
            mixin(enumMixinStr__POSIX_TYPED_MEMORY_OBJECTS);
        }
    }
    static if(!is(typeof(_POSIX_TRACE_LOG))) {
        private enum enumMixinStr__POSIX_TRACE_LOG = `enum _POSIX_TRACE_LOG = - 1;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_TRACE_LOG); }))) {
            mixin(enumMixinStr__POSIX_TRACE_LOG);
        }
    }




    static if(!is(typeof(_POSIX_TRACE_INHERIT))) {
        private enum enumMixinStr__POSIX_TRACE_INHERIT = `enum _POSIX_TRACE_INHERIT = - 1;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_TRACE_INHERIT); }))) {
            mixin(enumMixinStr__POSIX_TRACE_INHERIT);
        }
    }




    static if(!is(typeof(_POSIX_TRACE_EVENT_FILTER))) {
        private enum enumMixinStr__POSIX_TRACE_EVENT_FILTER = `enum _POSIX_TRACE_EVENT_FILTER = - 1;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_TRACE_EVENT_FILTER); }))) {
            mixin(enumMixinStr__POSIX_TRACE_EVENT_FILTER);
        }
    }




    static if(!is(typeof(_POSIX_TRACE))) {
        private enum enumMixinStr__POSIX_TRACE = `enum _POSIX_TRACE = - 1;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_TRACE); }))) {
            mixin(enumMixinStr__POSIX_TRACE);
        }
    }




    static if(!is(typeof(_POSIX_THREAD_SPORADIC_SERVER))) {
        private enum enumMixinStr__POSIX_THREAD_SPORADIC_SERVER = `enum _POSIX_THREAD_SPORADIC_SERVER = - 1;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_THREAD_SPORADIC_SERVER); }))) {
            mixin(enumMixinStr__POSIX_THREAD_SPORADIC_SERVER);
        }
    }




    static if(!is(typeof(_POSIX_SPORADIC_SERVER))) {
        private enum enumMixinStr__POSIX_SPORADIC_SERVER = `enum _POSIX_SPORADIC_SERVER = - 1;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_SPORADIC_SERVER); }))) {
            mixin(enumMixinStr__POSIX_SPORADIC_SERVER);
        }
    }




    static if(!is(typeof(_POSIX2_CHAR_TERM))) {
        private enum enumMixinStr__POSIX2_CHAR_TERM = `enum _POSIX2_CHAR_TERM = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX2_CHAR_TERM); }))) {
            mixin(enumMixinStr__POSIX2_CHAR_TERM);
        }
    }




    static if(!is(typeof(_POSIX_RAW_SOCKETS))) {
        private enum enumMixinStr__POSIX_RAW_SOCKETS = `enum _POSIX_RAW_SOCKETS = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_RAW_SOCKETS); }))) {
            mixin(enumMixinStr__POSIX_RAW_SOCKETS);
        }
    }




    static if(!is(typeof(_POSIX_IPV6))) {
        private enum enumMixinStr__POSIX_IPV6 = `enum _POSIX_IPV6 = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_IPV6); }))) {
            mixin(enumMixinStr__POSIX_IPV6);
        }
    }




    static if(!is(typeof(_POSIX_ADVISORY_INFO))) {
        private enum enumMixinStr__POSIX_ADVISORY_INFO = `enum _POSIX_ADVISORY_INFO = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_ADVISORY_INFO); }))) {
            mixin(enumMixinStr__POSIX_ADVISORY_INFO);
        }
    }




    static if(!is(typeof(_POSIX_CLOCK_SELECTION))) {
        private enum enumMixinStr__POSIX_CLOCK_SELECTION = `enum _POSIX_CLOCK_SELECTION = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_CLOCK_SELECTION); }))) {
            mixin(enumMixinStr__POSIX_CLOCK_SELECTION);
        }
    }




    static if(!is(typeof(_POSIX_MONOTONIC_CLOCK))) {
        private enum enumMixinStr__POSIX_MONOTONIC_CLOCK = `enum _POSIX_MONOTONIC_CLOCK = 0;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_MONOTONIC_CLOCK); }))) {
            mixin(enumMixinStr__POSIX_MONOTONIC_CLOCK);
        }
    }




    static if(!is(typeof(_POSIX_THREAD_PROCESS_SHARED))) {
        private enum enumMixinStr__POSIX_THREAD_PROCESS_SHARED = `enum _POSIX_THREAD_PROCESS_SHARED = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_THREAD_PROCESS_SHARED); }))) {
            mixin(enumMixinStr__POSIX_THREAD_PROCESS_SHARED);
        }
    }




    static if(!is(typeof(_POSIX_MESSAGE_PASSING))) {
        private enum enumMixinStr__POSIX_MESSAGE_PASSING = `enum _POSIX_MESSAGE_PASSING = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_MESSAGE_PASSING); }))) {
            mixin(enumMixinStr__POSIX_MESSAGE_PASSING);
        }
    }




    static if(!is(typeof(_POSIX_BARRIERS))) {
        private enum enumMixinStr__POSIX_BARRIERS = `enum _POSIX_BARRIERS = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_BARRIERS); }))) {
            mixin(enumMixinStr__POSIX_BARRIERS);
        }
    }




    static if(!is(typeof(_POSIX_TIMERS))) {
        private enum enumMixinStr__POSIX_TIMERS = `enum _POSIX_TIMERS = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_TIMERS); }))) {
            mixin(enumMixinStr__POSIX_TIMERS);
        }
    }




    static if(!is(typeof(_POSIX_SPAWN))) {
        private enum enumMixinStr__POSIX_SPAWN = `enum _POSIX_SPAWN = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_SPAWN); }))) {
            mixin(enumMixinStr__POSIX_SPAWN);
        }
    }




    static if(!is(typeof(_POSIX_SPIN_LOCKS))) {
        private enum enumMixinStr__POSIX_SPIN_LOCKS = `enum _POSIX_SPIN_LOCKS = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_SPIN_LOCKS); }))) {
            mixin(enumMixinStr__POSIX_SPIN_LOCKS);
        }
    }




    static if(!is(typeof(_POSIX_TIMEOUTS))) {
        private enum enumMixinStr__POSIX_TIMEOUTS = `enum _POSIX_TIMEOUTS = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_TIMEOUTS); }))) {
            mixin(enumMixinStr__POSIX_TIMEOUTS);
        }
    }




    static if(!is(typeof(_POSIX_SHELL))) {
        private enum enumMixinStr__POSIX_SHELL = `enum _POSIX_SHELL = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_SHELL); }))) {
            mixin(enumMixinStr__POSIX_SHELL);
        }
    }




    static if(!is(typeof(_POSIX_READER_WRITER_LOCKS))) {
        private enum enumMixinStr__POSIX_READER_WRITER_LOCKS = `enum _POSIX_READER_WRITER_LOCKS = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_READER_WRITER_LOCKS); }))) {
            mixin(enumMixinStr__POSIX_READER_WRITER_LOCKS);
        }
    }




    static if(!is(typeof(_POSIX_REGEXP))) {
        private enum enumMixinStr__POSIX_REGEXP = `enum _POSIX_REGEXP = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_REGEXP); }))) {
            mixin(enumMixinStr__POSIX_REGEXP);
        }
    }




    static if(!is(typeof(_POSIX_THREAD_CPUTIME))) {
        private enum enumMixinStr__POSIX_THREAD_CPUTIME = `enum _POSIX_THREAD_CPUTIME = 0;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_THREAD_CPUTIME); }))) {
            mixin(enumMixinStr__POSIX_THREAD_CPUTIME);
        }
    }




    static if(!is(typeof(_POSIX_CPUTIME))) {
        private enum enumMixinStr__POSIX_CPUTIME = `enum _POSIX_CPUTIME = 0;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_CPUTIME); }))) {
            mixin(enumMixinStr__POSIX_CPUTIME);
        }
    }




    static if(!is(typeof(_POSIX_SHARED_MEMORY_OBJECTS))) {
        private enum enumMixinStr__POSIX_SHARED_MEMORY_OBJECTS = `enum _POSIX_SHARED_MEMORY_OBJECTS = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_SHARED_MEMORY_OBJECTS); }))) {
            mixin(enumMixinStr__POSIX_SHARED_MEMORY_OBJECTS);
        }
    }




    static if(!is(typeof(_LFS64_STDIO))) {
        private enum enumMixinStr__LFS64_STDIO = `enum _LFS64_STDIO = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__LFS64_STDIO); }))) {
            mixin(enumMixinStr__LFS64_STDIO);
        }
    }




    static if(!is(typeof(_LFS64_LARGEFILE))) {
        private enum enumMixinStr__LFS64_LARGEFILE = `enum _LFS64_LARGEFILE = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__LFS64_LARGEFILE); }))) {
            mixin(enumMixinStr__LFS64_LARGEFILE);
        }
    }




    static if(!is(typeof(_LFS_LARGEFILE))) {
        private enum enumMixinStr__LFS_LARGEFILE = `enum _LFS_LARGEFILE = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__LFS_LARGEFILE); }))) {
            mixin(enumMixinStr__LFS_LARGEFILE);
        }
    }




    static if(!is(typeof(_LFS64_ASYNCHRONOUS_IO))) {
        private enum enumMixinStr__LFS64_ASYNCHRONOUS_IO = `enum _LFS64_ASYNCHRONOUS_IO = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__LFS64_ASYNCHRONOUS_IO); }))) {
            mixin(enumMixinStr__LFS64_ASYNCHRONOUS_IO);
        }
    }




    static if(!is(typeof(_POSIX_PRIORITIZED_IO))) {
        private enum enumMixinStr__POSIX_PRIORITIZED_IO = `enum _POSIX_PRIORITIZED_IO = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_PRIORITIZED_IO); }))) {
            mixin(enumMixinStr__POSIX_PRIORITIZED_IO);
        }
    }




    static if(!is(typeof(_LFS_ASYNCHRONOUS_IO))) {
        private enum enumMixinStr__LFS_ASYNCHRONOUS_IO = `enum _LFS_ASYNCHRONOUS_IO = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__LFS_ASYNCHRONOUS_IO); }))) {
            mixin(enumMixinStr__LFS_ASYNCHRONOUS_IO);
        }
    }




    static if(!is(typeof(_POSIX_ASYNC_IO))) {
        private enum enumMixinStr__POSIX_ASYNC_IO = `enum _POSIX_ASYNC_IO = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_ASYNC_IO); }))) {
            mixin(enumMixinStr__POSIX_ASYNC_IO);
        }
    }




    static if(!is(typeof(_POSIX_ASYNCHRONOUS_IO))) {
        private enum enumMixinStr__POSIX_ASYNCHRONOUS_IO = `enum _POSIX_ASYNCHRONOUS_IO = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_ASYNCHRONOUS_IO); }))) {
            mixin(enumMixinStr__POSIX_ASYNCHRONOUS_IO);
        }
    }




    static if(!is(typeof(_POSIX_REALTIME_SIGNALS))) {
        private enum enumMixinStr__POSIX_REALTIME_SIGNALS = `enum _POSIX_REALTIME_SIGNALS = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_REALTIME_SIGNALS); }))) {
            mixin(enumMixinStr__POSIX_REALTIME_SIGNALS);
        }
    }




    static if(!is(typeof(_POSIX_SEMAPHORES))) {
        private enum enumMixinStr__POSIX_SEMAPHORES = `enum _POSIX_SEMAPHORES = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_SEMAPHORES); }))) {
            mixin(enumMixinStr__POSIX_SEMAPHORES);
        }
    }




    static if(!is(typeof(_POSIX_THREAD_ROBUST_PRIO_PROTECT))) {
        private enum enumMixinStr__POSIX_THREAD_ROBUST_PRIO_PROTECT = `enum _POSIX_THREAD_ROBUST_PRIO_PROTECT = - 1;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_THREAD_ROBUST_PRIO_PROTECT); }))) {
            mixin(enumMixinStr__POSIX_THREAD_ROBUST_PRIO_PROTECT);
        }
    }




    static if(!is(typeof(_POSIX_THREAD_ROBUST_PRIO_INHERIT))) {
        private enum enumMixinStr__POSIX_THREAD_ROBUST_PRIO_INHERIT = `enum _POSIX_THREAD_ROBUST_PRIO_INHERIT = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_THREAD_ROBUST_PRIO_INHERIT); }))) {
            mixin(enumMixinStr__POSIX_THREAD_ROBUST_PRIO_INHERIT);
        }
    }




    static if(!is(typeof(_POSIX_THREAD_PRIO_PROTECT))) {
        private enum enumMixinStr__POSIX_THREAD_PRIO_PROTECT = `enum _POSIX_THREAD_PRIO_PROTECT = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_THREAD_PRIO_PROTECT); }))) {
            mixin(enumMixinStr__POSIX_THREAD_PRIO_PROTECT);
        }
    }




    static if(!is(typeof(_POSIX_THREAD_PRIO_INHERIT))) {
        private enum enumMixinStr__POSIX_THREAD_PRIO_INHERIT = `enum _POSIX_THREAD_PRIO_INHERIT = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_THREAD_PRIO_INHERIT); }))) {
            mixin(enumMixinStr__POSIX_THREAD_PRIO_INHERIT);
        }
    }




    static if(!is(typeof(_POSIX_THREAD_ATTR_STACKADDR))) {
        private enum enumMixinStr__POSIX_THREAD_ATTR_STACKADDR = `enum _POSIX_THREAD_ATTR_STACKADDR = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_THREAD_ATTR_STACKADDR); }))) {
            mixin(enumMixinStr__POSIX_THREAD_ATTR_STACKADDR);
        }
    }




    static if(!is(typeof(_POSIX_THREAD_ATTR_STACKSIZE))) {
        private enum enumMixinStr__POSIX_THREAD_ATTR_STACKSIZE = `enum _POSIX_THREAD_ATTR_STACKSIZE = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_THREAD_ATTR_STACKSIZE); }))) {
            mixin(enumMixinStr__POSIX_THREAD_ATTR_STACKSIZE);
        }
    }




    static if(!is(typeof(_POSIX_THREAD_PRIORITY_SCHEDULING))) {
        private enum enumMixinStr__POSIX_THREAD_PRIORITY_SCHEDULING = `enum _POSIX_THREAD_PRIORITY_SCHEDULING = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_THREAD_PRIORITY_SCHEDULING); }))) {
            mixin(enumMixinStr__POSIX_THREAD_PRIORITY_SCHEDULING);
        }
    }




    static if(!is(typeof(_POSIX_THREAD_SAFE_FUNCTIONS))) {
        private enum enumMixinStr__POSIX_THREAD_SAFE_FUNCTIONS = `enum _POSIX_THREAD_SAFE_FUNCTIONS = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_THREAD_SAFE_FUNCTIONS); }))) {
            mixin(enumMixinStr__POSIX_THREAD_SAFE_FUNCTIONS);
        }
    }




    static if(!is(typeof(_POSIX_REENTRANT_FUNCTIONS))) {
        private enum enumMixinStr__POSIX_REENTRANT_FUNCTIONS = `enum _POSIX_REENTRANT_FUNCTIONS = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_REENTRANT_FUNCTIONS); }))) {
            mixin(enumMixinStr__POSIX_REENTRANT_FUNCTIONS);
        }
    }




    static if(!is(typeof(_POSIX_THREADS))) {
        private enum enumMixinStr__POSIX_THREADS = `enum _POSIX_THREADS = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_THREADS); }))) {
            mixin(enumMixinStr__POSIX_THREADS);
        }
    }




    static if(!is(typeof(_XOPEN_SHM))) {
        private enum enumMixinStr__XOPEN_SHM = `enum _XOPEN_SHM = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__XOPEN_SHM); }))) {
            mixin(enumMixinStr__XOPEN_SHM);
        }
    }




    static if(!is(typeof(_XOPEN_REALTIME_THREADS))) {
        private enum enumMixinStr__XOPEN_REALTIME_THREADS = `enum _XOPEN_REALTIME_THREADS = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__XOPEN_REALTIME_THREADS); }))) {
            mixin(enumMixinStr__XOPEN_REALTIME_THREADS);
        }
    }




    static if(!is(typeof(_XOPEN_REALTIME))) {
        private enum enumMixinStr__XOPEN_REALTIME = `enum _XOPEN_REALTIME = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__XOPEN_REALTIME); }))) {
            mixin(enumMixinStr__XOPEN_REALTIME);
        }
    }




    static if(!is(typeof(_POSIX_NO_TRUNC))) {
        private enum enumMixinStr__POSIX_NO_TRUNC = `enum _POSIX_NO_TRUNC = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_NO_TRUNC); }))) {
            mixin(enumMixinStr__POSIX_NO_TRUNC);
        }
    }




    static if(!is(typeof(_POSIX_VDISABLE))) {
        private enum enumMixinStr__POSIX_VDISABLE = `enum _POSIX_VDISABLE = '\0';`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_VDISABLE); }))) {
            mixin(enumMixinStr__POSIX_VDISABLE);
        }
    }




    static if(!is(typeof(_POSIX_CHOWN_RESTRICTED))) {
        private enum enumMixinStr__POSIX_CHOWN_RESTRICTED = `enum _POSIX_CHOWN_RESTRICTED = 0;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_CHOWN_RESTRICTED); }))) {
            mixin(enumMixinStr__POSIX_CHOWN_RESTRICTED);
        }
    }




    static if(!is(typeof(_POSIX_MEMORY_PROTECTION))) {
        private enum enumMixinStr__POSIX_MEMORY_PROTECTION = `enum _POSIX_MEMORY_PROTECTION = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_MEMORY_PROTECTION); }))) {
            mixin(enumMixinStr__POSIX_MEMORY_PROTECTION);
        }
    }




    static if(!is(typeof(_POSIX_MEMLOCK_RANGE))) {
        private enum enumMixinStr__POSIX_MEMLOCK_RANGE = `enum _POSIX_MEMLOCK_RANGE = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_MEMLOCK_RANGE); }))) {
            mixin(enumMixinStr__POSIX_MEMLOCK_RANGE);
        }
    }




    static if(!is(typeof(_POSIX_MEMLOCK))) {
        private enum enumMixinStr__POSIX_MEMLOCK = `enum _POSIX_MEMLOCK = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_MEMLOCK); }))) {
            mixin(enumMixinStr__POSIX_MEMLOCK);
        }
    }




    static if(!is(typeof(_POSIX_MAPPED_FILES))) {
        private enum enumMixinStr__POSIX_MAPPED_FILES = `enum _POSIX_MAPPED_FILES = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_MAPPED_FILES); }))) {
            mixin(enumMixinStr__POSIX_MAPPED_FILES);
        }
    }




    static if(!is(typeof(_POSIX_FSYNC))) {
        private enum enumMixinStr__POSIX_FSYNC = `enum _POSIX_FSYNC = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_FSYNC); }))) {
            mixin(enumMixinStr__POSIX_FSYNC);
        }
    }




    static if(!is(typeof(_POSIX_SYNCHRONIZED_IO))) {
        private enum enumMixinStr__POSIX_SYNCHRONIZED_IO = `enum _POSIX_SYNCHRONIZED_IO = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_SYNCHRONIZED_IO); }))) {
            mixin(enumMixinStr__POSIX_SYNCHRONIZED_IO);
        }
    }




    static if(!is(typeof(_POSIX_PRIORITY_SCHEDULING))) {
        private enum enumMixinStr__POSIX_PRIORITY_SCHEDULING = `enum _POSIX_PRIORITY_SCHEDULING = 200809L;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_PRIORITY_SCHEDULING); }))) {
            mixin(enumMixinStr__POSIX_PRIORITY_SCHEDULING);
        }
    }




    static if(!is(typeof(_POSIX_SAVED_IDS))) {
        private enum enumMixinStr__POSIX_SAVED_IDS = `enum _POSIX_SAVED_IDS = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_SAVED_IDS); }))) {
            mixin(enumMixinStr__POSIX_SAVED_IDS);
        }
    }




    static if(!is(typeof(_POSIX_JOB_CONTROL))) {
        private enum enumMixinStr__POSIX_JOB_CONTROL = `enum _POSIX_JOB_CONTROL = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_JOB_CONTROL); }))) {
            mixin(enumMixinStr__POSIX_JOB_CONTROL);
        }
    }




    static if(!is(typeof(_BITS_POSIX_OPT_H))) {
        private enum enumMixinStr__BITS_POSIX_OPT_H = `enum _BITS_POSIX_OPT_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_POSIX_OPT_H); }))) {
            mixin(enumMixinStr__BITS_POSIX_OPT_H);
        }
    }




    static if(!is(typeof(RE_DUP_MAX))) {
        private enum enumMixinStr_RE_DUP_MAX = `enum RE_DUP_MAX = ( 0x7fff );`;
        static if(is(typeof({ mixin(enumMixinStr_RE_DUP_MAX); }))) {
            mixin(enumMixinStr_RE_DUP_MAX);
        }
    }




    static if(!is(typeof(CHARCLASS_NAME_MAX))) {
        private enum enumMixinStr_CHARCLASS_NAME_MAX = `enum CHARCLASS_NAME_MAX = 2048;`;
        static if(is(typeof({ mixin(enumMixinStr_CHARCLASS_NAME_MAX); }))) {
            mixin(enumMixinStr_CHARCLASS_NAME_MAX);
        }
    }




    static if(!is(typeof(LINE_MAX))) {
        private enum enumMixinStr_LINE_MAX = `enum LINE_MAX = _POSIX2_LINE_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr_LINE_MAX); }))) {
            mixin(enumMixinStr_LINE_MAX);
        }
    }




    static if(!is(typeof(ipv4addr))) {
        private enum enumMixinStr_ipv4addr = `enum ipv4addr = __inaddr_u . __addr;`;
        static if(is(typeof({ mixin(enumMixinStr_ipv4addr); }))) {
            mixin(enumMixinStr_ipv4addr);
        }
    }




    static if(!is(typeof(ipv6addr))) {
        private enum enumMixinStr_ipv6addr = `enum ipv6addr = __inaddr_u . __addr6;`;
        static if(is(typeof({ mixin(enumMixinStr_ipv6addr); }))) {
            mixin(enumMixinStr_ipv6addr);
        }
    }
    static if(!is(typeof(ZSYS_RANDOF_FLT))) {
        private enum enumMixinStr_ZSYS_RANDOF_FLT = `enum ZSYS_RANDOF_FLT = float;`;
        static if(is(typeof({ mixin(enumMixinStr_ZSYS_RANDOF_FLT); }))) {
            mixin(enumMixinStr_ZSYS_RANDOF_FLT);
        }
    }




    static if(!is(typeof(ZSYS_RANDOF_FUNC))) {
        private enum enumMixinStr_ZSYS_RANDOF_FUNC = `enum ZSYS_RANDOF_FUNC = random;`;
        static if(is(typeof({ mixin(enumMixinStr_ZSYS_RANDOF_FUNC); }))) {
            mixin(enumMixinStr_ZSYS_RANDOF_FUNC);
        }
    }




    static if(!is(typeof(ZSYS_RANDOF_FUNC_BITS))) {
        private enum enumMixinStr_ZSYS_RANDOF_FUNC_BITS = `enum ZSYS_RANDOF_FUNC_BITS = 32;`;
        static if(is(typeof({ mixin(enumMixinStr_ZSYS_RANDOF_FUNC_BITS); }))) {
            mixin(enumMixinStr_ZSYS_RANDOF_FUNC_BITS);
        }
    }




    static if(!is(typeof(EXPR_NEST_MAX))) {
        private enum enumMixinStr_EXPR_NEST_MAX = `enum EXPR_NEST_MAX = _POSIX2_EXPR_NEST_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr_EXPR_NEST_MAX); }))) {
            mixin(enumMixinStr_EXPR_NEST_MAX);
        }
    }




    static if(!is(typeof(ZSYS_RANDOF_MAX))) {
        private enum enumMixinStr_ZSYS_RANDOF_MAX = `enum ZSYS_RANDOF_MAX = ( ( 4294967295U ) >> 6 );`;
        static if(is(typeof({ mixin(enumMixinStr_ZSYS_RANDOF_MAX); }))) {
            mixin(enumMixinStr_ZSYS_RANDOF_MAX);
        }
    }






    static if(!is(typeof(COLL_WEIGHTS_MAX))) {
        private enum enumMixinStr_COLL_WEIGHTS_MAX = `enum COLL_WEIGHTS_MAX = 255;`;
        static if(is(typeof({ mixin(enumMixinStr_COLL_WEIGHTS_MAX); }))) {
            mixin(enumMixinStr_COLL_WEIGHTS_MAX);
        }
    }




    static if(!is(typeof(BC_STRING_MAX))) {
        private enum enumMixinStr_BC_STRING_MAX = `enum BC_STRING_MAX = _POSIX2_BC_STRING_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr_BC_STRING_MAX); }))) {
            mixin(enumMixinStr_BC_STRING_MAX);
        }
    }






    static if(!is(typeof(BC_SCALE_MAX))) {
        private enum enumMixinStr_BC_SCALE_MAX = `enum BC_SCALE_MAX = _POSIX2_BC_SCALE_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr_BC_SCALE_MAX); }))) {
            mixin(enumMixinStr_BC_SCALE_MAX);
        }
    }




    static if(!is(typeof(BC_DIM_MAX))) {
        private enum enumMixinStr_BC_DIM_MAX = `enum BC_DIM_MAX = _POSIX2_BC_DIM_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr_BC_DIM_MAX); }))) {
            mixin(enumMixinStr_BC_DIM_MAX);
        }
    }




    static if(!is(typeof(BC_BASE_MAX))) {
        private enum enumMixinStr_BC_BASE_MAX = `enum BC_BASE_MAX = _POSIX2_BC_BASE_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr_BC_BASE_MAX); }))) {
            mixin(enumMixinStr_BC_BASE_MAX);
        }
    }




    static if(!is(typeof(_POSIX2_CHARCLASS_NAME_MAX))) {
        private enum enumMixinStr__POSIX2_CHARCLASS_NAME_MAX = `enum _POSIX2_CHARCLASS_NAME_MAX = 14;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX2_CHARCLASS_NAME_MAX); }))) {
            mixin(enumMixinStr__POSIX2_CHARCLASS_NAME_MAX);
        }
    }




    static if(!is(typeof(CZMQ_THREADLS))) {
        private enum enumMixinStr_CZMQ_THREADLS = `enum CZMQ_THREADLS = __thread;`;
        static if(is(typeof({ mixin(enumMixinStr_CZMQ_THREADLS); }))) {
            mixin(enumMixinStr_CZMQ_THREADLS);
        }
    }




    static if(!is(typeof(_POSIX2_RE_DUP_MAX))) {
        private enum enumMixinStr__POSIX2_RE_DUP_MAX = `enum _POSIX2_RE_DUP_MAX = 255;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX2_RE_DUP_MAX); }))) {
            mixin(enumMixinStr__POSIX2_RE_DUP_MAX);
        }
    }




    static if(!is(typeof(_POSIX2_LINE_MAX))) {
        private enum enumMixinStr__POSIX2_LINE_MAX = `enum _POSIX2_LINE_MAX = 2048;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX2_LINE_MAX); }))) {
            mixin(enumMixinStr__POSIX2_LINE_MAX);
        }
    }




    static if(!is(typeof(_POSIX2_EXPR_NEST_MAX))) {
        private enum enumMixinStr__POSIX2_EXPR_NEST_MAX = `enum _POSIX2_EXPR_NEST_MAX = 32;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX2_EXPR_NEST_MAX); }))) {
            mixin(enumMixinStr__POSIX2_EXPR_NEST_MAX);
        }
    }




    static if(!is(typeof(_POSIX2_COLL_WEIGHTS_MAX))) {
        private enum enumMixinStr__POSIX2_COLL_WEIGHTS_MAX = `enum _POSIX2_COLL_WEIGHTS_MAX = 2;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX2_COLL_WEIGHTS_MAX); }))) {
            mixin(enumMixinStr__POSIX2_COLL_WEIGHTS_MAX);
        }
    }




    static if(!is(typeof(_POSIX2_BC_STRING_MAX))) {
        private enum enumMixinStr__POSIX2_BC_STRING_MAX = `enum _POSIX2_BC_STRING_MAX = 1000;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX2_BC_STRING_MAX); }))) {
            mixin(enumMixinStr__POSIX2_BC_STRING_MAX);
        }
    }






    static if(!is(typeof(_POSIX2_BC_SCALE_MAX))) {
        private enum enumMixinStr__POSIX2_BC_SCALE_MAX = `enum _POSIX2_BC_SCALE_MAX = 99;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX2_BC_SCALE_MAX); }))) {
            mixin(enumMixinStr__POSIX2_BC_SCALE_MAX);
        }
    }




    static if(!is(typeof(_POSIX2_BC_DIM_MAX))) {
        private enum enumMixinStr__POSIX2_BC_DIM_MAX = `enum _POSIX2_BC_DIM_MAX = 2048;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX2_BC_DIM_MAX); }))) {
            mixin(enumMixinStr__POSIX2_BC_DIM_MAX);
        }
    }






    static if(!is(typeof(_POSIX2_BC_BASE_MAX))) {
        private enum enumMixinStr__POSIX2_BC_BASE_MAX = `enum _POSIX2_BC_BASE_MAX = 99;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX2_BC_BASE_MAX); }))) {
            mixin(enumMixinStr__POSIX2_BC_BASE_MAX);
        }
    }




    static if(!is(typeof(closesocket))) {
        private enum enumMixinStr_closesocket = `enum closesocket = close;`;
        static if(is(typeof({ mixin(enumMixinStr_closesocket); }))) {
            mixin(enumMixinStr_closesocket);
        }
    }




    static if(!is(typeof(INVALID_SOCKET))) {
        private enum enumMixinStr_INVALID_SOCKET = `enum INVALID_SOCKET = - 1;`;
        static if(is(typeof({ mixin(enumMixinStr_INVALID_SOCKET); }))) {
            mixin(enumMixinStr_INVALID_SOCKET);
        }
    }




    static if(!is(typeof(SOCKET_ERROR))) {
        private enum enumMixinStr_SOCKET_ERROR = `enum SOCKET_ERROR = - 1;`;
        static if(is(typeof({ mixin(enumMixinStr_SOCKET_ERROR); }))) {
            mixin(enumMixinStr_SOCKET_ERROR);
        }
    }




    static if(!is(typeof(O_BINARY))) {
        private enum enumMixinStr_O_BINARY = `enum O_BINARY = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_O_BINARY); }))) {
            mixin(enumMixinStr_O_BINARY);
        }
    }




    static if(!is(typeof(_BITS_POSIX2_LIM_H))) {
        private enum enumMixinStr__BITS_POSIX2_LIM_H = `enum _BITS_POSIX2_LIM_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_POSIX2_LIM_H); }))) {
            mixin(enumMixinStr__BITS_POSIX2_LIM_H);
        }
    }




    static if(!is(typeof(ZMQ_POLL_MSEC))) {
        private enum enumMixinStr_ZMQ_POLL_MSEC = `enum ZMQ_POLL_MSEC = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_ZMQ_POLL_MSEC); }))) {
            mixin(enumMixinStr_ZMQ_POLL_MSEC);
        }
    }






    static if(!is(typeof(SSIZE_MAX))) {
        private enum enumMixinStr_SSIZE_MAX = `enum SSIZE_MAX = 0x7fffffffffffffffL;`;
        static if(is(typeof({ mixin(enumMixinStr_SSIZE_MAX); }))) {
            mixin(enumMixinStr_SSIZE_MAX);
        }
    }




    static if(!is(typeof(_POSIX_CLOCKRES_MIN))) {
        private enum enumMixinStr__POSIX_CLOCKRES_MIN = `enum _POSIX_CLOCKRES_MIN = 20000000;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_CLOCKRES_MIN); }))) {
            mixin(enumMixinStr__POSIX_CLOCKRES_MIN);
        }
    }




    static if(!is(typeof(_POSIX_TZNAME_MAX))) {
        private enum enumMixinStr__POSIX_TZNAME_MAX = `enum _POSIX_TZNAME_MAX = 6;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_TZNAME_MAX); }))) {
            mixin(enumMixinStr__POSIX_TZNAME_MAX);
        }
    }




    static if(!is(typeof(_POSIX_TTY_NAME_MAX))) {
        private enum enumMixinStr__POSIX_TTY_NAME_MAX = `enum _POSIX_TTY_NAME_MAX = 9;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_TTY_NAME_MAX); }))) {
            mixin(enumMixinStr__POSIX_TTY_NAME_MAX);
        }
    }




    static if(!is(typeof(_POSIX_TIMER_MAX))) {
        private enum enumMixinStr__POSIX_TIMER_MAX = `enum _POSIX_TIMER_MAX = 32;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_TIMER_MAX); }))) {
            mixin(enumMixinStr__POSIX_TIMER_MAX);
        }
    }




    static if(!is(typeof(_POSIX_SYMLOOP_MAX))) {
        private enum enumMixinStr__POSIX_SYMLOOP_MAX = `enum _POSIX_SYMLOOP_MAX = 8;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_SYMLOOP_MAX); }))) {
            mixin(enumMixinStr__POSIX_SYMLOOP_MAX);
        }
    }




    static if(!is(typeof(_POSIX_SYMLINK_MAX))) {
        private enum enumMixinStr__POSIX_SYMLINK_MAX = `enum _POSIX_SYMLINK_MAX = 255;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_SYMLINK_MAX); }))) {
            mixin(enumMixinStr__POSIX_SYMLINK_MAX);
        }
    }




    static if(!is(typeof(_POSIX_STREAM_MAX))) {
        private enum enumMixinStr__POSIX_STREAM_MAX = `enum _POSIX_STREAM_MAX = 8;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_STREAM_MAX); }))) {
            mixin(enumMixinStr__POSIX_STREAM_MAX);
        }
    }




    static if(!is(typeof(_POSIX_SSIZE_MAX))) {
        private enum enumMixinStr__POSIX_SSIZE_MAX = `enum _POSIX_SSIZE_MAX = 32767;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_SSIZE_MAX); }))) {
            mixin(enumMixinStr__POSIX_SSIZE_MAX);
        }
    }




    static if(!is(typeof(_POSIX_SIGQUEUE_MAX))) {
        private enum enumMixinStr__POSIX_SIGQUEUE_MAX = `enum _POSIX_SIGQUEUE_MAX = 32;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_SIGQUEUE_MAX); }))) {
            mixin(enumMixinStr__POSIX_SIGQUEUE_MAX);
        }
    }




    static if(!is(typeof(_POSIX_SEM_VALUE_MAX))) {
        private enum enumMixinStr__POSIX_SEM_VALUE_MAX = `enum _POSIX_SEM_VALUE_MAX = 32767;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_SEM_VALUE_MAX); }))) {
            mixin(enumMixinStr__POSIX_SEM_VALUE_MAX);
        }
    }




    static if(!is(typeof(_POSIX_SEM_NSEMS_MAX))) {
        private enum enumMixinStr__POSIX_SEM_NSEMS_MAX = `enum _POSIX_SEM_NSEMS_MAX = 256;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_SEM_NSEMS_MAX); }))) {
            mixin(enumMixinStr__POSIX_SEM_NSEMS_MAX);
        }
    }




    static if(!is(typeof(_POSIX_RTSIG_MAX))) {
        private enum enumMixinStr__POSIX_RTSIG_MAX = `enum _POSIX_RTSIG_MAX = 8;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_RTSIG_MAX); }))) {
            mixin(enumMixinStr__POSIX_RTSIG_MAX);
        }
    }




    static if(!is(typeof(_POSIX_RE_DUP_MAX))) {
        private enum enumMixinStr__POSIX_RE_DUP_MAX = `enum _POSIX_RE_DUP_MAX = 255;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_RE_DUP_MAX); }))) {
            mixin(enumMixinStr__POSIX_RE_DUP_MAX);
        }
    }




    static if(!is(typeof(_POSIX_PIPE_BUF))) {
        private enum enumMixinStr__POSIX_PIPE_BUF = `enum _POSIX_PIPE_BUF = 512;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_PIPE_BUF); }))) {
            mixin(enumMixinStr__POSIX_PIPE_BUF);
        }
    }




    static if(!is(typeof(_POSIX_PATH_MAX))) {
        private enum enumMixinStr__POSIX_PATH_MAX = `enum _POSIX_PATH_MAX = 256;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_PATH_MAX); }))) {
            mixin(enumMixinStr__POSIX_PATH_MAX);
        }
    }




    static if(!is(typeof(_POSIX_OPEN_MAX))) {
        private enum enumMixinStr__POSIX_OPEN_MAX = `enum _POSIX_OPEN_MAX = 20;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_OPEN_MAX); }))) {
            mixin(enumMixinStr__POSIX_OPEN_MAX);
        }
    }




    static if(!is(typeof(_POSIX_NGROUPS_MAX))) {
        private enum enumMixinStr__POSIX_NGROUPS_MAX = `enum _POSIX_NGROUPS_MAX = 8;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_NGROUPS_MAX); }))) {
            mixin(enumMixinStr__POSIX_NGROUPS_MAX);
        }
    }




    static if(!is(typeof(_POSIX_NAME_MAX))) {
        private enum enumMixinStr__POSIX_NAME_MAX = `enum _POSIX_NAME_MAX = 14;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_NAME_MAX); }))) {
            mixin(enumMixinStr__POSIX_NAME_MAX);
        }
    }






    static if(!is(typeof(ZARMOUR_MODE_BASE64_STD))) {
        private enum enumMixinStr_ZARMOUR_MODE_BASE64_STD = `enum ZARMOUR_MODE_BASE64_STD = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_ZARMOUR_MODE_BASE64_STD); }))) {
            mixin(enumMixinStr_ZARMOUR_MODE_BASE64_STD);
        }
    }




    static if(!is(typeof(ZARMOUR_MODE_BASE64_URL))) {
        private enum enumMixinStr_ZARMOUR_MODE_BASE64_URL = `enum ZARMOUR_MODE_BASE64_URL = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_ZARMOUR_MODE_BASE64_URL); }))) {
            mixin(enumMixinStr_ZARMOUR_MODE_BASE64_URL);
        }
    }




    static if(!is(typeof(ZARMOUR_MODE_BASE32_STD))) {
        private enum enumMixinStr_ZARMOUR_MODE_BASE32_STD = `enum ZARMOUR_MODE_BASE32_STD = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_ZARMOUR_MODE_BASE32_STD); }))) {
            mixin(enumMixinStr_ZARMOUR_MODE_BASE32_STD);
        }
    }




    static if(!is(typeof(ZARMOUR_MODE_BASE32_HEX))) {
        private enum enumMixinStr_ZARMOUR_MODE_BASE32_HEX = `enum ZARMOUR_MODE_BASE32_HEX = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_ZARMOUR_MODE_BASE32_HEX); }))) {
            mixin(enumMixinStr_ZARMOUR_MODE_BASE32_HEX);
        }
    }




    static if(!is(typeof(ZARMOUR_MODE_BASE16))) {
        private enum enumMixinStr_ZARMOUR_MODE_BASE16 = `enum ZARMOUR_MODE_BASE16 = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_ZARMOUR_MODE_BASE16); }))) {
            mixin(enumMixinStr_ZARMOUR_MODE_BASE16);
        }
    }




    static if(!is(typeof(ZARMOUR_MODE_Z85))) {
        private enum enumMixinStr_ZARMOUR_MODE_Z85 = `enum ZARMOUR_MODE_Z85 = 5;`;
        static if(is(typeof({ mixin(enumMixinStr_ZARMOUR_MODE_Z85); }))) {
            mixin(enumMixinStr_ZARMOUR_MODE_Z85);
        }
    }




    static if(!is(typeof(_POSIX_MQ_PRIO_MAX))) {
        private enum enumMixinStr__POSIX_MQ_PRIO_MAX = `enum _POSIX_MQ_PRIO_MAX = 32;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_MQ_PRIO_MAX); }))) {
            mixin(enumMixinStr__POSIX_MQ_PRIO_MAX);
        }
    }




    static if(!is(typeof(_POSIX_MQ_OPEN_MAX))) {
        private enum enumMixinStr__POSIX_MQ_OPEN_MAX = `enum _POSIX_MQ_OPEN_MAX = 8;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_MQ_OPEN_MAX); }))) {
            mixin(enumMixinStr__POSIX_MQ_OPEN_MAX);
        }
    }




    static if(!is(typeof(_POSIX_MAX_INPUT))) {
        private enum enumMixinStr__POSIX_MAX_INPUT = `enum _POSIX_MAX_INPUT = 255;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_MAX_INPUT); }))) {
            mixin(enumMixinStr__POSIX_MAX_INPUT);
        }
    }




    static if(!is(typeof(_POSIX_MAX_CANON))) {
        private enum enumMixinStr__POSIX_MAX_CANON = `enum _POSIX_MAX_CANON = 255;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_MAX_CANON); }))) {
            mixin(enumMixinStr__POSIX_MAX_CANON);
        }
    }




    static if(!is(typeof(_POSIX_LOGIN_NAME_MAX))) {
        private enum enumMixinStr__POSIX_LOGIN_NAME_MAX = `enum _POSIX_LOGIN_NAME_MAX = 9;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_LOGIN_NAME_MAX); }))) {
            mixin(enumMixinStr__POSIX_LOGIN_NAME_MAX);
        }
    }




    static if(!is(typeof(_POSIX_LINK_MAX))) {
        private enum enumMixinStr__POSIX_LINK_MAX = `enum _POSIX_LINK_MAX = 8;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_LINK_MAX); }))) {
            mixin(enumMixinStr__POSIX_LINK_MAX);
        }
    }




    static if(!is(typeof(_POSIX_HOST_NAME_MAX))) {
        private enum enumMixinStr__POSIX_HOST_NAME_MAX = `enum _POSIX_HOST_NAME_MAX = 255;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_HOST_NAME_MAX); }))) {
            mixin(enumMixinStr__POSIX_HOST_NAME_MAX);
        }
    }




    static if(!is(typeof(_POSIX_DELAYTIMER_MAX))) {
        private enum enumMixinStr__POSIX_DELAYTIMER_MAX = `enum _POSIX_DELAYTIMER_MAX = 32;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_DELAYTIMER_MAX); }))) {
            mixin(enumMixinStr__POSIX_DELAYTIMER_MAX);
        }
    }




    static if(!is(typeof(_POSIX_CHILD_MAX))) {
        private enum enumMixinStr__POSIX_CHILD_MAX = `enum _POSIX_CHILD_MAX = 25;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_CHILD_MAX); }))) {
            mixin(enumMixinStr__POSIX_CHILD_MAX);
        }
    }




    static if(!is(typeof(_POSIX_ARG_MAX))) {
        private enum enumMixinStr__POSIX_ARG_MAX = `enum _POSIX_ARG_MAX = 4096;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_ARG_MAX); }))) {
            mixin(enumMixinStr__POSIX_ARG_MAX);
        }
    }




    static if(!is(typeof(_POSIX_AIO_MAX))) {
        private enum enumMixinStr__POSIX_AIO_MAX = `enum _POSIX_AIO_MAX = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_AIO_MAX); }))) {
            mixin(enumMixinStr__POSIX_AIO_MAX);
        }
    }




    static if(!is(typeof(_POSIX_AIO_LISTIO_MAX))) {
        private enum enumMixinStr__POSIX_AIO_LISTIO_MAX = `enum _POSIX_AIO_LISTIO_MAX = 2;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_AIO_LISTIO_MAX); }))) {
            mixin(enumMixinStr__POSIX_AIO_LISTIO_MAX);
        }
    }




    static if(!is(typeof(_BITS_POSIX1_LIM_H))) {
        private enum enumMixinStr__BITS_POSIX1_LIM_H = `enum _BITS_POSIX1_LIM_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_POSIX1_LIM_H); }))) {
            mixin(enumMixinStr__BITS_POSIX1_LIM_H);
        }
    }




    static if(!is(typeof(NCARGS))) {
        private enum enumMixinStr_NCARGS = `enum NCARGS = 131072;`;
        static if(is(typeof({ mixin(enumMixinStr_NCARGS); }))) {
            mixin(enumMixinStr_NCARGS);
        }
    }




    static if(!is(typeof(NOFILE))) {
        private enum enumMixinStr_NOFILE = `enum NOFILE = 256;`;
        static if(is(typeof({ mixin(enumMixinStr_NOFILE); }))) {
            mixin(enumMixinStr_NOFILE);
        }
    }




    static if(!is(typeof(MAXSYMLINKS))) {
        private enum enumMixinStr_MAXSYMLINKS = `enum MAXSYMLINKS = 20;`;
        static if(is(typeof({ mixin(enumMixinStr_MAXSYMLINKS); }))) {
            mixin(enumMixinStr_MAXSYMLINKS);
        }
    }






    static if(!is(typeof(__LONG_DOUBLE_USES_FLOAT128))) {
        private enum enumMixinStr___LONG_DOUBLE_USES_FLOAT128 = `enum __LONG_DOUBLE_USES_FLOAT128 = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___LONG_DOUBLE_USES_FLOAT128); }))) {
            mixin(enumMixinStr___LONG_DOUBLE_USES_FLOAT128);
        }
    }




    static if(!is(typeof(SEM_VALUE_MAX))) {
        private enum enumMixinStr_SEM_VALUE_MAX = `enum SEM_VALUE_MAX = ( 2147483647 );`;
        static if(is(typeof({ mixin(enumMixinStr_SEM_VALUE_MAX); }))) {
            mixin(enumMixinStr_SEM_VALUE_MAX);
        }
    }




    static if(!is(typeof(MQ_PRIO_MAX))) {
        private enum enumMixinStr_MQ_PRIO_MAX = `enum MQ_PRIO_MAX = 32768;`;
        static if(is(typeof({ mixin(enumMixinStr_MQ_PRIO_MAX); }))) {
            mixin(enumMixinStr_MQ_PRIO_MAX);
        }
    }




    static if(!is(typeof(HOST_NAME_MAX))) {
        private enum enumMixinStr_HOST_NAME_MAX = `enum HOST_NAME_MAX = 64;`;
        static if(is(typeof({ mixin(enumMixinStr_HOST_NAME_MAX); }))) {
            mixin(enumMixinStr_HOST_NAME_MAX);
        }
    }




    static if(!is(typeof(LOGIN_NAME_MAX))) {
        private enum enumMixinStr_LOGIN_NAME_MAX = `enum LOGIN_NAME_MAX = 256;`;
        static if(is(typeof({ mixin(enumMixinStr_LOGIN_NAME_MAX); }))) {
            mixin(enumMixinStr_LOGIN_NAME_MAX);
        }
    }




    static if(!is(typeof(TTY_NAME_MAX))) {
        private enum enumMixinStr_TTY_NAME_MAX = `enum TTY_NAME_MAX = 32;`;
        static if(is(typeof({ mixin(enumMixinStr_TTY_NAME_MAX); }))) {
            mixin(enumMixinStr_TTY_NAME_MAX);
        }
    }




    static if(!is(typeof(DELAYTIMER_MAX))) {
        private enum enumMixinStr_DELAYTIMER_MAX = `enum DELAYTIMER_MAX = 2147483647;`;
        static if(is(typeof({ mixin(enumMixinStr_DELAYTIMER_MAX); }))) {
            mixin(enumMixinStr_DELAYTIMER_MAX);
        }
    }




    static if(!is(typeof(PTHREAD_STACK_MIN))) {
        private enum enumMixinStr_PTHREAD_STACK_MIN = `enum PTHREAD_STACK_MIN = 16384;`;
        static if(is(typeof({ mixin(enumMixinStr_PTHREAD_STACK_MIN); }))) {
            mixin(enumMixinStr_PTHREAD_STACK_MIN);
        }
    }




    static if(!is(typeof(AIO_PRIO_DELTA_MAX))) {
        private enum enumMixinStr_AIO_PRIO_DELTA_MAX = `enum AIO_PRIO_DELTA_MAX = 20;`;
        static if(is(typeof({ mixin(enumMixinStr_AIO_PRIO_DELTA_MAX); }))) {
            mixin(enumMixinStr_AIO_PRIO_DELTA_MAX);
        }
    }




    static if(!is(typeof(_POSIX_THREAD_THREADS_MAX))) {
        private enum enumMixinStr__POSIX_THREAD_THREADS_MAX = `enum _POSIX_THREAD_THREADS_MAX = 64;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_THREAD_THREADS_MAX); }))) {
            mixin(enumMixinStr__POSIX_THREAD_THREADS_MAX);
        }
    }




    static if(!is(typeof(PTHREAD_DESTRUCTOR_ITERATIONS))) {
        private enum enumMixinStr_PTHREAD_DESTRUCTOR_ITERATIONS = `enum PTHREAD_DESTRUCTOR_ITERATIONS = _POSIX_THREAD_DESTRUCTOR_ITERATIONS;`;
        static if(is(typeof({ mixin(enumMixinStr_PTHREAD_DESTRUCTOR_ITERATIONS); }))) {
            mixin(enumMixinStr_PTHREAD_DESTRUCTOR_ITERATIONS);
        }
    }




    static if(!is(typeof(_POSIX_THREAD_DESTRUCTOR_ITERATIONS))) {
        private enum enumMixinStr__POSIX_THREAD_DESTRUCTOR_ITERATIONS = `enum _POSIX_THREAD_DESTRUCTOR_ITERATIONS = 4;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_THREAD_DESTRUCTOR_ITERATIONS); }))) {
            mixin(enumMixinStr__POSIX_THREAD_DESTRUCTOR_ITERATIONS);
        }
    }




    static if(!is(typeof(PTHREAD_KEYS_MAX))) {
        private enum enumMixinStr_PTHREAD_KEYS_MAX = `enum PTHREAD_KEYS_MAX = 1024;`;
        static if(is(typeof({ mixin(enumMixinStr_PTHREAD_KEYS_MAX); }))) {
            mixin(enumMixinStr_PTHREAD_KEYS_MAX);
        }
    }




    static if(!is(typeof(_POSIX_THREAD_KEYS_MAX))) {
        private enum enumMixinStr__POSIX_THREAD_KEYS_MAX = `enum _POSIX_THREAD_KEYS_MAX = 128;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_THREAD_KEYS_MAX); }))) {
            mixin(enumMixinStr__POSIX_THREAD_KEYS_MAX);
        }
    }
    static if(!is(typeof(CURVE_ALLOW_ANY))) {
        private enum enumMixinStr_CURVE_ALLOW_ANY = `enum CURVE_ALLOW_ANY = "*";`;
        static if(is(typeof({ mixin(enumMixinStr_CURVE_ALLOW_ANY); }))) {
            mixin(enumMixinStr_CURVE_ALLOW_ANY);
        }
    }
    static if(!is(typeof(_BITS_LIBM_SIMD_DECL_STUBS_H))) {
        private enum enumMixinStr__BITS_LIBM_SIMD_DECL_STUBS_H = `enum _BITS_LIBM_SIMD_DECL_STUBS_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_LIBM_SIMD_DECL_STUBS_H); }))) {
            mixin(enumMixinStr__BITS_LIBM_SIMD_DECL_STUBS_H);
        }
    }




    static if(!is(typeof(__GLIBC_USE_IEC_60559_TYPES_EXT))) {
        private enum enumMixinStr___GLIBC_USE_IEC_60559_TYPES_EXT = `enum __GLIBC_USE_IEC_60559_TYPES_EXT = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___GLIBC_USE_IEC_60559_TYPES_EXT); }))) {
            mixin(enumMixinStr___GLIBC_USE_IEC_60559_TYPES_EXT);
        }
    }
    static if(!is(typeof(__GLIBC_USE_IEC_60559_FUNCS_EXT_C2X))) {
        private enum enumMixinStr___GLIBC_USE_IEC_60559_FUNCS_EXT_C2X = `enum __GLIBC_USE_IEC_60559_FUNCS_EXT_C2X = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___GLIBC_USE_IEC_60559_FUNCS_EXT_C2X); }))) {
            mixin(enumMixinStr___GLIBC_USE_IEC_60559_FUNCS_EXT_C2X);
        }
    }




    static if(!is(typeof(__GLIBC_USE_IEC_60559_FUNCS_EXT))) {
        private enum enumMixinStr___GLIBC_USE_IEC_60559_FUNCS_EXT = `enum __GLIBC_USE_IEC_60559_FUNCS_EXT = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___GLIBC_USE_IEC_60559_FUNCS_EXT); }))) {
            mixin(enumMixinStr___GLIBC_USE_IEC_60559_FUNCS_EXT);
        }
    }




    static if(!is(typeof(__GLIBC_USE_IEC_60559_BFP_EXT_C2X))) {
        private enum enumMixinStr___GLIBC_USE_IEC_60559_BFP_EXT_C2X = `enum __GLIBC_USE_IEC_60559_BFP_EXT_C2X = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___GLIBC_USE_IEC_60559_BFP_EXT_C2X); }))) {
            mixin(enumMixinStr___GLIBC_USE_IEC_60559_BFP_EXT_C2X);
        }
    }




    static if(!is(typeof(__GLIBC_USE_IEC_60559_BFP_EXT))) {
        private enum enumMixinStr___GLIBC_USE_IEC_60559_BFP_EXT = `enum __GLIBC_USE_IEC_60559_BFP_EXT = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___GLIBC_USE_IEC_60559_BFP_EXT); }))) {
            mixin(enumMixinStr___GLIBC_USE_IEC_60559_BFP_EXT);
        }
    }




    static if(!is(typeof(__GLIBC_USE_LIB_EXT2))) {
        private enum enumMixinStr___GLIBC_USE_LIB_EXT2 = `enum __GLIBC_USE_LIB_EXT2 = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___GLIBC_USE_LIB_EXT2); }))) {
            mixin(enumMixinStr___GLIBC_USE_LIB_EXT2);
        }
    }




    static if(!is(typeof(SIOCPROTOPRIVATE))) {
        private enum enumMixinStr_SIOCPROTOPRIVATE = `enum SIOCPROTOPRIVATE = 0x89E0;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCPROTOPRIVATE); }))) {
            mixin(enumMixinStr_SIOCPROTOPRIVATE);
        }
    }




    static if(!is(typeof(SIOCDEVPRIVATE))) {
        private enum enumMixinStr_SIOCDEVPRIVATE = `enum SIOCDEVPRIVATE = 0x89F0;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCDEVPRIVATE); }))) {
            mixin(enumMixinStr_SIOCDEVPRIVATE);
        }
    }




    static if(!is(typeof(SIOCDELDLCI))) {
        private enum enumMixinStr_SIOCDELDLCI = `enum SIOCDELDLCI = 0x8981;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCDELDLCI); }))) {
            mixin(enumMixinStr_SIOCDELDLCI);
        }
    }




    static if(!is(typeof(SIOCADDDLCI))) {
        private enum enumMixinStr_SIOCADDDLCI = `enum SIOCADDDLCI = 0x8980;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCADDDLCI); }))) {
            mixin(enumMixinStr_SIOCADDDLCI);
        }
    }




    static if(!is(typeof(SIOCSIFMAP))) {
        private enum enumMixinStr_SIOCSIFMAP = `enum SIOCSIFMAP = 0x8971;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCSIFMAP); }))) {
            mixin(enumMixinStr_SIOCSIFMAP);
        }
    }




    static if(!is(typeof(SIOCGIFMAP))) {
        private enum enumMixinStr_SIOCGIFMAP = `enum SIOCGIFMAP = 0x8970;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCGIFMAP); }))) {
            mixin(enumMixinStr_SIOCGIFMAP);
        }
    }




    static if(!is(typeof(SIOCSRARP))) {
        private enum enumMixinStr_SIOCSRARP = `enum SIOCSRARP = 0x8962;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCSRARP); }))) {
            mixin(enumMixinStr_SIOCSRARP);
        }
    }




    static if(!is(typeof(SIOCGRARP))) {
        private enum enumMixinStr_SIOCGRARP = `enum SIOCGRARP = 0x8961;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCGRARP); }))) {
            mixin(enumMixinStr_SIOCGRARP);
        }
    }




    static if(!is(typeof(SIOCDRARP))) {
        private enum enumMixinStr_SIOCDRARP = `enum SIOCDRARP = 0x8960;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCDRARP); }))) {
            mixin(enumMixinStr_SIOCDRARP);
        }
    }




    static if(!is(typeof(SIOCSARP))) {
        private enum enumMixinStr_SIOCSARP = `enum SIOCSARP = 0x8955;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCSARP); }))) {
            mixin(enumMixinStr_SIOCSARP);
        }
    }




    static if(!is(typeof(SIOCGARP))) {
        private enum enumMixinStr_SIOCGARP = `enum SIOCGARP = 0x8954;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCGARP); }))) {
            mixin(enumMixinStr_SIOCGARP);
        }
    }




    static if(!is(typeof(SIOCDARP))) {
        private enum enumMixinStr_SIOCDARP = `enum SIOCDARP = 0x8953;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCDARP); }))) {
            mixin(enumMixinStr_SIOCDARP);
        }
    }




    static if(!is(typeof(SIOCSIFTXQLEN))) {
        private enum enumMixinStr_SIOCSIFTXQLEN = `enum SIOCSIFTXQLEN = 0x8943;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCSIFTXQLEN); }))) {
            mixin(enumMixinStr_SIOCSIFTXQLEN);
        }
    }




    static if(!is(typeof(SIOCGIFTXQLEN))) {
        private enum enumMixinStr_SIOCGIFTXQLEN = `enum SIOCGIFTXQLEN = 0x8942;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCGIFTXQLEN); }))) {
            mixin(enumMixinStr_SIOCGIFTXQLEN);
        }
    }




    static if(!is(typeof(SIOCSIFBR))) {
        private enum enumMixinStr_SIOCSIFBR = `enum SIOCSIFBR = 0x8941;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCSIFBR); }))) {
            mixin(enumMixinStr_SIOCSIFBR);
        }
    }




    static if(!is(typeof(SIOCGIFBR))) {
        private enum enumMixinStr_SIOCGIFBR = `enum SIOCGIFBR = 0x8940;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCGIFBR); }))) {
            mixin(enumMixinStr_SIOCGIFBR);
        }
    }




    static if(!is(typeof(SIOCGIFCOUNT))) {
        private enum enumMixinStr_SIOCGIFCOUNT = `enum SIOCGIFCOUNT = 0x8938;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCGIFCOUNT); }))) {
            mixin(enumMixinStr_SIOCGIFCOUNT);
        }
    }




    static if(!is(typeof(SIOCSIFHWBROADCAST))) {
        private enum enumMixinStr_SIOCSIFHWBROADCAST = `enum SIOCSIFHWBROADCAST = 0x8937;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCSIFHWBROADCAST); }))) {
            mixin(enumMixinStr_SIOCSIFHWBROADCAST);
        }
    }




    static if(!is(typeof(SIOCDIFADDR))) {
        private enum enumMixinStr_SIOCDIFADDR = `enum SIOCDIFADDR = 0x8936;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCDIFADDR); }))) {
            mixin(enumMixinStr_SIOCDIFADDR);
        }
    }




    static if(!is(typeof(SIOCGIFPFLAGS))) {
        private enum enumMixinStr_SIOCGIFPFLAGS = `enum SIOCGIFPFLAGS = 0x8935;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCGIFPFLAGS); }))) {
            mixin(enumMixinStr_SIOCGIFPFLAGS);
        }
    }




    static if(!is(typeof(SIOCSIFPFLAGS))) {
        private enum enumMixinStr_SIOCSIFPFLAGS = `enum SIOCSIFPFLAGS = 0x8934;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCSIFPFLAGS); }))) {
            mixin(enumMixinStr_SIOCSIFPFLAGS);
        }
    }




    static if(!is(typeof(SIOGIFINDEX))) {
        private enum enumMixinStr_SIOGIFINDEX = `enum SIOGIFINDEX = SIOCGIFINDEX;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOGIFINDEX); }))) {
            mixin(enumMixinStr_SIOGIFINDEX);
        }
    }




    static if(!is(typeof(SIOCGIFINDEX))) {
        private enum enumMixinStr_SIOCGIFINDEX = `enum SIOCGIFINDEX = 0x8933;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCGIFINDEX); }))) {
            mixin(enumMixinStr_SIOCGIFINDEX);
        }
    }




    static if(!is(typeof(SIOCDELMULTI))) {
        private enum enumMixinStr_SIOCDELMULTI = `enum SIOCDELMULTI = 0x8932;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCDELMULTI); }))) {
            mixin(enumMixinStr_SIOCDELMULTI);
        }
    }




    static if(!is(typeof(SIOCADDMULTI))) {
        private enum enumMixinStr_SIOCADDMULTI = `enum SIOCADDMULTI = 0x8931;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCADDMULTI); }))) {
            mixin(enumMixinStr_SIOCADDMULTI);
        }
    }




    static if(!is(typeof(SIOCSIFSLAVE))) {
        private enum enumMixinStr_SIOCSIFSLAVE = `enum SIOCSIFSLAVE = 0x8930;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCSIFSLAVE); }))) {
            mixin(enumMixinStr_SIOCSIFSLAVE);
        }
    }






    static if(!is(typeof(SIOCGIFSLAVE))) {
        private enum enumMixinStr_SIOCGIFSLAVE = `enum SIOCGIFSLAVE = 0x8929;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCGIFSLAVE); }))) {
            mixin(enumMixinStr_SIOCGIFSLAVE);
        }
    }




    static if(!is(typeof(SIOCGIFHWADDR))) {
        private enum enumMixinStr_SIOCGIFHWADDR = `enum SIOCGIFHWADDR = 0x8927;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCGIFHWADDR); }))) {
            mixin(enumMixinStr_SIOCGIFHWADDR);
        }
    }




    static if(!is(typeof(SIOCSIFENCAP))) {
        private enum enumMixinStr_SIOCSIFENCAP = `enum SIOCSIFENCAP = 0x8926;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCSIFENCAP); }))) {
            mixin(enumMixinStr_SIOCSIFENCAP);
        }
    }




    static if(!is(typeof(SIOCGIFENCAP))) {
        private enum enumMixinStr_SIOCGIFENCAP = `enum SIOCGIFENCAP = 0x8925;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCGIFENCAP); }))) {
            mixin(enumMixinStr_SIOCGIFENCAP);
        }
    }




    static if(!is(typeof(SIOCSIFHWADDR))) {
        private enum enumMixinStr_SIOCSIFHWADDR = `enum SIOCSIFHWADDR = 0x8924;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCSIFHWADDR); }))) {
            mixin(enumMixinStr_SIOCSIFHWADDR);
        }
    }




    static if(!is(typeof(SIOCSIFNAME))) {
        private enum enumMixinStr_SIOCSIFNAME = `enum SIOCSIFNAME = 0x8923;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCSIFNAME); }))) {
            mixin(enumMixinStr_SIOCSIFNAME);
        }
    }




    static if(!is(typeof(SIOCSIFMTU))) {
        private enum enumMixinStr_SIOCSIFMTU = `enum SIOCSIFMTU = 0x8922;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCSIFMTU); }))) {
            mixin(enumMixinStr_SIOCSIFMTU);
        }
    }




    static if(!is(typeof(SIOCGIFMTU))) {
        private enum enumMixinStr_SIOCGIFMTU = `enum SIOCGIFMTU = 0x8921;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCGIFMTU); }))) {
            mixin(enumMixinStr_SIOCGIFMTU);
        }
    }




    static if(!is(typeof(SIOCSIFMEM))) {
        private enum enumMixinStr_SIOCSIFMEM = `enum SIOCSIFMEM = 0x8920;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCSIFMEM); }))) {
            mixin(enumMixinStr_SIOCSIFMEM);
        }
    }




    static if(!is(typeof(SIOCGIFMEM))) {
        private enum enumMixinStr_SIOCGIFMEM = `enum SIOCGIFMEM = 0x891f;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCGIFMEM); }))) {
            mixin(enumMixinStr_SIOCGIFMEM);
        }
    }




    static if(!is(typeof(SIOCSIFMETRIC))) {
        private enum enumMixinStr_SIOCSIFMETRIC = `enum SIOCSIFMETRIC = 0x891e;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCSIFMETRIC); }))) {
            mixin(enumMixinStr_SIOCSIFMETRIC);
        }
    }




    static if(!is(typeof(SIOCGIFMETRIC))) {
        private enum enumMixinStr_SIOCGIFMETRIC = `enum SIOCGIFMETRIC = 0x891d;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCGIFMETRIC); }))) {
            mixin(enumMixinStr_SIOCGIFMETRIC);
        }
    }




    static if(!is(typeof(SIOCSIFNETMASK))) {
        private enum enumMixinStr_SIOCSIFNETMASK = `enum SIOCSIFNETMASK = 0x891c;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCSIFNETMASK); }))) {
            mixin(enumMixinStr_SIOCSIFNETMASK);
        }
    }




    static if(!is(typeof(SIOCGIFNETMASK))) {
        private enum enumMixinStr_SIOCGIFNETMASK = `enum SIOCGIFNETMASK = 0x891b;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCGIFNETMASK); }))) {
            mixin(enumMixinStr_SIOCGIFNETMASK);
        }
    }




    static if(!is(typeof(SIOCSIFBRDADDR))) {
        private enum enumMixinStr_SIOCSIFBRDADDR = `enum SIOCSIFBRDADDR = 0x891a;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCSIFBRDADDR); }))) {
            mixin(enumMixinStr_SIOCSIFBRDADDR);
        }
    }




    static if(!is(typeof(SIOCGIFBRDADDR))) {
        private enum enumMixinStr_SIOCGIFBRDADDR = `enum SIOCGIFBRDADDR = 0x8919;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCGIFBRDADDR); }))) {
            mixin(enumMixinStr_SIOCGIFBRDADDR);
        }
    }




    static if(!is(typeof(SIOCSIFDSTADDR))) {
        private enum enumMixinStr_SIOCSIFDSTADDR = `enum SIOCSIFDSTADDR = 0x8918;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCSIFDSTADDR); }))) {
            mixin(enumMixinStr_SIOCSIFDSTADDR);
        }
    }






    static if(!is(typeof(SIOCGIFDSTADDR))) {
        private enum enumMixinStr_SIOCGIFDSTADDR = `enum SIOCGIFDSTADDR = 0x8917;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCGIFDSTADDR); }))) {
            mixin(enumMixinStr_SIOCGIFDSTADDR);
        }
    }




    static if(!is(typeof(SIOCSIFADDR))) {
        private enum enumMixinStr_SIOCSIFADDR = `enum SIOCSIFADDR = 0x8916;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCSIFADDR); }))) {
            mixin(enumMixinStr_SIOCSIFADDR);
        }
    }




    static if(!is(typeof(SIOCGIFADDR))) {
        private enum enumMixinStr_SIOCGIFADDR = `enum SIOCGIFADDR = 0x8915;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCGIFADDR); }))) {
            mixin(enumMixinStr_SIOCGIFADDR);
        }
    }




    static if(!is(typeof(SIOCSIFFLAGS))) {
        private enum enumMixinStr_SIOCSIFFLAGS = `enum SIOCSIFFLAGS = 0x8914;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCSIFFLAGS); }))) {
            mixin(enumMixinStr_SIOCSIFFLAGS);
        }
    }




    static if(!is(typeof(SIOCGIFFLAGS))) {
        private enum enumMixinStr_SIOCGIFFLAGS = `enum SIOCGIFFLAGS = 0x8913;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCGIFFLAGS); }))) {
            mixin(enumMixinStr_SIOCGIFFLAGS);
        }
    }




    static if(!is(typeof(SIOCGIFCONF))) {
        private enum enumMixinStr_SIOCGIFCONF = `enum SIOCGIFCONF = 0x8912;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCGIFCONF); }))) {
            mixin(enumMixinStr_SIOCGIFCONF);
        }
    }




    static if(!is(typeof(SIOCSIFLINK))) {
        private enum enumMixinStr_SIOCSIFLINK = `enum SIOCSIFLINK = 0x8911;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCSIFLINK); }))) {
            mixin(enumMixinStr_SIOCSIFLINK);
        }
    }




    static if(!is(typeof(SIOCGIFNAME))) {
        private enum enumMixinStr_SIOCGIFNAME = `enum SIOCGIFNAME = 0x8910;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCGIFNAME); }))) {
            mixin(enumMixinStr_SIOCGIFNAME);
        }
    }




    static if(!is(typeof(SIOCRTMSG))) {
        private enum enumMixinStr_SIOCRTMSG = `enum SIOCRTMSG = 0x890D;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCRTMSG); }))) {
            mixin(enumMixinStr_SIOCRTMSG);
        }
    }




    static if(!is(typeof(SIOCDELRT))) {
        private enum enumMixinStr_SIOCDELRT = `enum SIOCDELRT = 0x890C;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCDELRT); }))) {
            mixin(enumMixinStr_SIOCDELRT);
        }
    }




    static if(!is(typeof(SIOCADDRT))) {
        private enum enumMixinStr_SIOCADDRT = `enum SIOCADDRT = 0x890B;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCADDRT); }))) {
            mixin(enumMixinStr_SIOCADDRT);
        }
    }




    static if(!is(typeof(N_HCI))) {
        private enum enumMixinStr_N_HCI = `enum N_HCI = 15;`;
        static if(is(typeof({ mixin(enumMixinStr_N_HCI); }))) {
            mixin(enumMixinStr_N_HCI);
        }
    }




    static if(!is(typeof(N_SYNC_PPP))) {
        private enum enumMixinStr_N_SYNC_PPP = `enum N_SYNC_PPP = 14;`;
        static if(is(typeof({ mixin(enumMixinStr_N_SYNC_PPP); }))) {
            mixin(enumMixinStr_N_SYNC_PPP);
        }
    }




    static if(!is(typeof(N_HDLC))) {
        private enum enumMixinStr_N_HDLC = `enum N_HDLC = 13;`;
        static if(is(typeof({ mixin(enumMixinStr_N_HDLC); }))) {
            mixin(enumMixinStr_N_HDLC);
        }
    }




    static if(!is(typeof(N_SMSBLOCK))) {
        private enum enumMixinStr_N_SMSBLOCK = `enum N_SMSBLOCK = 12;`;
        static if(is(typeof({ mixin(enumMixinStr_N_SMSBLOCK); }))) {
            mixin(enumMixinStr_N_SMSBLOCK);
        }
    }




    static if(!is(typeof(N_IRDA))) {
        private enum enumMixinStr_N_IRDA = `enum N_IRDA = 11;`;
        static if(is(typeof({ mixin(enumMixinStr_N_IRDA); }))) {
            mixin(enumMixinStr_N_IRDA);
        }
    }




    static if(!is(typeof(N_PROFIBUS_FDL))) {
        private enum enumMixinStr_N_PROFIBUS_FDL = `enum N_PROFIBUS_FDL = 10;`;
        static if(is(typeof({ mixin(enumMixinStr_N_PROFIBUS_FDL); }))) {
            mixin(enumMixinStr_N_PROFIBUS_FDL);
        }
    }




    static if(!is(typeof(N_R3964))) {
        private enum enumMixinStr_N_R3964 = `enum N_R3964 = 9;`;
        static if(is(typeof({ mixin(enumMixinStr_N_R3964); }))) {
            mixin(enumMixinStr_N_R3964);
        }
    }




    static if(!is(typeof(N_MASC))) {
        private enum enumMixinStr_N_MASC = `enum N_MASC = 8;`;
        static if(is(typeof({ mixin(enumMixinStr_N_MASC); }))) {
            mixin(enumMixinStr_N_MASC);
        }
    }




    static if(!is(typeof(N_6PACK))) {
        private enum enumMixinStr_N_6PACK = `enum N_6PACK = 7;`;
        static if(is(typeof({ mixin(enumMixinStr_N_6PACK); }))) {
            mixin(enumMixinStr_N_6PACK);
        }
    }




    static if(!is(typeof(N_X25))) {
        private enum enumMixinStr_N_X25 = `enum N_X25 = 6;`;
        static if(is(typeof({ mixin(enumMixinStr_N_X25); }))) {
            mixin(enumMixinStr_N_X25);
        }
    }




    static if(!is(typeof(N_AX25))) {
        private enum enumMixinStr_N_AX25 = `enum N_AX25 = 5;`;
        static if(is(typeof({ mixin(enumMixinStr_N_AX25); }))) {
            mixin(enumMixinStr_N_AX25);
        }
    }




    static if(!is(typeof(N_STRIP))) {
        private enum enumMixinStr_N_STRIP = `enum N_STRIP = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_N_STRIP); }))) {
            mixin(enumMixinStr_N_STRIP);
        }
    }




    static if(!is(typeof(N_PPP))) {
        private enum enumMixinStr_N_PPP = `enum N_PPP = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_N_PPP); }))) {
            mixin(enumMixinStr_N_PPP);
        }
    }




    static if(!is(typeof(N_MOUSE))) {
        private enum enumMixinStr_N_MOUSE = `enum N_MOUSE = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_N_MOUSE); }))) {
            mixin(enumMixinStr_N_MOUSE);
        }
    }




    static if(!is(typeof(N_SLIP))) {
        private enum enumMixinStr_N_SLIP = `enum N_SLIP = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_N_SLIP); }))) {
            mixin(enumMixinStr_N_SLIP);
        }
    }




    static if(!is(typeof(N_TTY))) {
        private enum enumMixinStr_N_TTY = `enum N_TTY = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_N_TTY); }))) {
            mixin(enumMixinStr_N_TTY);
        }
    }




    static if(!is(typeof(TIOCM_RI))) {
        private enum enumMixinStr_TIOCM_RI = `enum TIOCM_RI = TIOCM_RNG;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCM_RI); }))) {
            mixin(enumMixinStr_TIOCM_RI);
        }
    }




    static if(!is(typeof(TIOCM_CD))) {
        private enum enumMixinStr_TIOCM_CD = `enum TIOCM_CD = TIOCM_CAR;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCM_CD); }))) {
            mixin(enumMixinStr_TIOCM_CD);
        }
    }




    static if(!is(typeof(TIOCM_DSR))) {
        private enum enumMixinStr_TIOCM_DSR = `enum TIOCM_DSR = 0x100;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCM_DSR); }))) {
            mixin(enumMixinStr_TIOCM_DSR);
        }
    }




    static if(!is(typeof(TIOCM_RNG))) {
        private enum enumMixinStr_TIOCM_RNG = `enum TIOCM_RNG = 0x080;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCM_RNG); }))) {
            mixin(enumMixinStr_TIOCM_RNG);
        }
    }




    static if(!is(typeof(TIOCM_CAR))) {
        private enum enumMixinStr_TIOCM_CAR = `enum TIOCM_CAR = 0x040;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCM_CAR); }))) {
            mixin(enumMixinStr_TIOCM_CAR);
        }
    }




    static if(!is(typeof(TIOCM_CTS))) {
        private enum enumMixinStr_TIOCM_CTS = `enum TIOCM_CTS = 0x020;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCM_CTS); }))) {
            mixin(enumMixinStr_TIOCM_CTS);
        }
    }




    static if(!is(typeof(TIOCM_SR))) {
        private enum enumMixinStr_TIOCM_SR = `enum TIOCM_SR = 0x010;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCM_SR); }))) {
            mixin(enumMixinStr_TIOCM_SR);
        }
    }




    static if(!is(typeof(TIOCM_ST))) {
        private enum enumMixinStr_TIOCM_ST = `enum TIOCM_ST = 0x008;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCM_ST); }))) {
            mixin(enumMixinStr_TIOCM_ST);
        }
    }




    static if(!is(typeof(TIOCM_RTS))) {
        private enum enumMixinStr_TIOCM_RTS = `enum TIOCM_RTS = 0x004;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCM_RTS); }))) {
            mixin(enumMixinStr_TIOCM_RTS);
        }
    }




    static if(!is(typeof(TIOCM_DTR))) {
        private enum enumMixinStr_TIOCM_DTR = `enum TIOCM_DTR = 0x002;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCM_DTR); }))) {
            mixin(enumMixinStr_TIOCM_DTR);
        }
    }




    static if(!is(typeof(TIOCM_LE))) {
        private enum enumMixinStr_TIOCM_LE = `enum TIOCM_LE = 0x001;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCM_LE); }))) {
            mixin(enumMixinStr_TIOCM_LE);
        }
    }




    static if(!is(typeof(NCC))) {
        private enum enumMixinStr_NCC = `enum NCC = 8;`;
        static if(is(typeof({ mixin(enumMixinStr_NCC); }))) {
            mixin(enumMixinStr_NCC);
        }
    }




    static if(!is(typeof(IPV6_RTHDR_TYPE_0))) {
        private enum enumMixinStr_IPV6_RTHDR_TYPE_0 = `enum IPV6_RTHDR_TYPE_0 = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_RTHDR_TYPE_0); }))) {
            mixin(enumMixinStr_IPV6_RTHDR_TYPE_0);
        }
    }




    static if(!is(typeof(IPV6_RTHDR_STRICT))) {
        private enum enumMixinStr_IPV6_RTHDR_STRICT = `enum IPV6_RTHDR_STRICT = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_RTHDR_STRICT); }))) {
            mixin(enumMixinStr_IPV6_RTHDR_STRICT);
        }
    }




    static if(!is(typeof(IPV6_RTHDR_LOOSE))) {
        private enum enumMixinStr_IPV6_RTHDR_LOOSE = `enum IPV6_RTHDR_LOOSE = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_RTHDR_LOOSE); }))) {
            mixin(enumMixinStr_IPV6_RTHDR_LOOSE);
        }
    }




    static if(!is(typeof(SOL_ICMPV6))) {
        private enum enumMixinStr_SOL_ICMPV6 = `enum SOL_ICMPV6 = 58;`;
        static if(is(typeof({ mixin(enumMixinStr_SOL_ICMPV6); }))) {
            mixin(enumMixinStr_SOL_ICMPV6);
        }
    }




    static if(!is(typeof(SOL_IPV6))) {
        private enum enumMixinStr_SOL_IPV6 = `enum SOL_IPV6 = 41;`;
        static if(is(typeof({ mixin(enumMixinStr_SOL_IPV6); }))) {
            mixin(enumMixinStr_SOL_IPV6);
        }
    }




    static if(!is(typeof(IPV6_PMTUDISC_OMIT))) {
        private enum enumMixinStr_IPV6_PMTUDISC_OMIT = `enum IPV6_PMTUDISC_OMIT = 5;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_PMTUDISC_OMIT); }))) {
            mixin(enumMixinStr_IPV6_PMTUDISC_OMIT);
        }
    }




    static if(!is(typeof(IPV6_PMTUDISC_INTERFACE))) {
        private enum enumMixinStr_IPV6_PMTUDISC_INTERFACE = `enum IPV6_PMTUDISC_INTERFACE = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_PMTUDISC_INTERFACE); }))) {
            mixin(enumMixinStr_IPV6_PMTUDISC_INTERFACE);
        }
    }




    static if(!is(typeof(IPV6_PMTUDISC_PROBE))) {
        private enum enumMixinStr_IPV6_PMTUDISC_PROBE = `enum IPV6_PMTUDISC_PROBE = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_PMTUDISC_PROBE); }))) {
            mixin(enumMixinStr_IPV6_PMTUDISC_PROBE);
        }
    }




    static if(!is(typeof(IPV6_PMTUDISC_DO))) {
        private enum enumMixinStr_IPV6_PMTUDISC_DO = `enum IPV6_PMTUDISC_DO = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_PMTUDISC_DO); }))) {
            mixin(enumMixinStr_IPV6_PMTUDISC_DO);
        }
    }




    static if(!is(typeof(IPV6_PMTUDISC_WANT))) {
        private enum enumMixinStr_IPV6_PMTUDISC_WANT = `enum IPV6_PMTUDISC_WANT = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_PMTUDISC_WANT); }))) {
            mixin(enumMixinStr_IPV6_PMTUDISC_WANT);
        }
    }




    static if(!is(typeof(IPV6_PMTUDISC_DONT))) {
        private enum enumMixinStr_IPV6_PMTUDISC_DONT = `enum IPV6_PMTUDISC_DONT = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_PMTUDISC_DONT); }))) {
            mixin(enumMixinStr_IPV6_PMTUDISC_DONT);
        }
    }




    static if(!is(typeof(IPV6_RXDSTOPTS))) {
        private enum enumMixinStr_IPV6_RXDSTOPTS = `enum IPV6_RXDSTOPTS = IPV6_DSTOPTS;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_RXDSTOPTS); }))) {
            mixin(enumMixinStr_IPV6_RXDSTOPTS);
        }
    }




    static if(!is(typeof(IPV6_RXHOPOPTS))) {
        private enum enumMixinStr_IPV6_RXHOPOPTS = `enum IPV6_RXHOPOPTS = IPV6_HOPOPTS;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_RXHOPOPTS); }))) {
            mixin(enumMixinStr_IPV6_RXHOPOPTS);
        }
    }




    static if(!is(typeof(IPV6_DROP_MEMBERSHIP))) {
        private enum enumMixinStr_IPV6_DROP_MEMBERSHIP = `enum IPV6_DROP_MEMBERSHIP = IPV6_LEAVE_GROUP;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_DROP_MEMBERSHIP); }))) {
            mixin(enumMixinStr_IPV6_DROP_MEMBERSHIP);
        }
    }




    static if(!is(typeof(IPV6_ADD_MEMBERSHIP))) {
        private enum enumMixinStr_IPV6_ADD_MEMBERSHIP = `enum IPV6_ADD_MEMBERSHIP = IPV6_JOIN_GROUP;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_ADD_MEMBERSHIP); }))) {
            mixin(enumMixinStr_IPV6_ADD_MEMBERSHIP);
        }
    }




    static if(!is(typeof(IPV6_FREEBIND))) {
        private enum enumMixinStr_IPV6_FREEBIND = `enum IPV6_FREEBIND = 78;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_FREEBIND); }))) {
            mixin(enumMixinStr_IPV6_FREEBIND);
        }
    }




    static if(!is(typeof(IPV6_RECVFRAGSIZE))) {
        private enum enumMixinStr_IPV6_RECVFRAGSIZE = `enum IPV6_RECVFRAGSIZE = 77;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_RECVFRAGSIZE); }))) {
            mixin(enumMixinStr_IPV6_RECVFRAGSIZE);
        }
    }




    static if(!is(typeof(IPV6_UNICAST_IF))) {
        private enum enumMixinStr_IPV6_UNICAST_IF = `enum IPV6_UNICAST_IF = 76;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_UNICAST_IF); }))) {
            mixin(enumMixinStr_IPV6_UNICAST_IF);
        }
    }




    static if(!is(typeof(IPV6_TRANSPARENT))) {
        private enum enumMixinStr_IPV6_TRANSPARENT = `enum IPV6_TRANSPARENT = 75;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_TRANSPARENT); }))) {
            mixin(enumMixinStr_IPV6_TRANSPARENT);
        }
    }




    static if(!is(typeof(IPV6_RECVORIGDSTADDR))) {
        private enum enumMixinStr_IPV6_RECVORIGDSTADDR = `enum IPV6_RECVORIGDSTADDR = IPV6_ORIGDSTADDR;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_RECVORIGDSTADDR); }))) {
            mixin(enumMixinStr_IPV6_RECVORIGDSTADDR);
        }
    }




    static if(!is(typeof(IPV6_ORIGDSTADDR))) {
        private enum enumMixinStr_IPV6_ORIGDSTADDR = `enum IPV6_ORIGDSTADDR = 74;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_ORIGDSTADDR); }))) {
            mixin(enumMixinStr_IPV6_ORIGDSTADDR);
        }
    }




    static if(!is(typeof(IPV6_MINHOPCOUNT))) {
        private enum enumMixinStr_IPV6_MINHOPCOUNT = `enum IPV6_MINHOPCOUNT = 73;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_MINHOPCOUNT); }))) {
            mixin(enumMixinStr_IPV6_MINHOPCOUNT);
        }
    }




    static if(!is(typeof(IPV6_ADDR_PREFERENCES))) {
        private enum enumMixinStr_IPV6_ADDR_PREFERENCES = `enum IPV6_ADDR_PREFERENCES = 72;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_ADDR_PREFERENCES); }))) {
            mixin(enumMixinStr_IPV6_ADDR_PREFERENCES);
        }
    }




    static if(!is(typeof(IPV6_AUTOFLOWLABEL))) {
        private enum enumMixinStr_IPV6_AUTOFLOWLABEL = `enum IPV6_AUTOFLOWLABEL = 70;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_AUTOFLOWLABEL); }))) {
            mixin(enumMixinStr_IPV6_AUTOFLOWLABEL);
        }
    }




    static if(!is(typeof(IPV6_TCLASS))) {
        private enum enumMixinStr_IPV6_TCLASS = `enum IPV6_TCLASS = 67;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_TCLASS); }))) {
            mixin(enumMixinStr_IPV6_TCLASS);
        }
    }




    static if(!is(typeof(IPV6_RECVTCLASS))) {
        private enum enumMixinStr_IPV6_RECVTCLASS = `enum IPV6_RECVTCLASS = 66;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_RECVTCLASS); }))) {
            mixin(enumMixinStr_IPV6_RECVTCLASS);
        }
    }




    static if(!is(typeof(IPV6_DONTFRAG))) {
        private enum enumMixinStr_IPV6_DONTFRAG = `enum IPV6_DONTFRAG = 62;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_DONTFRAG); }))) {
            mixin(enumMixinStr_IPV6_DONTFRAG);
        }
    }




    static if(!is(typeof(IPV6_PATHMTU))) {
        private enum enumMixinStr_IPV6_PATHMTU = `enum IPV6_PATHMTU = 61;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_PATHMTU); }))) {
            mixin(enumMixinStr_IPV6_PATHMTU);
        }
    }




    static if(!is(typeof(IPV6_RECVPATHMTU))) {
        private enum enumMixinStr_IPV6_RECVPATHMTU = `enum IPV6_RECVPATHMTU = 60;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_RECVPATHMTU); }))) {
            mixin(enumMixinStr_IPV6_RECVPATHMTU);
        }
    }




    static if(!is(typeof(IPV6_DSTOPTS))) {
        private enum enumMixinStr_IPV6_DSTOPTS = `enum IPV6_DSTOPTS = 59;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_DSTOPTS); }))) {
            mixin(enumMixinStr_IPV6_DSTOPTS);
        }
    }




    static if(!is(typeof(IPV6_RECVDSTOPTS))) {
        private enum enumMixinStr_IPV6_RECVDSTOPTS = `enum IPV6_RECVDSTOPTS = 58;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_RECVDSTOPTS); }))) {
            mixin(enumMixinStr_IPV6_RECVDSTOPTS);
        }
    }




    static if(!is(typeof(IPV6_RTHDR))) {
        private enum enumMixinStr_IPV6_RTHDR = `enum IPV6_RTHDR = 57;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_RTHDR); }))) {
            mixin(enumMixinStr_IPV6_RTHDR);
        }
    }




    static if(!is(typeof(IPV6_RECVRTHDR))) {
        private enum enumMixinStr_IPV6_RECVRTHDR = `enum IPV6_RECVRTHDR = 56;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_RECVRTHDR); }))) {
            mixin(enumMixinStr_IPV6_RECVRTHDR);
        }
    }
    static if(!is(typeof(IPV6_RTHDRDSTOPTS))) {
        private enum enumMixinStr_IPV6_RTHDRDSTOPTS = `enum IPV6_RTHDRDSTOPTS = 55;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_RTHDRDSTOPTS); }))) {
            mixin(enumMixinStr_IPV6_RTHDRDSTOPTS);
        }
    }




    static if(!is(typeof(IPV6_HOPOPTS))) {
        private enum enumMixinStr_IPV6_HOPOPTS = `enum IPV6_HOPOPTS = 54;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_HOPOPTS); }))) {
            mixin(enumMixinStr_IPV6_HOPOPTS);
        }
    }




    static if(!is(typeof(IPV6_RECVHOPOPTS))) {
        private enum enumMixinStr_IPV6_RECVHOPOPTS = `enum IPV6_RECVHOPOPTS = 53;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_RECVHOPOPTS); }))) {
            mixin(enumMixinStr_IPV6_RECVHOPOPTS);
        }
    }




    static if(!is(typeof(IPV6_HOPLIMIT))) {
        private enum enumMixinStr_IPV6_HOPLIMIT = `enum IPV6_HOPLIMIT = 52;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_HOPLIMIT); }))) {
            mixin(enumMixinStr_IPV6_HOPLIMIT);
        }
    }




    static if(!is(typeof(IPV6_RECVHOPLIMIT))) {
        private enum enumMixinStr_IPV6_RECVHOPLIMIT = `enum IPV6_RECVHOPLIMIT = 51;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_RECVHOPLIMIT); }))) {
            mixin(enumMixinStr_IPV6_RECVHOPLIMIT);
        }
    }




    static if(!is(typeof(IPV6_PKTINFO))) {
        private enum enumMixinStr_IPV6_PKTINFO = `enum IPV6_PKTINFO = 50;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_PKTINFO); }))) {
            mixin(enumMixinStr_IPV6_PKTINFO);
        }
    }




    static if(!is(typeof(IPV6_RECVPKTINFO))) {
        private enum enumMixinStr_IPV6_RECVPKTINFO = `enum IPV6_RECVPKTINFO = 49;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_RECVPKTINFO); }))) {
            mixin(enumMixinStr_IPV6_RECVPKTINFO);
        }
    }




    static if(!is(typeof(IPV6_HDRINCL))) {
        private enum enumMixinStr_IPV6_HDRINCL = `enum IPV6_HDRINCL = 36;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_HDRINCL); }))) {
            mixin(enumMixinStr_IPV6_HDRINCL);
        }
    }




    static if(!is(typeof(IPV6_XFRM_POLICY))) {
        private enum enumMixinStr_IPV6_XFRM_POLICY = `enum IPV6_XFRM_POLICY = 35;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_XFRM_POLICY); }))) {
            mixin(enumMixinStr_IPV6_XFRM_POLICY);
        }
    }




    static if(!is(typeof(IPV6_IPSEC_POLICY))) {
        private enum enumMixinStr_IPV6_IPSEC_POLICY = `enum IPV6_IPSEC_POLICY = 34;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_IPSEC_POLICY); }))) {
            mixin(enumMixinStr_IPV6_IPSEC_POLICY);
        }
    }




    static if(!is(typeof(IPV6_ROUTER_ALERT_ISOLATE))) {
        private enum enumMixinStr_IPV6_ROUTER_ALERT_ISOLATE = `enum IPV6_ROUTER_ALERT_ISOLATE = 30;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_ROUTER_ALERT_ISOLATE); }))) {
            mixin(enumMixinStr_IPV6_ROUTER_ALERT_ISOLATE);
        }
    }




    static if(!is(typeof(IPV6_MULTICAST_ALL))) {
        private enum enumMixinStr_IPV6_MULTICAST_ALL = `enum IPV6_MULTICAST_ALL = 29;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_MULTICAST_ALL); }))) {
            mixin(enumMixinStr_IPV6_MULTICAST_ALL);
        }
    }




    static if(!is(typeof(IPV6_LEAVE_ANYCAST))) {
        private enum enumMixinStr_IPV6_LEAVE_ANYCAST = `enum IPV6_LEAVE_ANYCAST = 28;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_LEAVE_ANYCAST); }))) {
            mixin(enumMixinStr_IPV6_LEAVE_ANYCAST);
        }
    }




    static if(!is(typeof(IPV6_JOIN_ANYCAST))) {
        private enum enumMixinStr_IPV6_JOIN_ANYCAST = `enum IPV6_JOIN_ANYCAST = 27;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_JOIN_ANYCAST); }))) {
            mixin(enumMixinStr_IPV6_JOIN_ANYCAST);
        }
    }




    static if(!is(typeof(IPV6_V6ONLY))) {
        private enum enumMixinStr_IPV6_V6ONLY = `enum IPV6_V6ONLY = 26;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_V6ONLY); }))) {
            mixin(enumMixinStr_IPV6_V6ONLY);
        }
    }






    static if(!is(typeof(IPV6_RECVERR))) {
        private enum enumMixinStr_IPV6_RECVERR = `enum IPV6_RECVERR = 25;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_RECVERR); }))) {
            mixin(enumMixinStr_IPV6_RECVERR);
        }
    }




    static if(!is(typeof(IPV6_MTU))) {
        private enum enumMixinStr_IPV6_MTU = `enum IPV6_MTU = 24;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_MTU); }))) {
            mixin(enumMixinStr_IPV6_MTU);
        }
    }




    static if(!is(typeof(IPV6_MTU_DISCOVER))) {
        private enum enumMixinStr_IPV6_MTU_DISCOVER = `enum IPV6_MTU_DISCOVER = 23;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_MTU_DISCOVER); }))) {
            mixin(enumMixinStr_IPV6_MTU_DISCOVER);
        }
    }




    static if(!is(typeof(IPV6_ROUTER_ALERT))) {
        private enum enumMixinStr_IPV6_ROUTER_ALERT = `enum IPV6_ROUTER_ALERT = 22;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_ROUTER_ALERT); }))) {
            mixin(enumMixinStr_IPV6_ROUTER_ALERT);
        }
    }




    static if(!is(typeof(IPV6_LEAVE_GROUP))) {
        private enum enumMixinStr_IPV6_LEAVE_GROUP = `enum IPV6_LEAVE_GROUP = 21;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_LEAVE_GROUP); }))) {
            mixin(enumMixinStr_IPV6_LEAVE_GROUP);
        }
    }




    static if(!is(typeof(IPV6_JOIN_GROUP))) {
        private enum enumMixinStr_IPV6_JOIN_GROUP = `enum IPV6_JOIN_GROUP = 20;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_JOIN_GROUP); }))) {
            mixin(enumMixinStr_IPV6_JOIN_GROUP);
        }
    }




    static if(!is(typeof(IPV6_MULTICAST_LOOP))) {
        private enum enumMixinStr_IPV6_MULTICAST_LOOP = `enum IPV6_MULTICAST_LOOP = 19;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_MULTICAST_LOOP); }))) {
            mixin(enumMixinStr_IPV6_MULTICAST_LOOP);
        }
    }




    static if(!is(typeof(IPV6_MULTICAST_HOPS))) {
        private enum enumMixinStr_IPV6_MULTICAST_HOPS = `enum IPV6_MULTICAST_HOPS = 18;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_MULTICAST_HOPS); }))) {
            mixin(enumMixinStr_IPV6_MULTICAST_HOPS);
        }
    }




    static if(!is(typeof(IPV6_MULTICAST_IF))) {
        private enum enumMixinStr_IPV6_MULTICAST_IF = `enum IPV6_MULTICAST_IF = 17;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_MULTICAST_IF); }))) {
            mixin(enumMixinStr_IPV6_MULTICAST_IF);
        }
    }




    static if(!is(typeof(IPV6_UNICAST_HOPS))) {
        private enum enumMixinStr_IPV6_UNICAST_HOPS = `enum IPV6_UNICAST_HOPS = 16;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_UNICAST_HOPS); }))) {
            mixin(enumMixinStr_IPV6_UNICAST_HOPS);
        }
    }




    static if(!is(typeof(IPV6_AUTHHDR))) {
        private enum enumMixinStr_IPV6_AUTHHDR = `enum IPV6_AUTHHDR = 10;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_AUTHHDR); }))) {
            mixin(enumMixinStr_IPV6_AUTHHDR);
        }
    }




    static if(!is(typeof(IPV6_NEXTHOP))) {
        private enum enumMixinStr_IPV6_NEXTHOP = `enum IPV6_NEXTHOP = 9;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_NEXTHOP); }))) {
            mixin(enumMixinStr_IPV6_NEXTHOP);
        }
    }




    static if(!is(typeof(SCM_SRCRT))) {
        private enum enumMixinStr_SCM_SRCRT = `enum SCM_SRCRT = IPV6_RXSRCRT;`;
        static if(is(typeof({ mixin(enumMixinStr_SCM_SRCRT); }))) {
            mixin(enumMixinStr_SCM_SRCRT);
        }
    }




    static if(!is(typeof(IPV6_2292HOPLIMIT))) {
        private enum enumMixinStr_IPV6_2292HOPLIMIT = `enum IPV6_2292HOPLIMIT = 8;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_2292HOPLIMIT); }))) {
            mixin(enumMixinStr_IPV6_2292HOPLIMIT);
        }
    }




    static if(!is(typeof(IPV6_CHECKSUM))) {
        private enum enumMixinStr_IPV6_CHECKSUM = `enum IPV6_CHECKSUM = 7;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_CHECKSUM); }))) {
            mixin(enumMixinStr_IPV6_CHECKSUM);
        }
    }




    static if(!is(typeof(IPV6_2292PKTOPTIONS))) {
        private enum enumMixinStr_IPV6_2292PKTOPTIONS = `enum IPV6_2292PKTOPTIONS = 6;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_2292PKTOPTIONS); }))) {
            mixin(enumMixinStr_IPV6_2292PKTOPTIONS);
        }
    }




    static if(!is(typeof(IPV6_2292RTHDR))) {
        private enum enumMixinStr_IPV6_2292RTHDR = `enum IPV6_2292RTHDR = 5;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_2292RTHDR); }))) {
            mixin(enumMixinStr_IPV6_2292RTHDR);
        }
    }




    static if(!is(typeof(IPV6_2292DSTOPTS))) {
        private enum enumMixinStr_IPV6_2292DSTOPTS = `enum IPV6_2292DSTOPTS = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_2292DSTOPTS); }))) {
            mixin(enumMixinStr_IPV6_2292DSTOPTS);
        }
    }




    static if(!is(typeof(IPV6_2292HOPOPTS))) {
        private enum enumMixinStr_IPV6_2292HOPOPTS = `enum IPV6_2292HOPOPTS = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_2292HOPOPTS); }))) {
            mixin(enumMixinStr_IPV6_2292HOPOPTS);
        }
    }




    static if(!is(typeof(IPV6_2292PKTINFO))) {
        private enum enumMixinStr_IPV6_2292PKTINFO = `enum IPV6_2292PKTINFO = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_2292PKTINFO); }))) {
            mixin(enumMixinStr_IPV6_2292PKTINFO);
        }
    }




    static if(!is(typeof(IPV6_ADDRFORM))) {
        private enum enumMixinStr_IPV6_ADDRFORM = `enum IPV6_ADDRFORM = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_IPV6_ADDRFORM); }))) {
            mixin(enumMixinStr_IPV6_ADDRFORM);
        }
    }




    static if(!is(typeof(IP_MAX_MEMBERSHIPS))) {
        private enum enumMixinStr_IP_MAX_MEMBERSHIPS = `enum IP_MAX_MEMBERSHIPS = 20;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_MAX_MEMBERSHIPS); }))) {
            mixin(enumMixinStr_IP_MAX_MEMBERSHIPS);
        }
    }




    static if(!is(typeof(IP_DEFAULT_MULTICAST_LOOP))) {
        private enum enumMixinStr_IP_DEFAULT_MULTICAST_LOOP = `enum IP_DEFAULT_MULTICAST_LOOP = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_DEFAULT_MULTICAST_LOOP); }))) {
            mixin(enumMixinStr_IP_DEFAULT_MULTICAST_LOOP);
        }
    }




    static if(!is(typeof(IP_DEFAULT_MULTICAST_TTL))) {
        private enum enumMixinStr_IP_DEFAULT_MULTICAST_TTL = `enum IP_DEFAULT_MULTICAST_TTL = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_DEFAULT_MULTICAST_TTL); }))) {
            mixin(enumMixinStr_IP_DEFAULT_MULTICAST_TTL);
        }
    }




    static if(!is(typeof(SOL_IP))) {
        private enum enumMixinStr_SOL_IP = `enum SOL_IP = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_SOL_IP); }))) {
            mixin(enumMixinStr_SOL_IP);
        }
    }




    static if(!is(typeof(IP_UNICAST_IF))) {
        private enum enumMixinStr_IP_UNICAST_IF = `enum IP_UNICAST_IF = 50;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_UNICAST_IF); }))) {
            mixin(enumMixinStr_IP_UNICAST_IF);
        }
    }




    static if(!is(typeof(IP_MULTICAST_ALL))) {
        private enum enumMixinStr_IP_MULTICAST_ALL = `enum IP_MULTICAST_ALL = 49;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_MULTICAST_ALL); }))) {
            mixin(enumMixinStr_IP_MULTICAST_ALL);
        }
    }




    static if(!is(typeof(IP_MSFILTER))) {
        private enum enumMixinStr_IP_MSFILTER = `enum IP_MSFILTER = 41;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_MSFILTER); }))) {
            mixin(enumMixinStr_IP_MSFILTER);
        }
    }




    static if(!is(typeof(IP_DROP_SOURCE_MEMBERSHIP))) {
        private enum enumMixinStr_IP_DROP_SOURCE_MEMBERSHIP = `enum IP_DROP_SOURCE_MEMBERSHIP = 40;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_DROP_SOURCE_MEMBERSHIP); }))) {
            mixin(enumMixinStr_IP_DROP_SOURCE_MEMBERSHIP);
        }
    }




    static if(!is(typeof(IP_ADD_SOURCE_MEMBERSHIP))) {
        private enum enumMixinStr_IP_ADD_SOURCE_MEMBERSHIP = `enum IP_ADD_SOURCE_MEMBERSHIP = 39;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_ADD_SOURCE_MEMBERSHIP); }))) {
            mixin(enumMixinStr_IP_ADD_SOURCE_MEMBERSHIP);
        }
    }




    static if(!is(typeof(IP_BLOCK_SOURCE))) {
        private enum enumMixinStr_IP_BLOCK_SOURCE = `enum IP_BLOCK_SOURCE = 38;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_BLOCK_SOURCE); }))) {
            mixin(enumMixinStr_IP_BLOCK_SOURCE);
        }
    }




    static if(!is(typeof(IP_UNBLOCK_SOURCE))) {
        private enum enumMixinStr_IP_UNBLOCK_SOURCE = `enum IP_UNBLOCK_SOURCE = 37;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_UNBLOCK_SOURCE); }))) {
            mixin(enumMixinStr_IP_UNBLOCK_SOURCE);
        }
    }




    static if(!is(typeof(IP_DROP_MEMBERSHIP))) {
        private enum enumMixinStr_IP_DROP_MEMBERSHIP = `enum IP_DROP_MEMBERSHIP = 36;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_DROP_MEMBERSHIP); }))) {
            mixin(enumMixinStr_IP_DROP_MEMBERSHIP);
        }
    }




    static if(!is(typeof(IP_ADD_MEMBERSHIP))) {
        private enum enumMixinStr_IP_ADD_MEMBERSHIP = `enum IP_ADD_MEMBERSHIP = 35;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_ADD_MEMBERSHIP); }))) {
            mixin(enumMixinStr_IP_ADD_MEMBERSHIP);
        }
    }




    static if(!is(typeof(IP_MULTICAST_LOOP))) {
        private enum enumMixinStr_IP_MULTICAST_LOOP = `enum IP_MULTICAST_LOOP = 34;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_MULTICAST_LOOP); }))) {
            mixin(enumMixinStr_IP_MULTICAST_LOOP);
        }
    }




    static if(!is(typeof(IP_MULTICAST_TTL))) {
        private enum enumMixinStr_IP_MULTICAST_TTL = `enum IP_MULTICAST_TTL = 33;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_MULTICAST_TTL); }))) {
            mixin(enumMixinStr_IP_MULTICAST_TTL);
        }
    }
    static if(!is(typeof(patch_create))) {
        private enum enumMixinStr_patch_create = `enum patch_create = ZDIR_PATCH_CREATE;`;
        static if(is(typeof({ mixin(enumMixinStr_patch_create); }))) {
            mixin(enumMixinStr_patch_create);
        }
    }




    static if(!is(typeof(patch_delete))) {
        private enum enumMixinStr_patch_delete = `enum patch_delete = ZDIR_PATCH_DELETE;`;
        static if(is(typeof({ mixin(enumMixinStr_patch_delete); }))) {
            mixin(enumMixinStr_patch_delete);
        }
    }




    static if(!is(typeof(ZDIR_PATCH_CREATE))) {
        private enum enumMixinStr_ZDIR_PATCH_CREATE = `enum ZDIR_PATCH_CREATE = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_ZDIR_PATCH_CREATE); }))) {
            mixin(enumMixinStr_ZDIR_PATCH_CREATE);
        }
    }




    static if(!is(typeof(ZDIR_PATCH_DELETE))) {
        private enum enumMixinStr_ZDIR_PATCH_DELETE = `enum ZDIR_PATCH_DELETE = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_ZDIR_PATCH_DELETE); }))) {
            mixin(enumMixinStr_ZDIR_PATCH_DELETE);
        }
    }




    static if(!is(typeof(IP_MULTICAST_IF))) {
        private enum enumMixinStr_IP_MULTICAST_IF = `enum IP_MULTICAST_IF = 32;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_MULTICAST_IF); }))) {
            mixin(enumMixinStr_IP_MULTICAST_IF);
        }
    }




    static if(!is(typeof(IP_PMTUDISC_OMIT))) {
        private enum enumMixinStr_IP_PMTUDISC_OMIT = `enum IP_PMTUDISC_OMIT = 5;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_PMTUDISC_OMIT); }))) {
            mixin(enumMixinStr_IP_PMTUDISC_OMIT);
        }
    }




    static if(!is(typeof(IP_PMTUDISC_INTERFACE))) {
        private enum enumMixinStr_IP_PMTUDISC_INTERFACE = `enum IP_PMTUDISC_INTERFACE = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_PMTUDISC_INTERFACE); }))) {
            mixin(enumMixinStr_IP_PMTUDISC_INTERFACE);
        }
    }




    static if(!is(typeof(IP_PMTUDISC_PROBE))) {
        private enum enumMixinStr_IP_PMTUDISC_PROBE = `enum IP_PMTUDISC_PROBE = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_PMTUDISC_PROBE); }))) {
            mixin(enumMixinStr_IP_PMTUDISC_PROBE);
        }
    }




    static if(!is(typeof(IP_PMTUDISC_DO))) {
        private enum enumMixinStr_IP_PMTUDISC_DO = `enum IP_PMTUDISC_DO = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_PMTUDISC_DO); }))) {
            mixin(enumMixinStr_IP_PMTUDISC_DO);
        }
    }




    static if(!is(typeof(IP_PMTUDISC_WANT))) {
        private enum enumMixinStr_IP_PMTUDISC_WANT = `enum IP_PMTUDISC_WANT = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_PMTUDISC_WANT); }))) {
            mixin(enumMixinStr_IP_PMTUDISC_WANT);
        }
    }




    static if(!is(typeof(IP_PMTUDISC_DONT))) {
        private enum enumMixinStr_IP_PMTUDISC_DONT = `enum IP_PMTUDISC_DONT = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_PMTUDISC_DONT); }))) {
            mixin(enumMixinStr_IP_PMTUDISC_DONT);
        }
    }




    static if(!is(typeof(IP_RECVFRAGSIZE))) {
        private enum enumMixinStr_IP_RECVFRAGSIZE = `enum IP_RECVFRAGSIZE = 25;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_RECVFRAGSIZE); }))) {
            mixin(enumMixinStr_IP_RECVFRAGSIZE);
        }
    }




    static if(!is(typeof(IP_BIND_ADDRESS_NO_PORT))) {
        private enum enumMixinStr_IP_BIND_ADDRESS_NO_PORT = `enum IP_BIND_ADDRESS_NO_PORT = 24;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_BIND_ADDRESS_NO_PORT); }))) {
            mixin(enumMixinStr_IP_BIND_ADDRESS_NO_PORT);
        }
    }




    static if(!is(typeof(IP_CHECKSUM))) {
        private enum enumMixinStr_IP_CHECKSUM = `enum IP_CHECKSUM = 23;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_CHECKSUM); }))) {
            mixin(enumMixinStr_IP_CHECKSUM);
        }
    }




    static if(!is(typeof(IP_NODEFRAG))) {
        private enum enumMixinStr_IP_NODEFRAG = `enum IP_NODEFRAG = 22;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_NODEFRAG); }))) {
            mixin(enumMixinStr_IP_NODEFRAG);
        }
    }




    static if(!is(typeof(IP_MINTTL))) {
        private enum enumMixinStr_IP_MINTTL = `enum IP_MINTTL = 21;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_MINTTL); }))) {
            mixin(enumMixinStr_IP_MINTTL);
        }
    }




    static if(!is(typeof(IP_RECVORIGDSTADDR))) {
        private enum enumMixinStr_IP_RECVORIGDSTADDR = `enum IP_RECVORIGDSTADDR = IP_ORIGDSTADDR;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_RECVORIGDSTADDR); }))) {
            mixin(enumMixinStr_IP_RECVORIGDSTADDR);
        }
    }




    static if(!is(typeof(IP_ORIGDSTADDR))) {
        private enum enumMixinStr_IP_ORIGDSTADDR = `enum IP_ORIGDSTADDR = 20;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_ORIGDSTADDR); }))) {
            mixin(enumMixinStr_IP_ORIGDSTADDR);
        }
    }




    static if(!is(typeof(IP_TRANSPARENT))) {
        private enum enumMixinStr_IP_TRANSPARENT = `enum IP_TRANSPARENT = 19;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_TRANSPARENT); }))) {
            mixin(enumMixinStr_IP_TRANSPARENT);
        }
    }




    static if(!is(typeof(IP_PASSSEC))) {
        private enum enumMixinStr_IP_PASSSEC = `enum IP_PASSSEC = 18;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_PASSSEC); }))) {
            mixin(enumMixinStr_IP_PASSSEC);
        }
    }




    static if(!is(typeof(IP_XFRM_POLICY))) {
        private enum enumMixinStr_IP_XFRM_POLICY = `enum IP_XFRM_POLICY = 17;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_XFRM_POLICY); }))) {
            mixin(enumMixinStr_IP_XFRM_POLICY);
        }
    }




    static if(!is(typeof(IP_IPSEC_POLICY))) {
        private enum enumMixinStr_IP_IPSEC_POLICY = `enum IP_IPSEC_POLICY = 16;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_IPSEC_POLICY); }))) {
            mixin(enumMixinStr_IP_IPSEC_POLICY);
        }
    }




    static if(!is(typeof(IP_FREEBIND))) {
        private enum enumMixinStr_IP_FREEBIND = `enum IP_FREEBIND = 15;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_FREEBIND); }))) {
            mixin(enumMixinStr_IP_FREEBIND);
        }
    }




    static if(!is(typeof(IP_MTU))) {
        private enum enumMixinStr_IP_MTU = `enum IP_MTU = 14;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_MTU); }))) {
            mixin(enumMixinStr_IP_MTU);
        }
    }






    static if(!is(typeof(IP_RECVTOS))) {
        private enum enumMixinStr_IP_RECVTOS = `enum IP_RECVTOS = 13;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_RECVTOS); }))) {
            mixin(enumMixinStr_IP_RECVTOS);
        }
    }




    static if(!is(typeof(IP_RECVTTL))) {
        private enum enumMixinStr_IP_RECVTTL = `enum IP_RECVTTL = 12;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_RECVTTL); }))) {
            mixin(enumMixinStr_IP_RECVTTL);
        }
    }




    static if(!is(typeof(IP_RECVERR))) {
        private enum enumMixinStr_IP_RECVERR = `enum IP_RECVERR = 11;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_RECVERR); }))) {
            mixin(enumMixinStr_IP_RECVERR);
        }
    }




    static if(!is(typeof(IP_MTU_DISCOVER))) {
        private enum enumMixinStr_IP_MTU_DISCOVER = `enum IP_MTU_DISCOVER = 10;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_MTU_DISCOVER); }))) {
            mixin(enumMixinStr_IP_MTU_DISCOVER);
        }
    }




    static if(!is(typeof(IP_PMTUDISC))) {
        private enum enumMixinStr_IP_PMTUDISC = `enum IP_PMTUDISC = 10;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_PMTUDISC); }))) {
            mixin(enumMixinStr_IP_PMTUDISC);
        }
    }




    static if(!is(typeof(IP_PKTOPTIONS))) {
        private enum enumMixinStr_IP_PKTOPTIONS = `enum IP_PKTOPTIONS = 9;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_PKTOPTIONS); }))) {
            mixin(enumMixinStr_IP_PKTOPTIONS);
        }
    }




    static if(!is(typeof(IP_PKTINFO))) {
        private enum enumMixinStr_IP_PKTINFO = `enum IP_PKTINFO = 8;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_PKTINFO); }))) {
            mixin(enumMixinStr_IP_PKTINFO);
        }
    }




    static if(!is(typeof(IP_ROUTER_ALERT))) {
        private enum enumMixinStr_IP_ROUTER_ALERT = `enum IP_ROUTER_ALERT = 5;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_ROUTER_ALERT); }))) {
            mixin(enumMixinStr_IP_ROUTER_ALERT);
        }
    }




    static if(!is(typeof(MCAST_INCLUDE))) {
        private enum enumMixinStr_MCAST_INCLUDE = `enum MCAST_INCLUDE = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_MCAST_INCLUDE); }))) {
            mixin(enumMixinStr_MCAST_INCLUDE);
        }
    }




    static if(!is(typeof(MCAST_EXCLUDE))) {
        private enum enumMixinStr_MCAST_EXCLUDE = `enum MCAST_EXCLUDE = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_MCAST_EXCLUDE); }))) {
            mixin(enumMixinStr_MCAST_EXCLUDE);
        }
    }




    static if(!is(typeof(MCAST_MSFILTER))) {
        private enum enumMixinStr_MCAST_MSFILTER = `enum MCAST_MSFILTER = 48;`;
        static if(is(typeof({ mixin(enumMixinStr_MCAST_MSFILTER); }))) {
            mixin(enumMixinStr_MCAST_MSFILTER);
        }
    }




    static if(!is(typeof(MCAST_LEAVE_SOURCE_GROUP))) {
        private enum enumMixinStr_MCAST_LEAVE_SOURCE_GROUP = `enum MCAST_LEAVE_SOURCE_GROUP = 47;`;
        static if(is(typeof({ mixin(enumMixinStr_MCAST_LEAVE_SOURCE_GROUP); }))) {
            mixin(enumMixinStr_MCAST_LEAVE_SOURCE_GROUP);
        }
    }




    static if(!is(typeof(MCAST_JOIN_SOURCE_GROUP))) {
        private enum enumMixinStr_MCAST_JOIN_SOURCE_GROUP = `enum MCAST_JOIN_SOURCE_GROUP = 46;`;
        static if(is(typeof({ mixin(enumMixinStr_MCAST_JOIN_SOURCE_GROUP); }))) {
            mixin(enumMixinStr_MCAST_JOIN_SOURCE_GROUP);
        }
    }




    static if(!is(typeof(MCAST_LEAVE_GROUP))) {
        private enum enumMixinStr_MCAST_LEAVE_GROUP = `enum MCAST_LEAVE_GROUP = 45;`;
        static if(is(typeof({ mixin(enumMixinStr_MCAST_LEAVE_GROUP); }))) {
            mixin(enumMixinStr_MCAST_LEAVE_GROUP);
        }
    }




    static if(!is(typeof(MCAST_UNBLOCK_SOURCE))) {
        private enum enumMixinStr_MCAST_UNBLOCK_SOURCE = `enum MCAST_UNBLOCK_SOURCE = 44;`;
        static if(is(typeof({ mixin(enumMixinStr_MCAST_UNBLOCK_SOURCE); }))) {
            mixin(enumMixinStr_MCAST_UNBLOCK_SOURCE);
        }
    }




    static if(!is(typeof(MCAST_BLOCK_SOURCE))) {
        private enum enumMixinStr_MCAST_BLOCK_SOURCE = `enum MCAST_BLOCK_SOURCE = 43;`;
        static if(is(typeof({ mixin(enumMixinStr_MCAST_BLOCK_SOURCE); }))) {
            mixin(enumMixinStr_MCAST_BLOCK_SOURCE);
        }
    }




    static if(!is(typeof(MCAST_JOIN_GROUP))) {
        private enum enumMixinStr_MCAST_JOIN_GROUP = `enum MCAST_JOIN_GROUP = 42;`;
        static if(is(typeof({ mixin(enumMixinStr_MCAST_JOIN_GROUP); }))) {
            mixin(enumMixinStr_MCAST_JOIN_GROUP);
        }
    }




    static if(!is(typeof(IP_RETOPTS))) {
        private enum enumMixinStr_IP_RETOPTS = `enum IP_RETOPTS = 7;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_RETOPTS); }))) {
            mixin(enumMixinStr_IP_RETOPTS);
        }
    }




    static if(!is(typeof(IP_RECVRETOPTS))) {
        private enum enumMixinStr_IP_RECVRETOPTS = `enum IP_RECVRETOPTS = 7;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_RECVRETOPTS); }))) {
            mixin(enumMixinStr_IP_RECVRETOPTS);
        }
    }




    static if(!is(typeof(IP_RECVOPTS))) {
        private enum enumMixinStr_IP_RECVOPTS = `enum IP_RECVOPTS = 6;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_RECVOPTS); }))) {
            mixin(enumMixinStr_IP_RECVOPTS);
        }
    }




    static if(!is(typeof(IP_TTL))) {
        private enum enumMixinStr_IP_TTL = `enum IP_TTL = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_TTL); }))) {
            mixin(enumMixinStr_IP_TTL);
        }
    }




    static if(!is(typeof(IP_TOS))) {
        private enum enumMixinStr_IP_TOS = `enum IP_TOS = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_TOS); }))) {
            mixin(enumMixinStr_IP_TOS);
        }
    }




    static if(!is(typeof(IP_HDRINCL))) {
        private enum enumMixinStr_IP_HDRINCL = `enum IP_HDRINCL = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_HDRINCL); }))) {
            mixin(enumMixinStr_IP_HDRINCL);
        }
    }




    static if(!is(typeof(IP_OPTIONS))) {
        private enum enumMixinStr_IP_OPTIONS = `enum IP_OPTIONS = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_IP_OPTIONS); }))) {
            mixin(enumMixinStr_IP_OPTIONS);
        }
    }




    static if(!is(typeof(__USE_KERNEL_IPV6_DEFS))) {
        private enum enumMixinStr___USE_KERNEL_IPV6_DEFS = `enum __USE_KERNEL_IPV6_DEFS = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___USE_KERNEL_IPV6_DEFS); }))) {
            mixin(enumMixinStr___USE_KERNEL_IPV6_DEFS);
        }
    }




    static if(!is(typeof(_GETOPT_POSIX_H))) {
        private enum enumMixinStr__GETOPT_POSIX_H = `enum _GETOPT_POSIX_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__GETOPT_POSIX_H); }))) {
            mixin(enumMixinStr__GETOPT_POSIX_H);
        }
    }




    static if(!is(typeof(_GETOPT_CORE_H))) {
        private enum enumMixinStr__GETOPT_CORE_H = `enum _GETOPT_CORE_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__GETOPT_CORE_H); }))) {
            mixin(enumMixinStr__GETOPT_CORE_H);
        }
    }




    static if(!is(typeof(__FP_LOGBNAN_IS_MIN))) {
        private enum enumMixinStr___FP_LOGBNAN_IS_MIN = `enum __FP_LOGBNAN_IS_MIN = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___FP_LOGBNAN_IS_MIN); }))) {
            mixin(enumMixinStr___FP_LOGBNAN_IS_MIN);
        }
    }




    static if(!is(typeof(__FP_LOGB0_IS_MIN))) {
        private enum enumMixinStr___FP_LOGB0_IS_MIN = `enum __FP_LOGB0_IS_MIN = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___FP_LOGB0_IS_MIN); }))) {
            mixin(enumMixinStr___FP_LOGB0_IS_MIN);
        }
    }




    static if(!is(typeof(__GLIBC_FLT_EVAL_METHOD))) {
        private enum enumMixinStr___GLIBC_FLT_EVAL_METHOD = `enum __GLIBC_FLT_EVAL_METHOD = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___GLIBC_FLT_EVAL_METHOD); }))) {
            mixin(enumMixinStr___GLIBC_FLT_EVAL_METHOD);
        }
    }




    static if(!is(typeof(__HAVE_FLOAT64X_LONG_DOUBLE))) {
        private enum enumMixinStr___HAVE_FLOAT64X_LONG_DOUBLE = `enum __HAVE_FLOAT64X_LONG_DOUBLE = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___HAVE_FLOAT64X_LONG_DOUBLE); }))) {
            mixin(enumMixinStr___HAVE_FLOAT64X_LONG_DOUBLE);
        }
    }




    static if(!is(typeof(__HAVE_FLOAT64X))) {
        private enum enumMixinStr___HAVE_FLOAT64X = `enum __HAVE_FLOAT64X = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___HAVE_FLOAT64X); }))) {
            mixin(enumMixinStr___HAVE_FLOAT64X);
        }
    }




    static if(!is(typeof(__HAVE_DISTINCT_FLOAT128))) {
        private enum enumMixinStr___HAVE_DISTINCT_FLOAT128 = `enum __HAVE_DISTINCT_FLOAT128 = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___HAVE_DISTINCT_FLOAT128); }))) {
            mixin(enumMixinStr___HAVE_DISTINCT_FLOAT128);
        }
    }




    static if(!is(typeof(__HAVE_FLOAT128))) {
        private enum enumMixinStr___HAVE_FLOAT128 = `enum __HAVE_FLOAT128 = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___HAVE_FLOAT128); }))) {
            mixin(enumMixinStr___HAVE_FLOAT128);
        }
    }
    static if(!is(typeof(__CFLOAT64X))) {
        private enum enumMixinStr___CFLOAT64X = `enum __CFLOAT64X = _Complex long double;`;
        static if(is(typeof({ mixin(enumMixinStr___CFLOAT64X); }))) {
            mixin(enumMixinStr___CFLOAT64X);
        }
    }




    static if(!is(typeof(__CFLOAT32X))) {
        private enum enumMixinStr___CFLOAT32X = `enum __CFLOAT32X = _Complex double;`;
        static if(is(typeof({ mixin(enumMixinStr___CFLOAT32X); }))) {
            mixin(enumMixinStr___CFLOAT32X);
        }
    }




    static if(!is(typeof(__CFLOAT64))) {
        private enum enumMixinStr___CFLOAT64 = `enum __CFLOAT64 = _Complex double;`;
        static if(is(typeof({ mixin(enumMixinStr___CFLOAT64); }))) {
            mixin(enumMixinStr___CFLOAT64);
        }
    }




    static if(!is(typeof(__CFLOAT32))) {
        private enum enumMixinStr___CFLOAT32 = `enum __CFLOAT32 = _Complex float;`;
        static if(is(typeof({ mixin(enumMixinStr___CFLOAT32); }))) {
            mixin(enumMixinStr___CFLOAT32);
        }
    }
    static if(!is(typeof(__HAVE_FLOATN_NOT_TYPEDEF))) {
        private enum enumMixinStr___HAVE_FLOATN_NOT_TYPEDEF = `enum __HAVE_FLOATN_NOT_TYPEDEF = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___HAVE_FLOATN_NOT_TYPEDEF); }))) {
            mixin(enumMixinStr___HAVE_FLOATN_NOT_TYPEDEF);
        }
    }




    static if(!is(typeof(__HAVE_FLOAT128_UNLIKE_LDBL))) {
        private enum enumMixinStr___HAVE_FLOAT128_UNLIKE_LDBL = `enum __HAVE_FLOAT128_UNLIKE_LDBL = ( 0 && 64 != 113 );`;
        static if(is(typeof({ mixin(enumMixinStr___HAVE_FLOAT128_UNLIKE_LDBL); }))) {
            mixin(enumMixinStr___HAVE_FLOAT128_UNLIKE_LDBL);
        }
    }




    static if(!is(typeof(__HAVE_DISTINCT_FLOAT128X))) {
        private enum enumMixinStr___HAVE_DISTINCT_FLOAT128X = `enum __HAVE_DISTINCT_FLOAT128X = __HAVE_FLOAT128X;`;
        static if(is(typeof({ mixin(enumMixinStr___HAVE_DISTINCT_FLOAT128X); }))) {
            mixin(enumMixinStr___HAVE_DISTINCT_FLOAT128X);
        }
    }




    static if(!is(typeof(__HAVE_DISTINCT_FLOAT64X))) {
        private enum enumMixinStr___HAVE_DISTINCT_FLOAT64X = `enum __HAVE_DISTINCT_FLOAT64X = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___HAVE_DISTINCT_FLOAT64X); }))) {
            mixin(enumMixinStr___HAVE_DISTINCT_FLOAT64X);
        }
    }




    static if(!is(typeof(__HAVE_DISTINCT_FLOAT32X))) {
        private enum enumMixinStr___HAVE_DISTINCT_FLOAT32X = `enum __HAVE_DISTINCT_FLOAT32X = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___HAVE_DISTINCT_FLOAT32X); }))) {
            mixin(enumMixinStr___HAVE_DISTINCT_FLOAT32X);
        }
    }






    static if(!is(typeof(ZFRAME_MORE))) {
        private enum enumMixinStr_ZFRAME_MORE = `enum ZFRAME_MORE = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_ZFRAME_MORE); }))) {
            mixin(enumMixinStr_ZFRAME_MORE);
        }
    }




    static if(!is(typeof(ZFRAME_REUSE))) {
        private enum enumMixinStr_ZFRAME_REUSE = `enum ZFRAME_REUSE = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_ZFRAME_REUSE); }))) {
            mixin(enumMixinStr_ZFRAME_REUSE);
        }
    }




    static if(!is(typeof(ZFRAME_DONTWAIT))) {
        private enum enumMixinStr_ZFRAME_DONTWAIT = `enum ZFRAME_DONTWAIT = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_ZFRAME_DONTWAIT); }))) {
            mixin(enumMixinStr_ZFRAME_DONTWAIT);
        }
    }




    static if(!is(typeof(__HAVE_DISTINCT_FLOAT64))) {
        private enum enumMixinStr___HAVE_DISTINCT_FLOAT64 = `enum __HAVE_DISTINCT_FLOAT64 = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___HAVE_DISTINCT_FLOAT64); }))) {
            mixin(enumMixinStr___HAVE_DISTINCT_FLOAT64);
        }
    }




    static if(!is(typeof(__HAVE_DISTINCT_FLOAT32))) {
        private enum enumMixinStr___HAVE_DISTINCT_FLOAT32 = `enum __HAVE_DISTINCT_FLOAT32 = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___HAVE_DISTINCT_FLOAT32); }))) {
            mixin(enumMixinStr___HAVE_DISTINCT_FLOAT32);
        }
    }




    static if(!is(typeof(__HAVE_DISTINCT_FLOAT16))) {
        private enum enumMixinStr___HAVE_DISTINCT_FLOAT16 = `enum __HAVE_DISTINCT_FLOAT16 = __HAVE_FLOAT16;`;
        static if(is(typeof({ mixin(enumMixinStr___HAVE_DISTINCT_FLOAT16); }))) {
            mixin(enumMixinStr___HAVE_DISTINCT_FLOAT16);
        }
    }




    static if(!is(typeof(__HAVE_FLOAT128X))) {
        private enum enumMixinStr___HAVE_FLOAT128X = `enum __HAVE_FLOAT128X = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___HAVE_FLOAT128X); }))) {
            mixin(enumMixinStr___HAVE_FLOAT128X);
        }
    }




    static if(!is(typeof(__HAVE_FLOAT32X))) {
        private enum enumMixinStr___HAVE_FLOAT32X = `enum __HAVE_FLOAT32X = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___HAVE_FLOAT32X); }))) {
            mixin(enumMixinStr___HAVE_FLOAT32X);
        }
    }




    static if(!is(typeof(__HAVE_FLOAT64))) {
        private enum enumMixinStr___HAVE_FLOAT64 = `enum __HAVE_FLOAT64 = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___HAVE_FLOAT64); }))) {
            mixin(enumMixinStr___HAVE_FLOAT64);
        }
    }




    static if(!is(typeof(__HAVE_FLOAT32))) {
        private enum enumMixinStr___HAVE_FLOAT32 = `enum __HAVE_FLOAT32 = 1;`;
        static if(is(typeof({ mixin(enumMixinStr___HAVE_FLOAT32); }))) {
            mixin(enumMixinStr___HAVE_FLOAT32);
        }
    }




    static if(!is(typeof(__HAVE_FLOAT16))) {
        private enum enumMixinStr___HAVE_FLOAT16 = `enum __HAVE_FLOAT16 = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___HAVE_FLOAT16); }))) {
            mixin(enumMixinStr___HAVE_FLOAT16);
        }
    }






    static if(!is(typeof(F_SETLKW64))) {
        private enum enumMixinStr_F_SETLKW64 = `enum F_SETLKW64 = 7;`;
        static if(is(typeof({ mixin(enumMixinStr_F_SETLKW64); }))) {
            mixin(enumMixinStr_F_SETLKW64);
        }
    }




    static if(!is(typeof(F_SETLK64))) {
        private enum enumMixinStr_F_SETLK64 = `enum F_SETLK64 = 6;`;
        static if(is(typeof({ mixin(enumMixinStr_F_SETLK64); }))) {
            mixin(enumMixinStr_F_SETLK64);
        }
    }




    static if(!is(typeof(F_GETLK64))) {
        private enum enumMixinStr_F_GETLK64 = `enum F_GETLK64 = 5;`;
        static if(is(typeof({ mixin(enumMixinStr_F_GETLK64); }))) {
            mixin(enumMixinStr_F_GETLK64);
        }
    }




    static if(!is(typeof(__O_LARGEFILE))) {
        private enum enumMixinStr___O_LARGEFILE = `enum __O_LARGEFILE = 0;`;
        static if(is(typeof({ mixin(enumMixinStr___O_LARGEFILE); }))) {
            mixin(enumMixinStr___O_LARGEFILE);
        }
    }




    static if(!is(typeof(POSIX_FADV_NOREUSE))) {
        private enum enumMixinStr_POSIX_FADV_NOREUSE = `enum POSIX_FADV_NOREUSE = __POSIX_FADV_NOREUSE;`;
        static if(is(typeof({ mixin(enumMixinStr_POSIX_FADV_NOREUSE); }))) {
            mixin(enumMixinStr_POSIX_FADV_NOREUSE);
        }
    }




    static if(!is(typeof(POSIX_FADV_DONTNEED))) {
        private enum enumMixinStr_POSIX_FADV_DONTNEED = `enum POSIX_FADV_DONTNEED = __POSIX_FADV_DONTNEED;`;
        static if(is(typeof({ mixin(enumMixinStr_POSIX_FADV_DONTNEED); }))) {
            mixin(enumMixinStr_POSIX_FADV_DONTNEED);
        }
    }




    static if(!is(typeof(POSIX_FADV_WILLNEED))) {
        private enum enumMixinStr_POSIX_FADV_WILLNEED = `enum POSIX_FADV_WILLNEED = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_POSIX_FADV_WILLNEED); }))) {
            mixin(enumMixinStr_POSIX_FADV_WILLNEED);
        }
    }




    static if(!is(typeof(POSIX_FADV_SEQUENTIAL))) {
        private enum enumMixinStr_POSIX_FADV_SEQUENTIAL = `enum POSIX_FADV_SEQUENTIAL = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_POSIX_FADV_SEQUENTIAL); }))) {
            mixin(enumMixinStr_POSIX_FADV_SEQUENTIAL);
        }
    }




    static if(!is(typeof(POSIX_FADV_RANDOM))) {
        private enum enumMixinStr_POSIX_FADV_RANDOM = `enum POSIX_FADV_RANDOM = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_POSIX_FADV_RANDOM); }))) {
            mixin(enumMixinStr_POSIX_FADV_RANDOM);
        }
    }




    static if(!is(typeof(POSIX_FADV_NORMAL))) {
        private enum enumMixinStr_POSIX_FADV_NORMAL = `enum POSIX_FADV_NORMAL = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_POSIX_FADV_NORMAL); }))) {
            mixin(enumMixinStr_POSIX_FADV_NORMAL);
        }
    }




    static if(!is(typeof(__POSIX_FADV_NOREUSE))) {
        private enum enumMixinStr___POSIX_FADV_NOREUSE = `enum __POSIX_FADV_NOREUSE = 5;`;
        static if(is(typeof({ mixin(enumMixinStr___POSIX_FADV_NOREUSE); }))) {
            mixin(enumMixinStr___POSIX_FADV_NOREUSE);
        }
    }




    static if(!is(typeof(__POSIX_FADV_DONTNEED))) {
        private enum enumMixinStr___POSIX_FADV_DONTNEED = `enum __POSIX_FADV_DONTNEED = 4;`;
        static if(is(typeof({ mixin(enumMixinStr___POSIX_FADV_DONTNEED); }))) {
            mixin(enumMixinStr___POSIX_FADV_DONTNEED);
        }
    }




    static if(!is(typeof(FNDELAY))) {
        private enum enumMixinStr_FNDELAY = `enum FNDELAY = O_NDELAY;`;
        static if(is(typeof({ mixin(enumMixinStr_FNDELAY); }))) {
            mixin(enumMixinStr_FNDELAY);
        }
    }




    static if(!is(typeof(FNONBLOCK))) {
        private enum enumMixinStr_FNONBLOCK = `enum FNONBLOCK = O_NONBLOCK;`;
        static if(is(typeof({ mixin(enumMixinStr_FNONBLOCK); }))) {
            mixin(enumMixinStr_FNONBLOCK);
        }
    }




    static if(!is(typeof(FASYNC))) {
        private enum enumMixinStr_FASYNC = `enum FASYNC = O_ASYNC;`;
        static if(is(typeof({ mixin(enumMixinStr_FASYNC); }))) {
            mixin(enumMixinStr_FASYNC);
        }
    }




    static if(!is(typeof(FFSYNC))) {
        private enum enumMixinStr_FFSYNC = `enum FFSYNC = O_FSYNC;`;
        static if(is(typeof({ mixin(enumMixinStr_FFSYNC); }))) {
            mixin(enumMixinStr_FFSYNC);
        }
    }




    static if(!is(typeof(FAPPEND))) {
        private enum enumMixinStr_FAPPEND = `enum FAPPEND = O_APPEND;`;
        static if(is(typeof({ mixin(enumMixinStr_FAPPEND); }))) {
            mixin(enumMixinStr_FAPPEND);
        }
    }




    static if(!is(typeof(F_SHLCK))) {
        private enum enumMixinStr_F_SHLCK = `enum F_SHLCK = 8;`;
        static if(is(typeof({ mixin(enumMixinStr_F_SHLCK); }))) {
            mixin(enumMixinStr_F_SHLCK);
        }
    }




    static if(!is(typeof(F_EXLCK))) {
        private enum enumMixinStr_F_EXLCK = `enum F_EXLCK = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_F_EXLCK); }))) {
            mixin(enumMixinStr_F_EXLCK);
        }
    }




    static if(!is(typeof(F_UNLCK))) {
        private enum enumMixinStr_F_UNLCK = `enum F_UNLCK = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_F_UNLCK); }))) {
            mixin(enumMixinStr_F_UNLCK);
        }
    }




    static if(!is(typeof(F_WRLCK))) {
        private enum enumMixinStr_F_WRLCK = `enum F_WRLCK = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_F_WRLCK); }))) {
            mixin(enumMixinStr_F_WRLCK);
        }
    }




    static if(!is(typeof(F_RDLCK))) {
        private enum enumMixinStr_F_RDLCK = `enum F_RDLCK = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_F_RDLCK); }))) {
            mixin(enumMixinStr_F_RDLCK);
        }
    }




    static if(!is(typeof(FD_CLOEXEC))) {
        private enum enumMixinStr_FD_CLOEXEC = `enum FD_CLOEXEC = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_FD_CLOEXEC); }))) {
            mixin(enumMixinStr_FD_CLOEXEC);
        }
    }




    static if(!is(typeof(F_DUPFD_CLOEXEC))) {
        private enum enumMixinStr_F_DUPFD_CLOEXEC = `enum F_DUPFD_CLOEXEC = 1030;`;
        static if(is(typeof({ mixin(enumMixinStr_F_DUPFD_CLOEXEC); }))) {
            mixin(enumMixinStr_F_DUPFD_CLOEXEC);
        }
    }




    static if(!is(typeof(__F_GETOWN_EX))) {
        private enum enumMixinStr___F_GETOWN_EX = `enum __F_GETOWN_EX = 16;`;
        static if(is(typeof({ mixin(enumMixinStr___F_GETOWN_EX); }))) {
            mixin(enumMixinStr___F_GETOWN_EX);
        }
    }




    static if(!is(typeof(__F_SETOWN_EX))) {
        private enum enumMixinStr___F_SETOWN_EX = `enum __F_SETOWN_EX = 15;`;
        static if(is(typeof({ mixin(enumMixinStr___F_SETOWN_EX); }))) {
            mixin(enumMixinStr___F_SETOWN_EX);
        }
    }




    static if(!is(typeof(__F_GETSIG))) {
        private enum enumMixinStr___F_GETSIG = `enum __F_GETSIG = 11;`;
        static if(is(typeof({ mixin(enumMixinStr___F_GETSIG); }))) {
            mixin(enumMixinStr___F_GETSIG);
        }
    }




    static if(!is(typeof(__F_SETSIG))) {
        private enum enumMixinStr___F_SETSIG = `enum __F_SETSIG = 10;`;
        static if(is(typeof({ mixin(enumMixinStr___F_SETSIG); }))) {
            mixin(enumMixinStr___F_SETSIG);
        }
    }




    static if(!is(typeof(F_GETOWN))) {
        private enum enumMixinStr_F_GETOWN = `enum F_GETOWN = __F_GETOWN;`;
        static if(is(typeof({ mixin(enumMixinStr_F_GETOWN); }))) {
            mixin(enumMixinStr_F_GETOWN);
        }
    }




    static if(!is(typeof(F_SETOWN))) {
        private enum enumMixinStr_F_SETOWN = `enum F_SETOWN = __F_SETOWN;`;
        static if(is(typeof({ mixin(enumMixinStr_F_SETOWN); }))) {
            mixin(enumMixinStr_F_SETOWN);
        }
    }




    static if(!is(typeof(__F_GETOWN))) {
        private enum enumMixinStr___F_GETOWN = `enum __F_GETOWN = 9;`;
        static if(is(typeof({ mixin(enumMixinStr___F_GETOWN); }))) {
            mixin(enumMixinStr___F_GETOWN);
        }
    }




    static if(!is(typeof(__F_SETOWN))) {
        private enum enumMixinStr___F_SETOWN = `enum __F_SETOWN = 8;`;
        static if(is(typeof({ mixin(enumMixinStr___F_SETOWN); }))) {
            mixin(enumMixinStr___F_SETOWN);
        }
    }




    static if(!is(typeof(F_SETFL))) {
        private enum enumMixinStr_F_SETFL = `enum F_SETFL = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_F_SETFL); }))) {
            mixin(enumMixinStr_F_SETFL);
        }
    }




    static if(!is(typeof(F_GETFL))) {
        private enum enumMixinStr_F_GETFL = `enum F_GETFL = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_F_GETFL); }))) {
            mixin(enumMixinStr_F_GETFL);
        }
    }




    static if(!is(typeof(F_SETFD))) {
        private enum enumMixinStr_F_SETFD = `enum F_SETFD = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_F_SETFD); }))) {
            mixin(enumMixinStr_F_SETFD);
        }
    }
    static if(!is(typeof(F_GETFD))) {
        private enum enumMixinStr_F_GETFD = `enum F_GETFD = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_F_GETFD); }))) {
            mixin(enumMixinStr_F_GETFD);
        }
    }




    static if(!is(typeof(F_DUPFD))) {
        private enum enumMixinStr_F_DUPFD = `enum F_DUPFD = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_F_DUPFD); }))) {
            mixin(enumMixinStr_F_DUPFD);
        }
    }




    static if(!is(typeof(O_RSYNC))) {
        private enum enumMixinStr_O_RSYNC = `enum O_RSYNC = O_SYNC;`;
        static if(is(typeof({ mixin(enumMixinStr_O_RSYNC); }))) {
            mixin(enumMixinStr_O_RSYNC);
        }
    }




    static if(!is(typeof(O_DSYNC))) {
        private enum enumMixinStr_O_DSYNC = `enum O_DSYNC = __O_DSYNC;`;
        static if(is(typeof({ mixin(enumMixinStr_O_DSYNC); }))) {
            mixin(enumMixinStr_O_DSYNC);
        }
    }




    static if(!is(typeof(O_CLOEXEC))) {
        private enum enumMixinStr_O_CLOEXEC = `enum O_CLOEXEC = __O_CLOEXEC;`;
        static if(is(typeof({ mixin(enumMixinStr_O_CLOEXEC); }))) {
            mixin(enumMixinStr_O_CLOEXEC);
        }
    }




    static if(!is(typeof(O_NOFOLLOW))) {
        private enum enumMixinStr_O_NOFOLLOW = `enum O_NOFOLLOW = __O_NOFOLLOW;`;
        static if(is(typeof({ mixin(enumMixinStr_O_NOFOLLOW); }))) {
            mixin(enumMixinStr_O_NOFOLLOW);
        }
    }






    static if(!is(typeof(O_DIRECTORY))) {
        private enum enumMixinStr_O_DIRECTORY = `enum O_DIRECTORY = __O_DIRECTORY;`;
        static if(is(typeof({ mixin(enumMixinStr_O_DIRECTORY); }))) {
            mixin(enumMixinStr_O_DIRECTORY);
        }
    }




    static if(!is(typeof(F_SETLKW))) {
        private enum enumMixinStr_F_SETLKW = `enum F_SETLKW = 7;`;
        static if(is(typeof({ mixin(enumMixinStr_F_SETLKW); }))) {
            mixin(enumMixinStr_F_SETLKW);
        }
    }




    static if(!is(typeof(F_SETLK))) {
        private enum enumMixinStr_F_SETLK = `enum F_SETLK = 6;`;
        static if(is(typeof({ mixin(enumMixinStr_F_SETLK); }))) {
            mixin(enumMixinStr_F_SETLK);
        }
    }




    static if(!is(typeof(F_GETLK))) {
        private enum enumMixinStr_F_GETLK = `enum F_GETLK = 5;`;
        static if(is(typeof({ mixin(enumMixinStr_F_GETLK); }))) {
            mixin(enumMixinStr_F_GETLK);
        }
    }




    static if(!is(typeof(__O_TMPFILE))) {
        private enum enumMixinStr___O_TMPFILE = `enum __O_TMPFILE = ( 020000000 | __O_DIRECTORY );`;
        static if(is(typeof({ mixin(enumMixinStr___O_TMPFILE); }))) {
            mixin(enumMixinStr___O_TMPFILE);
        }
    }




    static if(!is(typeof(__O_DSYNC))) {
        private enum enumMixinStr___O_DSYNC = `enum __O_DSYNC = std.conv.octal!10000;`;
        static if(is(typeof({ mixin(enumMixinStr___O_DSYNC); }))) {
            mixin(enumMixinStr___O_DSYNC);
        }
    }




    static if(!is(typeof(__O_PATH))) {
        private enum enumMixinStr___O_PATH = `enum __O_PATH = std.conv.octal!10000000;`;
        static if(is(typeof({ mixin(enumMixinStr___O_PATH); }))) {
            mixin(enumMixinStr___O_PATH);
        }
    }




    static if(!is(typeof(__O_NOATIME))) {
        private enum enumMixinStr___O_NOATIME = `enum __O_NOATIME = std.conv.octal!1000000;`;
        static if(is(typeof({ mixin(enumMixinStr___O_NOATIME); }))) {
            mixin(enumMixinStr___O_NOATIME);
        }
    }




    static if(!is(typeof(__O_DIRECT))) {
        private enum enumMixinStr___O_DIRECT = `enum __O_DIRECT = std.conv.octal!40000;`;
        static if(is(typeof({ mixin(enumMixinStr___O_DIRECT); }))) {
            mixin(enumMixinStr___O_DIRECT);
        }
    }




    static if(!is(typeof(__O_CLOEXEC))) {
        private enum enumMixinStr___O_CLOEXEC = `enum __O_CLOEXEC = std.conv.octal!2000000;`;
        static if(is(typeof({ mixin(enumMixinStr___O_CLOEXEC); }))) {
            mixin(enumMixinStr___O_CLOEXEC);
        }
    }




    static if(!is(typeof(__O_NOFOLLOW))) {
        private enum enumMixinStr___O_NOFOLLOW = `enum __O_NOFOLLOW = std.conv.octal!400000;`;
        static if(is(typeof({ mixin(enumMixinStr___O_NOFOLLOW); }))) {
            mixin(enumMixinStr___O_NOFOLLOW);
        }
    }




    static if(!is(typeof(__O_DIRECTORY))) {
        private enum enumMixinStr___O_DIRECTORY = `enum __O_DIRECTORY = std.conv.octal!200000;`;
        static if(is(typeof({ mixin(enumMixinStr___O_DIRECTORY); }))) {
            mixin(enumMixinStr___O_DIRECTORY);
        }
    }




    static if(!is(typeof(O_ASYNC))) {
        private enum enumMixinStr_O_ASYNC = `enum O_ASYNC = std.conv.octal!20000;`;
        static if(is(typeof({ mixin(enumMixinStr_O_ASYNC); }))) {
            mixin(enumMixinStr_O_ASYNC);
        }
    }




    static if(!is(typeof(O_FSYNC))) {
        private enum enumMixinStr_O_FSYNC = `enum O_FSYNC = O_SYNC;`;
        static if(is(typeof({ mixin(enumMixinStr_O_FSYNC); }))) {
            mixin(enumMixinStr_O_FSYNC);
        }
    }




    static if(!is(typeof(O_SYNC))) {
        private enum enumMixinStr_O_SYNC = `enum O_SYNC = std.conv.octal!4010000;`;
        static if(is(typeof({ mixin(enumMixinStr_O_SYNC); }))) {
            mixin(enumMixinStr_O_SYNC);
        }
    }




    static if(!is(typeof(O_NDELAY))) {
        private enum enumMixinStr_O_NDELAY = `enum O_NDELAY = O_NONBLOCK;`;
        static if(is(typeof({ mixin(enumMixinStr_O_NDELAY); }))) {
            mixin(enumMixinStr_O_NDELAY);
        }
    }




    static if(!is(typeof(O_NONBLOCK))) {
        private enum enumMixinStr_O_NONBLOCK = `enum O_NONBLOCK = std.conv.octal!4000;`;
        static if(is(typeof({ mixin(enumMixinStr_O_NONBLOCK); }))) {
            mixin(enumMixinStr_O_NONBLOCK);
        }
    }




    static if(!is(typeof(O_APPEND))) {
        private enum enumMixinStr_O_APPEND = `enum O_APPEND = std.conv.octal!2000;`;
        static if(is(typeof({ mixin(enumMixinStr_O_APPEND); }))) {
            mixin(enumMixinStr_O_APPEND);
        }
    }




    static if(!is(typeof(O_TRUNC))) {
        private enum enumMixinStr_O_TRUNC = `enum O_TRUNC = std.conv.octal!1000;`;
        static if(is(typeof({ mixin(enumMixinStr_O_TRUNC); }))) {
            mixin(enumMixinStr_O_TRUNC);
        }
    }




    static if(!is(typeof(O_NOCTTY))) {
        private enum enumMixinStr_O_NOCTTY = `enum O_NOCTTY = std.conv.octal!400;`;
        static if(is(typeof({ mixin(enumMixinStr_O_NOCTTY); }))) {
            mixin(enumMixinStr_O_NOCTTY);
        }
    }




    static if(!is(typeof(O_EXCL))) {
        private enum enumMixinStr_O_EXCL = `enum O_EXCL = std.conv.octal!200;`;
        static if(is(typeof({ mixin(enumMixinStr_O_EXCL); }))) {
            mixin(enumMixinStr_O_EXCL);
        }
    }




    static if(!is(typeof(O_CREAT))) {
        private enum enumMixinStr_O_CREAT = `enum O_CREAT = std.conv.octal!100;`;
        static if(is(typeof({ mixin(enumMixinStr_O_CREAT); }))) {
            mixin(enumMixinStr_O_CREAT);
        }
    }




    static if(!is(typeof(O_RDWR))) {
        private enum enumMixinStr_O_RDWR = `enum O_RDWR = std.conv.octal!2;`;
        static if(is(typeof({ mixin(enumMixinStr_O_RDWR); }))) {
            mixin(enumMixinStr_O_RDWR);
        }
    }




    static if(!is(typeof(O_WRONLY))) {
        private enum enumMixinStr_O_WRONLY = `enum O_WRONLY = std.conv.octal!1;`;
        static if(is(typeof({ mixin(enumMixinStr_O_WRONLY); }))) {
            mixin(enumMixinStr_O_WRONLY);
        }
    }




    static if(!is(typeof(O_RDONLY))) {
        private enum enumMixinStr_O_RDONLY = `enum O_RDONLY = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_O_RDONLY); }))) {
            mixin(enumMixinStr_O_RDONLY);
        }
    }




    static if(!is(typeof(O_ACCMODE))) {
        private enum enumMixinStr_O_ACCMODE = `enum O_ACCMODE = std.conv.octal!3;`;
        static if(is(typeof({ mixin(enumMixinStr_O_ACCMODE); }))) {
            mixin(enumMixinStr_O_ACCMODE);
        }
    }




    static if(!is(typeof(ENOTSUP))) {
        private enum enumMixinStr_ENOTSUP = `enum ENOTSUP = EOPNOTSUPP;`;
        static if(is(typeof({ mixin(enumMixinStr_ENOTSUP); }))) {
            mixin(enumMixinStr_ENOTSUP);
        }
    }




    static if(!is(typeof(_BITS_ERRNO_H))) {
        private enum enumMixinStr__BITS_ERRNO_H = `enum _BITS_ERRNO_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_ERRNO_H); }))) {
            mixin(enumMixinStr__BITS_ERRNO_H);
        }
    }




    static if(!is(typeof(__LP64_OFF64_LDFLAGS))) {
        private enum enumMixinStr___LP64_OFF64_LDFLAGS = `enum __LP64_OFF64_LDFLAGS = "-m64";`;
        static if(is(typeof({ mixin(enumMixinStr___LP64_OFF64_LDFLAGS); }))) {
            mixin(enumMixinStr___LP64_OFF64_LDFLAGS);
        }
    }




    static if(!is(typeof(__LP64_OFF64_CFLAGS))) {
        private enum enumMixinStr___LP64_OFF64_CFLAGS = `enum __LP64_OFF64_CFLAGS = "-m64";`;
        static if(is(typeof({ mixin(enumMixinStr___LP64_OFF64_CFLAGS); }))) {
            mixin(enumMixinStr___LP64_OFF64_CFLAGS);
        }
    }




    static if(!is(typeof(__ILP32_OFFBIG_LDFLAGS))) {
        private enum enumMixinStr___ILP32_OFFBIG_LDFLAGS = `enum __ILP32_OFFBIG_LDFLAGS = "-m32";`;
        static if(is(typeof({ mixin(enumMixinStr___ILP32_OFFBIG_LDFLAGS); }))) {
            mixin(enumMixinStr___ILP32_OFFBIG_LDFLAGS);
        }
    }




    static if(!is(typeof(__ILP32_OFFBIG_CFLAGS))) {
        private enum enumMixinStr___ILP32_OFFBIG_CFLAGS = `enum __ILP32_OFFBIG_CFLAGS = "-m32 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64";`;
        static if(is(typeof({ mixin(enumMixinStr___ILP32_OFFBIG_CFLAGS); }))) {
            mixin(enumMixinStr___ILP32_OFFBIG_CFLAGS);
        }
    }




    static if(!is(typeof(__ILP32_OFF32_LDFLAGS))) {
        private enum enumMixinStr___ILP32_OFF32_LDFLAGS = `enum __ILP32_OFF32_LDFLAGS = "-m32";`;
        static if(is(typeof({ mixin(enumMixinStr___ILP32_OFF32_LDFLAGS); }))) {
            mixin(enumMixinStr___ILP32_OFF32_LDFLAGS);
        }
    }




    static if(!is(typeof(__ILP32_OFF32_CFLAGS))) {
        private enum enumMixinStr___ILP32_OFF32_CFLAGS = `enum __ILP32_OFF32_CFLAGS = "-m32";`;
        static if(is(typeof({ mixin(enumMixinStr___ILP32_OFF32_CFLAGS); }))) {
            mixin(enumMixinStr___ILP32_OFF32_CFLAGS);
        }
    }




    static if(!is(typeof(_XBS5_LP64_OFF64))) {
        private enum enumMixinStr__XBS5_LP64_OFF64 = `enum _XBS5_LP64_OFF64 = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__XBS5_LP64_OFF64); }))) {
            mixin(enumMixinStr__XBS5_LP64_OFF64);
        }
    }




    static if(!is(typeof(_POSIX_V6_LP64_OFF64))) {
        private enum enumMixinStr__POSIX_V6_LP64_OFF64 = `enum _POSIX_V6_LP64_OFF64 = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_V6_LP64_OFF64); }))) {
            mixin(enumMixinStr__POSIX_V6_LP64_OFF64);
        }
    }




    static if(!is(typeof(_POSIX_V7_LP64_OFF64))) {
        private enum enumMixinStr__POSIX_V7_LP64_OFF64 = `enum _POSIX_V7_LP64_OFF64 = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_V7_LP64_OFF64); }))) {
            mixin(enumMixinStr__POSIX_V7_LP64_OFF64);
        }
    }




    static if(!is(typeof(_XBS5_LPBIG_OFFBIG))) {
        private enum enumMixinStr__XBS5_LPBIG_OFFBIG = `enum _XBS5_LPBIG_OFFBIG = - 1;`;
        static if(is(typeof({ mixin(enumMixinStr__XBS5_LPBIG_OFFBIG); }))) {
            mixin(enumMixinStr__XBS5_LPBIG_OFFBIG);
        }
    }




    static if(!is(typeof(_POSIX_V6_LPBIG_OFFBIG))) {
        private enum enumMixinStr__POSIX_V6_LPBIG_OFFBIG = `enum _POSIX_V6_LPBIG_OFFBIG = - 1;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_V6_LPBIG_OFFBIG); }))) {
            mixin(enumMixinStr__POSIX_V6_LPBIG_OFFBIG);
        }
    }




    static if(!is(typeof(_POSIX_V7_LPBIG_OFFBIG))) {
        private enum enumMixinStr__POSIX_V7_LPBIG_OFFBIG = `enum _POSIX_V7_LPBIG_OFFBIG = - 1;`;
        static if(is(typeof({ mixin(enumMixinStr__POSIX_V7_LPBIG_OFFBIG); }))) {
            mixin(enumMixinStr__POSIX_V7_LPBIG_OFFBIG);
        }
    }




    static if(!is(typeof(__BYTE_ORDER))) {
        private enum enumMixinStr___BYTE_ORDER = `enum __BYTE_ORDER = __LITTLE_ENDIAN;`;
        static if(is(typeof({ mixin(enumMixinStr___BYTE_ORDER); }))) {
            mixin(enumMixinStr___BYTE_ORDER);
        }
    }




    static if(!is(typeof(_BITS_ENDIANNESS_H))) {
        private enum enumMixinStr__BITS_ENDIANNESS_H = `enum _BITS_ENDIANNESS_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_ENDIANNESS_H); }))) {
            mixin(enumMixinStr__BITS_ENDIANNESS_H);
        }
    }






    static if(!is(typeof(__FLOAT_WORD_ORDER))) {
        private enum enumMixinStr___FLOAT_WORD_ORDER = `enum __FLOAT_WORD_ORDER = __LITTLE_ENDIAN;`;
        static if(is(typeof({ mixin(enumMixinStr___FLOAT_WORD_ORDER); }))) {
            mixin(enumMixinStr___FLOAT_WORD_ORDER);
        }
    }




    static if(!is(typeof(__PDP_ENDIAN))) {
        private enum enumMixinStr___PDP_ENDIAN = `enum __PDP_ENDIAN = 3412;`;
        static if(is(typeof({ mixin(enumMixinStr___PDP_ENDIAN); }))) {
            mixin(enumMixinStr___PDP_ENDIAN);
        }
    }




    static if(!is(typeof(__BIG_ENDIAN))) {
        private enum enumMixinStr___BIG_ENDIAN = `enum __BIG_ENDIAN = 4321;`;
        static if(is(typeof({ mixin(enumMixinStr___BIG_ENDIAN); }))) {
            mixin(enumMixinStr___BIG_ENDIAN);
        }
    }




    static if(!is(typeof(__LITTLE_ENDIAN))) {
        private enum enumMixinStr___LITTLE_ENDIAN = `enum __LITTLE_ENDIAN = 1234;`;
        static if(is(typeof({ mixin(enumMixinStr___LITTLE_ENDIAN); }))) {
            mixin(enumMixinStr___LITTLE_ENDIAN);
        }
    }






    static if(!is(typeof(_BITS_ENDIAN_H))) {
        private enum enumMixinStr__BITS_ENDIAN_H = `enum _BITS_ENDIAN_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_ENDIAN_H); }))) {
            mixin(enumMixinStr__BITS_ENDIAN_H);
        }
    }




    static if(!is(typeof(_DIRENT_MATCHES_DIRENT64))) {
        private enum enumMixinStr__DIRENT_MATCHES_DIRENT64 = `enum _DIRENT_MATCHES_DIRENT64 = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__DIRENT_MATCHES_DIRENT64); }))) {
            mixin(enumMixinStr__DIRENT_MATCHES_DIRENT64);
        }
    }
    static if(!is(typeof(d_fileno))) {
        private enum enumMixinStr_d_fileno = `enum d_fileno = d_ino;`;
        static if(is(typeof({ mixin(enumMixinStr_d_fileno); }))) {
            mixin(enumMixinStr_d_fileno);
        }
    }
    static if(!is(typeof(__NCPUBITS))) {
        private enum enumMixinStr___NCPUBITS = `enum __NCPUBITS = ( 8 * ( __cpu_mask ) .sizeof );`;
        static if(is(typeof({ mixin(enumMixinStr___NCPUBITS); }))) {
            mixin(enumMixinStr___NCPUBITS);
        }
    }




    static if(!is(typeof(__CPU_SETSIZE))) {
        private enum enumMixinStr___CPU_SETSIZE = `enum __CPU_SETSIZE = 1024;`;
        static if(is(typeof({ mixin(enumMixinStr___CPU_SETSIZE); }))) {
            mixin(enumMixinStr___CPU_SETSIZE);
        }
    }




    static if(!is(typeof(_BITS_CPU_SET_H))) {
        private enum enumMixinStr__BITS_CPU_SET_H = `enum _BITS_CPU_SET_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_CPU_SET_H); }))) {
            mixin(enumMixinStr__BITS_CPU_SET_H);
        }
    }




    static if(!is(typeof(_CS_V7_ENV))) {
        private enum enumMixinStr__CS_V7_ENV = `enum _CS_V7_ENV = _CS_V7_ENV;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_V7_ENV); }))) {
            mixin(enumMixinStr__CS_V7_ENV);
        }
    }




    static if(!is(typeof(_CS_V6_ENV))) {
        private enum enumMixinStr__CS_V6_ENV = `enum _CS_V6_ENV = _CS_V6_ENV;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_V6_ENV); }))) {
            mixin(enumMixinStr__CS_V6_ENV);
        }
    }




    static if(!is(typeof(_CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS))) {
        private enum enumMixinStr__CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS = `enum _CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS = _CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS); }))) {
            mixin(enumMixinStr__CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V7_LPBIG_OFFBIG_LIBS))) {
        private enum enumMixinStr__CS_POSIX_V7_LPBIG_OFFBIG_LIBS = `enum _CS_POSIX_V7_LPBIG_OFFBIG_LIBS = _CS_POSIX_V7_LPBIG_OFFBIG_LIBS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V7_LPBIG_OFFBIG_LIBS); }))) {
            mixin(enumMixinStr__CS_POSIX_V7_LPBIG_OFFBIG_LIBS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS))) {
        private enum enumMixinStr__CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS = `enum _CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS = _CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS); }))) {
            mixin(enumMixinStr__CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS))) {
        private enum enumMixinStr__CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS = `enum _CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS = _CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS); }))) {
            mixin(enumMixinStr__CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V7_LP64_OFF64_LINTFLAGS))) {
        private enum enumMixinStr__CS_POSIX_V7_LP64_OFF64_LINTFLAGS = `enum _CS_POSIX_V7_LP64_OFF64_LINTFLAGS = _CS_POSIX_V7_LP64_OFF64_LINTFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V7_LP64_OFF64_LINTFLAGS); }))) {
            mixin(enumMixinStr__CS_POSIX_V7_LP64_OFF64_LINTFLAGS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V7_LP64_OFF64_LIBS))) {
        private enum enumMixinStr__CS_POSIX_V7_LP64_OFF64_LIBS = `enum _CS_POSIX_V7_LP64_OFF64_LIBS = _CS_POSIX_V7_LP64_OFF64_LIBS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V7_LP64_OFF64_LIBS); }))) {
            mixin(enumMixinStr__CS_POSIX_V7_LP64_OFF64_LIBS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V7_LP64_OFF64_LDFLAGS))) {
        private enum enumMixinStr__CS_POSIX_V7_LP64_OFF64_LDFLAGS = `enum _CS_POSIX_V7_LP64_OFF64_LDFLAGS = _CS_POSIX_V7_LP64_OFF64_LDFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V7_LP64_OFF64_LDFLAGS); }))) {
            mixin(enumMixinStr__CS_POSIX_V7_LP64_OFF64_LDFLAGS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V7_LP64_OFF64_CFLAGS))) {
        private enum enumMixinStr__CS_POSIX_V7_LP64_OFF64_CFLAGS = `enum _CS_POSIX_V7_LP64_OFF64_CFLAGS = _CS_POSIX_V7_LP64_OFF64_CFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V7_LP64_OFF64_CFLAGS); }))) {
            mixin(enumMixinStr__CS_POSIX_V7_LP64_OFF64_CFLAGS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS))) {
        private enum enumMixinStr__CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS = `enum _CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS = _CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS); }))) {
            mixin(enumMixinStr__CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V7_ILP32_OFFBIG_LIBS))) {
        private enum enumMixinStr__CS_POSIX_V7_ILP32_OFFBIG_LIBS = `enum _CS_POSIX_V7_ILP32_OFFBIG_LIBS = _CS_POSIX_V7_ILP32_OFFBIG_LIBS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V7_ILP32_OFFBIG_LIBS); }))) {
            mixin(enumMixinStr__CS_POSIX_V7_ILP32_OFFBIG_LIBS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS))) {
        private enum enumMixinStr__CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS = `enum _CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS = _CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS); }))) {
            mixin(enumMixinStr__CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V7_ILP32_OFFBIG_CFLAGS))) {
        private enum enumMixinStr__CS_POSIX_V7_ILP32_OFFBIG_CFLAGS = `enum _CS_POSIX_V7_ILP32_OFFBIG_CFLAGS = _CS_POSIX_V7_ILP32_OFFBIG_CFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V7_ILP32_OFFBIG_CFLAGS); }))) {
            mixin(enumMixinStr__CS_POSIX_V7_ILP32_OFFBIG_CFLAGS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V7_ILP32_OFF32_LINTFLAGS))) {
        private enum enumMixinStr__CS_POSIX_V7_ILP32_OFF32_LINTFLAGS = `enum _CS_POSIX_V7_ILP32_OFF32_LINTFLAGS = _CS_POSIX_V7_ILP32_OFF32_LINTFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V7_ILP32_OFF32_LINTFLAGS); }))) {
            mixin(enumMixinStr__CS_POSIX_V7_ILP32_OFF32_LINTFLAGS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V7_ILP32_OFF32_LIBS))) {
        private enum enumMixinStr__CS_POSIX_V7_ILP32_OFF32_LIBS = `enum _CS_POSIX_V7_ILP32_OFF32_LIBS = _CS_POSIX_V7_ILP32_OFF32_LIBS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V7_ILP32_OFF32_LIBS); }))) {
            mixin(enumMixinStr__CS_POSIX_V7_ILP32_OFF32_LIBS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V7_ILP32_OFF32_LDFLAGS))) {
        private enum enumMixinStr__CS_POSIX_V7_ILP32_OFF32_LDFLAGS = `enum _CS_POSIX_V7_ILP32_OFF32_LDFLAGS = _CS_POSIX_V7_ILP32_OFF32_LDFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V7_ILP32_OFF32_LDFLAGS); }))) {
            mixin(enumMixinStr__CS_POSIX_V7_ILP32_OFF32_LDFLAGS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V7_ILP32_OFF32_CFLAGS))) {
        private enum enumMixinStr__CS_POSIX_V7_ILP32_OFF32_CFLAGS = `enum _CS_POSIX_V7_ILP32_OFF32_CFLAGS = _CS_POSIX_V7_ILP32_OFF32_CFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V7_ILP32_OFF32_CFLAGS); }))) {
            mixin(enumMixinStr__CS_POSIX_V7_ILP32_OFF32_CFLAGS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS))) {
        private enum enumMixinStr__CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS = `enum _CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS = _CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS); }))) {
            mixin(enumMixinStr__CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V6_LPBIG_OFFBIG_LIBS))) {
        private enum enumMixinStr__CS_POSIX_V6_LPBIG_OFFBIG_LIBS = `enum _CS_POSIX_V6_LPBIG_OFFBIG_LIBS = _CS_POSIX_V6_LPBIG_OFFBIG_LIBS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V6_LPBIG_OFFBIG_LIBS); }))) {
            mixin(enumMixinStr__CS_POSIX_V6_LPBIG_OFFBIG_LIBS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS))) {
        private enum enumMixinStr__CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS = `enum _CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS = _CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS); }))) {
            mixin(enumMixinStr__CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS))) {
        private enum enumMixinStr__CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS = `enum _CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS = _CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS); }))) {
            mixin(enumMixinStr__CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V6_LP64_OFF64_LINTFLAGS))) {
        private enum enumMixinStr__CS_POSIX_V6_LP64_OFF64_LINTFLAGS = `enum _CS_POSIX_V6_LP64_OFF64_LINTFLAGS = _CS_POSIX_V6_LP64_OFF64_LINTFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V6_LP64_OFF64_LINTFLAGS); }))) {
            mixin(enumMixinStr__CS_POSIX_V6_LP64_OFF64_LINTFLAGS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V6_LP64_OFF64_LIBS))) {
        private enum enumMixinStr__CS_POSIX_V6_LP64_OFF64_LIBS = `enum _CS_POSIX_V6_LP64_OFF64_LIBS = _CS_POSIX_V6_LP64_OFF64_LIBS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V6_LP64_OFF64_LIBS); }))) {
            mixin(enumMixinStr__CS_POSIX_V6_LP64_OFF64_LIBS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V6_LP64_OFF64_LDFLAGS))) {
        private enum enumMixinStr__CS_POSIX_V6_LP64_OFF64_LDFLAGS = `enum _CS_POSIX_V6_LP64_OFF64_LDFLAGS = _CS_POSIX_V6_LP64_OFF64_LDFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V6_LP64_OFF64_LDFLAGS); }))) {
            mixin(enumMixinStr__CS_POSIX_V6_LP64_OFF64_LDFLAGS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V6_LP64_OFF64_CFLAGS))) {
        private enum enumMixinStr__CS_POSIX_V6_LP64_OFF64_CFLAGS = `enum _CS_POSIX_V6_LP64_OFF64_CFLAGS = _CS_POSIX_V6_LP64_OFF64_CFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V6_LP64_OFF64_CFLAGS); }))) {
            mixin(enumMixinStr__CS_POSIX_V6_LP64_OFF64_CFLAGS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS))) {
        private enum enumMixinStr__CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS = `enum _CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS = _CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS); }))) {
            mixin(enumMixinStr__CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V6_ILP32_OFFBIG_LIBS))) {
        private enum enumMixinStr__CS_POSIX_V6_ILP32_OFFBIG_LIBS = `enum _CS_POSIX_V6_ILP32_OFFBIG_LIBS = _CS_POSIX_V6_ILP32_OFFBIG_LIBS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V6_ILP32_OFFBIG_LIBS); }))) {
            mixin(enumMixinStr__CS_POSIX_V6_ILP32_OFFBIG_LIBS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS))) {
        private enum enumMixinStr__CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS = `enum _CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS = _CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS); }))) {
            mixin(enumMixinStr__CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V6_ILP32_OFFBIG_CFLAGS))) {
        private enum enumMixinStr__CS_POSIX_V6_ILP32_OFFBIG_CFLAGS = `enum _CS_POSIX_V6_ILP32_OFFBIG_CFLAGS = _CS_POSIX_V6_ILP32_OFFBIG_CFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V6_ILP32_OFFBIG_CFLAGS); }))) {
            mixin(enumMixinStr__CS_POSIX_V6_ILP32_OFFBIG_CFLAGS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V6_ILP32_OFF32_LINTFLAGS))) {
        private enum enumMixinStr__CS_POSIX_V6_ILP32_OFF32_LINTFLAGS = `enum _CS_POSIX_V6_ILP32_OFF32_LINTFLAGS = _CS_POSIX_V6_ILP32_OFF32_LINTFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V6_ILP32_OFF32_LINTFLAGS); }))) {
            mixin(enumMixinStr__CS_POSIX_V6_ILP32_OFF32_LINTFLAGS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V6_ILP32_OFF32_LIBS))) {
        private enum enumMixinStr__CS_POSIX_V6_ILP32_OFF32_LIBS = `enum _CS_POSIX_V6_ILP32_OFF32_LIBS = _CS_POSIX_V6_ILP32_OFF32_LIBS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V6_ILP32_OFF32_LIBS); }))) {
            mixin(enumMixinStr__CS_POSIX_V6_ILP32_OFF32_LIBS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V6_ILP32_OFF32_LDFLAGS))) {
        private enum enumMixinStr__CS_POSIX_V6_ILP32_OFF32_LDFLAGS = `enum _CS_POSIX_V6_ILP32_OFF32_LDFLAGS = _CS_POSIX_V6_ILP32_OFF32_LDFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V6_ILP32_OFF32_LDFLAGS); }))) {
            mixin(enumMixinStr__CS_POSIX_V6_ILP32_OFF32_LDFLAGS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V6_ILP32_OFF32_CFLAGS))) {
        private enum enumMixinStr__CS_POSIX_V6_ILP32_OFF32_CFLAGS = `enum _CS_POSIX_V6_ILP32_OFF32_CFLAGS = _CS_POSIX_V6_ILP32_OFF32_CFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V6_ILP32_OFF32_CFLAGS); }))) {
            mixin(enumMixinStr__CS_POSIX_V6_ILP32_OFF32_CFLAGS);
        }
    }




    static if(!is(typeof(_CS_XBS5_LPBIG_OFFBIG_LINTFLAGS))) {
        private enum enumMixinStr__CS_XBS5_LPBIG_OFFBIG_LINTFLAGS = `enum _CS_XBS5_LPBIG_OFFBIG_LINTFLAGS = _CS_XBS5_LPBIG_OFFBIG_LINTFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_XBS5_LPBIG_OFFBIG_LINTFLAGS); }))) {
            mixin(enumMixinStr__CS_XBS5_LPBIG_OFFBIG_LINTFLAGS);
        }
    }




    static if(!is(typeof(_CS_XBS5_LPBIG_OFFBIG_LIBS))) {
        private enum enumMixinStr__CS_XBS5_LPBIG_OFFBIG_LIBS = `enum _CS_XBS5_LPBIG_OFFBIG_LIBS = _CS_XBS5_LPBIG_OFFBIG_LIBS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_XBS5_LPBIG_OFFBIG_LIBS); }))) {
            mixin(enumMixinStr__CS_XBS5_LPBIG_OFFBIG_LIBS);
        }
    }




    static if(!is(typeof(_CS_XBS5_LPBIG_OFFBIG_LDFLAGS))) {
        private enum enumMixinStr__CS_XBS5_LPBIG_OFFBIG_LDFLAGS = `enum _CS_XBS5_LPBIG_OFFBIG_LDFLAGS = _CS_XBS5_LPBIG_OFFBIG_LDFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_XBS5_LPBIG_OFFBIG_LDFLAGS); }))) {
            mixin(enumMixinStr__CS_XBS5_LPBIG_OFFBIG_LDFLAGS);
        }
    }




    static if(!is(typeof(_CS_XBS5_LPBIG_OFFBIG_CFLAGS))) {
        private enum enumMixinStr__CS_XBS5_LPBIG_OFFBIG_CFLAGS = `enum _CS_XBS5_LPBIG_OFFBIG_CFLAGS = _CS_XBS5_LPBIG_OFFBIG_CFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_XBS5_LPBIG_OFFBIG_CFLAGS); }))) {
            mixin(enumMixinStr__CS_XBS5_LPBIG_OFFBIG_CFLAGS);
        }
    }




    static if(!is(typeof(_CS_XBS5_LP64_OFF64_LINTFLAGS))) {
        private enum enumMixinStr__CS_XBS5_LP64_OFF64_LINTFLAGS = `enum _CS_XBS5_LP64_OFF64_LINTFLAGS = _CS_XBS5_LP64_OFF64_LINTFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_XBS5_LP64_OFF64_LINTFLAGS); }))) {
            mixin(enumMixinStr__CS_XBS5_LP64_OFF64_LINTFLAGS);
        }
    }




    static if(!is(typeof(_CS_XBS5_LP64_OFF64_LIBS))) {
        private enum enumMixinStr__CS_XBS5_LP64_OFF64_LIBS = `enum _CS_XBS5_LP64_OFF64_LIBS = _CS_XBS5_LP64_OFF64_LIBS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_XBS5_LP64_OFF64_LIBS); }))) {
            mixin(enumMixinStr__CS_XBS5_LP64_OFF64_LIBS);
        }
    }




    static if(!is(typeof(_CS_XBS5_LP64_OFF64_LDFLAGS))) {
        private enum enumMixinStr__CS_XBS5_LP64_OFF64_LDFLAGS = `enum _CS_XBS5_LP64_OFF64_LDFLAGS = _CS_XBS5_LP64_OFF64_LDFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_XBS5_LP64_OFF64_LDFLAGS); }))) {
            mixin(enumMixinStr__CS_XBS5_LP64_OFF64_LDFLAGS);
        }
    }




    static if(!is(typeof(_CS_XBS5_LP64_OFF64_CFLAGS))) {
        private enum enumMixinStr__CS_XBS5_LP64_OFF64_CFLAGS = `enum _CS_XBS5_LP64_OFF64_CFLAGS = _CS_XBS5_LP64_OFF64_CFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_XBS5_LP64_OFF64_CFLAGS); }))) {
            mixin(enumMixinStr__CS_XBS5_LP64_OFF64_CFLAGS);
        }
    }




    static if(!is(typeof(_CS_XBS5_ILP32_OFFBIG_LINTFLAGS))) {
        private enum enumMixinStr__CS_XBS5_ILP32_OFFBIG_LINTFLAGS = `enum _CS_XBS5_ILP32_OFFBIG_LINTFLAGS = _CS_XBS5_ILP32_OFFBIG_LINTFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_XBS5_ILP32_OFFBIG_LINTFLAGS); }))) {
            mixin(enumMixinStr__CS_XBS5_ILP32_OFFBIG_LINTFLAGS);
        }
    }




    static if(!is(typeof(_CS_XBS5_ILP32_OFFBIG_LIBS))) {
        private enum enumMixinStr__CS_XBS5_ILP32_OFFBIG_LIBS = `enum _CS_XBS5_ILP32_OFFBIG_LIBS = _CS_XBS5_ILP32_OFFBIG_LIBS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_XBS5_ILP32_OFFBIG_LIBS); }))) {
            mixin(enumMixinStr__CS_XBS5_ILP32_OFFBIG_LIBS);
        }
    }




    static if(!is(typeof(_CS_XBS5_ILP32_OFFBIG_LDFLAGS))) {
        private enum enumMixinStr__CS_XBS5_ILP32_OFFBIG_LDFLAGS = `enum _CS_XBS5_ILP32_OFFBIG_LDFLAGS = _CS_XBS5_ILP32_OFFBIG_LDFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_XBS5_ILP32_OFFBIG_LDFLAGS); }))) {
            mixin(enumMixinStr__CS_XBS5_ILP32_OFFBIG_LDFLAGS);
        }
    }




    static if(!is(typeof(_CS_XBS5_ILP32_OFFBIG_CFLAGS))) {
        private enum enumMixinStr__CS_XBS5_ILP32_OFFBIG_CFLAGS = `enum _CS_XBS5_ILP32_OFFBIG_CFLAGS = _CS_XBS5_ILP32_OFFBIG_CFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_XBS5_ILP32_OFFBIG_CFLAGS); }))) {
            mixin(enumMixinStr__CS_XBS5_ILP32_OFFBIG_CFLAGS);
        }
    }




    static if(!is(typeof(_CS_XBS5_ILP32_OFF32_LINTFLAGS))) {
        private enum enumMixinStr__CS_XBS5_ILP32_OFF32_LINTFLAGS = `enum _CS_XBS5_ILP32_OFF32_LINTFLAGS = _CS_XBS5_ILP32_OFF32_LINTFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_XBS5_ILP32_OFF32_LINTFLAGS); }))) {
            mixin(enumMixinStr__CS_XBS5_ILP32_OFF32_LINTFLAGS);
        }
    }




    static if(!is(typeof(_CS_XBS5_ILP32_OFF32_LIBS))) {
        private enum enumMixinStr__CS_XBS5_ILP32_OFF32_LIBS = `enum _CS_XBS5_ILP32_OFF32_LIBS = _CS_XBS5_ILP32_OFF32_LIBS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_XBS5_ILP32_OFF32_LIBS); }))) {
            mixin(enumMixinStr__CS_XBS5_ILP32_OFF32_LIBS);
        }
    }






    static if(!is(typeof(_CS_XBS5_ILP32_OFF32_LDFLAGS))) {
        private enum enumMixinStr__CS_XBS5_ILP32_OFF32_LDFLAGS = `enum _CS_XBS5_ILP32_OFF32_LDFLAGS = _CS_XBS5_ILP32_OFF32_LDFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_XBS5_ILP32_OFF32_LDFLAGS); }))) {
            mixin(enumMixinStr__CS_XBS5_ILP32_OFF32_LDFLAGS);
        }
    }




    static if(!is(typeof(_CS_XBS5_ILP32_OFF32_CFLAGS))) {
        private enum enumMixinStr__CS_XBS5_ILP32_OFF32_CFLAGS = `enum _CS_XBS5_ILP32_OFF32_CFLAGS = _CS_XBS5_ILP32_OFF32_CFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_XBS5_ILP32_OFF32_CFLAGS); }))) {
            mixin(enumMixinStr__CS_XBS5_ILP32_OFF32_CFLAGS);
        }
    }




    static if(!is(typeof(_CS_LFS64_LINTFLAGS))) {
        private enum enumMixinStr__CS_LFS64_LINTFLAGS = `enum _CS_LFS64_LINTFLAGS = _CS_LFS64_LINTFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_LFS64_LINTFLAGS); }))) {
            mixin(enumMixinStr__CS_LFS64_LINTFLAGS);
        }
    }




    static if(!is(typeof(_CS_LFS64_LIBS))) {
        private enum enumMixinStr__CS_LFS64_LIBS = `enum _CS_LFS64_LIBS = _CS_LFS64_LIBS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_LFS64_LIBS); }))) {
            mixin(enumMixinStr__CS_LFS64_LIBS);
        }
    }




    static if(!is(typeof(_CS_LFS64_LDFLAGS))) {
        private enum enumMixinStr__CS_LFS64_LDFLAGS = `enum _CS_LFS64_LDFLAGS = _CS_LFS64_LDFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_LFS64_LDFLAGS); }))) {
            mixin(enumMixinStr__CS_LFS64_LDFLAGS);
        }
    }




    static if(!is(typeof(_CS_LFS64_CFLAGS))) {
        private enum enumMixinStr__CS_LFS64_CFLAGS = `enum _CS_LFS64_CFLAGS = _CS_LFS64_CFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_LFS64_CFLAGS); }))) {
            mixin(enumMixinStr__CS_LFS64_CFLAGS);
        }
    }




    static if(!is(typeof(_CS_LFS_LINTFLAGS))) {
        private enum enumMixinStr__CS_LFS_LINTFLAGS = `enum _CS_LFS_LINTFLAGS = _CS_LFS_LINTFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_LFS_LINTFLAGS); }))) {
            mixin(enumMixinStr__CS_LFS_LINTFLAGS);
        }
    }




    static if(!is(typeof(_CS_LFS_LIBS))) {
        private enum enumMixinStr__CS_LFS_LIBS = `enum _CS_LFS_LIBS = _CS_LFS_LIBS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_LFS_LIBS); }))) {
            mixin(enumMixinStr__CS_LFS_LIBS);
        }
    }




    static if(!is(typeof(_CS_LFS_LDFLAGS))) {
        private enum enumMixinStr__CS_LFS_LDFLAGS = `enum _CS_LFS_LDFLAGS = _CS_LFS_LDFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_LFS_LDFLAGS); }))) {
            mixin(enumMixinStr__CS_LFS_LDFLAGS);
        }
    }




    static if(!is(typeof(_CS_LFS_CFLAGS))) {
        private enum enumMixinStr__CS_LFS_CFLAGS = `enum _CS_LFS_CFLAGS = _CS_LFS_CFLAGS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_LFS_CFLAGS); }))) {
            mixin(enumMixinStr__CS_LFS_CFLAGS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V7_WIDTH_RESTRICTED_ENVS))) {
        private enum enumMixinStr__CS_POSIX_V7_WIDTH_RESTRICTED_ENVS = `enum _CS_POSIX_V7_WIDTH_RESTRICTED_ENVS = _CS_V7_WIDTH_RESTRICTED_ENVS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V7_WIDTH_RESTRICTED_ENVS); }))) {
            mixin(enumMixinStr__CS_POSIX_V7_WIDTH_RESTRICTED_ENVS);
        }
    }




    static if(!is(typeof(_CS_V7_WIDTH_RESTRICTED_ENVS))) {
        private enum enumMixinStr__CS_V7_WIDTH_RESTRICTED_ENVS = `enum _CS_V7_WIDTH_RESTRICTED_ENVS = _CS_V7_WIDTH_RESTRICTED_ENVS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_V7_WIDTH_RESTRICTED_ENVS); }))) {
            mixin(enumMixinStr__CS_V7_WIDTH_RESTRICTED_ENVS);
        }
    }




    static if(!is(typeof(_CS_POSIX_V5_WIDTH_RESTRICTED_ENVS))) {
        private enum enumMixinStr__CS_POSIX_V5_WIDTH_RESTRICTED_ENVS = `enum _CS_POSIX_V5_WIDTH_RESTRICTED_ENVS = _CS_V5_WIDTH_RESTRICTED_ENVS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V5_WIDTH_RESTRICTED_ENVS); }))) {
            mixin(enumMixinStr__CS_POSIX_V5_WIDTH_RESTRICTED_ENVS);
        }
    }




    static if(!is(typeof(_CS_V5_WIDTH_RESTRICTED_ENVS))) {
        private enum enumMixinStr__CS_V5_WIDTH_RESTRICTED_ENVS = `enum _CS_V5_WIDTH_RESTRICTED_ENVS = _CS_V5_WIDTH_RESTRICTED_ENVS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_V5_WIDTH_RESTRICTED_ENVS); }))) {
            mixin(enumMixinStr__CS_V5_WIDTH_RESTRICTED_ENVS);
        }
    }




    static if(!is(typeof(_CS_GNU_LIBPTHREAD_VERSION))) {
        private enum enumMixinStr__CS_GNU_LIBPTHREAD_VERSION = `enum _CS_GNU_LIBPTHREAD_VERSION = _CS_GNU_LIBPTHREAD_VERSION;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_GNU_LIBPTHREAD_VERSION); }))) {
            mixin(enumMixinStr__CS_GNU_LIBPTHREAD_VERSION);
        }
    }




    static if(!is(typeof(_CS_GNU_LIBC_VERSION))) {
        private enum enumMixinStr__CS_GNU_LIBC_VERSION = `enum _CS_GNU_LIBC_VERSION = _CS_GNU_LIBC_VERSION;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_GNU_LIBC_VERSION); }))) {
            mixin(enumMixinStr__CS_GNU_LIBC_VERSION);
        }
    }




    static if(!is(typeof(_CS_POSIX_V6_WIDTH_RESTRICTED_ENVS))) {
        private enum enumMixinStr__CS_POSIX_V6_WIDTH_RESTRICTED_ENVS = `enum _CS_POSIX_V6_WIDTH_RESTRICTED_ENVS = _CS_V6_WIDTH_RESTRICTED_ENVS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_POSIX_V6_WIDTH_RESTRICTED_ENVS); }))) {
            mixin(enumMixinStr__CS_POSIX_V6_WIDTH_RESTRICTED_ENVS);
        }
    }




    static if(!is(typeof(_CS_V6_WIDTH_RESTRICTED_ENVS))) {
        private enum enumMixinStr__CS_V6_WIDTH_RESTRICTED_ENVS = `enum _CS_V6_WIDTH_RESTRICTED_ENVS = _CS_V6_WIDTH_RESTRICTED_ENVS;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_V6_WIDTH_RESTRICTED_ENVS); }))) {
            mixin(enumMixinStr__CS_V6_WIDTH_RESTRICTED_ENVS);
        }
    }




    static if(!is(typeof(_CS_PATH))) {
        private enum enumMixinStr__CS_PATH = `enum _CS_PATH = _CS_PATH;`;
        static if(is(typeof({ mixin(enumMixinStr__CS_PATH); }))) {
            mixin(enumMixinStr__CS_PATH);
        }
    }




    static if(!is(typeof(_SC_THREAD_ROBUST_PRIO_PROTECT))) {
        private enum enumMixinStr__SC_THREAD_ROBUST_PRIO_PROTECT = `enum _SC_THREAD_ROBUST_PRIO_PROTECT = _SC_THREAD_ROBUST_PRIO_PROTECT;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_THREAD_ROBUST_PRIO_PROTECT); }))) {
            mixin(enumMixinStr__SC_THREAD_ROBUST_PRIO_PROTECT);
        }
    }




    static if(!is(typeof(_SC_THREAD_ROBUST_PRIO_INHERIT))) {
        private enum enumMixinStr__SC_THREAD_ROBUST_PRIO_INHERIT = `enum _SC_THREAD_ROBUST_PRIO_INHERIT = _SC_THREAD_ROBUST_PRIO_INHERIT;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_THREAD_ROBUST_PRIO_INHERIT); }))) {
            mixin(enumMixinStr__SC_THREAD_ROBUST_PRIO_INHERIT);
        }
    }




    static if(!is(typeof(_SC_XOPEN_STREAMS))) {
        private enum enumMixinStr__SC_XOPEN_STREAMS = `enum _SC_XOPEN_STREAMS = _SC_XOPEN_STREAMS;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_XOPEN_STREAMS); }))) {
            mixin(enumMixinStr__SC_XOPEN_STREAMS);
        }
    }




    static if(!is(typeof(_SC_TRACE_USER_EVENT_MAX))) {
        private enum enumMixinStr__SC_TRACE_USER_EVENT_MAX = `enum _SC_TRACE_USER_EVENT_MAX = _SC_TRACE_USER_EVENT_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_TRACE_USER_EVENT_MAX); }))) {
            mixin(enumMixinStr__SC_TRACE_USER_EVENT_MAX);
        }
    }






    static if(!is(typeof(_SC_TRACE_SYS_MAX))) {
        private enum enumMixinStr__SC_TRACE_SYS_MAX = `enum _SC_TRACE_SYS_MAX = _SC_TRACE_SYS_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_TRACE_SYS_MAX); }))) {
            mixin(enumMixinStr__SC_TRACE_SYS_MAX);
        }
    }




    static if(!is(typeof(_SC_TRACE_NAME_MAX))) {
        private enum enumMixinStr__SC_TRACE_NAME_MAX = `enum _SC_TRACE_NAME_MAX = _SC_TRACE_NAME_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_TRACE_NAME_MAX); }))) {
            mixin(enumMixinStr__SC_TRACE_NAME_MAX);
        }
    }




    static if(!is(typeof(_SC_TRACE_EVENT_NAME_MAX))) {
        private enum enumMixinStr__SC_TRACE_EVENT_NAME_MAX = `enum _SC_TRACE_EVENT_NAME_MAX = _SC_TRACE_EVENT_NAME_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_TRACE_EVENT_NAME_MAX); }))) {
            mixin(enumMixinStr__SC_TRACE_EVENT_NAME_MAX);
        }
    }




    static if(!is(typeof(_SC_SS_REPL_MAX))) {
        private enum enumMixinStr__SC_SS_REPL_MAX = `enum _SC_SS_REPL_MAX = _SC_SS_REPL_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_SS_REPL_MAX); }))) {
            mixin(enumMixinStr__SC_SS_REPL_MAX);
        }
    }




    static if(!is(typeof(_SC_V7_LPBIG_OFFBIG))) {
        private enum enumMixinStr__SC_V7_LPBIG_OFFBIG = `enum _SC_V7_LPBIG_OFFBIG = _SC_V7_LPBIG_OFFBIG;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_V7_LPBIG_OFFBIG); }))) {
            mixin(enumMixinStr__SC_V7_LPBIG_OFFBIG);
        }
    }




    static if(!is(typeof(_SC_V7_LP64_OFF64))) {
        private enum enumMixinStr__SC_V7_LP64_OFF64 = `enum _SC_V7_LP64_OFF64 = _SC_V7_LP64_OFF64;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_V7_LP64_OFF64); }))) {
            mixin(enumMixinStr__SC_V7_LP64_OFF64);
        }
    }




    static if(!is(typeof(_SC_V7_ILP32_OFFBIG))) {
        private enum enumMixinStr__SC_V7_ILP32_OFFBIG = `enum _SC_V7_ILP32_OFFBIG = _SC_V7_ILP32_OFFBIG;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_V7_ILP32_OFFBIG); }))) {
            mixin(enumMixinStr__SC_V7_ILP32_OFFBIG);
        }
    }




    static if(!is(typeof(_SC_V7_ILP32_OFF32))) {
        private enum enumMixinStr__SC_V7_ILP32_OFF32 = `enum _SC_V7_ILP32_OFF32 = _SC_V7_ILP32_OFF32;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_V7_ILP32_OFF32); }))) {
            mixin(enumMixinStr__SC_V7_ILP32_OFF32);
        }
    }




    static if(!is(typeof(_SC_RAW_SOCKETS))) {
        private enum enumMixinStr__SC_RAW_SOCKETS = `enum _SC_RAW_SOCKETS = _SC_RAW_SOCKETS;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_RAW_SOCKETS); }))) {
            mixin(enumMixinStr__SC_RAW_SOCKETS);
        }
    }




    static if(!is(typeof(_SC_IPV6))) {
        private enum enumMixinStr__SC_IPV6 = `enum _SC_IPV6 = _SC_IPV6;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_IPV6); }))) {
            mixin(enumMixinStr__SC_IPV6);
        }
    }




    static if(!is(typeof(_SC_LEVEL4_CACHE_LINESIZE))) {
        private enum enumMixinStr__SC_LEVEL4_CACHE_LINESIZE = `enum _SC_LEVEL4_CACHE_LINESIZE = _SC_LEVEL4_CACHE_LINESIZE;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_LEVEL4_CACHE_LINESIZE); }))) {
            mixin(enumMixinStr__SC_LEVEL4_CACHE_LINESIZE);
        }
    }




    static if(!is(typeof(_SC_LEVEL4_CACHE_ASSOC))) {
        private enum enumMixinStr__SC_LEVEL4_CACHE_ASSOC = `enum _SC_LEVEL4_CACHE_ASSOC = _SC_LEVEL4_CACHE_ASSOC;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_LEVEL4_CACHE_ASSOC); }))) {
            mixin(enumMixinStr__SC_LEVEL4_CACHE_ASSOC);
        }
    }




    static if(!is(typeof(_SC_LEVEL4_CACHE_SIZE))) {
        private enum enumMixinStr__SC_LEVEL4_CACHE_SIZE = `enum _SC_LEVEL4_CACHE_SIZE = _SC_LEVEL4_CACHE_SIZE;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_LEVEL4_CACHE_SIZE); }))) {
            mixin(enumMixinStr__SC_LEVEL4_CACHE_SIZE);
        }
    }




    static if(!is(typeof(_SC_LEVEL3_CACHE_LINESIZE))) {
        private enum enumMixinStr__SC_LEVEL3_CACHE_LINESIZE = `enum _SC_LEVEL3_CACHE_LINESIZE = _SC_LEVEL3_CACHE_LINESIZE;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_LEVEL3_CACHE_LINESIZE); }))) {
            mixin(enumMixinStr__SC_LEVEL3_CACHE_LINESIZE);
        }
    }




    static if(!is(typeof(_SC_LEVEL3_CACHE_ASSOC))) {
        private enum enumMixinStr__SC_LEVEL3_CACHE_ASSOC = `enum _SC_LEVEL3_CACHE_ASSOC = _SC_LEVEL3_CACHE_ASSOC;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_LEVEL3_CACHE_ASSOC); }))) {
            mixin(enumMixinStr__SC_LEVEL3_CACHE_ASSOC);
        }
    }




    static if(!is(typeof(_SC_LEVEL3_CACHE_SIZE))) {
        private enum enumMixinStr__SC_LEVEL3_CACHE_SIZE = `enum _SC_LEVEL3_CACHE_SIZE = _SC_LEVEL3_CACHE_SIZE;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_LEVEL3_CACHE_SIZE); }))) {
            mixin(enumMixinStr__SC_LEVEL3_CACHE_SIZE);
        }
    }




    static if(!is(typeof(_SC_LEVEL2_CACHE_LINESIZE))) {
        private enum enumMixinStr__SC_LEVEL2_CACHE_LINESIZE = `enum _SC_LEVEL2_CACHE_LINESIZE = _SC_LEVEL2_CACHE_LINESIZE;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_LEVEL2_CACHE_LINESIZE); }))) {
            mixin(enumMixinStr__SC_LEVEL2_CACHE_LINESIZE);
        }
    }




    static if(!is(typeof(_SC_LEVEL2_CACHE_ASSOC))) {
        private enum enumMixinStr__SC_LEVEL2_CACHE_ASSOC = `enum _SC_LEVEL2_CACHE_ASSOC = _SC_LEVEL2_CACHE_ASSOC;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_LEVEL2_CACHE_ASSOC); }))) {
            mixin(enumMixinStr__SC_LEVEL2_CACHE_ASSOC);
        }
    }




    static if(!is(typeof(_SC_LEVEL2_CACHE_SIZE))) {
        private enum enumMixinStr__SC_LEVEL2_CACHE_SIZE = `enum _SC_LEVEL2_CACHE_SIZE = _SC_LEVEL2_CACHE_SIZE;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_LEVEL2_CACHE_SIZE); }))) {
            mixin(enumMixinStr__SC_LEVEL2_CACHE_SIZE);
        }
    }




    static if(!is(typeof(_SC_LEVEL1_DCACHE_LINESIZE))) {
        private enum enumMixinStr__SC_LEVEL1_DCACHE_LINESIZE = `enum _SC_LEVEL1_DCACHE_LINESIZE = _SC_LEVEL1_DCACHE_LINESIZE;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_LEVEL1_DCACHE_LINESIZE); }))) {
            mixin(enumMixinStr__SC_LEVEL1_DCACHE_LINESIZE);
        }
    }




    static if(!is(typeof(_SC_LEVEL1_DCACHE_ASSOC))) {
        private enum enumMixinStr__SC_LEVEL1_DCACHE_ASSOC = `enum _SC_LEVEL1_DCACHE_ASSOC = _SC_LEVEL1_DCACHE_ASSOC;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_LEVEL1_DCACHE_ASSOC); }))) {
            mixin(enumMixinStr__SC_LEVEL1_DCACHE_ASSOC);
        }
    }




    static if(!is(typeof(_SC_LEVEL1_DCACHE_SIZE))) {
        private enum enumMixinStr__SC_LEVEL1_DCACHE_SIZE = `enum _SC_LEVEL1_DCACHE_SIZE = _SC_LEVEL1_DCACHE_SIZE;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_LEVEL1_DCACHE_SIZE); }))) {
            mixin(enumMixinStr__SC_LEVEL1_DCACHE_SIZE);
        }
    }




    static if(!is(typeof(_SC_LEVEL1_ICACHE_LINESIZE))) {
        private enum enumMixinStr__SC_LEVEL1_ICACHE_LINESIZE = `enum _SC_LEVEL1_ICACHE_LINESIZE = _SC_LEVEL1_ICACHE_LINESIZE;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_LEVEL1_ICACHE_LINESIZE); }))) {
            mixin(enumMixinStr__SC_LEVEL1_ICACHE_LINESIZE);
        }
    }




    static if(!is(typeof(_SC_LEVEL1_ICACHE_ASSOC))) {
        private enum enumMixinStr__SC_LEVEL1_ICACHE_ASSOC = `enum _SC_LEVEL1_ICACHE_ASSOC = _SC_LEVEL1_ICACHE_ASSOC;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_LEVEL1_ICACHE_ASSOC); }))) {
            mixin(enumMixinStr__SC_LEVEL1_ICACHE_ASSOC);
        }
    }




    static if(!is(typeof(_SC_LEVEL1_ICACHE_SIZE))) {
        private enum enumMixinStr__SC_LEVEL1_ICACHE_SIZE = `enum _SC_LEVEL1_ICACHE_SIZE = _SC_LEVEL1_ICACHE_SIZE;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_LEVEL1_ICACHE_SIZE); }))) {
            mixin(enumMixinStr__SC_LEVEL1_ICACHE_SIZE);
        }
    }




    static if(!is(typeof(_SC_TRACE_LOG))) {
        private enum enumMixinStr__SC_TRACE_LOG = `enum _SC_TRACE_LOG = _SC_TRACE_LOG;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_TRACE_LOG); }))) {
            mixin(enumMixinStr__SC_TRACE_LOG);
        }
    }




    static if(!is(typeof(_SC_TRACE_INHERIT))) {
        private enum enumMixinStr__SC_TRACE_INHERIT = `enum _SC_TRACE_INHERIT = _SC_TRACE_INHERIT;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_TRACE_INHERIT); }))) {
            mixin(enumMixinStr__SC_TRACE_INHERIT);
        }
    }




    static if(!is(typeof(_SC_TRACE_EVENT_FILTER))) {
        private enum enumMixinStr__SC_TRACE_EVENT_FILTER = `enum _SC_TRACE_EVENT_FILTER = _SC_TRACE_EVENT_FILTER;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_TRACE_EVENT_FILTER); }))) {
            mixin(enumMixinStr__SC_TRACE_EVENT_FILTER);
        }
    }




    static if(!is(typeof(_SC_TRACE))) {
        private enum enumMixinStr__SC_TRACE = `enum _SC_TRACE = _SC_TRACE;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_TRACE); }))) {
            mixin(enumMixinStr__SC_TRACE);
        }
    }




    static if(!is(typeof(_SC_HOST_NAME_MAX))) {
        private enum enumMixinStr__SC_HOST_NAME_MAX = `enum _SC_HOST_NAME_MAX = _SC_HOST_NAME_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_HOST_NAME_MAX); }))) {
            mixin(enumMixinStr__SC_HOST_NAME_MAX);
        }
    }




    static if(!is(typeof(_SC_V6_LPBIG_OFFBIG))) {
        private enum enumMixinStr__SC_V6_LPBIG_OFFBIG = `enum _SC_V6_LPBIG_OFFBIG = _SC_V6_LPBIG_OFFBIG;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_V6_LPBIG_OFFBIG); }))) {
            mixin(enumMixinStr__SC_V6_LPBIG_OFFBIG);
        }
    }




    static if(!is(typeof(_SC_V6_LP64_OFF64))) {
        private enum enumMixinStr__SC_V6_LP64_OFF64 = `enum _SC_V6_LP64_OFF64 = _SC_V6_LP64_OFF64;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_V6_LP64_OFF64); }))) {
            mixin(enumMixinStr__SC_V6_LP64_OFF64);
        }
    }




    static if(!is(typeof(_SC_V6_ILP32_OFFBIG))) {
        private enum enumMixinStr__SC_V6_ILP32_OFFBIG = `enum _SC_V6_ILP32_OFFBIG = _SC_V6_ILP32_OFFBIG;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_V6_ILP32_OFFBIG); }))) {
            mixin(enumMixinStr__SC_V6_ILP32_OFFBIG);
        }
    }




    static if(!is(typeof(_SC_V6_ILP32_OFF32))) {
        private enum enumMixinStr__SC_V6_ILP32_OFF32 = `enum _SC_V6_ILP32_OFF32 = _SC_V6_ILP32_OFF32;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_V6_ILP32_OFF32); }))) {
            mixin(enumMixinStr__SC_V6_ILP32_OFF32);
        }
    }




    static if(!is(typeof(_SC_2_PBS_CHECKPOINT))) {
        private enum enumMixinStr__SC_2_PBS_CHECKPOINT = `enum _SC_2_PBS_CHECKPOINT = _SC_2_PBS_CHECKPOINT;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_2_PBS_CHECKPOINT); }))) {
            mixin(enumMixinStr__SC_2_PBS_CHECKPOINT);
        }
    }




    static if(!is(typeof(_SC_STREAMS))) {
        private enum enumMixinStr__SC_STREAMS = `enum _SC_STREAMS = _SC_STREAMS;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_STREAMS); }))) {
            mixin(enumMixinStr__SC_STREAMS);
        }
    }




    static if(!is(typeof(_SC_SYMLOOP_MAX))) {
        private enum enumMixinStr__SC_SYMLOOP_MAX = `enum _SC_SYMLOOP_MAX = _SC_SYMLOOP_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_SYMLOOP_MAX); }))) {
            mixin(enumMixinStr__SC_SYMLOOP_MAX);
        }
    }




    static if(!is(typeof(_SC_2_PBS_TRACK))) {
        private enum enumMixinStr__SC_2_PBS_TRACK = `enum _SC_2_PBS_TRACK = _SC_2_PBS_TRACK;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_2_PBS_TRACK); }))) {
            mixin(enumMixinStr__SC_2_PBS_TRACK);
        }
    }




    static if(!is(typeof(_SC_2_PBS_MESSAGE))) {
        private enum enumMixinStr__SC_2_PBS_MESSAGE = `enum _SC_2_PBS_MESSAGE = _SC_2_PBS_MESSAGE;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_2_PBS_MESSAGE); }))) {
            mixin(enumMixinStr__SC_2_PBS_MESSAGE);
        }
    }




    static if(!is(typeof(_SC_2_PBS_LOCATE))) {
        private enum enumMixinStr__SC_2_PBS_LOCATE = `enum _SC_2_PBS_LOCATE = _SC_2_PBS_LOCATE;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_2_PBS_LOCATE); }))) {
            mixin(enumMixinStr__SC_2_PBS_LOCATE);
        }
    }




    static if(!is(typeof(_SC_2_PBS_ACCOUNTING))) {
        private enum enumMixinStr__SC_2_PBS_ACCOUNTING = `enum _SC_2_PBS_ACCOUNTING = _SC_2_PBS_ACCOUNTING;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_2_PBS_ACCOUNTING); }))) {
            mixin(enumMixinStr__SC_2_PBS_ACCOUNTING);
        }
    }




    static if(!is(typeof(_SC_2_PBS))) {
        private enum enumMixinStr__SC_2_PBS = `enum _SC_2_PBS = _SC_2_PBS;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_2_PBS); }))) {
            mixin(enumMixinStr__SC_2_PBS);
        }
    }




    static if(!is(typeof(_SC_USER_GROUPS_R))) {
        private enum enumMixinStr__SC_USER_GROUPS_R = `enum _SC_USER_GROUPS_R = _SC_USER_GROUPS_R;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_USER_GROUPS_R); }))) {
            mixin(enumMixinStr__SC_USER_GROUPS_R);
        }
    }




    static if(!is(typeof(_SC_USER_GROUPS))) {
        private enum enumMixinStr__SC_USER_GROUPS = `enum _SC_USER_GROUPS = _SC_USER_GROUPS;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_USER_GROUPS); }))) {
            mixin(enumMixinStr__SC_USER_GROUPS);
        }
    }




    static if(!is(typeof(_SC_TYPED_MEMORY_OBJECTS))) {
        private enum enumMixinStr__SC_TYPED_MEMORY_OBJECTS = `enum _SC_TYPED_MEMORY_OBJECTS = _SC_TYPED_MEMORY_OBJECTS;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_TYPED_MEMORY_OBJECTS); }))) {
            mixin(enumMixinStr__SC_TYPED_MEMORY_OBJECTS);
        }
    }




    static if(!is(typeof(_SC_TIMEOUTS))) {
        private enum enumMixinStr__SC_TIMEOUTS = `enum _SC_TIMEOUTS = _SC_TIMEOUTS;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_TIMEOUTS); }))) {
            mixin(enumMixinStr__SC_TIMEOUTS);
        }
    }




    static if(!is(typeof(_SC_SYSTEM_DATABASE_R))) {
        private enum enumMixinStr__SC_SYSTEM_DATABASE_R = `enum _SC_SYSTEM_DATABASE_R = _SC_SYSTEM_DATABASE_R;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_SYSTEM_DATABASE_R); }))) {
            mixin(enumMixinStr__SC_SYSTEM_DATABASE_R);
        }
    }






    static if(!is(typeof(_SC_SYSTEM_DATABASE))) {
        private enum enumMixinStr__SC_SYSTEM_DATABASE = `enum _SC_SYSTEM_DATABASE = _SC_SYSTEM_DATABASE;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_SYSTEM_DATABASE); }))) {
            mixin(enumMixinStr__SC_SYSTEM_DATABASE);
        }
    }




    static if(!is(typeof(_SC_THREAD_SPORADIC_SERVER))) {
        private enum enumMixinStr__SC_THREAD_SPORADIC_SERVER = `enum _SC_THREAD_SPORADIC_SERVER = _SC_THREAD_SPORADIC_SERVER;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_THREAD_SPORADIC_SERVER); }))) {
            mixin(enumMixinStr__SC_THREAD_SPORADIC_SERVER);
        }
    }




    static if(!is(typeof(_SC_SPORADIC_SERVER))) {
        private enum enumMixinStr__SC_SPORADIC_SERVER = `enum _SC_SPORADIC_SERVER = _SC_SPORADIC_SERVER;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_SPORADIC_SERVER); }))) {
            mixin(enumMixinStr__SC_SPORADIC_SERVER);
        }
    }




    static if(!is(typeof(_SC_SPAWN))) {
        private enum enumMixinStr__SC_SPAWN = `enum _SC_SPAWN = _SC_SPAWN;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_SPAWN); }))) {
            mixin(enumMixinStr__SC_SPAWN);
        }
    }




    static if(!is(typeof(_SC_SIGNALS))) {
        private enum enumMixinStr__SC_SIGNALS = `enum _SC_SIGNALS = _SC_SIGNALS;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_SIGNALS); }))) {
            mixin(enumMixinStr__SC_SIGNALS);
        }
    }




    static if(!is(typeof(_SC_SHELL))) {
        private enum enumMixinStr__SC_SHELL = `enum _SC_SHELL = _SC_SHELL;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_SHELL); }))) {
            mixin(enumMixinStr__SC_SHELL);
        }
    }




    static if(!is(typeof(_SC_REGEX_VERSION))) {
        private enum enumMixinStr__SC_REGEX_VERSION = `enum _SC_REGEX_VERSION = _SC_REGEX_VERSION;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_REGEX_VERSION); }))) {
            mixin(enumMixinStr__SC_REGEX_VERSION);
        }
    }




    static if(!is(typeof(_SC_REGEXP))) {
        private enum enumMixinStr__SC_REGEXP = `enum _SC_REGEXP = _SC_REGEXP;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_REGEXP); }))) {
            mixin(enumMixinStr__SC_REGEXP);
        }
    }




    static if(!is(typeof(_SC_SPIN_LOCKS))) {
        private enum enumMixinStr__SC_SPIN_LOCKS = `enum _SC_SPIN_LOCKS = _SC_SPIN_LOCKS;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_SPIN_LOCKS); }))) {
            mixin(enumMixinStr__SC_SPIN_LOCKS);
        }
    }




    static if(!is(typeof(_SC_READER_WRITER_LOCKS))) {
        private enum enumMixinStr__SC_READER_WRITER_LOCKS = `enum _SC_READER_WRITER_LOCKS = _SC_READER_WRITER_LOCKS;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_READER_WRITER_LOCKS); }))) {
            mixin(enumMixinStr__SC_READER_WRITER_LOCKS);
        }
    }




    static if(!is(typeof(_SC_NETWORKING))) {
        private enum enumMixinStr__SC_NETWORKING = `enum _SC_NETWORKING = _SC_NETWORKING;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_NETWORKING); }))) {
            mixin(enumMixinStr__SC_NETWORKING);
        }
    }




    static if(!is(typeof(_SC_SINGLE_PROCESS))) {
        private enum enumMixinStr__SC_SINGLE_PROCESS = `enum _SC_SINGLE_PROCESS = _SC_SINGLE_PROCESS;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_SINGLE_PROCESS); }))) {
            mixin(enumMixinStr__SC_SINGLE_PROCESS);
        }
    }




    static if(!is(typeof(_SC_MULTI_PROCESS))) {
        private enum enumMixinStr__SC_MULTI_PROCESS = `enum _SC_MULTI_PROCESS = _SC_MULTI_PROCESS;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_MULTI_PROCESS); }))) {
            mixin(enumMixinStr__SC_MULTI_PROCESS);
        }
    }




    static if(!is(typeof(_SC_MONOTONIC_CLOCK))) {
        private enum enumMixinStr__SC_MONOTONIC_CLOCK = `enum _SC_MONOTONIC_CLOCK = _SC_MONOTONIC_CLOCK;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_MONOTONIC_CLOCK); }))) {
            mixin(enumMixinStr__SC_MONOTONIC_CLOCK);
        }
    }




    static if(!is(typeof(_SC_FILE_SYSTEM))) {
        private enum enumMixinStr__SC_FILE_SYSTEM = `enum _SC_FILE_SYSTEM = _SC_FILE_SYSTEM;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_FILE_SYSTEM); }))) {
            mixin(enumMixinStr__SC_FILE_SYSTEM);
        }
    }




    static if(!is(typeof(_SC_FILE_LOCKING))) {
        private enum enumMixinStr__SC_FILE_LOCKING = `enum _SC_FILE_LOCKING = _SC_FILE_LOCKING;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_FILE_LOCKING); }))) {
            mixin(enumMixinStr__SC_FILE_LOCKING);
        }
    }




    static if(!is(typeof(_SC_FILE_ATTRIBUTES))) {
        private enum enumMixinStr__SC_FILE_ATTRIBUTES = `enum _SC_FILE_ATTRIBUTES = _SC_FILE_ATTRIBUTES;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_FILE_ATTRIBUTES); }))) {
            mixin(enumMixinStr__SC_FILE_ATTRIBUTES);
        }
    }




    static if(!is(typeof(_SC_PIPE))) {
        private enum enumMixinStr__SC_PIPE = `enum _SC_PIPE = _SC_PIPE;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_PIPE); }))) {
            mixin(enumMixinStr__SC_PIPE);
        }
    }




    static if(!is(typeof(_SC_FIFO))) {
        private enum enumMixinStr__SC_FIFO = `enum _SC_FIFO = _SC_FIFO;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_FIFO); }))) {
            mixin(enumMixinStr__SC_FIFO);
        }
    }




    static if(!is(typeof(_SC_FD_MGMT))) {
        private enum enumMixinStr__SC_FD_MGMT = `enum _SC_FD_MGMT = _SC_FD_MGMT;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_FD_MGMT); }))) {
            mixin(enumMixinStr__SC_FD_MGMT);
        }
    }




    static if(!is(typeof(_SC_DEVICE_SPECIFIC_R))) {
        private enum enumMixinStr__SC_DEVICE_SPECIFIC_R = `enum _SC_DEVICE_SPECIFIC_R = _SC_DEVICE_SPECIFIC_R;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_DEVICE_SPECIFIC_R); }))) {
            mixin(enumMixinStr__SC_DEVICE_SPECIFIC_R);
        }
    }




    static if(!is(typeof(_SC_DEVICE_SPECIFIC))) {
        private enum enumMixinStr__SC_DEVICE_SPECIFIC = `enum _SC_DEVICE_SPECIFIC = _SC_DEVICE_SPECIFIC;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_DEVICE_SPECIFIC); }))) {
            mixin(enumMixinStr__SC_DEVICE_SPECIFIC);
        }
    }




    static if(!is(typeof(_SC_DEVICE_IO))) {
        private enum enumMixinStr__SC_DEVICE_IO = `enum _SC_DEVICE_IO = _SC_DEVICE_IO;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_DEVICE_IO); }))) {
            mixin(enumMixinStr__SC_DEVICE_IO);
        }
    }




    static if(!is(typeof(_SC_THREAD_CPUTIME))) {
        private enum enumMixinStr__SC_THREAD_CPUTIME = `enum _SC_THREAD_CPUTIME = _SC_THREAD_CPUTIME;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_THREAD_CPUTIME); }))) {
            mixin(enumMixinStr__SC_THREAD_CPUTIME);
        }
    }




    static if(!is(typeof(_SC_CPUTIME))) {
        private enum enumMixinStr__SC_CPUTIME = `enum _SC_CPUTIME = _SC_CPUTIME;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_CPUTIME); }))) {
            mixin(enumMixinStr__SC_CPUTIME);
        }
    }




    static if(!is(typeof(_SC_CLOCK_SELECTION))) {
        private enum enumMixinStr__SC_CLOCK_SELECTION = `enum _SC_CLOCK_SELECTION = _SC_CLOCK_SELECTION;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_CLOCK_SELECTION); }))) {
            mixin(enumMixinStr__SC_CLOCK_SELECTION);
        }
    }




    static if(!is(typeof(_SC_C_LANG_SUPPORT_R))) {
        private enum enumMixinStr__SC_C_LANG_SUPPORT_R = `enum _SC_C_LANG_SUPPORT_R = _SC_C_LANG_SUPPORT_R;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_C_LANG_SUPPORT_R); }))) {
            mixin(enumMixinStr__SC_C_LANG_SUPPORT_R);
        }
    }




    static if(!is(typeof(_SC_C_LANG_SUPPORT))) {
        private enum enumMixinStr__SC_C_LANG_SUPPORT = `enum _SC_C_LANG_SUPPORT = _SC_C_LANG_SUPPORT;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_C_LANG_SUPPORT); }))) {
            mixin(enumMixinStr__SC_C_LANG_SUPPORT);
        }
    }




    static if(!is(typeof(_SC_BASE))) {
        private enum enumMixinStr__SC_BASE = `enum _SC_BASE = _SC_BASE;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_BASE); }))) {
            mixin(enumMixinStr__SC_BASE);
        }
    }




    static if(!is(typeof(_SC_BARRIERS))) {
        private enum enumMixinStr__SC_BARRIERS = `enum _SC_BARRIERS = _SC_BARRIERS;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_BARRIERS); }))) {
            mixin(enumMixinStr__SC_BARRIERS);
        }
    }




    static if(!is(typeof(_SC_ADVISORY_INFO))) {
        private enum enumMixinStr__SC_ADVISORY_INFO = `enum _SC_ADVISORY_INFO = _SC_ADVISORY_INFO;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_ADVISORY_INFO); }))) {
            mixin(enumMixinStr__SC_ADVISORY_INFO);
        }
    }




    static if(!is(typeof(_SC_XOPEN_REALTIME_THREADS))) {
        private enum enumMixinStr__SC_XOPEN_REALTIME_THREADS = `enum _SC_XOPEN_REALTIME_THREADS = _SC_XOPEN_REALTIME_THREADS;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_XOPEN_REALTIME_THREADS); }))) {
            mixin(enumMixinStr__SC_XOPEN_REALTIME_THREADS);
        }
    }




    static if(!is(typeof(_SC_XOPEN_REALTIME))) {
        private enum enumMixinStr__SC_XOPEN_REALTIME = `enum _SC_XOPEN_REALTIME = _SC_XOPEN_REALTIME;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_XOPEN_REALTIME); }))) {
            mixin(enumMixinStr__SC_XOPEN_REALTIME);
        }
    }




    static if(!is(typeof(_SC_XOPEN_LEGACY))) {
        private enum enumMixinStr__SC_XOPEN_LEGACY = `enum _SC_XOPEN_LEGACY = _SC_XOPEN_LEGACY;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_XOPEN_LEGACY); }))) {
            mixin(enumMixinStr__SC_XOPEN_LEGACY);
        }
    }




    static if(!is(typeof(_SC_XBS5_LPBIG_OFFBIG))) {
        private enum enumMixinStr__SC_XBS5_LPBIG_OFFBIG = `enum _SC_XBS5_LPBIG_OFFBIG = _SC_XBS5_LPBIG_OFFBIG;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_XBS5_LPBIG_OFFBIG); }))) {
            mixin(enumMixinStr__SC_XBS5_LPBIG_OFFBIG);
        }
    }




    static if(!is(typeof(_SC_XBS5_LP64_OFF64))) {
        private enum enumMixinStr__SC_XBS5_LP64_OFF64 = `enum _SC_XBS5_LP64_OFF64 = _SC_XBS5_LP64_OFF64;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_XBS5_LP64_OFF64); }))) {
            mixin(enumMixinStr__SC_XBS5_LP64_OFF64);
        }
    }




    static if(!is(typeof(_SC_XBS5_ILP32_OFFBIG))) {
        private enum enumMixinStr__SC_XBS5_ILP32_OFFBIG = `enum _SC_XBS5_ILP32_OFFBIG = _SC_XBS5_ILP32_OFFBIG;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_XBS5_ILP32_OFFBIG); }))) {
            mixin(enumMixinStr__SC_XBS5_ILP32_OFFBIG);
        }
    }




    static if(!is(typeof(_SC_XBS5_ILP32_OFF32))) {
        private enum enumMixinStr__SC_XBS5_ILP32_OFF32 = `enum _SC_XBS5_ILP32_OFF32 = _SC_XBS5_ILP32_OFF32;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_XBS5_ILP32_OFF32); }))) {
            mixin(enumMixinStr__SC_XBS5_ILP32_OFF32);
        }
    }




    static if(!is(typeof(_SC_NL_TEXTMAX))) {
        private enum enumMixinStr__SC_NL_TEXTMAX = `enum _SC_NL_TEXTMAX = _SC_NL_TEXTMAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_NL_TEXTMAX); }))) {
            mixin(enumMixinStr__SC_NL_TEXTMAX);
        }
    }




    static if(!is(typeof(_SC_NL_SETMAX))) {
        private enum enumMixinStr__SC_NL_SETMAX = `enum _SC_NL_SETMAX = _SC_NL_SETMAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_NL_SETMAX); }))) {
            mixin(enumMixinStr__SC_NL_SETMAX);
        }
    }




    static if(!is(typeof(_SC_NL_NMAX))) {
        private enum enumMixinStr__SC_NL_NMAX = `enum _SC_NL_NMAX = _SC_NL_NMAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_NL_NMAX); }))) {
            mixin(enumMixinStr__SC_NL_NMAX);
        }
    }




    static if(!is(typeof(_SC_NL_MSGMAX))) {
        private enum enumMixinStr__SC_NL_MSGMAX = `enum _SC_NL_MSGMAX = _SC_NL_MSGMAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_NL_MSGMAX); }))) {
            mixin(enumMixinStr__SC_NL_MSGMAX);
        }
    }




    static if(!is(typeof(_SC_NL_LANGMAX))) {
        private enum enumMixinStr__SC_NL_LANGMAX = `enum _SC_NL_LANGMAX = _SC_NL_LANGMAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_NL_LANGMAX); }))) {
            mixin(enumMixinStr__SC_NL_LANGMAX);
        }
    }




    static if(!is(typeof(_SC_NL_ARGMAX))) {
        private enum enumMixinStr__SC_NL_ARGMAX = `enum _SC_NL_ARGMAX = _SC_NL_ARGMAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_NL_ARGMAX); }))) {
            mixin(enumMixinStr__SC_NL_ARGMAX);
        }
    }




    static if(!is(typeof(_SC_USHRT_MAX))) {
        private enum enumMixinStr__SC_USHRT_MAX = `enum _SC_USHRT_MAX = _SC_USHRT_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_USHRT_MAX); }))) {
            mixin(enumMixinStr__SC_USHRT_MAX);
        }
    }




    static if(!is(typeof(_SC_ULONG_MAX))) {
        private enum enumMixinStr__SC_ULONG_MAX = `enum _SC_ULONG_MAX = _SC_ULONG_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_ULONG_MAX); }))) {
            mixin(enumMixinStr__SC_ULONG_MAX);
        }
    }




    static if(!is(typeof(_SC_UINT_MAX))) {
        private enum enumMixinStr__SC_UINT_MAX = `enum _SC_UINT_MAX = _SC_UINT_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_UINT_MAX); }))) {
            mixin(enumMixinStr__SC_UINT_MAX);
        }
    }




    static if(!is(typeof(_SC_UCHAR_MAX))) {
        private enum enumMixinStr__SC_UCHAR_MAX = `enum _SC_UCHAR_MAX = _SC_UCHAR_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_UCHAR_MAX); }))) {
            mixin(enumMixinStr__SC_UCHAR_MAX);
        }
    }




    static if(!is(typeof(_SC_SHRT_MIN))) {
        private enum enumMixinStr__SC_SHRT_MIN = `enum _SC_SHRT_MIN = _SC_SHRT_MIN;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_SHRT_MIN); }))) {
            mixin(enumMixinStr__SC_SHRT_MIN);
        }
    }




    static if(!is(typeof(_SC_SHRT_MAX))) {
        private enum enumMixinStr__SC_SHRT_MAX = `enum _SC_SHRT_MAX = _SC_SHRT_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_SHRT_MAX); }))) {
            mixin(enumMixinStr__SC_SHRT_MAX);
        }
    }




    static if(!is(typeof(_SC_SCHAR_MIN))) {
        private enum enumMixinStr__SC_SCHAR_MIN = `enum _SC_SCHAR_MIN = _SC_SCHAR_MIN;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_SCHAR_MIN); }))) {
            mixin(enumMixinStr__SC_SCHAR_MIN);
        }
    }




    static if(!is(typeof(_SC_SCHAR_MAX))) {
        private enum enumMixinStr__SC_SCHAR_MAX = `enum _SC_SCHAR_MAX = _SC_SCHAR_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_SCHAR_MAX); }))) {
            mixin(enumMixinStr__SC_SCHAR_MAX);
        }
    }




    static if(!is(typeof(_SC_SSIZE_MAX))) {
        private enum enumMixinStr__SC_SSIZE_MAX = `enum _SC_SSIZE_MAX = _SC_SSIZE_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_SSIZE_MAX); }))) {
            mixin(enumMixinStr__SC_SSIZE_MAX);
        }
    }




    static if(!is(typeof(_SC_NZERO))) {
        private enum enumMixinStr__SC_NZERO = `enum _SC_NZERO = _SC_NZERO;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_NZERO); }))) {
            mixin(enumMixinStr__SC_NZERO);
        }
    }




    static if(!is(typeof(_SC_MB_LEN_MAX))) {
        private enum enumMixinStr__SC_MB_LEN_MAX = `enum _SC_MB_LEN_MAX = _SC_MB_LEN_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_MB_LEN_MAX); }))) {
            mixin(enumMixinStr__SC_MB_LEN_MAX);
        }
    }




    static if(!is(typeof(_SC_WORD_BIT))) {
        private enum enumMixinStr__SC_WORD_BIT = `enum _SC_WORD_BIT = _SC_WORD_BIT;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_WORD_BIT); }))) {
            mixin(enumMixinStr__SC_WORD_BIT);
        }
    }




    static if(!is(typeof(_SC_LONG_BIT))) {
        private enum enumMixinStr__SC_LONG_BIT = `enum _SC_LONG_BIT = _SC_LONG_BIT;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_LONG_BIT); }))) {
            mixin(enumMixinStr__SC_LONG_BIT);
        }
    }




    static if(!is(typeof(_SC_INT_MIN))) {
        private enum enumMixinStr__SC_INT_MIN = `enum _SC_INT_MIN = _SC_INT_MIN;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_INT_MIN); }))) {
            mixin(enumMixinStr__SC_INT_MIN);
        }
    }




    static if(!is(typeof(_SC_INT_MAX))) {
        private enum enumMixinStr__SC_INT_MAX = `enum _SC_INT_MAX = _SC_INT_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_INT_MAX); }))) {
            mixin(enumMixinStr__SC_INT_MAX);
        }
    }




    static if(!is(typeof(_SC_CHAR_MIN))) {
        private enum enumMixinStr__SC_CHAR_MIN = `enum _SC_CHAR_MIN = _SC_CHAR_MIN;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_CHAR_MIN); }))) {
            mixin(enumMixinStr__SC_CHAR_MIN);
        }
    }




    static if(!is(typeof(_SC_CHAR_MAX))) {
        private enum enumMixinStr__SC_CHAR_MAX = `enum _SC_CHAR_MAX = _SC_CHAR_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_CHAR_MAX); }))) {
            mixin(enumMixinStr__SC_CHAR_MAX);
        }
    }




    static if(!is(typeof(_SC_CHAR_BIT))) {
        private enum enumMixinStr__SC_CHAR_BIT = `enum _SC_CHAR_BIT = _SC_CHAR_BIT;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_CHAR_BIT); }))) {
            mixin(enumMixinStr__SC_CHAR_BIT);
        }
    }




    static if(!is(typeof(_SC_XOPEN_XPG4))) {
        private enum enumMixinStr__SC_XOPEN_XPG4 = `enum _SC_XOPEN_XPG4 = _SC_XOPEN_XPG4;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_XOPEN_XPG4); }))) {
            mixin(enumMixinStr__SC_XOPEN_XPG4);
        }
    }




    static if(!is(typeof(_SC_XOPEN_XPG3))) {
        private enum enumMixinStr__SC_XOPEN_XPG3 = `enum _SC_XOPEN_XPG3 = _SC_XOPEN_XPG3;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_XOPEN_XPG3); }))) {
            mixin(enumMixinStr__SC_XOPEN_XPG3);
        }
    }






    static if(!is(typeof(_SC_XOPEN_XPG2))) {
        private enum enumMixinStr__SC_XOPEN_XPG2 = `enum _SC_XOPEN_XPG2 = _SC_XOPEN_XPG2;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_XOPEN_XPG2); }))) {
            mixin(enumMixinStr__SC_XOPEN_XPG2);
        }
    }




    static if(!is(typeof(_SC_2_UPE))) {
        private enum enumMixinStr__SC_2_UPE = `enum _SC_2_UPE = _SC_2_UPE;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_2_UPE); }))) {
            mixin(enumMixinStr__SC_2_UPE);
        }
    }




    static if(!is(typeof(_SC_2_C_VERSION))) {
        private enum enumMixinStr__SC_2_C_VERSION = `enum _SC_2_C_VERSION = _SC_2_C_VERSION;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_2_C_VERSION); }))) {
            mixin(enumMixinStr__SC_2_C_VERSION);
        }
    }




    static if(!is(typeof(_SC_2_CHAR_TERM))) {
        private enum enumMixinStr__SC_2_CHAR_TERM = `enum _SC_2_CHAR_TERM = _SC_2_CHAR_TERM;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_2_CHAR_TERM); }))) {
            mixin(enumMixinStr__SC_2_CHAR_TERM);
        }
    }




    static if(!is(typeof(_SC_XOPEN_SHM))) {
        private enum enumMixinStr__SC_XOPEN_SHM = `enum _SC_XOPEN_SHM = _SC_XOPEN_SHM;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_XOPEN_SHM); }))) {
            mixin(enumMixinStr__SC_XOPEN_SHM);
        }
    }




    static if(!is(typeof(_SC_XOPEN_ENH_I18N))) {
        private enum enumMixinStr__SC_XOPEN_ENH_I18N = `enum _SC_XOPEN_ENH_I18N = _SC_XOPEN_ENH_I18N;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_XOPEN_ENH_I18N); }))) {
            mixin(enumMixinStr__SC_XOPEN_ENH_I18N);
        }
    }




    static if(!is(typeof(_SC_XOPEN_CRYPT))) {
        private enum enumMixinStr__SC_XOPEN_CRYPT = `enum _SC_XOPEN_CRYPT = _SC_XOPEN_CRYPT;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_XOPEN_CRYPT); }))) {
            mixin(enumMixinStr__SC_XOPEN_CRYPT);
        }
    }




    static if(!is(typeof(_SC_XOPEN_UNIX))) {
        private enum enumMixinStr__SC_XOPEN_UNIX = `enum _SC_XOPEN_UNIX = _SC_XOPEN_UNIX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_XOPEN_UNIX); }))) {
            mixin(enumMixinStr__SC_XOPEN_UNIX);
        }
    }




    static if(!is(typeof(_SC_XOPEN_XCU_VERSION))) {
        private enum enumMixinStr__SC_XOPEN_XCU_VERSION = `enum _SC_XOPEN_XCU_VERSION = _SC_XOPEN_XCU_VERSION;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_XOPEN_XCU_VERSION); }))) {
            mixin(enumMixinStr__SC_XOPEN_XCU_VERSION);
        }
    }




    static if(!is(typeof(_SC_XOPEN_VERSION))) {
        private enum enumMixinStr__SC_XOPEN_VERSION = `enum _SC_XOPEN_VERSION = _SC_XOPEN_VERSION;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_XOPEN_VERSION); }))) {
            mixin(enumMixinStr__SC_XOPEN_VERSION);
        }
    }




    static if(!is(typeof(_SC_PASS_MAX))) {
        private enum enumMixinStr__SC_PASS_MAX = `enum _SC_PASS_MAX = _SC_PASS_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_PASS_MAX); }))) {
            mixin(enumMixinStr__SC_PASS_MAX);
        }
    }




    static if(!is(typeof(_SC_ATEXIT_MAX))) {
        private enum enumMixinStr__SC_ATEXIT_MAX = `enum _SC_ATEXIT_MAX = _SC_ATEXIT_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_ATEXIT_MAX); }))) {
            mixin(enumMixinStr__SC_ATEXIT_MAX);
        }
    }




    static if(!is(typeof(_SC_AVPHYS_PAGES))) {
        private enum enumMixinStr__SC_AVPHYS_PAGES = `enum _SC_AVPHYS_PAGES = _SC_AVPHYS_PAGES;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_AVPHYS_PAGES); }))) {
            mixin(enumMixinStr__SC_AVPHYS_PAGES);
        }
    }




    static if(!is(typeof(_SC_PHYS_PAGES))) {
        private enum enumMixinStr__SC_PHYS_PAGES = `enum _SC_PHYS_PAGES = _SC_PHYS_PAGES;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_PHYS_PAGES); }))) {
            mixin(enumMixinStr__SC_PHYS_PAGES);
        }
    }




    static if(!is(typeof(_SC_NPROCESSORS_ONLN))) {
        private enum enumMixinStr__SC_NPROCESSORS_ONLN = `enum _SC_NPROCESSORS_ONLN = _SC_NPROCESSORS_ONLN;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_NPROCESSORS_ONLN); }))) {
            mixin(enumMixinStr__SC_NPROCESSORS_ONLN);
        }
    }




    static if(!is(typeof(_SC_NPROCESSORS_CONF))) {
        private enum enumMixinStr__SC_NPROCESSORS_CONF = `enum _SC_NPROCESSORS_CONF = _SC_NPROCESSORS_CONF;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_NPROCESSORS_CONF); }))) {
            mixin(enumMixinStr__SC_NPROCESSORS_CONF);
        }
    }




    static if(!is(typeof(_SC_THREAD_PROCESS_SHARED))) {
        private enum enumMixinStr__SC_THREAD_PROCESS_SHARED = `enum _SC_THREAD_PROCESS_SHARED = _SC_THREAD_PROCESS_SHARED;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_THREAD_PROCESS_SHARED); }))) {
            mixin(enumMixinStr__SC_THREAD_PROCESS_SHARED);
        }
    }




    static if(!is(typeof(_SC_THREAD_PRIO_PROTECT))) {
        private enum enumMixinStr__SC_THREAD_PRIO_PROTECT = `enum _SC_THREAD_PRIO_PROTECT = _SC_THREAD_PRIO_PROTECT;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_THREAD_PRIO_PROTECT); }))) {
            mixin(enumMixinStr__SC_THREAD_PRIO_PROTECT);
        }
    }




    static if(!is(typeof(_SC_THREAD_PRIO_INHERIT))) {
        private enum enumMixinStr__SC_THREAD_PRIO_INHERIT = `enum _SC_THREAD_PRIO_INHERIT = _SC_THREAD_PRIO_INHERIT;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_THREAD_PRIO_INHERIT); }))) {
            mixin(enumMixinStr__SC_THREAD_PRIO_INHERIT);
        }
    }




    static if(!is(typeof(_SC_THREAD_PRIORITY_SCHEDULING))) {
        private enum enumMixinStr__SC_THREAD_PRIORITY_SCHEDULING = `enum _SC_THREAD_PRIORITY_SCHEDULING = _SC_THREAD_PRIORITY_SCHEDULING;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_THREAD_PRIORITY_SCHEDULING); }))) {
            mixin(enumMixinStr__SC_THREAD_PRIORITY_SCHEDULING);
        }
    }




    static if(!is(typeof(_SC_THREAD_ATTR_STACKSIZE))) {
        private enum enumMixinStr__SC_THREAD_ATTR_STACKSIZE = `enum _SC_THREAD_ATTR_STACKSIZE = _SC_THREAD_ATTR_STACKSIZE;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_THREAD_ATTR_STACKSIZE); }))) {
            mixin(enumMixinStr__SC_THREAD_ATTR_STACKSIZE);
        }
    }




    static if(!is(typeof(_SC_THREAD_ATTR_STACKADDR))) {
        private enum enumMixinStr__SC_THREAD_ATTR_STACKADDR = `enum _SC_THREAD_ATTR_STACKADDR = _SC_THREAD_ATTR_STACKADDR;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_THREAD_ATTR_STACKADDR); }))) {
            mixin(enumMixinStr__SC_THREAD_ATTR_STACKADDR);
        }
    }




    static if(!is(typeof(_SC_THREAD_THREADS_MAX))) {
        private enum enumMixinStr__SC_THREAD_THREADS_MAX = `enum _SC_THREAD_THREADS_MAX = _SC_THREAD_THREADS_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_THREAD_THREADS_MAX); }))) {
            mixin(enumMixinStr__SC_THREAD_THREADS_MAX);
        }
    }




    static if(!is(typeof(_SC_THREAD_STACK_MIN))) {
        private enum enumMixinStr__SC_THREAD_STACK_MIN = `enum _SC_THREAD_STACK_MIN = _SC_THREAD_STACK_MIN;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_THREAD_STACK_MIN); }))) {
            mixin(enumMixinStr__SC_THREAD_STACK_MIN);
        }
    }




    static if(!is(typeof(_SC_THREAD_KEYS_MAX))) {
        private enum enumMixinStr__SC_THREAD_KEYS_MAX = `enum _SC_THREAD_KEYS_MAX = _SC_THREAD_KEYS_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_THREAD_KEYS_MAX); }))) {
            mixin(enumMixinStr__SC_THREAD_KEYS_MAX);
        }
    }




    static if(!is(typeof(_SC_THREAD_DESTRUCTOR_ITERATIONS))) {
        private enum enumMixinStr__SC_THREAD_DESTRUCTOR_ITERATIONS = `enum _SC_THREAD_DESTRUCTOR_ITERATIONS = _SC_THREAD_DESTRUCTOR_ITERATIONS;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_THREAD_DESTRUCTOR_ITERATIONS); }))) {
            mixin(enumMixinStr__SC_THREAD_DESTRUCTOR_ITERATIONS);
        }
    }




    static if(!is(typeof(_SC_TTY_NAME_MAX))) {
        private enum enumMixinStr__SC_TTY_NAME_MAX = `enum _SC_TTY_NAME_MAX = _SC_TTY_NAME_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_TTY_NAME_MAX); }))) {
            mixin(enumMixinStr__SC_TTY_NAME_MAX);
        }
    }




    static if(!is(typeof(_SC_LOGIN_NAME_MAX))) {
        private enum enumMixinStr__SC_LOGIN_NAME_MAX = `enum _SC_LOGIN_NAME_MAX = _SC_LOGIN_NAME_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_LOGIN_NAME_MAX); }))) {
            mixin(enumMixinStr__SC_LOGIN_NAME_MAX);
        }
    }




    static if(!is(typeof(_SC_GETPW_R_SIZE_MAX))) {
        private enum enumMixinStr__SC_GETPW_R_SIZE_MAX = `enum _SC_GETPW_R_SIZE_MAX = _SC_GETPW_R_SIZE_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_GETPW_R_SIZE_MAX); }))) {
            mixin(enumMixinStr__SC_GETPW_R_SIZE_MAX);
        }
    }




    static if(!is(typeof(_SC_GETGR_R_SIZE_MAX))) {
        private enum enumMixinStr__SC_GETGR_R_SIZE_MAX = `enum _SC_GETGR_R_SIZE_MAX = _SC_GETGR_R_SIZE_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_GETGR_R_SIZE_MAX); }))) {
            mixin(enumMixinStr__SC_GETGR_R_SIZE_MAX);
        }
    }




    static if(!is(typeof(_SC_THREAD_SAFE_FUNCTIONS))) {
        private enum enumMixinStr__SC_THREAD_SAFE_FUNCTIONS = `enum _SC_THREAD_SAFE_FUNCTIONS = _SC_THREAD_SAFE_FUNCTIONS;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_THREAD_SAFE_FUNCTIONS); }))) {
            mixin(enumMixinStr__SC_THREAD_SAFE_FUNCTIONS);
        }
    }




    static if(!is(typeof(_SC_THREADS))) {
        private enum enumMixinStr__SC_THREADS = `enum _SC_THREADS = _SC_THREADS;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_THREADS); }))) {
            mixin(enumMixinStr__SC_THREADS);
        }
    }




    static if(!is(typeof(_SC_T_IOV_MAX))) {
        private enum enumMixinStr__SC_T_IOV_MAX = `enum _SC_T_IOV_MAX = _SC_T_IOV_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_T_IOV_MAX); }))) {
            mixin(enumMixinStr__SC_T_IOV_MAX);
        }
    }




    static if(!is(typeof(_SC_PII_OSI_M))) {
        private enum enumMixinStr__SC_PII_OSI_M = `enum _SC_PII_OSI_M = _SC_PII_OSI_M;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_PII_OSI_M); }))) {
            mixin(enumMixinStr__SC_PII_OSI_M);
        }
    }




    static if(!is(typeof(_SC_PII_OSI_CLTS))) {
        private enum enumMixinStr__SC_PII_OSI_CLTS = `enum _SC_PII_OSI_CLTS = _SC_PII_OSI_CLTS;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_PII_OSI_CLTS); }))) {
            mixin(enumMixinStr__SC_PII_OSI_CLTS);
        }
    }




    static if(!is(typeof(_SC_PII_OSI_COTS))) {
        private enum enumMixinStr__SC_PII_OSI_COTS = `enum _SC_PII_OSI_COTS = _SC_PII_OSI_COTS;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_PII_OSI_COTS); }))) {
            mixin(enumMixinStr__SC_PII_OSI_COTS);
        }
    }




    static if(!is(typeof(_SC_PII_INTERNET_DGRAM))) {
        private enum enumMixinStr__SC_PII_INTERNET_DGRAM = `enum _SC_PII_INTERNET_DGRAM = _SC_PII_INTERNET_DGRAM;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_PII_INTERNET_DGRAM); }))) {
            mixin(enumMixinStr__SC_PII_INTERNET_DGRAM);
        }
    }




    static if(!is(typeof(_SC_PII_INTERNET_STREAM))) {
        private enum enumMixinStr__SC_PII_INTERNET_STREAM = `enum _SC_PII_INTERNET_STREAM = _SC_PII_INTERNET_STREAM;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_PII_INTERNET_STREAM); }))) {
            mixin(enumMixinStr__SC_PII_INTERNET_STREAM);
        }
    }




    static if(!is(typeof(_SC_IOV_MAX))) {
        private enum enumMixinStr__SC_IOV_MAX = `enum _SC_IOV_MAX = _SC_IOV_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_IOV_MAX); }))) {
            mixin(enumMixinStr__SC_IOV_MAX);
        }
    }




    static if(!is(typeof(_SC_UIO_MAXIOV))) {
        private enum enumMixinStr__SC_UIO_MAXIOV = `enum _SC_UIO_MAXIOV = _SC_UIO_MAXIOV;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_UIO_MAXIOV); }))) {
            mixin(enumMixinStr__SC_UIO_MAXIOV);
        }
    }




    static if(!is(typeof(_SC_SELECT))) {
        private enum enumMixinStr__SC_SELECT = `enum _SC_SELECT = _SC_SELECT;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_SELECT); }))) {
            mixin(enumMixinStr__SC_SELECT);
        }
    }




    static if(!is(typeof(_SC_POLL))) {
        private enum enumMixinStr__SC_POLL = `enum _SC_POLL = _SC_POLL;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_POLL); }))) {
            mixin(enumMixinStr__SC_POLL);
        }
    }




    static if(!is(typeof(_SC_PII_OSI))) {
        private enum enumMixinStr__SC_PII_OSI = `enum _SC_PII_OSI = _SC_PII_OSI;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_PII_OSI); }))) {
            mixin(enumMixinStr__SC_PII_OSI);
        }
    }




    static if(!is(typeof(_SC_PII_INTERNET))) {
        private enum enumMixinStr__SC_PII_INTERNET = `enum _SC_PII_INTERNET = _SC_PII_INTERNET;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_PII_INTERNET); }))) {
            mixin(enumMixinStr__SC_PII_INTERNET);
        }
    }
    static if(!is(typeof(_SC_PII_SOCKET))) {
        private enum enumMixinStr__SC_PII_SOCKET = `enum _SC_PII_SOCKET = _SC_PII_SOCKET;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_PII_SOCKET); }))) {
            mixin(enumMixinStr__SC_PII_SOCKET);
        }
    }




    static if(!is(typeof(_SC_PII_XTI))) {
        private enum enumMixinStr__SC_PII_XTI = `enum _SC_PII_XTI = _SC_PII_XTI;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_PII_XTI); }))) {
            mixin(enumMixinStr__SC_PII_XTI);
        }
    }




    static if(!is(typeof(_SC_PII))) {
        private enum enumMixinStr__SC_PII = `enum _SC_PII = _SC_PII;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_PII); }))) {
            mixin(enumMixinStr__SC_PII);
        }
    }




    static if(!is(typeof(_SC_2_LOCALEDEF))) {
        private enum enumMixinStr__SC_2_LOCALEDEF = `enum _SC_2_LOCALEDEF = _SC_2_LOCALEDEF;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_2_LOCALEDEF); }))) {
            mixin(enumMixinStr__SC_2_LOCALEDEF);
        }
    }




    static if(!is(typeof(_SC_2_SW_DEV))) {
        private enum enumMixinStr__SC_2_SW_DEV = `enum _SC_2_SW_DEV = _SC_2_SW_DEV;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_2_SW_DEV); }))) {
            mixin(enumMixinStr__SC_2_SW_DEV);
        }
    }






    static if(!is(typeof(_SC_2_FORT_RUN))) {
        private enum enumMixinStr__SC_2_FORT_RUN = `enum _SC_2_FORT_RUN = _SC_2_FORT_RUN;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_2_FORT_RUN); }))) {
            mixin(enumMixinStr__SC_2_FORT_RUN);
        }
    }




    static if(!is(typeof(_SC_2_FORT_DEV))) {
        private enum enumMixinStr__SC_2_FORT_DEV = `enum _SC_2_FORT_DEV = _SC_2_FORT_DEV;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_2_FORT_DEV); }))) {
            mixin(enumMixinStr__SC_2_FORT_DEV);
        }
    }




    static if(!is(typeof(_SC_2_C_DEV))) {
        private enum enumMixinStr__SC_2_C_DEV = `enum _SC_2_C_DEV = _SC_2_C_DEV;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_2_C_DEV); }))) {
            mixin(enumMixinStr__SC_2_C_DEV);
        }
    }




    static if(!is(typeof(_SC_2_C_BIND))) {
        private enum enumMixinStr__SC_2_C_BIND = `enum _SC_2_C_BIND = _SC_2_C_BIND;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_2_C_BIND); }))) {
            mixin(enumMixinStr__SC_2_C_BIND);
        }
    }




    static if(!is(typeof(_SC_2_VERSION))) {
        private enum enumMixinStr__SC_2_VERSION = `enum _SC_2_VERSION = _SC_2_VERSION;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_2_VERSION); }))) {
            mixin(enumMixinStr__SC_2_VERSION);
        }
    }




    static if(!is(typeof(_SC_CHARCLASS_NAME_MAX))) {
        private enum enumMixinStr__SC_CHARCLASS_NAME_MAX = `enum _SC_CHARCLASS_NAME_MAX = _SC_CHARCLASS_NAME_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_CHARCLASS_NAME_MAX); }))) {
            mixin(enumMixinStr__SC_CHARCLASS_NAME_MAX);
        }
    }




    static if(!is(typeof(_SC_RE_DUP_MAX))) {
        private enum enumMixinStr__SC_RE_DUP_MAX = `enum _SC_RE_DUP_MAX = _SC_RE_DUP_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_RE_DUP_MAX); }))) {
            mixin(enumMixinStr__SC_RE_DUP_MAX);
        }
    }




    static if(!is(typeof(_SC_LINE_MAX))) {
        private enum enumMixinStr__SC_LINE_MAX = `enum _SC_LINE_MAX = _SC_LINE_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_LINE_MAX); }))) {
            mixin(enumMixinStr__SC_LINE_MAX);
        }
    }




    static if(!is(typeof(_SC_EXPR_NEST_MAX))) {
        private enum enumMixinStr__SC_EXPR_NEST_MAX = `enum _SC_EXPR_NEST_MAX = _SC_EXPR_NEST_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_EXPR_NEST_MAX); }))) {
            mixin(enumMixinStr__SC_EXPR_NEST_MAX);
        }
    }




    static if(!is(typeof(_SC_EQUIV_CLASS_MAX))) {
        private enum enumMixinStr__SC_EQUIV_CLASS_MAX = `enum _SC_EQUIV_CLASS_MAX = _SC_EQUIV_CLASS_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_EQUIV_CLASS_MAX); }))) {
            mixin(enumMixinStr__SC_EQUIV_CLASS_MAX);
        }
    }




    static if(!is(typeof(_SC_COLL_WEIGHTS_MAX))) {
        private enum enumMixinStr__SC_COLL_WEIGHTS_MAX = `enum _SC_COLL_WEIGHTS_MAX = _SC_COLL_WEIGHTS_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_COLL_WEIGHTS_MAX); }))) {
            mixin(enumMixinStr__SC_COLL_WEIGHTS_MAX);
        }
    }




    static if(!is(typeof(_SC_BC_STRING_MAX))) {
        private enum enumMixinStr__SC_BC_STRING_MAX = `enum _SC_BC_STRING_MAX = _SC_BC_STRING_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_BC_STRING_MAX); }))) {
            mixin(enumMixinStr__SC_BC_STRING_MAX);
        }
    }




    static if(!is(typeof(_SC_BC_SCALE_MAX))) {
        private enum enumMixinStr__SC_BC_SCALE_MAX = `enum _SC_BC_SCALE_MAX = _SC_BC_SCALE_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_BC_SCALE_MAX); }))) {
            mixin(enumMixinStr__SC_BC_SCALE_MAX);
        }
    }




    static if(!is(typeof(_SC_BC_DIM_MAX))) {
        private enum enumMixinStr__SC_BC_DIM_MAX = `enum _SC_BC_DIM_MAX = _SC_BC_DIM_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_BC_DIM_MAX); }))) {
            mixin(enumMixinStr__SC_BC_DIM_MAX);
        }
    }




    static if(!is(typeof(_SC_BC_BASE_MAX))) {
        private enum enumMixinStr__SC_BC_BASE_MAX = `enum _SC_BC_BASE_MAX = _SC_BC_BASE_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_BC_BASE_MAX); }))) {
            mixin(enumMixinStr__SC_BC_BASE_MAX);
        }
    }




    static if(!is(typeof(_SC_TIMER_MAX))) {
        private enum enumMixinStr__SC_TIMER_MAX = `enum _SC_TIMER_MAX = _SC_TIMER_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_TIMER_MAX); }))) {
            mixin(enumMixinStr__SC_TIMER_MAX);
        }
    }




    static if(!is(typeof(_SC_SIGQUEUE_MAX))) {
        private enum enumMixinStr__SC_SIGQUEUE_MAX = `enum _SC_SIGQUEUE_MAX = _SC_SIGQUEUE_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_SIGQUEUE_MAX); }))) {
            mixin(enumMixinStr__SC_SIGQUEUE_MAX);
        }
    }




    static if(!is(typeof(_SC_SEM_VALUE_MAX))) {
        private enum enumMixinStr__SC_SEM_VALUE_MAX = `enum _SC_SEM_VALUE_MAX = _SC_SEM_VALUE_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_SEM_VALUE_MAX); }))) {
            mixin(enumMixinStr__SC_SEM_VALUE_MAX);
        }
    }




    static if(!is(typeof(_SC_SEM_NSEMS_MAX))) {
        private enum enumMixinStr__SC_SEM_NSEMS_MAX = `enum _SC_SEM_NSEMS_MAX = _SC_SEM_NSEMS_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_SEM_NSEMS_MAX); }))) {
            mixin(enumMixinStr__SC_SEM_NSEMS_MAX);
        }
    }




    static if(!is(typeof(_SC_RTSIG_MAX))) {
        private enum enumMixinStr__SC_RTSIG_MAX = `enum _SC_RTSIG_MAX = _SC_RTSIG_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_RTSIG_MAX); }))) {
            mixin(enumMixinStr__SC_RTSIG_MAX);
        }
    }




    static if(!is(typeof(_SC_PAGE_SIZE))) {
        private enum enumMixinStr__SC_PAGE_SIZE = `enum _SC_PAGE_SIZE = _SC_PAGESIZE;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_PAGE_SIZE); }))) {
            mixin(enumMixinStr__SC_PAGE_SIZE);
        }
    }




    static if(!is(typeof(_SC_PAGESIZE))) {
        private enum enumMixinStr__SC_PAGESIZE = `enum _SC_PAGESIZE = _SC_PAGESIZE;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_PAGESIZE); }))) {
            mixin(enumMixinStr__SC_PAGESIZE);
        }
    }




    static if(!is(typeof(_SC_VERSION))) {
        private enum enumMixinStr__SC_VERSION = `enum _SC_VERSION = _SC_VERSION;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_VERSION); }))) {
            mixin(enumMixinStr__SC_VERSION);
        }
    }




    static if(!is(typeof(_SC_MQ_PRIO_MAX))) {
        private enum enumMixinStr__SC_MQ_PRIO_MAX = `enum _SC_MQ_PRIO_MAX = _SC_MQ_PRIO_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_MQ_PRIO_MAX); }))) {
            mixin(enumMixinStr__SC_MQ_PRIO_MAX);
        }
    }




    static if(!is(typeof(_SC_MQ_OPEN_MAX))) {
        private enum enumMixinStr__SC_MQ_OPEN_MAX = `enum _SC_MQ_OPEN_MAX = _SC_MQ_OPEN_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_MQ_OPEN_MAX); }))) {
            mixin(enumMixinStr__SC_MQ_OPEN_MAX);
        }
    }




    static if(!is(typeof(_SC_DELAYTIMER_MAX))) {
        private enum enumMixinStr__SC_DELAYTIMER_MAX = `enum _SC_DELAYTIMER_MAX = _SC_DELAYTIMER_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_DELAYTIMER_MAX); }))) {
            mixin(enumMixinStr__SC_DELAYTIMER_MAX);
        }
    }




    static if(!is(typeof(_SC_AIO_PRIO_DELTA_MAX))) {
        private enum enumMixinStr__SC_AIO_PRIO_DELTA_MAX = `enum _SC_AIO_PRIO_DELTA_MAX = _SC_AIO_PRIO_DELTA_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_AIO_PRIO_DELTA_MAX); }))) {
            mixin(enumMixinStr__SC_AIO_PRIO_DELTA_MAX);
        }
    }




    static if(!is(typeof(_SC_AIO_MAX))) {
        private enum enumMixinStr__SC_AIO_MAX = `enum _SC_AIO_MAX = _SC_AIO_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_AIO_MAX); }))) {
            mixin(enumMixinStr__SC_AIO_MAX);
        }
    }




    static if(!is(typeof(_SC_AIO_LISTIO_MAX))) {
        private enum enumMixinStr__SC_AIO_LISTIO_MAX = `enum _SC_AIO_LISTIO_MAX = _SC_AIO_LISTIO_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_AIO_LISTIO_MAX); }))) {
            mixin(enumMixinStr__SC_AIO_LISTIO_MAX);
        }
    }




    static if(!is(typeof(_SC_SHARED_MEMORY_OBJECTS))) {
        private enum enumMixinStr__SC_SHARED_MEMORY_OBJECTS = `enum _SC_SHARED_MEMORY_OBJECTS = _SC_SHARED_MEMORY_OBJECTS;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_SHARED_MEMORY_OBJECTS); }))) {
            mixin(enumMixinStr__SC_SHARED_MEMORY_OBJECTS);
        }
    }




    static if(!is(typeof(_SC_SEMAPHORES))) {
        private enum enumMixinStr__SC_SEMAPHORES = `enum _SC_SEMAPHORES = _SC_SEMAPHORES;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_SEMAPHORES); }))) {
            mixin(enumMixinStr__SC_SEMAPHORES);
        }
    }




    static if(!is(typeof(_SC_MESSAGE_PASSING))) {
        private enum enumMixinStr__SC_MESSAGE_PASSING = `enum _SC_MESSAGE_PASSING = _SC_MESSAGE_PASSING;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_MESSAGE_PASSING); }))) {
            mixin(enumMixinStr__SC_MESSAGE_PASSING);
        }
    }




    static if(!is(typeof(_SC_MEMORY_PROTECTION))) {
        private enum enumMixinStr__SC_MEMORY_PROTECTION = `enum _SC_MEMORY_PROTECTION = _SC_MEMORY_PROTECTION;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_MEMORY_PROTECTION); }))) {
            mixin(enumMixinStr__SC_MEMORY_PROTECTION);
        }
    }




    static if(!is(typeof(_SC_MEMLOCK_RANGE))) {
        private enum enumMixinStr__SC_MEMLOCK_RANGE = `enum _SC_MEMLOCK_RANGE = _SC_MEMLOCK_RANGE;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_MEMLOCK_RANGE); }))) {
            mixin(enumMixinStr__SC_MEMLOCK_RANGE);
        }
    }




    static if(!is(typeof(_SC_MEMLOCK))) {
        private enum enumMixinStr__SC_MEMLOCK = `enum _SC_MEMLOCK = _SC_MEMLOCK;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_MEMLOCK); }))) {
            mixin(enumMixinStr__SC_MEMLOCK);
        }
    }




    static if(!is(typeof(_SC_MAPPED_FILES))) {
        private enum enumMixinStr__SC_MAPPED_FILES = `enum _SC_MAPPED_FILES = _SC_MAPPED_FILES;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_MAPPED_FILES); }))) {
            mixin(enumMixinStr__SC_MAPPED_FILES);
        }
    }




    static if(!is(typeof(_SC_FSYNC))) {
        private enum enumMixinStr__SC_FSYNC = `enum _SC_FSYNC = _SC_FSYNC;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_FSYNC); }))) {
            mixin(enumMixinStr__SC_FSYNC);
        }
    }




    static if(!is(typeof(_SC_SYNCHRONIZED_IO))) {
        private enum enumMixinStr__SC_SYNCHRONIZED_IO = `enum _SC_SYNCHRONIZED_IO = _SC_SYNCHRONIZED_IO;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_SYNCHRONIZED_IO); }))) {
            mixin(enumMixinStr__SC_SYNCHRONIZED_IO);
        }
    }




    static if(!is(typeof(_SC_PRIORITIZED_IO))) {
        private enum enumMixinStr__SC_PRIORITIZED_IO = `enum _SC_PRIORITIZED_IO = _SC_PRIORITIZED_IO;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_PRIORITIZED_IO); }))) {
            mixin(enumMixinStr__SC_PRIORITIZED_IO);
        }
    }




    static if(!is(typeof(_SC_ASYNCHRONOUS_IO))) {
        private enum enumMixinStr__SC_ASYNCHRONOUS_IO = `enum _SC_ASYNCHRONOUS_IO = _SC_ASYNCHRONOUS_IO;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_ASYNCHRONOUS_IO); }))) {
            mixin(enumMixinStr__SC_ASYNCHRONOUS_IO);
        }
    }




    static if(!is(typeof(_SC_TIMERS))) {
        private enum enumMixinStr__SC_TIMERS = `enum _SC_TIMERS = _SC_TIMERS;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_TIMERS); }))) {
            mixin(enumMixinStr__SC_TIMERS);
        }
    }




    static if(!is(typeof(_SC_PRIORITY_SCHEDULING))) {
        private enum enumMixinStr__SC_PRIORITY_SCHEDULING = `enum _SC_PRIORITY_SCHEDULING = _SC_PRIORITY_SCHEDULING;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_PRIORITY_SCHEDULING); }))) {
            mixin(enumMixinStr__SC_PRIORITY_SCHEDULING);
        }
    }




    static if(!is(typeof(_SC_REALTIME_SIGNALS))) {
        private enum enumMixinStr__SC_REALTIME_SIGNALS = `enum _SC_REALTIME_SIGNALS = _SC_REALTIME_SIGNALS;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_REALTIME_SIGNALS); }))) {
            mixin(enumMixinStr__SC_REALTIME_SIGNALS);
        }
    }




    static if(!is(typeof(_SC_SAVED_IDS))) {
        private enum enumMixinStr__SC_SAVED_IDS = `enum _SC_SAVED_IDS = _SC_SAVED_IDS;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_SAVED_IDS); }))) {
            mixin(enumMixinStr__SC_SAVED_IDS);
        }
    }




    static if(!is(typeof(_SC_JOB_CONTROL))) {
        private enum enumMixinStr__SC_JOB_CONTROL = `enum _SC_JOB_CONTROL = _SC_JOB_CONTROL;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_JOB_CONTROL); }))) {
            mixin(enumMixinStr__SC_JOB_CONTROL);
        }
    }




    static if(!is(typeof(_SC_TZNAME_MAX))) {
        private enum enumMixinStr__SC_TZNAME_MAX = `enum _SC_TZNAME_MAX = _SC_TZNAME_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_TZNAME_MAX); }))) {
            mixin(enumMixinStr__SC_TZNAME_MAX);
        }
    }




    static if(!is(typeof(_SC_STREAM_MAX))) {
        private enum enumMixinStr__SC_STREAM_MAX = `enum _SC_STREAM_MAX = _SC_STREAM_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_STREAM_MAX); }))) {
            mixin(enumMixinStr__SC_STREAM_MAX);
        }
    }




    static if(!is(typeof(_SC_OPEN_MAX))) {
        private enum enumMixinStr__SC_OPEN_MAX = `enum _SC_OPEN_MAX = _SC_OPEN_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_OPEN_MAX); }))) {
            mixin(enumMixinStr__SC_OPEN_MAX);
        }
    }




    static if(!is(typeof(_SC_NGROUPS_MAX))) {
        private enum enumMixinStr__SC_NGROUPS_MAX = `enum _SC_NGROUPS_MAX = _SC_NGROUPS_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_NGROUPS_MAX); }))) {
            mixin(enumMixinStr__SC_NGROUPS_MAX);
        }
    }




    static if(!is(typeof(_SC_CLK_TCK))) {
        private enum enumMixinStr__SC_CLK_TCK = `enum _SC_CLK_TCK = _SC_CLK_TCK;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_CLK_TCK); }))) {
            mixin(enumMixinStr__SC_CLK_TCK);
        }
    }




    static if(!is(typeof(_SC_CHILD_MAX))) {
        private enum enumMixinStr__SC_CHILD_MAX = `enum _SC_CHILD_MAX = _SC_CHILD_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_CHILD_MAX); }))) {
            mixin(enumMixinStr__SC_CHILD_MAX);
        }
    }




    static if(!is(typeof(_SC_ARG_MAX))) {
        private enum enumMixinStr__SC_ARG_MAX = `enum _SC_ARG_MAX = _SC_ARG_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__SC_ARG_MAX); }))) {
            mixin(enumMixinStr__SC_ARG_MAX);
        }
    }




    static if(!is(typeof(_PC_2_SYMLINKS))) {
        private enum enumMixinStr__PC_2_SYMLINKS = `enum _PC_2_SYMLINKS = _PC_2_SYMLINKS;`;
        static if(is(typeof({ mixin(enumMixinStr__PC_2_SYMLINKS); }))) {
            mixin(enumMixinStr__PC_2_SYMLINKS);
        }
    }




    static if(!is(typeof(_PC_SYMLINK_MAX))) {
        private enum enumMixinStr__PC_SYMLINK_MAX = `enum _PC_SYMLINK_MAX = _PC_SYMLINK_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__PC_SYMLINK_MAX); }))) {
            mixin(enumMixinStr__PC_SYMLINK_MAX);
        }
    }




    static if(!is(typeof(_PC_ALLOC_SIZE_MIN))) {
        private enum enumMixinStr__PC_ALLOC_SIZE_MIN = `enum _PC_ALLOC_SIZE_MIN = _PC_ALLOC_SIZE_MIN;`;
        static if(is(typeof({ mixin(enumMixinStr__PC_ALLOC_SIZE_MIN); }))) {
            mixin(enumMixinStr__PC_ALLOC_SIZE_MIN);
        }
    }




    static if(!is(typeof(_PC_REC_XFER_ALIGN))) {
        private enum enumMixinStr__PC_REC_XFER_ALIGN = `enum _PC_REC_XFER_ALIGN = _PC_REC_XFER_ALIGN;`;
        static if(is(typeof({ mixin(enumMixinStr__PC_REC_XFER_ALIGN); }))) {
            mixin(enumMixinStr__PC_REC_XFER_ALIGN);
        }
    }




    static if(!is(typeof(_PC_REC_MIN_XFER_SIZE))) {
        private enum enumMixinStr__PC_REC_MIN_XFER_SIZE = `enum _PC_REC_MIN_XFER_SIZE = _PC_REC_MIN_XFER_SIZE;`;
        static if(is(typeof({ mixin(enumMixinStr__PC_REC_MIN_XFER_SIZE); }))) {
            mixin(enumMixinStr__PC_REC_MIN_XFER_SIZE);
        }
    }




    static if(!is(typeof(_PC_REC_MAX_XFER_SIZE))) {
        private enum enumMixinStr__PC_REC_MAX_XFER_SIZE = `enum _PC_REC_MAX_XFER_SIZE = _PC_REC_MAX_XFER_SIZE;`;
        static if(is(typeof({ mixin(enumMixinStr__PC_REC_MAX_XFER_SIZE); }))) {
            mixin(enumMixinStr__PC_REC_MAX_XFER_SIZE);
        }
    }




    static if(!is(typeof(_PC_REC_INCR_XFER_SIZE))) {
        private enum enumMixinStr__PC_REC_INCR_XFER_SIZE = `enum _PC_REC_INCR_XFER_SIZE = _PC_REC_INCR_XFER_SIZE;`;
        static if(is(typeof({ mixin(enumMixinStr__PC_REC_INCR_XFER_SIZE); }))) {
            mixin(enumMixinStr__PC_REC_INCR_XFER_SIZE);
        }
    }




    static if(!is(typeof(_PC_FILESIZEBITS))) {
        private enum enumMixinStr__PC_FILESIZEBITS = `enum _PC_FILESIZEBITS = _PC_FILESIZEBITS;`;
        static if(is(typeof({ mixin(enumMixinStr__PC_FILESIZEBITS); }))) {
            mixin(enumMixinStr__PC_FILESIZEBITS);
        }
    }




    static if(!is(typeof(_PC_SOCK_MAXBUF))) {
        private enum enumMixinStr__PC_SOCK_MAXBUF = `enum _PC_SOCK_MAXBUF = _PC_SOCK_MAXBUF;`;
        static if(is(typeof({ mixin(enumMixinStr__PC_SOCK_MAXBUF); }))) {
            mixin(enumMixinStr__PC_SOCK_MAXBUF);
        }
    }




    static if(!is(typeof(_PC_PRIO_IO))) {
        private enum enumMixinStr__PC_PRIO_IO = `enum _PC_PRIO_IO = _PC_PRIO_IO;`;
        static if(is(typeof({ mixin(enumMixinStr__PC_PRIO_IO); }))) {
            mixin(enumMixinStr__PC_PRIO_IO);
        }
    }




    static if(!is(typeof(_PC_ASYNC_IO))) {
        private enum enumMixinStr__PC_ASYNC_IO = `enum _PC_ASYNC_IO = _PC_ASYNC_IO;`;
        static if(is(typeof({ mixin(enumMixinStr__PC_ASYNC_IO); }))) {
            mixin(enumMixinStr__PC_ASYNC_IO);
        }
    }




    static if(!is(typeof(_PC_SYNC_IO))) {
        private enum enumMixinStr__PC_SYNC_IO = `enum _PC_SYNC_IO = _PC_SYNC_IO;`;
        static if(is(typeof({ mixin(enumMixinStr__PC_SYNC_IO); }))) {
            mixin(enumMixinStr__PC_SYNC_IO);
        }
    }




    static if(!is(typeof(_PC_VDISABLE))) {
        private enum enumMixinStr__PC_VDISABLE = `enum _PC_VDISABLE = _PC_VDISABLE;`;
        static if(is(typeof({ mixin(enumMixinStr__PC_VDISABLE); }))) {
            mixin(enumMixinStr__PC_VDISABLE);
        }
    }




    static if(!is(typeof(_PC_NO_TRUNC))) {
        private enum enumMixinStr__PC_NO_TRUNC = `enum _PC_NO_TRUNC = _PC_NO_TRUNC;`;
        static if(is(typeof({ mixin(enumMixinStr__PC_NO_TRUNC); }))) {
            mixin(enumMixinStr__PC_NO_TRUNC);
        }
    }




    static if(!is(typeof(_PC_CHOWN_RESTRICTED))) {
        private enum enumMixinStr__PC_CHOWN_RESTRICTED = `enum _PC_CHOWN_RESTRICTED = _PC_CHOWN_RESTRICTED;`;
        static if(is(typeof({ mixin(enumMixinStr__PC_CHOWN_RESTRICTED); }))) {
            mixin(enumMixinStr__PC_CHOWN_RESTRICTED);
        }
    }




    static if(!is(typeof(_PC_PIPE_BUF))) {
        private enum enumMixinStr__PC_PIPE_BUF = `enum _PC_PIPE_BUF = _PC_PIPE_BUF;`;
        static if(is(typeof({ mixin(enumMixinStr__PC_PIPE_BUF); }))) {
            mixin(enumMixinStr__PC_PIPE_BUF);
        }
    }




    static if(!is(typeof(_PC_PATH_MAX))) {
        private enum enumMixinStr__PC_PATH_MAX = `enum _PC_PATH_MAX = _PC_PATH_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__PC_PATH_MAX); }))) {
            mixin(enumMixinStr__PC_PATH_MAX);
        }
    }




    static if(!is(typeof(_PC_NAME_MAX))) {
        private enum enumMixinStr__PC_NAME_MAX = `enum _PC_NAME_MAX = _PC_NAME_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__PC_NAME_MAX); }))) {
            mixin(enumMixinStr__PC_NAME_MAX);
        }
    }




    static if(!is(typeof(_PC_MAX_INPUT))) {
        private enum enumMixinStr__PC_MAX_INPUT = `enum _PC_MAX_INPUT = _PC_MAX_INPUT;`;
        static if(is(typeof({ mixin(enumMixinStr__PC_MAX_INPUT); }))) {
            mixin(enumMixinStr__PC_MAX_INPUT);
        }
    }




    static if(!is(typeof(_PC_MAX_CANON))) {
        private enum enumMixinStr__PC_MAX_CANON = `enum _PC_MAX_CANON = _PC_MAX_CANON;`;
        static if(is(typeof({ mixin(enumMixinStr__PC_MAX_CANON); }))) {
            mixin(enumMixinStr__PC_MAX_CANON);
        }
    }




    static if(!is(typeof(_PC_LINK_MAX))) {
        private enum enumMixinStr__PC_LINK_MAX = `enum _PC_LINK_MAX = _PC_LINK_MAX;`;
        static if(is(typeof({ mixin(enumMixinStr__PC_LINK_MAX); }))) {
            mixin(enumMixinStr__PC_LINK_MAX);
        }
    }
    static if(!is(typeof(_BITS_BYTESWAP_H))) {
        private enum enumMixinStr__BITS_BYTESWAP_H = `enum _BITS_BYTESWAP_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__BITS_BYTESWAP_H); }))) {
            mixin(enumMixinStr__BITS_BYTESWAP_H);
        }
    }




    static if(!is(typeof(static_assert))) {
        private enum enumMixinStr_static_assert = `enum static_assert = _Static_assert;`;
        static if(is(typeof({ mixin(enumMixinStr_static_assert); }))) {
            mixin(enumMixinStr_static_assert);
        }
    }




    static if(!is(typeof(__ASSERT_FUNCTION))) {
        private enum enumMixinStr___ASSERT_FUNCTION = `enum __ASSERT_FUNCTION = __extension__ __PRETTY_FUNCTION__;`;
        static if(is(typeof({ mixin(enumMixinStr___ASSERT_FUNCTION); }))) {
            mixin(enumMixinStr___ASSERT_FUNCTION);
        }
    }






    static if(!is(typeof(__ASSERT_VOID_CAST))) {
        private enum enumMixinStr___ASSERT_VOID_CAST = `enum __ASSERT_VOID_CAST = cast( void );`;
        static if(is(typeof({ mixin(enumMixinStr___ASSERT_VOID_CAST); }))) {
            mixin(enumMixinStr___ASSERT_VOID_CAST);
        }
    }




    static if(!is(typeof(_ASSERT_H))) {
        private enum enumMixinStr__ASSERT_H = `enum _ASSERT_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__ASSERT_H); }))) {
            mixin(enumMixinStr__ASSERT_H);
        }
    }




    static if(!is(typeof(__kernel_old_dev_t))) {
        private enum enumMixinStr___kernel_old_dev_t = `enum __kernel_old_dev_t = __kernel_old_dev_t;`;
        static if(is(typeof({ mixin(enumMixinStr___kernel_old_dev_t); }))) {
            mixin(enumMixinStr___kernel_old_dev_t);
        }
    }




    static if(!is(typeof(__kernel_old_uid_t))) {
        private enum enumMixinStr___kernel_old_uid_t = `enum __kernel_old_uid_t = __kernel_old_uid_t;`;
        static if(is(typeof({ mixin(enumMixinStr___kernel_old_uid_t); }))) {
            mixin(enumMixinStr___kernel_old_uid_t);
        }
    }






    static if(!is(typeof(__BITS_PER_LONG))) {
        private enum enumMixinStr___BITS_PER_LONG = `enum __BITS_PER_LONG = 64;`;
        static if(is(typeof({ mixin(enumMixinStr___BITS_PER_LONG); }))) {
            mixin(enumMixinStr___BITS_PER_LONG);
        }
    }






    static if(!is(typeof(SIOCGSTAMPNS_OLD))) {
        private enum enumMixinStr_SIOCGSTAMPNS_OLD = `enum SIOCGSTAMPNS_OLD = 0x8907;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCGSTAMPNS_OLD); }))) {
            mixin(enumMixinStr_SIOCGSTAMPNS_OLD);
        }
    }




    static if(!is(typeof(SIOCGSTAMP_OLD))) {
        private enum enumMixinStr_SIOCGSTAMP_OLD = `enum SIOCGSTAMP_OLD = 0x8906;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCGSTAMP_OLD); }))) {
            mixin(enumMixinStr_SIOCGSTAMP_OLD);
        }
    }




    static if(!is(typeof(SIOCATMARK))) {
        private enum enumMixinStr_SIOCATMARK = `enum SIOCATMARK = 0x8905;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCATMARK); }))) {
            mixin(enumMixinStr_SIOCATMARK);
        }
    }
    static if(!is(typeof(SIOCGPGRP))) {
        private enum enumMixinStr_SIOCGPGRP = `enum SIOCGPGRP = 0x8904;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCGPGRP); }))) {
            mixin(enumMixinStr_SIOCGPGRP);
        }
    }




    static if(!is(typeof(FIOGETOWN))) {
        private enum enumMixinStr_FIOGETOWN = `enum FIOGETOWN = 0x8903;`;
        static if(is(typeof({ mixin(enumMixinStr_FIOGETOWN); }))) {
            mixin(enumMixinStr_FIOGETOWN);
        }
    }




    static if(!is(typeof(SIOCSPGRP))) {
        private enum enumMixinStr_SIOCSPGRP = `enum SIOCSPGRP = 0x8902;`;
        static if(is(typeof({ mixin(enumMixinStr_SIOCSPGRP); }))) {
            mixin(enumMixinStr_SIOCSPGRP);
        }
    }




    static if(!is(typeof(FIOSETOWN))) {
        private enum enumMixinStr_FIOSETOWN = `enum FIOSETOWN = 0x8901;`;
        static if(is(typeof({ mixin(enumMixinStr_FIOSETOWN); }))) {
            mixin(enumMixinStr_FIOSETOWN);
        }
    }






    static if(!is(typeof(SCM_TIMESTAMPING))) {
        private enum enumMixinStr_SCM_TIMESTAMPING = `enum SCM_TIMESTAMPING = SO_TIMESTAMPING;`;
        static if(is(typeof({ mixin(enumMixinStr_SCM_TIMESTAMPING); }))) {
            mixin(enumMixinStr_SCM_TIMESTAMPING);
        }
    }




    static if(!is(typeof(SCM_TIMESTAMPNS))) {
        private enum enumMixinStr_SCM_TIMESTAMPNS = `enum SCM_TIMESTAMPNS = SO_TIMESTAMPNS;`;
        static if(is(typeof({ mixin(enumMixinStr_SCM_TIMESTAMPNS); }))) {
            mixin(enumMixinStr_SCM_TIMESTAMPNS);
        }
    }




    static if(!is(typeof(SCM_TIMESTAMP))) {
        private enum enumMixinStr_SCM_TIMESTAMP = `enum SCM_TIMESTAMP = SO_TIMESTAMP;`;
        static if(is(typeof({ mixin(enumMixinStr_SCM_TIMESTAMP); }))) {
            mixin(enumMixinStr_SCM_TIMESTAMP);
        }
    }




    static if(!is(typeof(SO_SNDTIMEO))) {
        private enum enumMixinStr_SO_SNDTIMEO = `enum SO_SNDTIMEO = SO_SNDTIMEO_OLD;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_SNDTIMEO); }))) {
            mixin(enumMixinStr_SO_SNDTIMEO);
        }
    }




    static if(!is(typeof(SO_RCVTIMEO))) {
        private enum enumMixinStr_SO_RCVTIMEO = `enum SO_RCVTIMEO = SO_RCVTIMEO_OLD;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_RCVTIMEO); }))) {
            mixin(enumMixinStr_SO_RCVTIMEO);
        }
    }




    static if(!is(typeof(SO_TIMESTAMPING))) {
        private enum enumMixinStr_SO_TIMESTAMPING = `enum SO_TIMESTAMPING = SO_TIMESTAMPING_OLD;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_TIMESTAMPING); }))) {
            mixin(enumMixinStr_SO_TIMESTAMPING);
        }
    }




    static if(!is(typeof(SO_TIMESTAMPNS))) {
        private enum enumMixinStr_SO_TIMESTAMPNS = `enum SO_TIMESTAMPNS = SO_TIMESTAMPNS_OLD;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_TIMESTAMPNS); }))) {
            mixin(enumMixinStr_SO_TIMESTAMPNS);
        }
    }




    static if(!is(typeof(SO_TIMESTAMP))) {
        private enum enumMixinStr_SO_TIMESTAMP = `enum SO_TIMESTAMP = SO_TIMESTAMP_OLD;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_TIMESTAMP); }))) {
            mixin(enumMixinStr_SO_TIMESTAMP);
        }
    }




    static if(!is(typeof(SO_DETACH_REUSEPORT_BPF))) {
        private enum enumMixinStr_SO_DETACH_REUSEPORT_BPF = `enum SO_DETACH_REUSEPORT_BPF = 68;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_DETACH_REUSEPORT_BPF); }))) {
            mixin(enumMixinStr_SO_DETACH_REUSEPORT_BPF);
        }
    }




    static if(!is(typeof(SO_SNDTIMEO_NEW))) {
        private enum enumMixinStr_SO_SNDTIMEO_NEW = `enum SO_SNDTIMEO_NEW = 67;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_SNDTIMEO_NEW); }))) {
            mixin(enumMixinStr_SO_SNDTIMEO_NEW);
        }
    }




    static if(!is(typeof(SO_RCVTIMEO_NEW))) {
        private enum enumMixinStr_SO_RCVTIMEO_NEW = `enum SO_RCVTIMEO_NEW = 66;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_RCVTIMEO_NEW); }))) {
            mixin(enumMixinStr_SO_RCVTIMEO_NEW);
        }
    }




    static if(!is(typeof(SO_TIMESTAMPING_NEW))) {
        private enum enumMixinStr_SO_TIMESTAMPING_NEW = `enum SO_TIMESTAMPING_NEW = 65;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_TIMESTAMPING_NEW); }))) {
            mixin(enumMixinStr_SO_TIMESTAMPING_NEW);
        }
    }




    static if(!is(typeof(SO_TIMESTAMPNS_NEW))) {
        private enum enumMixinStr_SO_TIMESTAMPNS_NEW = `enum SO_TIMESTAMPNS_NEW = 64;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_TIMESTAMPNS_NEW); }))) {
            mixin(enumMixinStr_SO_TIMESTAMPNS_NEW);
        }
    }




    static if(!is(typeof(SO_TIMESTAMP_NEW))) {
        private enum enumMixinStr_SO_TIMESTAMP_NEW = `enum SO_TIMESTAMP_NEW = 63;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_TIMESTAMP_NEW); }))) {
            mixin(enumMixinStr_SO_TIMESTAMP_NEW);
        }
    }




    static if(!is(typeof(SO_TIMESTAMPING_OLD))) {
        private enum enumMixinStr_SO_TIMESTAMPING_OLD = `enum SO_TIMESTAMPING_OLD = 37;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_TIMESTAMPING_OLD); }))) {
            mixin(enumMixinStr_SO_TIMESTAMPING_OLD);
        }
    }




    static if(!is(typeof(SO_TIMESTAMPNS_OLD))) {
        private enum enumMixinStr_SO_TIMESTAMPNS_OLD = `enum SO_TIMESTAMPNS_OLD = 35;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_TIMESTAMPNS_OLD); }))) {
            mixin(enumMixinStr_SO_TIMESTAMPNS_OLD);
        }
    }




    static if(!is(typeof(SO_TIMESTAMP_OLD))) {
        private enum enumMixinStr_SO_TIMESTAMP_OLD = `enum SO_TIMESTAMP_OLD = 29;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_TIMESTAMP_OLD); }))) {
            mixin(enumMixinStr_SO_TIMESTAMP_OLD);
        }
    }






    static if(!is(typeof(SO_BINDTOIFINDEX))) {
        private enum enumMixinStr_SO_BINDTOIFINDEX = `enum SO_BINDTOIFINDEX = 62;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_BINDTOIFINDEX); }))) {
            mixin(enumMixinStr_SO_BINDTOIFINDEX);
        }
    }




    static if(!is(typeof(SCM_TXTIME))) {
        private enum enumMixinStr_SCM_TXTIME = `enum SCM_TXTIME = SO_TXTIME;`;
        static if(is(typeof({ mixin(enumMixinStr_SCM_TXTIME); }))) {
            mixin(enumMixinStr_SCM_TXTIME);
        }
    }




    static if(!is(typeof(SO_TXTIME))) {
        private enum enumMixinStr_SO_TXTIME = `enum SO_TXTIME = 61;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_TXTIME); }))) {
            mixin(enumMixinStr_SO_TXTIME);
        }
    }




    static if(!is(typeof(SO_ZEROCOPY))) {
        private enum enumMixinStr_SO_ZEROCOPY = `enum SO_ZEROCOPY = 60;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_ZEROCOPY); }))) {
            mixin(enumMixinStr_SO_ZEROCOPY);
        }
    }




    static if(!is(typeof(SO_PEERGROUPS))) {
        private enum enumMixinStr_SO_PEERGROUPS = `enum SO_PEERGROUPS = 59;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_PEERGROUPS); }))) {
            mixin(enumMixinStr_SO_PEERGROUPS);
        }
    }






    static if(!is(typeof(SCM_TIMESTAMPING_PKTINFO))) {
        private enum enumMixinStr_SCM_TIMESTAMPING_PKTINFO = `enum SCM_TIMESTAMPING_PKTINFO = 58;`;
        static if(is(typeof({ mixin(enumMixinStr_SCM_TIMESTAMPING_PKTINFO); }))) {
            mixin(enumMixinStr_SCM_TIMESTAMPING_PKTINFO);
        }
    }




    static if(!is(typeof(SO_COOKIE))) {
        private enum enumMixinStr_SO_COOKIE = `enum SO_COOKIE = 57;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_COOKIE); }))) {
            mixin(enumMixinStr_SO_COOKIE);
        }
    }




    static if(!is(typeof(SO_INCOMING_NAPI_ID))) {
        private enum enumMixinStr_SO_INCOMING_NAPI_ID = `enum SO_INCOMING_NAPI_ID = 56;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_INCOMING_NAPI_ID); }))) {
            mixin(enumMixinStr_SO_INCOMING_NAPI_ID);
        }
    }




    static if(!is(typeof(SO_MEMINFO))) {
        private enum enumMixinStr_SO_MEMINFO = `enum SO_MEMINFO = 55;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_MEMINFO); }))) {
            mixin(enumMixinStr_SO_MEMINFO);
        }
    }




    static if(!is(typeof(SCM_TIMESTAMPING_OPT_STATS))) {
        private enum enumMixinStr_SCM_TIMESTAMPING_OPT_STATS = `enum SCM_TIMESTAMPING_OPT_STATS = 54;`;
        static if(is(typeof({ mixin(enumMixinStr_SCM_TIMESTAMPING_OPT_STATS); }))) {
            mixin(enumMixinStr_SCM_TIMESTAMPING_OPT_STATS);
        }
    }




    static if(!is(typeof(SO_CNX_ADVICE))) {
        private enum enumMixinStr_SO_CNX_ADVICE = `enum SO_CNX_ADVICE = 53;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_CNX_ADVICE); }))) {
            mixin(enumMixinStr_SO_CNX_ADVICE);
        }
    }




    static if(!is(typeof(SO_ATTACH_REUSEPORT_EBPF))) {
        private enum enumMixinStr_SO_ATTACH_REUSEPORT_EBPF = `enum SO_ATTACH_REUSEPORT_EBPF = 52;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_ATTACH_REUSEPORT_EBPF); }))) {
            mixin(enumMixinStr_SO_ATTACH_REUSEPORT_EBPF);
        }
    }




    static if(!is(typeof(SO_ATTACH_REUSEPORT_CBPF))) {
        private enum enumMixinStr_SO_ATTACH_REUSEPORT_CBPF = `enum SO_ATTACH_REUSEPORT_CBPF = 51;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_ATTACH_REUSEPORT_CBPF); }))) {
            mixin(enumMixinStr_SO_ATTACH_REUSEPORT_CBPF);
        }
    }




    static if(!is(typeof(SO_DETACH_BPF))) {
        private enum enumMixinStr_SO_DETACH_BPF = `enum SO_DETACH_BPF = SO_DETACH_FILTER;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_DETACH_BPF); }))) {
            mixin(enumMixinStr_SO_DETACH_BPF);
        }
    }




    static if(!is(typeof(SO_ATTACH_BPF))) {
        private enum enumMixinStr_SO_ATTACH_BPF = `enum SO_ATTACH_BPF = 50;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_ATTACH_BPF); }))) {
            mixin(enumMixinStr_SO_ATTACH_BPF);
        }
    }




    static if(!is(typeof(SO_INCOMING_CPU))) {
        private enum enumMixinStr_SO_INCOMING_CPU = `enum SO_INCOMING_CPU = 49;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_INCOMING_CPU); }))) {
            mixin(enumMixinStr_SO_INCOMING_CPU);
        }
    }




    static if(!is(typeof(SO_BPF_EXTENSIONS))) {
        private enum enumMixinStr_SO_BPF_EXTENSIONS = `enum SO_BPF_EXTENSIONS = 48;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_BPF_EXTENSIONS); }))) {
            mixin(enumMixinStr_SO_BPF_EXTENSIONS);
        }
    }




    static if(!is(typeof(SO_MAX_PACING_RATE))) {
        private enum enumMixinStr_SO_MAX_PACING_RATE = `enum SO_MAX_PACING_RATE = 47;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_MAX_PACING_RATE); }))) {
            mixin(enumMixinStr_SO_MAX_PACING_RATE);
        }
    }




    static if(!is(typeof(SO_BUSY_POLL))) {
        private enum enumMixinStr_SO_BUSY_POLL = `enum SO_BUSY_POLL = 46;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_BUSY_POLL); }))) {
            mixin(enumMixinStr_SO_BUSY_POLL);
        }
    }




    static if(!is(typeof(SO_SELECT_ERR_QUEUE))) {
        private enum enumMixinStr_SO_SELECT_ERR_QUEUE = `enum SO_SELECT_ERR_QUEUE = 45;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_SELECT_ERR_QUEUE); }))) {
            mixin(enumMixinStr_SO_SELECT_ERR_QUEUE);
        }
    }




    static if(!is(typeof(SO_LOCK_FILTER))) {
        private enum enumMixinStr_SO_LOCK_FILTER = `enum SO_LOCK_FILTER = 44;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_LOCK_FILTER); }))) {
            mixin(enumMixinStr_SO_LOCK_FILTER);
        }
    }




    static if(!is(typeof(SO_NOFCS))) {
        private enum enumMixinStr_SO_NOFCS = `enum SO_NOFCS = 43;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_NOFCS); }))) {
            mixin(enumMixinStr_SO_NOFCS);
        }
    }




    static if(!is(typeof(SO_PEEK_OFF))) {
        private enum enumMixinStr_SO_PEEK_OFF = `enum SO_PEEK_OFF = 42;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_PEEK_OFF); }))) {
            mixin(enumMixinStr_SO_PEEK_OFF);
        }
    }




    static if(!is(typeof(SCM_WIFI_STATUS))) {
        private enum enumMixinStr_SCM_WIFI_STATUS = `enum SCM_WIFI_STATUS = SO_WIFI_STATUS;`;
        static if(is(typeof({ mixin(enumMixinStr_SCM_WIFI_STATUS); }))) {
            mixin(enumMixinStr_SCM_WIFI_STATUS);
        }
    }




    static if(!is(typeof(SO_WIFI_STATUS))) {
        private enum enumMixinStr_SO_WIFI_STATUS = `enum SO_WIFI_STATUS = 41;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_WIFI_STATUS); }))) {
            mixin(enumMixinStr_SO_WIFI_STATUS);
        }
    }




    static if(!is(typeof(SO_RXQ_OVFL))) {
        private enum enumMixinStr_SO_RXQ_OVFL = `enum SO_RXQ_OVFL = 40;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_RXQ_OVFL); }))) {
            mixin(enumMixinStr_SO_RXQ_OVFL);
        }
    }




    static if(!is(typeof(SO_DOMAIN))) {
        private enum enumMixinStr_SO_DOMAIN = `enum SO_DOMAIN = 39;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_DOMAIN); }))) {
            mixin(enumMixinStr_SO_DOMAIN);
        }
    }




    static if(!is(typeof(SO_PROTOCOL))) {
        private enum enumMixinStr_SO_PROTOCOL = `enum SO_PROTOCOL = 38;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_PROTOCOL); }))) {
            mixin(enumMixinStr_SO_PROTOCOL);
        }
    }




    static if(!is(typeof(SO_MARK))) {
        private enum enumMixinStr_SO_MARK = `enum SO_MARK = 36;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_MARK); }))) {
            mixin(enumMixinStr_SO_MARK);
        }
    }






    static if(!is(typeof(SO_PASSSEC))) {
        private enum enumMixinStr_SO_PASSSEC = `enum SO_PASSSEC = 34;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_PASSSEC); }))) {
            mixin(enumMixinStr_SO_PASSSEC);
        }
    }




    static if(!is(typeof(SO_PEERSEC))) {
        private enum enumMixinStr_SO_PEERSEC = `enum SO_PEERSEC = 31;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_PEERSEC); }))) {
            mixin(enumMixinStr_SO_PEERSEC);
        }
    }




    static if(!is(typeof(SO_ACCEPTCONN))) {
        private enum enumMixinStr_SO_ACCEPTCONN = `enum SO_ACCEPTCONN = 30;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_ACCEPTCONN); }))) {
            mixin(enumMixinStr_SO_ACCEPTCONN);
        }
    }




    static if(!is(typeof(SO_PEERNAME))) {
        private enum enumMixinStr_SO_PEERNAME = `enum SO_PEERNAME = 28;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_PEERNAME); }))) {
            mixin(enumMixinStr_SO_PEERNAME);
        }
    }




    static if(!is(typeof(SO_GET_FILTER))) {
        private enum enumMixinStr_SO_GET_FILTER = `enum SO_GET_FILTER = SO_ATTACH_FILTER;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_GET_FILTER); }))) {
            mixin(enumMixinStr_SO_GET_FILTER);
        }
    }




    static if(!is(typeof(SO_DETACH_FILTER))) {
        private enum enumMixinStr_SO_DETACH_FILTER = `enum SO_DETACH_FILTER = 27;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_DETACH_FILTER); }))) {
            mixin(enumMixinStr_SO_DETACH_FILTER);
        }
    }




    static if(!is(typeof(SO_ATTACH_FILTER))) {
        private enum enumMixinStr_SO_ATTACH_FILTER = `enum SO_ATTACH_FILTER = 26;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_ATTACH_FILTER); }))) {
            mixin(enumMixinStr_SO_ATTACH_FILTER);
        }
    }




    static if(!is(typeof(SO_BINDTODEVICE))) {
        private enum enumMixinStr_SO_BINDTODEVICE = `enum SO_BINDTODEVICE = 25;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_BINDTODEVICE); }))) {
            mixin(enumMixinStr_SO_BINDTODEVICE);
        }
    }




    static if(!is(typeof(SO_SECURITY_ENCRYPTION_NETWORK))) {
        private enum enumMixinStr_SO_SECURITY_ENCRYPTION_NETWORK = `enum SO_SECURITY_ENCRYPTION_NETWORK = 24;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_SECURITY_ENCRYPTION_NETWORK); }))) {
            mixin(enumMixinStr_SO_SECURITY_ENCRYPTION_NETWORK);
        }
    }




    static if(!is(typeof(SO_SECURITY_ENCRYPTION_TRANSPORT))) {
        private enum enumMixinStr_SO_SECURITY_ENCRYPTION_TRANSPORT = `enum SO_SECURITY_ENCRYPTION_TRANSPORT = 23;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_SECURITY_ENCRYPTION_TRANSPORT); }))) {
            mixin(enumMixinStr_SO_SECURITY_ENCRYPTION_TRANSPORT);
        }
    }




    static if(!is(typeof(SO_SECURITY_AUTHENTICATION))) {
        private enum enumMixinStr_SO_SECURITY_AUTHENTICATION = `enum SO_SECURITY_AUTHENTICATION = 22;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_SECURITY_AUTHENTICATION); }))) {
            mixin(enumMixinStr_SO_SECURITY_AUTHENTICATION);
        }
    }




    static if(!is(typeof(SO_SNDTIMEO_OLD))) {
        private enum enumMixinStr_SO_SNDTIMEO_OLD = `enum SO_SNDTIMEO_OLD = 21;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_SNDTIMEO_OLD); }))) {
            mixin(enumMixinStr_SO_SNDTIMEO_OLD);
        }
    }




    static if(!is(typeof(SO_RCVTIMEO_OLD))) {
        private enum enumMixinStr_SO_RCVTIMEO_OLD = `enum SO_RCVTIMEO_OLD = 20;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_RCVTIMEO_OLD); }))) {
            mixin(enumMixinStr_SO_RCVTIMEO_OLD);
        }
    }




    static if(!is(typeof(SO_SNDLOWAT))) {
        private enum enumMixinStr_SO_SNDLOWAT = `enum SO_SNDLOWAT = 19;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_SNDLOWAT); }))) {
            mixin(enumMixinStr_SO_SNDLOWAT);
        }
    }




    static if(!is(typeof(SO_RCVLOWAT))) {
        private enum enumMixinStr_SO_RCVLOWAT = `enum SO_RCVLOWAT = 18;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_RCVLOWAT); }))) {
            mixin(enumMixinStr_SO_RCVLOWAT);
        }
    }




    static if(!is(typeof(SO_PEERCRED))) {
        private enum enumMixinStr_SO_PEERCRED = `enum SO_PEERCRED = 17;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_PEERCRED); }))) {
            mixin(enumMixinStr_SO_PEERCRED);
        }
    }




    static if(!is(typeof(SO_PASSCRED))) {
        private enum enumMixinStr_SO_PASSCRED = `enum SO_PASSCRED = 16;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_PASSCRED); }))) {
            mixin(enumMixinStr_SO_PASSCRED);
        }
    }




    static if(!is(typeof(SO_REUSEPORT))) {
        private enum enumMixinStr_SO_REUSEPORT = `enum SO_REUSEPORT = 15;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_REUSEPORT); }))) {
            mixin(enumMixinStr_SO_REUSEPORT);
        }
    }




    static if(!is(typeof(SO_BSDCOMPAT))) {
        private enum enumMixinStr_SO_BSDCOMPAT = `enum SO_BSDCOMPAT = 14;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_BSDCOMPAT); }))) {
            mixin(enumMixinStr_SO_BSDCOMPAT);
        }
    }




    static if(!is(typeof(SO_LINGER))) {
        private enum enumMixinStr_SO_LINGER = `enum SO_LINGER = 13;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_LINGER); }))) {
            mixin(enumMixinStr_SO_LINGER);
        }
    }




    static if(!is(typeof(SO_PRIORITY))) {
        private enum enumMixinStr_SO_PRIORITY = `enum SO_PRIORITY = 12;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_PRIORITY); }))) {
            mixin(enumMixinStr_SO_PRIORITY);
        }
    }




    static if(!is(typeof(SO_NO_CHECK))) {
        private enum enumMixinStr_SO_NO_CHECK = `enum SO_NO_CHECK = 11;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_NO_CHECK); }))) {
            mixin(enumMixinStr_SO_NO_CHECK);
        }
    }




    static if(!is(typeof(SO_OOBINLINE))) {
        private enum enumMixinStr_SO_OOBINLINE = `enum SO_OOBINLINE = 10;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_OOBINLINE); }))) {
            mixin(enumMixinStr_SO_OOBINLINE);
        }
    }




    static if(!is(typeof(SO_KEEPALIVE))) {
        private enum enumMixinStr_SO_KEEPALIVE = `enum SO_KEEPALIVE = 9;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_KEEPALIVE); }))) {
            mixin(enumMixinStr_SO_KEEPALIVE);
        }
    }




    static if(!is(typeof(SO_RCVBUFFORCE))) {
        private enum enumMixinStr_SO_RCVBUFFORCE = `enum SO_RCVBUFFORCE = 33;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_RCVBUFFORCE); }))) {
            mixin(enumMixinStr_SO_RCVBUFFORCE);
        }
    }




    static if(!is(typeof(SO_SNDBUFFORCE))) {
        private enum enumMixinStr_SO_SNDBUFFORCE = `enum SO_SNDBUFFORCE = 32;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_SNDBUFFORCE); }))) {
            mixin(enumMixinStr_SO_SNDBUFFORCE);
        }
    }




    static if(!is(typeof(SO_RCVBUF))) {
        private enum enumMixinStr_SO_RCVBUF = `enum SO_RCVBUF = 8;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_RCVBUF); }))) {
            mixin(enumMixinStr_SO_RCVBUF);
        }
    }




    static if(!is(typeof(SO_SNDBUF))) {
        private enum enumMixinStr_SO_SNDBUF = `enum SO_SNDBUF = 7;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_SNDBUF); }))) {
            mixin(enumMixinStr_SO_SNDBUF);
        }
    }




    static if(!is(typeof(SO_BROADCAST))) {
        private enum enumMixinStr_SO_BROADCAST = `enum SO_BROADCAST = 6;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_BROADCAST); }))) {
            mixin(enumMixinStr_SO_BROADCAST);
        }
    }




    static if(!is(typeof(SO_DONTROUTE))) {
        private enum enumMixinStr_SO_DONTROUTE = `enum SO_DONTROUTE = 5;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_DONTROUTE); }))) {
            mixin(enumMixinStr_SO_DONTROUTE);
        }
    }




    static if(!is(typeof(SO_ERROR))) {
        private enum enumMixinStr_SO_ERROR = `enum SO_ERROR = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_ERROR); }))) {
            mixin(enumMixinStr_SO_ERROR);
        }
    }




    static if(!is(typeof(SO_TYPE))) {
        private enum enumMixinStr_SO_TYPE = `enum SO_TYPE = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_TYPE); }))) {
            mixin(enumMixinStr_SO_TYPE);
        }
    }




    static if(!is(typeof(SO_REUSEADDR))) {
        private enum enumMixinStr_SO_REUSEADDR = `enum SO_REUSEADDR = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_REUSEADDR); }))) {
            mixin(enumMixinStr_SO_REUSEADDR);
        }
    }




    static if(!is(typeof(SO_DEBUG))) {
        private enum enumMixinStr_SO_DEBUG = `enum SO_DEBUG = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_SO_DEBUG); }))) {
            mixin(enumMixinStr_SO_DEBUG);
        }
    }




    static if(!is(typeof(SOL_SOCKET))) {
        private enum enumMixinStr_SOL_SOCKET = `enum SOL_SOCKET = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_SOL_SOCKET); }))) {
            mixin(enumMixinStr_SOL_SOCKET);
        }
    }
    static if(!is(typeof(MAXHOSTNAMELEN))) {
        private enum enumMixinStr_MAXHOSTNAMELEN = `enum MAXHOSTNAMELEN = 64;`;
        static if(is(typeof({ mixin(enumMixinStr_MAXHOSTNAMELEN); }))) {
            mixin(enumMixinStr_MAXHOSTNAMELEN);
        }
    }




    static if(!is(typeof(NOGROUP))) {
        private enum enumMixinStr_NOGROUP = `enum NOGROUP = ( - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr_NOGROUP); }))) {
            mixin(enumMixinStr_NOGROUP);
        }
    }




    static if(!is(typeof(EXEC_PAGESIZE))) {
        private enum enumMixinStr_EXEC_PAGESIZE = `enum EXEC_PAGESIZE = 4096;`;
        static if(is(typeof({ mixin(enumMixinStr_EXEC_PAGESIZE); }))) {
            mixin(enumMixinStr_EXEC_PAGESIZE);
        }
    }




    static if(!is(typeof(HZ))) {
        private enum enumMixinStr_HZ = `enum HZ = 100;`;
        static if(is(typeof({ mixin(enumMixinStr_HZ); }))) {
            mixin(enumMixinStr_HZ);
        }
    }






    static if(!is(typeof(TIOCSER_TEMT))) {
        private enum enumMixinStr_TIOCSER_TEMT = `enum TIOCSER_TEMT = 0x01;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCSER_TEMT); }))) {
            mixin(enumMixinStr_TIOCSER_TEMT);
        }
    }




    static if(!is(typeof(TIOCPKT_IOCTL))) {
        private enum enumMixinStr_TIOCPKT_IOCTL = `enum TIOCPKT_IOCTL = 64;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCPKT_IOCTL); }))) {
            mixin(enumMixinStr_TIOCPKT_IOCTL);
        }
    }




    static if(!is(typeof(TIOCPKT_DOSTOP))) {
        private enum enumMixinStr_TIOCPKT_DOSTOP = `enum TIOCPKT_DOSTOP = 32;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCPKT_DOSTOP); }))) {
            mixin(enumMixinStr_TIOCPKT_DOSTOP);
        }
    }




    static if(!is(typeof(TIOCPKT_NOSTOP))) {
        private enum enumMixinStr_TIOCPKT_NOSTOP = `enum TIOCPKT_NOSTOP = 16;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCPKT_NOSTOP); }))) {
            mixin(enumMixinStr_TIOCPKT_NOSTOP);
        }
    }




    static if(!is(typeof(TIOCPKT_START))) {
        private enum enumMixinStr_TIOCPKT_START = `enum TIOCPKT_START = 8;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCPKT_START); }))) {
            mixin(enumMixinStr_TIOCPKT_START);
        }
    }




    static if(!is(typeof(TIOCPKT_STOP))) {
        private enum enumMixinStr_TIOCPKT_STOP = `enum TIOCPKT_STOP = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCPKT_STOP); }))) {
            mixin(enumMixinStr_TIOCPKT_STOP);
        }
    }




    static if(!is(typeof(TIOCPKT_FLUSHWRITE))) {
        private enum enumMixinStr_TIOCPKT_FLUSHWRITE = `enum TIOCPKT_FLUSHWRITE = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCPKT_FLUSHWRITE); }))) {
            mixin(enumMixinStr_TIOCPKT_FLUSHWRITE);
        }
    }




    static if(!is(typeof(TIOCPKT_FLUSHREAD))) {
        private enum enumMixinStr_TIOCPKT_FLUSHREAD = `enum TIOCPKT_FLUSHREAD = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCPKT_FLUSHREAD); }))) {
            mixin(enumMixinStr_TIOCPKT_FLUSHREAD);
        }
    }




    static if(!is(typeof(TIOCPKT_DATA))) {
        private enum enumMixinStr_TIOCPKT_DATA = `enum TIOCPKT_DATA = 0;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCPKT_DATA); }))) {
            mixin(enumMixinStr_TIOCPKT_DATA);
        }
    }




    static if(!is(typeof(FIOQSIZE))) {
        private enum enumMixinStr_FIOQSIZE = `enum FIOQSIZE = 0x5460;`;
        static if(is(typeof({ mixin(enumMixinStr_FIOQSIZE); }))) {
            mixin(enumMixinStr_FIOQSIZE);
        }
    }




    static if(!is(typeof(TIOCGICOUNT))) {
        private enum enumMixinStr_TIOCGICOUNT = `enum TIOCGICOUNT = 0x545D;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCGICOUNT); }))) {
            mixin(enumMixinStr_TIOCGICOUNT);
        }
    }




    static if(!is(typeof(TIOCMIWAIT))) {
        private enum enumMixinStr_TIOCMIWAIT = `enum TIOCMIWAIT = 0x545C;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCMIWAIT); }))) {
            mixin(enumMixinStr_TIOCMIWAIT);
        }
    }




    static if(!is(typeof(TIOCSERSETMULTI))) {
        private enum enumMixinStr_TIOCSERSETMULTI = `enum TIOCSERSETMULTI = 0x545B;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCSERSETMULTI); }))) {
            mixin(enumMixinStr_TIOCSERSETMULTI);
        }
    }




    static if(!is(typeof(TIOCSERGETMULTI))) {
        private enum enumMixinStr_TIOCSERGETMULTI = `enum TIOCSERGETMULTI = 0x545A;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCSERGETMULTI); }))) {
            mixin(enumMixinStr_TIOCSERGETMULTI);
        }
    }




    static if(!is(typeof(TIOCSERGETLSR))) {
        private enum enumMixinStr_TIOCSERGETLSR = `enum TIOCSERGETLSR = 0x5459;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCSERGETLSR); }))) {
            mixin(enumMixinStr_TIOCSERGETLSR);
        }
    }




    static if(!is(typeof(TIOCSERGSTRUCT))) {
        private enum enumMixinStr_TIOCSERGSTRUCT = `enum TIOCSERGSTRUCT = 0x5458;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCSERGSTRUCT); }))) {
            mixin(enumMixinStr_TIOCSERGSTRUCT);
        }
    }




    static if(!is(typeof(TIOCSLCKTRMIOS))) {
        private enum enumMixinStr_TIOCSLCKTRMIOS = `enum TIOCSLCKTRMIOS = 0x5457;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCSLCKTRMIOS); }))) {
            mixin(enumMixinStr_TIOCSLCKTRMIOS);
        }
    }




    static if(!is(typeof(TIOCGLCKTRMIOS))) {
        private enum enumMixinStr_TIOCGLCKTRMIOS = `enum TIOCGLCKTRMIOS = 0x5456;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCGLCKTRMIOS); }))) {
            mixin(enumMixinStr_TIOCGLCKTRMIOS);
        }
    }




    static if(!is(typeof(TIOCSERSWILD))) {
        private enum enumMixinStr_TIOCSERSWILD = `enum TIOCSERSWILD = 0x5455;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCSERSWILD); }))) {
            mixin(enumMixinStr_TIOCSERSWILD);
        }
    }




    static if(!is(typeof(TIOCSERGWILD))) {
        private enum enumMixinStr_TIOCSERGWILD = `enum TIOCSERGWILD = 0x5454;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCSERGWILD); }))) {
            mixin(enumMixinStr_TIOCSERGWILD);
        }
    }




    static if(!is(typeof(TIOCSERCONFIG))) {
        private enum enumMixinStr_TIOCSERCONFIG = `enum TIOCSERCONFIG = 0x5453;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCSERCONFIG); }))) {
            mixin(enumMixinStr_TIOCSERCONFIG);
        }
    }




    static if(!is(typeof(FIOASYNC))) {
        private enum enumMixinStr_FIOASYNC = `enum FIOASYNC = 0x5452;`;
        static if(is(typeof({ mixin(enumMixinStr_FIOASYNC); }))) {
            mixin(enumMixinStr_FIOASYNC);
        }
    }




    static if(!is(typeof(FIOCLEX))) {
        private enum enumMixinStr_FIOCLEX = `enum FIOCLEX = 0x5451;`;
        static if(is(typeof({ mixin(enumMixinStr_FIOCLEX); }))) {
            mixin(enumMixinStr_FIOCLEX);
        }
    }




    static if(!is(typeof(FIONCLEX))) {
        private enum enumMixinStr_FIONCLEX = `enum FIONCLEX = 0x5450;`;
        static if(is(typeof({ mixin(enumMixinStr_FIONCLEX); }))) {
            mixin(enumMixinStr_FIONCLEX);
        }
    }




    static if(!is(typeof(TIOCSISO7816))) {
        private enum enumMixinStr_TIOCSISO7816 = `enum TIOCSISO7816 = _IOWR ( 'T' , 0x43 , serial_iso7816 );`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCSISO7816); }))) {
            mixin(enumMixinStr_TIOCSISO7816);
        }
    }




    static if(!is(typeof(TIOCGISO7816))) {
        private enum enumMixinStr_TIOCGISO7816 = `enum TIOCGISO7816 = _IOR ( 'T' , 0x42 , serial_iso7816 );`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCGISO7816); }))) {
            mixin(enumMixinStr_TIOCGISO7816);
        }
    }




    static if(!is(typeof(TIOCGPTPEER))) {
        private enum enumMixinStr_TIOCGPTPEER = `enum TIOCGPTPEER = _IO ( 'T' , 0x41 );`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCGPTPEER); }))) {
            mixin(enumMixinStr_TIOCGPTPEER);
        }
    }




    static if(!is(typeof(TIOCGEXCL))) {
        private enum enumMixinStr_TIOCGEXCL = `enum TIOCGEXCL = _IOR ( 'T' , 0x40 , int );`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCGEXCL); }))) {
            mixin(enumMixinStr_TIOCGEXCL);
        }
    }




    static if(!is(typeof(TIOCGPTLCK))) {
        private enum enumMixinStr_TIOCGPTLCK = `enum TIOCGPTLCK = _IOR ( 'T' , 0x39 , int );`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCGPTLCK); }))) {
            mixin(enumMixinStr_TIOCGPTLCK);
        }
    }




    static if(!is(typeof(TIOCGPKT))) {
        private enum enumMixinStr_TIOCGPKT = `enum TIOCGPKT = _IOR ( 'T' , 0x38 , int );`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCGPKT); }))) {
            mixin(enumMixinStr_TIOCGPKT);
        }
    }




    static if(!is(typeof(TIOCVHANGUP))) {
        private enum enumMixinStr_TIOCVHANGUP = `enum TIOCVHANGUP = 0x5437;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCVHANGUP); }))) {
            mixin(enumMixinStr_TIOCVHANGUP);
        }
    }




    static if(!is(typeof(TIOCSIG))) {
        private enum enumMixinStr_TIOCSIG = `enum TIOCSIG = _IOW ( 'T' , 0x36 , int );`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCSIG); }))) {
            mixin(enumMixinStr_TIOCSIG);
        }
    }




    static if(!is(typeof(TCSETXW))) {
        private enum enumMixinStr_TCSETXW = `enum TCSETXW = 0x5435;`;
        static if(is(typeof({ mixin(enumMixinStr_TCSETXW); }))) {
            mixin(enumMixinStr_TCSETXW);
        }
    }




    static if(!is(typeof(TCSETXF))) {
        private enum enumMixinStr_TCSETXF = `enum TCSETXF = 0x5434;`;
        static if(is(typeof({ mixin(enumMixinStr_TCSETXF); }))) {
            mixin(enumMixinStr_TCSETXF);
        }
    }




    static if(!is(typeof(TCSETX))) {
        private enum enumMixinStr_TCSETX = `enum TCSETX = 0x5433;`;
        static if(is(typeof({ mixin(enumMixinStr_TCSETX); }))) {
            mixin(enumMixinStr_TCSETX);
        }
    }




    static if(!is(typeof(TCGETX))) {
        private enum enumMixinStr_TCGETX = `enum TCGETX = 0x5432;`;
        static if(is(typeof({ mixin(enumMixinStr_TCGETX); }))) {
            mixin(enumMixinStr_TCGETX);
        }
    }




    static if(!is(typeof(TIOCGDEV))) {
        private enum enumMixinStr_TIOCGDEV = `enum TIOCGDEV = _IOR ( 'T' , 0x32 , unsigned int );`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCGDEV); }))) {
            mixin(enumMixinStr_TIOCGDEV);
        }
    }




    static if(!is(typeof(TIOCSPTLCK))) {
        private enum enumMixinStr_TIOCSPTLCK = `enum TIOCSPTLCK = _IOW ( 'T' , 0x31 , int );`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCSPTLCK); }))) {
            mixin(enumMixinStr_TIOCSPTLCK);
        }
    }




    static if(!is(typeof(TIOCGPTN))) {
        private enum enumMixinStr_TIOCGPTN = `enum TIOCGPTN = _IOR ( 'T' , 0x30 , unsigned int );`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCGPTN); }))) {
            mixin(enumMixinStr_TIOCGPTN);
        }
    }




    static if(!is(typeof(TIOCSRS485))) {
        private enum enumMixinStr_TIOCSRS485 = `enum TIOCSRS485 = 0x542F;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCSRS485); }))) {
            mixin(enumMixinStr_TIOCSRS485);
        }
    }




    static if(!is(typeof(TIOCGRS485))) {
        private enum enumMixinStr_TIOCGRS485 = `enum TIOCGRS485 = 0x542E;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCGRS485); }))) {
            mixin(enumMixinStr_TIOCGRS485);
        }
    }




    static if(!is(typeof(TCSETSF2))) {
        private enum enumMixinStr_TCSETSF2 = `enum TCSETSF2 = _IOW ( 'T' , 0x2D , termios2 );`;
        static if(is(typeof({ mixin(enumMixinStr_TCSETSF2); }))) {
            mixin(enumMixinStr_TCSETSF2);
        }
    }




    static if(!is(typeof(TCSETSW2))) {
        private enum enumMixinStr_TCSETSW2 = `enum TCSETSW2 = _IOW ( 'T' , 0x2C , termios2 );`;
        static if(is(typeof({ mixin(enumMixinStr_TCSETSW2); }))) {
            mixin(enumMixinStr_TCSETSW2);
        }
    }




    static if(!is(typeof(TCSETS2))) {
        private enum enumMixinStr_TCSETS2 = `enum TCSETS2 = _IOW ( 'T' , 0x2B , termios2 );`;
        static if(is(typeof({ mixin(enumMixinStr_TCSETS2); }))) {
            mixin(enumMixinStr_TCSETS2);
        }
    }




    static if(!is(typeof(TCGETS2))) {
        private enum enumMixinStr_TCGETS2 = `enum TCGETS2 = _IOR ( 'T' , 0x2A , termios2 );`;
        static if(is(typeof({ mixin(enumMixinStr_TCGETS2); }))) {
            mixin(enumMixinStr_TCGETS2);
        }
    }




    static if(!is(typeof(TIOCGSID))) {
        private enum enumMixinStr_TIOCGSID = `enum TIOCGSID = 0x5429;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCGSID); }))) {
            mixin(enumMixinStr_TIOCGSID);
        }
    }




    static if(!is(typeof(TIOCCBRK))) {
        private enum enumMixinStr_TIOCCBRK = `enum TIOCCBRK = 0x5428;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCCBRK); }))) {
            mixin(enumMixinStr_TIOCCBRK);
        }
    }




    static if(!is(typeof(TIOCSBRK))) {
        private enum enumMixinStr_TIOCSBRK = `enum TIOCSBRK = 0x5427;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCSBRK); }))) {
            mixin(enumMixinStr_TIOCSBRK);
        }
    }




    static if(!is(typeof(TCSBRKP))) {
        private enum enumMixinStr_TCSBRKP = `enum TCSBRKP = 0x5425;`;
        static if(is(typeof({ mixin(enumMixinStr_TCSBRKP); }))) {
            mixin(enumMixinStr_TCSBRKP);
        }
    }




    static if(!is(typeof(TIOCGETD))) {
        private enum enumMixinStr_TIOCGETD = `enum TIOCGETD = 0x5424;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCGETD); }))) {
            mixin(enumMixinStr_TIOCGETD);
        }
    }




    static if(!is(typeof(TIOCSETD))) {
        private enum enumMixinStr_TIOCSETD = `enum TIOCSETD = 0x5423;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCSETD); }))) {
            mixin(enumMixinStr_TIOCSETD);
        }
    }




    static if(!is(typeof(TIOCNOTTY))) {
        private enum enumMixinStr_TIOCNOTTY = `enum TIOCNOTTY = 0x5422;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCNOTTY); }))) {
            mixin(enumMixinStr_TIOCNOTTY);
        }
    }




    static if(!is(typeof(FIONBIO))) {
        private enum enumMixinStr_FIONBIO = `enum FIONBIO = 0x5421;`;
        static if(is(typeof({ mixin(enumMixinStr_FIONBIO); }))) {
            mixin(enumMixinStr_FIONBIO);
        }
    }




    static if(!is(typeof(TIOCPKT))) {
        private enum enumMixinStr_TIOCPKT = `enum TIOCPKT = 0x5420;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCPKT); }))) {
            mixin(enumMixinStr_TIOCPKT);
        }
    }




    static if(!is(typeof(TIOCSSERIAL))) {
        private enum enumMixinStr_TIOCSSERIAL = `enum TIOCSSERIAL = 0x541F;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCSSERIAL); }))) {
            mixin(enumMixinStr_TIOCSSERIAL);
        }
    }




    static if(!is(typeof(TIOCGSERIAL))) {
        private enum enumMixinStr_TIOCGSERIAL = `enum TIOCGSERIAL = 0x541E;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCGSERIAL); }))) {
            mixin(enumMixinStr_TIOCGSERIAL);
        }
    }




    static if(!is(typeof(TIOCCONS))) {
        private enum enumMixinStr_TIOCCONS = `enum TIOCCONS = 0x541D;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCCONS); }))) {
            mixin(enumMixinStr_TIOCCONS);
        }
    }




    static if(!is(typeof(TIOCLINUX))) {
        private enum enumMixinStr_TIOCLINUX = `enum TIOCLINUX = 0x541C;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCLINUX); }))) {
            mixin(enumMixinStr_TIOCLINUX);
        }
    }




    static if(!is(typeof(TIOCINQ))) {
        private enum enumMixinStr_TIOCINQ = `enum TIOCINQ = FIONREAD;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCINQ); }))) {
            mixin(enumMixinStr_TIOCINQ);
        }
    }




    static if(!is(typeof(FIONREAD))) {
        private enum enumMixinStr_FIONREAD = `enum FIONREAD = 0x541B;`;
        static if(is(typeof({ mixin(enumMixinStr_FIONREAD); }))) {
            mixin(enumMixinStr_FIONREAD);
        }
    }




    static if(!is(typeof(TIOCSSOFTCAR))) {
        private enum enumMixinStr_TIOCSSOFTCAR = `enum TIOCSSOFTCAR = 0x541A;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCSSOFTCAR); }))) {
            mixin(enumMixinStr_TIOCSSOFTCAR);
        }
    }




    static if(!is(typeof(TIOCGSOFTCAR))) {
        private enum enumMixinStr_TIOCGSOFTCAR = `enum TIOCGSOFTCAR = 0x5419;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCGSOFTCAR); }))) {
            mixin(enumMixinStr_TIOCGSOFTCAR);
        }
    }




    static if(!is(typeof(TIOCMSET))) {
        private enum enumMixinStr_TIOCMSET = `enum TIOCMSET = 0x5418;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCMSET); }))) {
            mixin(enumMixinStr_TIOCMSET);
        }
    }




    static if(!is(typeof(TIOCMBIC))) {
        private enum enumMixinStr_TIOCMBIC = `enum TIOCMBIC = 0x5417;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCMBIC); }))) {
            mixin(enumMixinStr_TIOCMBIC);
        }
    }




    static if(!is(typeof(TIOCMBIS))) {
        private enum enumMixinStr_TIOCMBIS = `enum TIOCMBIS = 0x5416;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCMBIS); }))) {
            mixin(enumMixinStr_TIOCMBIS);
        }
    }




    static if(!is(typeof(TIOCMGET))) {
        private enum enumMixinStr_TIOCMGET = `enum TIOCMGET = 0x5415;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCMGET); }))) {
            mixin(enumMixinStr_TIOCMGET);
        }
    }




    static if(!is(typeof(TIOCSWINSZ))) {
        private enum enumMixinStr_TIOCSWINSZ = `enum TIOCSWINSZ = 0x5414;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCSWINSZ); }))) {
            mixin(enumMixinStr_TIOCSWINSZ);
        }
    }




    static if(!is(typeof(TIOCGWINSZ))) {
        private enum enumMixinStr_TIOCGWINSZ = `enum TIOCGWINSZ = 0x5413;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCGWINSZ); }))) {
            mixin(enumMixinStr_TIOCGWINSZ);
        }
    }




    static if(!is(typeof(TIOCSTI))) {
        private enum enumMixinStr_TIOCSTI = `enum TIOCSTI = 0x5412;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCSTI); }))) {
            mixin(enumMixinStr_TIOCSTI);
        }
    }




    static if(!is(typeof(TIOCOUTQ))) {
        private enum enumMixinStr_TIOCOUTQ = `enum TIOCOUTQ = 0x5411;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCOUTQ); }))) {
            mixin(enumMixinStr_TIOCOUTQ);
        }
    }




    static if(!is(typeof(TIOCSPGRP))) {
        private enum enumMixinStr_TIOCSPGRP = `enum TIOCSPGRP = 0x5410;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCSPGRP); }))) {
            mixin(enumMixinStr_TIOCSPGRP);
        }
    }




    static if(!is(typeof(TIOCGPGRP))) {
        private enum enumMixinStr_TIOCGPGRP = `enum TIOCGPGRP = 0x540F;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCGPGRP); }))) {
            mixin(enumMixinStr_TIOCGPGRP);
        }
    }




    static if(!is(typeof(TIOCSCTTY))) {
        private enum enumMixinStr_TIOCSCTTY = `enum TIOCSCTTY = 0x540E;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCSCTTY); }))) {
            mixin(enumMixinStr_TIOCSCTTY);
        }
    }




    static if(!is(typeof(TIOCNXCL))) {
        private enum enumMixinStr_TIOCNXCL = `enum TIOCNXCL = 0x540D;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCNXCL); }))) {
            mixin(enumMixinStr_TIOCNXCL);
        }
    }




    static if(!is(typeof(TIOCEXCL))) {
        private enum enumMixinStr_TIOCEXCL = `enum TIOCEXCL = 0x540C;`;
        static if(is(typeof({ mixin(enumMixinStr_TIOCEXCL); }))) {
            mixin(enumMixinStr_TIOCEXCL);
        }
    }




    static if(!is(typeof(TCFLSH))) {
        private enum enumMixinStr_TCFLSH = `enum TCFLSH = 0x540B;`;
        static if(is(typeof({ mixin(enumMixinStr_TCFLSH); }))) {
            mixin(enumMixinStr_TCFLSH);
        }
    }




    static if(!is(typeof(TCXONC))) {
        private enum enumMixinStr_TCXONC = `enum TCXONC = 0x540A;`;
        static if(is(typeof({ mixin(enumMixinStr_TCXONC); }))) {
            mixin(enumMixinStr_TCXONC);
        }
    }




    static if(!is(typeof(TCSBRK))) {
        private enum enumMixinStr_TCSBRK = `enum TCSBRK = 0x5409;`;
        static if(is(typeof({ mixin(enumMixinStr_TCSBRK); }))) {
            mixin(enumMixinStr_TCSBRK);
        }
    }




    static if(!is(typeof(TCSETAF))) {
        private enum enumMixinStr_TCSETAF = `enum TCSETAF = 0x5408;`;
        static if(is(typeof({ mixin(enumMixinStr_TCSETAF); }))) {
            mixin(enumMixinStr_TCSETAF);
        }
    }




    static if(!is(typeof(TCSETAW))) {
        private enum enumMixinStr_TCSETAW = `enum TCSETAW = 0x5407;`;
        static if(is(typeof({ mixin(enumMixinStr_TCSETAW); }))) {
            mixin(enumMixinStr_TCSETAW);
        }
    }




    static if(!is(typeof(TCSETA))) {
        private enum enumMixinStr_TCSETA = `enum TCSETA = 0x5406;`;
        static if(is(typeof({ mixin(enumMixinStr_TCSETA); }))) {
            mixin(enumMixinStr_TCSETA);
        }
    }




    static if(!is(typeof(TCGETA))) {
        private enum enumMixinStr_TCGETA = `enum TCGETA = 0x5405;`;
        static if(is(typeof({ mixin(enumMixinStr_TCGETA); }))) {
            mixin(enumMixinStr_TCGETA);
        }
    }




    static if(!is(typeof(TCSETSF))) {
        private enum enumMixinStr_TCSETSF = `enum TCSETSF = 0x5404;`;
        static if(is(typeof({ mixin(enumMixinStr_TCSETSF); }))) {
            mixin(enumMixinStr_TCSETSF);
        }
    }




    static if(!is(typeof(TCSETSW))) {
        private enum enumMixinStr_TCSETSW = `enum TCSETSW = 0x5403;`;
        static if(is(typeof({ mixin(enumMixinStr_TCSETSW); }))) {
            mixin(enumMixinStr_TCSETSW);
        }
    }




    static if(!is(typeof(TCSETS))) {
        private enum enumMixinStr_TCSETS = `enum TCSETS = 0x5402;`;
        static if(is(typeof({ mixin(enumMixinStr_TCSETS); }))) {
            mixin(enumMixinStr_TCSETS);
        }
    }




    static if(!is(typeof(TCGETS))) {
        private enum enumMixinStr_TCGETS = `enum TCGETS = 0x5401;`;
        static if(is(typeof({ mixin(enumMixinStr_TCGETS); }))) {
            mixin(enumMixinStr_TCGETS);
        }
    }






    static if(!is(typeof(IOCSIZE_SHIFT))) {
        private enum enumMixinStr_IOCSIZE_SHIFT = `enum IOCSIZE_SHIFT = ( _IOC_SIZESHIFT );`;
        static if(is(typeof({ mixin(enumMixinStr_IOCSIZE_SHIFT); }))) {
            mixin(enumMixinStr_IOCSIZE_SHIFT);
        }
    }




    static if(!is(typeof(IOCSIZE_MASK))) {
        private enum enumMixinStr_IOCSIZE_MASK = `enum IOCSIZE_MASK = ( _IOC_SIZEMASK << _IOC_SIZESHIFT );`;
        static if(is(typeof({ mixin(enumMixinStr_IOCSIZE_MASK); }))) {
            mixin(enumMixinStr_IOCSIZE_MASK);
        }
    }




    static if(!is(typeof(IOC_INOUT))) {
        private enum enumMixinStr_IOC_INOUT = `enum IOC_INOUT = ( ( _IOC_WRITE | _IOC_READ ) << _IOC_DIRSHIFT );`;
        static if(is(typeof({ mixin(enumMixinStr_IOC_INOUT); }))) {
            mixin(enumMixinStr_IOC_INOUT);
        }
    }




    static if(!is(typeof(IOC_OUT))) {
        private enum enumMixinStr_IOC_OUT = `enum IOC_OUT = ( _IOC_READ << _IOC_DIRSHIFT );`;
        static if(is(typeof({ mixin(enumMixinStr_IOC_OUT); }))) {
            mixin(enumMixinStr_IOC_OUT);
        }
    }




    static if(!is(typeof(IOC_IN))) {
        private enum enumMixinStr_IOC_IN = `enum IOC_IN = ( _IOC_WRITE << _IOC_DIRSHIFT );`;
        static if(is(typeof({ mixin(enumMixinStr_IOC_IN); }))) {
            mixin(enumMixinStr_IOC_IN);
        }
    }
    static if(!is(typeof(_IOC_READ))) {
        private enum enumMixinStr__IOC_READ = `enum _IOC_READ = 2U;`;
        static if(is(typeof({ mixin(enumMixinStr__IOC_READ); }))) {
            mixin(enumMixinStr__IOC_READ);
        }
    }




    static if(!is(typeof(_IOC_WRITE))) {
        private enum enumMixinStr__IOC_WRITE = `enum _IOC_WRITE = 1U;`;
        static if(is(typeof({ mixin(enumMixinStr__IOC_WRITE); }))) {
            mixin(enumMixinStr__IOC_WRITE);
        }
    }




    static if(!is(typeof(_IOC_NONE))) {
        private enum enumMixinStr__IOC_NONE = `enum _IOC_NONE = 0U;`;
        static if(is(typeof({ mixin(enumMixinStr__IOC_NONE); }))) {
            mixin(enumMixinStr__IOC_NONE);
        }
    }




    static if(!is(typeof(_IOC_DIRSHIFT))) {
        private enum enumMixinStr__IOC_DIRSHIFT = `enum _IOC_DIRSHIFT = ( _IOC_SIZESHIFT + _IOC_SIZEBITS );`;
        static if(is(typeof({ mixin(enumMixinStr__IOC_DIRSHIFT); }))) {
            mixin(enumMixinStr__IOC_DIRSHIFT);
        }
    }




    static if(!is(typeof(_IOC_SIZESHIFT))) {
        private enum enumMixinStr__IOC_SIZESHIFT = `enum _IOC_SIZESHIFT = ( _IOC_TYPESHIFT + _IOC_TYPEBITS );`;
        static if(is(typeof({ mixin(enumMixinStr__IOC_SIZESHIFT); }))) {
            mixin(enumMixinStr__IOC_SIZESHIFT);
        }
    }




    static if(!is(typeof(_IOC_TYPESHIFT))) {
        private enum enumMixinStr__IOC_TYPESHIFT = `enum _IOC_TYPESHIFT = ( _IOC_NRSHIFT + _IOC_NRBITS );`;
        static if(is(typeof({ mixin(enumMixinStr__IOC_TYPESHIFT); }))) {
            mixin(enumMixinStr__IOC_TYPESHIFT);
        }
    }




    static if(!is(typeof(_IOC_NRSHIFT))) {
        private enum enumMixinStr__IOC_NRSHIFT = `enum _IOC_NRSHIFT = 0;`;
        static if(is(typeof({ mixin(enumMixinStr__IOC_NRSHIFT); }))) {
            mixin(enumMixinStr__IOC_NRSHIFT);
        }
    }




    static if(!is(typeof(_IOC_DIRMASK))) {
        private enum enumMixinStr__IOC_DIRMASK = `enum _IOC_DIRMASK = ( ( 1 << _IOC_DIRBITS ) - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr__IOC_DIRMASK); }))) {
            mixin(enumMixinStr__IOC_DIRMASK);
        }
    }




    static if(!is(typeof(_IOC_SIZEMASK))) {
        private enum enumMixinStr__IOC_SIZEMASK = `enum _IOC_SIZEMASK = ( ( 1 << _IOC_SIZEBITS ) - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr__IOC_SIZEMASK); }))) {
            mixin(enumMixinStr__IOC_SIZEMASK);
        }
    }




    static if(!is(typeof(_IOC_TYPEMASK))) {
        private enum enumMixinStr__IOC_TYPEMASK = `enum _IOC_TYPEMASK = ( ( 1 << _IOC_TYPEBITS ) - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr__IOC_TYPEMASK); }))) {
            mixin(enumMixinStr__IOC_TYPEMASK);
        }
    }




    static if(!is(typeof(_IOC_NRMASK))) {
        private enum enumMixinStr__IOC_NRMASK = `enum _IOC_NRMASK = ( ( 1 << _IOC_NRBITS ) - 1 );`;
        static if(is(typeof({ mixin(enumMixinStr__IOC_NRMASK); }))) {
            mixin(enumMixinStr__IOC_NRMASK);
        }
    }




    static if(!is(typeof(_IOC_DIRBITS))) {
        private enum enumMixinStr__IOC_DIRBITS = `enum _IOC_DIRBITS = 2;`;
        static if(is(typeof({ mixin(enumMixinStr__IOC_DIRBITS); }))) {
            mixin(enumMixinStr__IOC_DIRBITS);
        }
    }




    static if(!is(typeof(_IOC_SIZEBITS))) {
        private enum enumMixinStr__IOC_SIZEBITS = `enum _IOC_SIZEBITS = 14;`;
        static if(is(typeof({ mixin(enumMixinStr__IOC_SIZEBITS); }))) {
            mixin(enumMixinStr__IOC_SIZEBITS);
        }
    }




    static if(!is(typeof(_IOC_TYPEBITS))) {
        private enum enumMixinStr__IOC_TYPEBITS = `enum _IOC_TYPEBITS = 8;`;
        static if(is(typeof({ mixin(enumMixinStr__IOC_TYPEBITS); }))) {
            mixin(enumMixinStr__IOC_TYPEBITS);
        }
    }




    static if(!is(typeof(_IOC_NRBITS))) {
        private enum enumMixinStr__IOC_NRBITS = `enum _IOC_NRBITS = 8;`;
        static if(is(typeof({ mixin(enumMixinStr__IOC_NRBITS); }))) {
            mixin(enumMixinStr__IOC_NRBITS);
        }
    }






    static if(!is(typeof(EHWPOISON))) {
        private enum enumMixinStr_EHWPOISON = `enum EHWPOISON = 133;`;
        static if(is(typeof({ mixin(enumMixinStr_EHWPOISON); }))) {
            mixin(enumMixinStr_EHWPOISON);
        }
    }




    static if(!is(typeof(ERFKILL))) {
        private enum enumMixinStr_ERFKILL = `enum ERFKILL = 132;`;
        static if(is(typeof({ mixin(enumMixinStr_ERFKILL); }))) {
            mixin(enumMixinStr_ERFKILL);
        }
    }




    static if(!is(typeof(ENOTRECOVERABLE))) {
        private enum enumMixinStr_ENOTRECOVERABLE = `enum ENOTRECOVERABLE = 131;`;
        static if(is(typeof({ mixin(enumMixinStr_ENOTRECOVERABLE); }))) {
            mixin(enumMixinStr_ENOTRECOVERABLE);
        }
    }




    static if(!is(typeof(EOWNERDEAD))) {
        private enum enumMixinStr_EOWNERDEAD = `enum EOWNERDEAD = 130;`;
        static if(is(typeof({ mixin(enumMixinStr_EOWNERDEAD); }))) {
            mixin(enumMixinStr_EOWNERDEAD);
        }
    }




    static if(!is(typeof(EKEYREJECTED))) {
        private enum enumMixinStr_EKEYREJECTED = `enum EKEYREJECTED = 129;`;
        static if(is(typeof({ mixin(enumMixinStr_EKEYREJECTED); }))) {
            mixin(enumMixinStr_EKEYREJECTED);
        }
    }




    static if(!is(typeof(EKEYREVOKED))) {
        private enum enumMixinStr_EKEYREVOKED = `enum EKEYREVOKED = 128;`;
        static if(is(typeof({ mixin(enumMixinStr_EKEYREVOKED); }))) {
            mixin(enumMixinStr_EKEYREVOKED);
        }
    }




    static if(!is(typeof(EKEYEXPIRED))) {
        private enum enumMixinStr_EKEYEXPIRED = `enum EKEYEXPIRED = 127;`;
        static if(is(typeof({ mixin(enumMixinStr_EKEYEXPIRED); }))) {
            mixin(enumMixinStr_EKEYEXPIRED);
        }
    }




    static if(!is(typeof(ENOKEY))) {
        private enum enumMixinStr_ENOKEY = `enum ENOKEY = 126;`;
        static if(is(typeof({ mixin(enumMixinStr_ENOKEY); }))) {
            mixin(enumMixinStr_ENOKEY);
        }
    }




    static if(!is(typeof(ECANCELED))) {
        private enum enumMixinStr_ECANCELED = `enum ECANCELED = 125;`;
        static if(is(typeof({ mixin(enumMixinStr_ECANCELED); }))) {
            mixin(enumMixinStr_ECANCELED);
        }
    }




    static if(!is(typeof(EMEDIUMTYPE))) {
        private enum enumMixinStr_EMEDIUMTYPE = `enum EMEDIUMTYPE = 124;`;
        static if(is(typeof({ mixin(enumMixinStr_EMEDIUMTYPE); }))) {
            mixin(enumMixinStr_EMEDIUMTYPE);
        }
    }




    static if(!is(typeof(ENOMEDIUM))) {
        private enum enumMixinStr_ENOMEDIUM = `enum ENOMEDIUM = 123;`;
        static if(is(typeof({ mixin(enumMixinStr_ENOMEDIUM); }))) {
            mixin(enumMixinStr_ENOMEDIUM);
        }
    }




    static if(!is(typeof(EDQUOT))) {
        private enum enumMixinStr_EDQUOT = `enum EDQUOT = 122;`;
        static if(is(typeof({ mixin(enumMixinStr_EDQUOT); }))) {
            mixin(enumMixinStr_EDQUOT);
        }
    }




    static if(!is(typeof(EREMOTEIO))) {
        private enum enumMixinStr_EREMOTEIO = `enum EREMOTEIO = 121;`;
        static if(is(typeof({ mixin(enumMixinStr_EREMOTEIO); }))) {
            mixin(enumMixinStr_EREMOTEIO);
        }
    }




    static if(!is(typeof(EISNAM))) {
        private enum enumMixinStr_EISNAM = `enum EISNAM = 120;`;
        static if(is(typeof({ mixin(enumMixinStr_EISNAM); }))) {
            mixin(enumMixinStr_EISNAM);
        }
    }




    static if(!is(typeof(ENAVAIL))) {
        private enum enumMixinStr_ENAVAIL = `enum ENAVAIL = 119;`;
        static if(is(typeof({ mixin(enumMixinStr_ENAVAIL); }))) {
            mixin(enumMixinStr_ENAVAIL);
        }
    }




    static if(!is(typeof(ENOTNAM))) {
        private enum enumMixinStr_ENOTNAM = `enum ENOTNAM = 118;`;
        static if(is(typeof({ mixin(enumMixinStr_ENOTNAM); }))) {
            mixin(enumMixinStr_ENOTNAM);
        }
    }




    static if(!is(typeof(EUCLEAN))) {
        private enum enumMixinStr_EUCLEAN = `enum EUCLEAN = 117;`;
        static if(is(typeof({ mixin(enumMixinStr_EUCLEAN); }))) {
            mixin(enumMixinStr_EUCLEAN);
        }
    }




    static if(!is(typeof(ESTALE))) {
        private enum enumMixinStr_ESTALE = `enum ESTALE = 116;`;
        static if(is(typeof({ mixin(enumMixinStr_ESTALE); }))) {
            mixin(enumMixinStr_ESTALE);
        }
    }




    static if(!is(typeof(EINPROGRESS))) {
        private enum enumMixinStr_EINPROGRESS = `enum EINPROGRESS = 115;`;
        static if(is(typeof({ mixin(enumMixinStr_EINPROGRESS); }))) {
            mixin(enumMixinStr_EINPROGRESS);
        }
    }




    static if(!is(typeof(EALREADY))) {
        private enum enumMixinStr_EALREADY = `enum EALREADY = 114;`;
        static if(is(typeof({ mixin(enumMixinStr_EALREADY); }))) {
            mixin(enumMixinStr_EALREADY);
        }
    }




    static if(!is(typeof(EHOSTUNREACH))) {
        private enum enumMixinStr_EHOSTUNREACH = `enum EHOSTUNREACH = 113;`;
        static if(is(typeof({ mixin(enumMixinStr_EHOSTUNREACH); }))) {
            mixin(enumMixinStr_EHOSTUNREACH);
        }
    }




    static if(!is(typeof(EHOSTDOWN))) {
        private enum enumMixinStr_EHOSTDOWN = `enum EHOSTDOWN = 112;`;
        static if(is(typeof({ mixin(enumMixinStr_EHOSTDOWN); }))) {
            mixin(enumMixinStr_EHOSTDOWN);
        }
    }




    static if(!is(typeof(ECONNREFUSED))) {
        private enum enumMixinStr_ECONNREFUSED = `enum ECONNREFUSED = 111;`;
        static if(is(typeof({ mixin(enumMixinStr_ECONNREFUSED); }))) {
            mixin(enumMixinStr_ECONNREFUSED);
        }
    }




    static if(!is(typeof(ETIMEDOUT))) {
        private enum enumMixinStr_ETIMEDOUT = `enum ETIMEDOUT = 110;`;
        static if(is(typeof({ mixin(enumMixinStr_ETIMEDOUT); }))) {
            mixin(enumMixinStr_ETIMEDOUT);
        }
    }




    static if(!is(typeof(ETOOMANYREFS))) {
        private enum enumMixinStr_ETOOMANYREFS = `enum ETOOMANYREFS = 109;`;
        static if(is(typeof({ mixin(enumMixinStr_ETOOMANYREFS); }))) {
            mixin(enumMixinStr_ETOOMANYREFS);
        }
    }




    static if(!is(typeof(ESHUTDOWN))) {
        private enum enumMixinStr_ESHUTDOWN = `enum ESHUTDOWN = 108;`;
        static if(is(typeof({ mixin(enumMixinStr_ESHUTDOWN); }))) {
            mixin(enumMixinStr_ESHUTDOWN);
        }
    }




    static if(!is(typeof(ENOTCONN))) {
        private enum enumMixinStr_ENOTCONN = `enum ENOTCONN = 107;`;
        static if(is(typeof({ mixin(enumMixinStr_ENOTCONN); }))) {
            mixin(enumMixinStr_ENOTCONN);
        }
    }




    static if(!is(typeof(EISCONN))) {
        private enum enumMixinStr_EISCONN = `enum EISCONN = 106;`;
        static if(is(typeof({ mixin(enumMixinStr_EISCONN); }))) {
            mixin(enumMixinStr_EISCONN);
        }
    }




    static if(!is(typeof(ENOBUFS))) {
        private enum enumMixinStr_ENOBUFS = `enum ENOBUFS = 105;`;
        static if(is(typeof({ mixin(enumMixinStr_ENOBUFS); }))) {
            mixin(enumMixinStr_ENOBUFS);
        }
    }




    static if(!is(typeof(ECONNRESET))) {
        private enum enumMixinStr_ECONNRESET = `enum ECONNRESET = 104;`;
        static if(is(typeof({ mixin(enumMixinStr_ECONNRESET); }))) {
            mixin(enumMixinStr_ECONNRESET);
        }
    }




    static if(!is(typeof(ECONNABORTED))) {
        private enum enumMixinStr_ECONNABORTED = `enum ECONNABORTED = 103;`;
        static if(is(typeof({ mixin(enumMixinStr_ECONNABORTED); }))) {
            mixin(enumMixinStr_ECONNABORTED);
        }
    }




    static if(!is(typeof(ENETRESET))) {
        private enum enumMixinStr_ENETRESET = `enum ENETRESET = 102;`;
        static if(is(typeof({ mixin(enumMixinStr_ENETRESET); }))) {
            mixin(enumMixinStr_ENETRESET);
        }
    }




    static if(!is(typeof(ENETUNREACH))) {
        private enum enumMixinStr_ENETUNREACH = `enum ENETUNREACH = 101;`;
        static if(is(typeof({ mixin(enumMixinStr_ENETUNREACH); }))) {
            mixin(enumMixinStr_ENETUNREACH);
        }
    }




    static if(!is(typeof(ENETDOWN))) {
        private enum enumMixinStr_ENETDOWN = `enum ENETDOWN = 100;`;
        static if(is(typeof({ mixin(enumMixinStr_ENETDOWN); }))) {
            mixin(enumMixinStr_ENETDOWN);
        }
    }




    static if(!is(typeof(EADDRNOTAVAIL))) {
        private enum enumMixinStr_EADDRNOTAVAIL = `enum EADDRNOTAVAIL = 99;`;
        static if(is(typeof({ mixin(enumMixinStr_EADDRNOTAVAIL); }))) {
            mixin(enumMixinStr_EADDRNOTAVAIL);
        }
    }




    static if(!is(typeof(EADDRINUSE))) {
        private enum enumMixinStr_EADDRINUSE = `enum EADDRINUSE = 98;`;
        static if(is(typeof({ mixin(enumMixinStr_EADDRINUSE); }))) {
            mixin(enumMixinStr_EADDRINUSE);
        }
    }




    static if(!is(typeof(EAFNOSUPPORT))) {
        private enum enumMixinStr_EAFNOSUPPORT = `enum EAFNOSUPPORT = 97;`;
        static if(is(typeof({ mixin(enumMixinStr_EAFNOSUPPORT); }))) {
            mixin(enumMixinStr_EAFNOSUPPORT);
        }
    }




    static if(!is(typeof(EPFNOSUPPORT))) {
        private enum enumMixinStr_EPFNOSUPPORT = `enum EPFNOSUPPORT = 96;`;
        static if(is(typeof({ mixin(enumMixinStr_EPFNOSUPPORT); }))) {
            mixin(enumMixinStr_EPFNOSUPPORT);
        }
    }




    static if(!is(typeof(EOPNOTSUPP))) {
        private enum enumMixinStr_EOPNOTSUPP = `enum EOPNOTSUPP = 95;`;
        static if(is(typeof({ mixin(enumMixinStr_EOPNOTSUPP); }))) {
            mixin(enumMixinStr_EOPNOTSUPP);
        }
    }




    static if(!is(typeof(ESOCKTNOSUPPORT))) {
        private enum enumMixinStr_ESOCKTNOSUPPORT = `enum ESOCKTNOSUPPORT = 94;`;
        static if(is(typeof({ mixin(enumMixinStr_ESOCKTNOSUPPORT); }))) {
            mixin(enumMixinStr_ESOCKTNOSUPPORT);
        }
    }




    static if(!is(typeof(EPROTONOSUPPORT))) {
        private enum enumMixinStr_EPROTONOSUPPORT = `enum EPROTONOSUPPORT = 93;`;
        static if(is(typeof({ mixin(enumMixinStr_EPROTONOSUPPORT); }))) {
            mixin(enumMixinStr_EPROTONOSUPPORT);
        }
    }




    static if(!is(typeof(ENOPROTOOPT))) {
        private enum enumMixinStr_ENOPROTOOPT = `enum ENOPROTOOPT = 92;`;
        static if(is(typeof({ mixin(enumMixinStr_ENOPROTOOPT); }))) {
            mixin(enumMixinStr_ENOPROTOOPT);
        }
    }




    static if(!is(typeof(EPROTOTYPE))) {
        private enum enumMixinStr_EPROTOTYPE = `enum EPROTOTYPE = 91;`;
        static if(is(typeof({ mixin(enumMixinStr_EPROTOTYPE); }))) {
            mixin(enumMixinStr_EPROTOTYPE);
        }
    }




    static if(!is(typeof(EMSGSIZE))) {
        private enum enumMixinStr_EMSGSIZE = `enum EMSGSIZE = 90;`;
        static if(is(typeof({ mixin(enumMixinStr_EMSGSIZE); }))) {
            mixin(enumMixinStr_EMSGSIZE);
        }
    }




    static if(!is(typeof(EDESTADDRREQ))) {
        private enum enumMixinStr_EDESTADDRREQ = `enum EDESTADDRREQ = 89;`;
        static if(is(typeof({ mixin(enumMixinStr_EDESTADDRREQ); }))) {
            mixin(enumMixinStr_EDESTADDRREQ);
        }
    }




    static if(!is(typeof(ENOTSOCK))) {
        private enum enumMixinStr_ENOTSOCK = `enum ENOTSOCK = 88;`;
        static if(is(typeof({ mixin(enumMixinStr_ENOTSOCK); }))) {
            mixin(enumMixinStr_ENOTSOCK);
        }
    }




    static if(!is(typeof(EUSERS))) {
        private enum enumMixinStr_EUSERS = `enum EUSERS = 87;`;
        static if(is(typeof({ mixin(enumMixinStr_EUSERS); }))) {
            mixin(enumMixinStr_EUSERS);
        }
    }




    static if(!is(typeof(ESTRPIPE))) {
        private enum enumMixinStr_ESTRPIPE = `enum ESTRPIPE = 86;`;
        static if(is(typeof({ mixin(enumMixinStr_ESTRPIPE); }))) {
            mixin(enumMixinStr_ESTRPIPE);
        }
    }




    static if(!is(typeof(ERESTART))) {
        private enum enumMixinStr_ERESTART = `enum ERESTART = 85;`;
        static if(is(typeof({ mixin(enumMixinStr_ERESTART); }))) {
            mixin(enumMixinStr_ERESTART);
        }
    }




    static if(!is(typeof(EILSEQ))) {
        private enum enumMixinStr_EILSEQ = `enum EILSEQ = 84;`;
        static if(is(typeof({ mixin(enumMixinStr_EILSEQ); }))) {
            mixin(enumMixinStr_EILSEQ);
        }
    }




    static if(!is(typeof(ELIBEXEC))) {
        private enum enumMixinStr_ELIBEXEC = `enum ELIBEXEC = 83;`;
        static if(is(typeof({ mixin(enumMixinStr_ELIBEXEC); }))) {
            mixin(enumMixinStr_ELIBEXEC);
        }
    }




    static if(!is(typeof(ELIBMAX))) {
        private enum enumMixinStr_ELIBMAX = `enum ELIBMAX = 82;`;
        static if(is(typeof({ mixin(enumMixinStr_ELIBMAX); }))) {
            mixin(enumMixinStr_ELIBMAX);
        }
    }




    static if(!is(typeof(ELIBSCN))) {
        private enum enumMixinStr_ELIBSCN = `enum ELIBSCN = 81;`;
        static if(is(typeof({ mixin(enumMixinStr_ELIBSCN); }))) {
            mixin(enumMixinStr_ELIBSCN);
        }
    }




    static if(!is(typeof(ELIBBAD))) {
        private enum enumMixinStr_ELIBBAD = `enum ELIBBAD = 80;`;
        static if(is(typeof({ mixin(enumMixinStr_ELIBBAD); }))) {
            mixin(enumMixinStr_ELIBBAD);
        }
    }




    static if(!is(typeof(ELIBACC))) {
        private enum enumMixinStr_ELIBACC = `enum ELIBACC = 79;`;
        static if(is(typeof({ mixin(enumMixinStr_ELIBACC); }))) {
            mixin(enumMixinStr_ELIBACC);
        }
    }




    static if(!is(typeof(EREMCHG))) {
        private enum enumMixinStr_EREMCHG = `enum EREMCHG = 78;`;
        static if(is(typeof({ mixin(enumMixinStr_EREMCHG); }))) {
            mixin(enumMixinStr_EREMCHG);
        }
    }




    static if(!is(typeof(EBADFD))) {
        private enum enumMixinStr_EBADFD = `enum EBADFD = 77;`;
        static if(is(typeof({ mixin(enumMixinStr_EBADFD); }))) {
            mixin(enumMixinStr_EBADFD);
        }
    }




    static if(!is(typeof(ENOTUNIQ))) {
        private enum enumMixinStr_ENOTUNIQ = `enum ENOTUNIQ = 76;`;
        static if(is(typeof({ mixin(enumMixinStr_ENOTUNIQ); }))) {
            mixin(enumMixinStr_ENOTUNIQ);
        }
    }




    static if(!is(typeof(EOVERFLOW))) {
        private enum enumMixinStr_EOVERFLOW = `enum EOVERFLOW = 75;`;
        static if(is(typeof({ mixin(enumMixinStr_EOVERFLOW); }))) {
            mixin(enumMixinStr_EOVERFLOW);
        }
    }




    static if(!is(typeof(EBADMSG))) {
        private enum enumMixinStr_EBADMSG = `enum EBADMSG = 74;`;
        static if(is(typeof({ mixin(enumMixinStr_EBADMSG); }))) {
            mixin(enumMixinStr_EBADMSG);
        }
    }




    static if(!is(typeof(EDOTDOT))) {
        private enum enumMixinStr_EDOTDOT = `enum EDOTDOT = 73;`;
        static if(is(typeof({ mixin(enumMixinStr_EDOTDOT); }))) {
            mixin(enumMixinStr_EDOTDOT);
        }
    }




    static if(!is(typeof(EMULTIHOP))) {
        private enum enumMixinStr_EMULTIHOP = `enum EMULTIHOP = 72;`;
        static if(is(typeof({ mixin(enumMixinStr_EMULTIHOP); }))) {
            mixin(enumMixinStr_EMULTIHOP);
        }
    }




    static if(!is(typeof(EPROTO))) {
        private enum enumMixinStr_EPROTO = `enum EPROTO = 71;`;
        static if(is(typeof({ mixin(enumMixinStr_EPROTO); }))) {
            mixin(enumMixinStr_EPROTO);
        }
    }




    static if(!is(typeof(ECOMM))) {
        private enum enumMixinStr_ECOMM = `enum ECOMM = 70;`;
        static if(is(typeof({ mixin(enumMixinStr_ECOMM); }))) {
            mixin(enumMixinStr_ECOMM);
        }
    }




    static if(!is(typeof(ESRMNT))) {
        private enum enumMixinStr_ESRMNT = `enum ESRMNT = 69;`;
        static if(is(typeof({ mixin(enumMixinStr_ESRMNT); }))) {
            mixin(enumMixinStr_ESRMNT);
        }
    }




    static if(!is(typeof(EADV))) {
        private enum enumMixinStr_EADV = `enum EADV = 68;`;
        static if(is(typeof({ mixin(enumMixinStr_EADV); }))) {
            mixin(enumMixinStr_EADV);
        }
    }




    static if(!is(typeof(ENOLINK))) {
        private enum enumMixinStr_ENOLINK = `enum ENOLINK = 67;`;
        static if(is(typeof({ mixin(enumMixinStr_ENOLINK); }))) {
            mixin(enumMixinStr_ENOLINK);
        }
    }




    static if(!is(typeof(EREMOTE))) {
        private enum enumMixinStr_EREMOTE = `enum EREMOTE = 66;`;
        static if(is(typeof({ mixin(enumMixinStr_EREMOTE); }))) {
            mixin(enumMixinStr_EREMOTE);
        }
    }




    static if(!is(typeof(ENOPKG))) {
        private enum enumMixinStr_ENOPKG = `enum ENOPKG = 65;`;
        static if(is(typeof({ mixin(enumMixinStr_ENOPKG); }))) {
            mixin(enumMixinStr_ENOPKG);
        }
    }




    static if(!is(typeof(ENONET))) {
        private enum enumMixinStr_ENONET = `enum ENONET = 64;`;
        static if(is(typeof({ mixin(enumMixinStr_ENONET); }))) {
            mixin(enumMixinStr_ENONET);
        }
    }




    static if(!is(typeof(ENOSR))) {
        private enum enumMixinStr_ENOSR = `enum ENOSR = 63;`;
        static if(is(typeof({ mixin(enumMixinStr_ENOSR); }))) {
            mixin(enumMixinStr_ENOSR);
        }
    }




    static if(!is(typeof(ETIME))) {
        private enum enumMixinStr_ETIME = `enum ETIME = 62;`;
        static if(is(typeof({ mixin(enumMixinStr_ETIME); }))) {
            mixin(enumMixinStr_ETIME);
        }
    }




    static if(!is(typeof(ENODATA))) {
        private enum enumMixinStr_ENODATA = `enum ENODATA = 61;`;
        static if(is(typeof({ mixin(enumMixinStr_ENODATA); }))) {
            mixin(enumMixinStr_ENODATA);
        }
    }




    static if(!is(typeof(ENOSTR))) {
        private enum enumMixinStr_ENOSTR = `enum ENOSTR = 60;`;
        static if(is(typeof({ mixin(enumMixinStr_ENOSTR); }))) {
            mixin(enumMixinStr_ENOSTR);
        }
    }




    static if(!is(typeof(EBFONT))) {
        private enum enumMixinStr_EBFONT = `enum EBFONT = 59;`;
        static if(is(typeof({ mixin(enumMixinStr_EBFONT); }))) {
            mixin(enumMixinStr_EBFONT);
        }
    }




    static if(!is(typeof(EDEADLOCK))) {
        private enum enumMixinStr_EDEADLOCK = `enum EDEADLOCK = EDEADLK;`;
        static if(is(typeof({ mixin(enumMixinStr_EDEADLOCK); }))) {
            mixin(enumMixinStr_EDEADLOCK);
        }
    }




    static if(!is(typeof(EBADSLT))) {
        private enum enumMixinStr_EBADSLT = `enum EBADSLT = 57;`;
        static if(is(typeof({ mixin(enumMixinStr_EBADSLT); }))) {
            mixin(enumMixinStr_EBADSLT);
        }
    }




    static if(!is(typeof(EBADRQC))) {
        private enum enumMixinStr_EBADRQC = `enum EBADRQC = 56;`;
        static if(is(typeof({ mixin(enumMixinStr_EBADRQC); }))) {
            mixin(enumMixinStr_EBADRQC);
        }
    }




    static if(!is(typeof(ENOANO))) {
        private enum enumMixinStr_ENOANO = `enum ENOANO = 55;`;
        static if(is(typeof({ mixin(enumMixinStr_ENOANO); }))) {
            mixin(enumMixinStr_ENOANO);
        }
    }




    static if(!is(typeof(EXFULL))) {
        private enum enumMixinStr_EXFULL = `enum EXFULL = 54;`;
        static if(is(typeof({ mixin(enumMixinStr_EXFULL); }))) {
            mixin(enumMixinStr_EXFULL);
        }
    }




    static if(!is(typeof(EBADR))) {
        private enum enumMixinStr_EBADR = `enum EBADR = 53;`;
        static if(is(typeof({ mixin(enumMixinStr_EBADR); }))) {
            mixin(enumMixinStr_EBADR);
        }
    }




    static if(!is(typeof(EBADE))) {
        private enum enumMixinStr_EBADE = `enum EBADE = 52;`;
        static if(is(typeof({ mixin(enumMixinStr_EBADE); }))) {
            mixin(enumMixinStr_EBADE);
        }
    }




    static if(!is(typeof(EL2HLT))) {
        private enum enumMixinStr_EL2HLT = `enum EL2HLT = 51;`;
        static if(is(typeof({ mixin(enumMixinStr_EL2HLT); }))) {
            mixin(enumMixinStr_EL2HLT);
        }
    }




    static if(!is(typeof(ENOCSI))) {
        private enum enumMixinStr_ENOCSI = `enum ENOCSI = 50;`;
        static if(is(typeof({ mixin(enumMixinStr_ENOCSI); }))) {
            mixin(enumMixinStr_ENOCSI);
        }
    }




    static if(!is(typeof(EUNATCH))) {
        private enum enumMixinStr_EUNATCH = `enum EUNATCH = 49;`;
        static if(is(typeof({ mixin(enumMixinStr_EUNATCH); }))) {
            mixin(enumMixinStr_EUNATCH);
        }
    }




    static if(!is(typeof(ELNRNG))) {
        private enum enumMixinStr_ELNRNG = `enum ELNRNG = 48;`;
        static if(is(typeof({ mixin(enumMixinStr_ELNRNG); }))) {
            mixin(enumMixinStr_ELNRNG);
        }
    }




    static if(!is(typeof(EL3RST))) {
        private enum enumMixinStr_EL3RST = `enum EL3RST = 47;`;
        static if(is(typeof({ mixin(enumMixinStr_EL3RST); }))) {
            mixin(enumMixinStr_EL3RST);
        }
    }




    static if(!is(typeof(EL3HLT))) {
        private enum enumMixinStr_EL3HLT = `enum EL3HLT = 46;`;
        static if(is(typeof({ mixin(enumMixinStr_EL3HLT); }))) {
            mixin(enumMixinStr_EL3HLT);
        }
    }




    static if(!is(typeof(EL2NSYNC))) {
        private enum enumMixinStr_EL2NSYNC = `enum EL2NSYNC = 45;`;
        static if(is(typeof({ mixin(enumMixinStr_EL2NSYNC); }))) {
            mixin(enumMixinStr_EL2NSYNC);
        }
    }




    static if(!is(typeof(ECHRNG))) {
        private enum enumMixinStr_ECHRNG = `enum ECHRNG = 44;`;
        static if(is(typeof({ mixin(enumMixinStr_ECHRNG); }))) {
            mixin(enumMixinStr_ECHRNG);
        }
    }




    static if(!is(typeof(EIDRM))) {
        private enum enumMixinStr_EIDRM = `enum EIDRM = 43;`;
        static if(is(typeof({ mixin(enumMixinStr_EIDRM); }))) {
            mixin(enumMixinStr_EIDRM);
        }
    }




    static if(!is(typeof(ENOMSG))) {
        private enum enumMixinStr_ENOMSG = `enum ENOMSG = 42;`;
        static if(is(typeof({ mixin(enumMixinStr_ENOMSG); }))) {
            mixin(enumMixinStr_ENOMSG);
        }
    }




    static if(!is(typeof(EWOULDBLOCK))) {
        private enum enumMixinStr_EWOULDBLOCK = `enum EWOULDBLOCK = EAGAIN;`;
        static if(is(typeof({ mixin(enumMixinStr_EWOULDBLOCK); }))) {
            mixin(enumMixinStr_EWOULDBLOCK);
        }
    }




    static if(!is(typeof(ELOOP))) {
        private enum enumMixinStr_ELOOP = `enum ELOOP = 40;`;
        static if(is(typeof({ mixin(enumMixinStr_ELOOP); }))) {
            mixin(enumMixinStr_ELOOP);
        }
    }




    static if(!is(typeof(ENOTEMPTY))) {
        private enum enumMixinStr_ENOTEMPTY = `enum ENOTEMPTY = 39;`;
        static if(is(typeof({ mixin(enumMixinStr_ENOTEMPTY); }))) {
            mixin(enumMixinStr_ENOTEMPTY);
        }
    }




    static if(!is(typeof(ENOSYS))) {
        private enum enumMixinStr_ENOSYS = `enum ENOSYS = 38;`;
        static if(is(typeof({ mixin(enumMixinStr_ENOSYS); }))) {
            mixin(enumMixinStr_ENOSYS);
        }
    }




    static if(!is(typeof(ENOLCK))) {
        private enum enumMixinStr_ENOLCK = `enum ENOLCK = 37;`;
        static if(is(typeof({ mixin(enumMixinStr_ENOLCK); }))) {
            mixin(enumMixinStr_ENOLCK);
        }
    }




    static if(!is(typeof(ENAMETOOLONG))) {
        private enum enumMixinStr_ENAMETOOLONG = `enum ENAMETOOLONG = 36;`;
        static if(is(typeof({ mixin(enumMixinStr_ENAMETOOLONG); }))) {
            mixin(enumMixinStr_ENAMETOOLONG);
        }
    }




    static if(!is(typeof(EDEADLK))) {
        private enum enumMixinStr_EDEADLK = `enum EDEADLK = 35;`;
        static if(is(typeof({ mixin(enumMixinStr_EDEADLK); }))) {
            mixin(enumMixinStr_EDEADLK);
        }
    }






    static if(!is(typeof(ERANGE))) {
        private enum enumMixinStr_ERANGE = `enum ERANGE = 34;`;
        static if(is(typeof({ mixin(enumMixinStr_ERANGE); }))) {
            mixin(enumMixinStr_ERANGE);
        }
    }




    static if(!is(typeof(EDOM))) {
        private enum enumMixinStr_EDOM = `enum EDOM = 33;`;
        static if(is(typeof({ mixin(enumMixinStr_EDOM); }))) {
            mixin(enumMixinStr_EDOM);
        }
    }




    static if(!is(typeof(EPIPE))) {
        private enum enumMixinStr_EPIPE = `enum EPIPE = 32;`;
        static if(is(typeof({ mixin(enumMixinStr_EPIPE); }))) {
            mixin(enumMixinStr_EPIPE);
        }
    }




    static if(!is(typeof(EMLINK))) {
        private enum enumMixinStr_EMLINK = `enum EMLINK = 31;`;
        static if(is(typeof({ mixin(enumMixinStr_EMLINK); }))) {
            mixin(enumMixinStr_EMLINK);
        }
    }




    static if(!is(typeof(EROFS))) {
        private enum enumMixinStr_EROFS = `enum EROFS = 30;`;
        static if(is(typeof({ mixin(enumMixinStr_EROFS); }))) {
            mixin(enumMixinStr_EROFS);
        }
    }




    static if(!is(typeof(ESPIPE))) {
        private enum enumMixinStr_ESPIPE = `enum ESPIPE = 29;`;
        static if(is(typeof({ mixin(enumMixinStr_ESPIPE); }))) {
            mixin(enumMixinStr_ESPIPE);
        }
    }




    static if(!is(typeof(ENOSPC))) {
        private enum enumMixinStr_ENOSPC = `enum ENOSPC = 28;`;
        static if(is(typeof({ mixin(enumMixinStr_ENOSPC); }))) {
            mixin(enumMixinStr_ENOSPC);
        }
    }




    static if(!is(typeof(EFBIG))) {
        private enum enumMixinStr_EFBIG = `enum EFBIG = 27;`;
        static if(is(typeof({ mixin(enumMixinStr_EFBIG); }))) {
            mixin(enumMixinStr_EFBIG);
        }
    }




    static if(!is(typeof(ETXTBSY))) {
        private enum enumMixinStr_ETXTBSY = `enum ETXTBSY = 26;`;
        static if(is(typeof({ mixin(enumMixinStr_ETXTBSY); }))) {
            mixin(enumMixinStr_ETXTBSY);
        }
    }




    static if(!is(typeof(ENOTTY))) {
        private enum enumMixinStr_ENOTTY = `enum ENOTTY = 25;`;
        static if(is(typeof({ mixin(enumMixinStr_ENOTTY); }))) {
            mixin(enumMixinStr_ENOTTY);
        }
    }




    static if(!is(typeof(EMFILE))) {
        private enum enumMixinStr_EMFILE = `enum EMFILE = 24;`;
        static if(is(typeof({ mixin(enumMixinStr_EMFILE); }))) {
            mixin(enumMixinStr_EMFILE);
        }
    }




    static if(!is(typeof(ENFILE))) {
        private enum enumMixinStr_ENFILE = `enum ENFILE = 23;`;
        static if(is(typeof({ mixin(enumMixinStr_ENFILE); }))) {
            mixin(enumMixinStr_ENFILE);
        }
    }




    static if(!is(typeof(EINVAL))) {
        private enum enumMixinStr_EINVAL = `enum EINVAL = 22;`;
        static if(is(typeof({ mixin(enumMixinStr_EINVAL); }))) {
            mixin(enumMixinStr_EINVAL);
        }
    }




    static if(!is(typeof(EISDIR))) {
        private enum enumMixinStr_EISDIR = `enum EISDIR = 21;`;
        static if(is(typeof({ mixin(enumMixinStr_EISDIR); }))) {
            mixin(enumMixinStr_EISDIR);
        }
    }




    static if(!is(typeof(ENOTDIR))) {
        private enum enumMixinStr_ENOTDIR = `enum ENOTDIR = 20;`;
        static if(is(typeof({ mixin(enumMixinStr_ENOTDIR); }))) {
            mixin(enumMixinStr_ENOTDIR);
        }
    }




    static if(!is(typeof(ENODEV))) {
        private enum enumMixinStr_ENODEV = `enum ENODEV = 19;`;
        static if(is(typeof({ mixin(enumMixinStr_ENODEV); }))) {
            mixin(enumMixinStr_ENODEV);
        }
    }




    static if(!is(typeof(EXDEV))) {
        private enum enumMixinStr_EXDEV = `enum EXDEV = 18;`;
        static if(is(typeof({ mixin(enumMixinStr_EXDEV); }))) {
            mixin(enumMixinStr_EXDEV);
        }
    }




    static if(!is(typeof(EEXIST))) {
        private enum enumMixinStr_EEXIST = `enum EEXIST = 17;`;
        static if(is(typeof({ mixin(enumMixinStr_EEXIST); }))) {
            mixin(enumMixinStr_EEXIST);
        }
    }




    static if(!is(typeof(EBUSY))) {
        private enum enumMixinStr_EBUSY = `enum EBUSY = 16;`;
        static if(is(typeof({ mixin(enumMixinStr_EBUSY); }))) {
            mixin(enumMixinStr_EBUSY);
        }
    }




    static if(!is(typeof(ENOTBLK))) {
        private enum enumMixinStr_ENOTBLK = `enum ENOTBLK = 15;`;
        static if(is(typeof({ mixin(enumMixinStr_ENOTBLK); }))) {
            mixin(enumMixinStr_ENOTBLK);
        }
    }




    static if(!is(typeof(EFAULT))) {
        private enum enumMixinStr_EFAULT = `enum EFAULT = 14;`;
        static if(is(typeof({ mixin(enumMixinStr_EFAULT); }))) {
            mixin(enumMixinStr_EFAULT);
        }
    }




    static if(!is(typeof(EACCES))) {
        private enum enumMixinStr_EACCES = `enum EACCES = 13;`;
        static if(is(typeof({ mixin(enumMixinStr_EACCES); }))) {
            mixin(enumMixinStr_EACCES);
        }
    }




    static if(!is(typeof(ENOMEM))) {
        private enum enumMixinStr_ENOMEM = `enum ENOMEM = 12;`;
        static if(is(typeof({ mixin(enumMixinStr_ENOMEM); }))) {
            mixin(enumMixinStr_ENOMEM);
        }
    }




    static if(!is(typeof(EAGAIN))) {
        private enum enumMixinStr_EAGAIN = `enum EAGAIN = 11;`;
        static if(is(typeof({ mixin(enumMixinStr_EAGAIN); }))) {
            mixin(enumMixinStr_EAGAIN);
        }
    }




    static if(!is(typeof(ECHILD))) {
        private enum enumMixinStr_ECHILD = `enum ECHILD = 10;`;
        static if(is(typeof({ mixin(enumMixinStr_ECHILD); }))) {
            mixin(enumMixinStr_ECHILD);
        }
    }




    static if(!is(typeof(EBADF))) {
        private enum enumMixinStr_EBADF = `enum EBADF = 9;`;
        static if(is(typeof({ mixin(enumMixinStr_EBADF); }))) {
            mixin(enumMixinStr_EBADF);
        }
    }




    static if(!is(typeof(ENOEXEC))) {
        private enum enumMixinStr_ENOEXEC = `enum ENOEXEC = 8;`;
        static if(is(typeof({ mixin(enumMixinStr_ENOEXEC); }))) {
            mixin(enumMixinStr_ENOEXEC);
        }
    }




    static if(!is(typeof(E2BIG))) {
        private enum enumMixinStr_E2BIG = `enum E2BIG = 7;`;
        static if(is(typeof({ mixin(enumMixinStr_E2BIG); }))) {
            mixin(enumMixinStr_E2BIG);
        }
    }




    static if(!is(typeof(ENXIO))) {
        private enum enumMixinStr_ENXIO = `enum ENXIO = 6;`;
        static if(is(typeof({ mixin(enumMixinStr_ENXIO); }))) {
            mixin(enumMixinStr_ENXIO);
        }
    }




    static if(!is(typeof(EIO))) {
        private enum enumMixinStr_EIO = `enum EIO = 5;`;
        static if(is(typeof({ mixin(enumMixinStr_EIO); }))) {
            mixin(enumMixinStr_EIO);
        }
    }




    static if(!is(typeof(EINTR))) {
        private enum enumMixinStr_EINTR = `enum EINTR = 4;`;
        static if(is(typeof({ mixin(enumMixinStr_EINTR); }))) {
            mixin(enumMixinStr_EINTR);
        }
    }




    static if(!is(typeof(ESRCH))) {
        private enum enumMixinStr_ESRCH = `enum ESRCH = 3;`;
        static if(is(typeof({ mixin(enumMixinStr_ESRCH); }))) {
            mixin(enumMixinStr_ESRCH);
        }
    }




    static if(!is(typeof(ENOENT))) {
        private enum enumMixinStr_ENOENT = `enum ENOENT = 2;`;
        static if(is(typeof({ mixin(enumMixinStr_ENOENT); }))) {
            mixin(enumMixinStr_ENOENT);
        }
    }




    static if(!is(typeof(EPERM))) {
        private enum enumMixinStr_EPERM = `enum EPERM = 1;`;
        static if(is(typeof({ mixin(enumMixinStr_EPERM); }))) {
            mixin(enumMixinStr_EPERM);
        }
    }
    static if(!is(typeof(_ARPA_INET_H))) {
        private enum enumMixinStr__ARPA_INET_H = `enum _ARPA_INET_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__ARPA_INET_H); }))) {
            mixin(enumMixinStr__ARPA_INET_H);
        }
    }






    static if(!is(typeof(_ALLOCA_H))) {
        private enum enumMixinStr__ALLOCA_H = `enum _ALLOCA_H = 1;`;
        static if(is(typeof({ mixin(enumMixinStr__ALLOCA_H); }))) {
            mixin(enumMixinStr__ALLOCA_H);
        }
    }
    static if(!is(typeof(UDP_FRAME_MAX))) {
        private enum enumMixinStr_UDP_FRAME_MAX = `enum UDP_FRAME_MAX = 255;`;
        static if(is(typeof({ mixin(enumMixinStr_UDP_FRAME_MAX); }))) {
            mixin(enumMixinStr_UDP_FRAME_MAX);
        }
    }






    static if(!is(typeof(ZUUID_LEN))) {
        private enum enumMixinStr_ZUUID_LEN = `enum ZUUID_LEN = 16;`;
        static if(is(typeof({ mixin(enumMixinStr_ZUUID_LEN); }))) {
            mixin(enumMixinStr_ZUUID_LEN);
        }
    }




    static if(!is(typeof(ZUUID_STR_LEN))) {
        private enum enumMixinStr_ZUUID_STR_LEN = `enum ZUUID_STR_LEN = ( 16 * 2 );`;
        static if(is(typeof({ mixin(enumMixinStr_ZUUID_STR_LEN); }))) {
            mixin(enumMixinStr_ZUUID_STR_LEN);
        }
    }

}


struct __va_list_tag;
