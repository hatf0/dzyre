module zyre.node;
import zyre.generated;
import zyre.resource;
import zyre.logger;
import zyre.group;
import zyre.list;
import zyre.message;
import std.string : fromStringz, toStringz;

public import std.experimental.allocator : theAllocator, make, dispose;
import core.time;

/// An object representing our node on the Zyre network.
/// IMPORTANT: Do not modify the state of the node with the handle! It should be done through the helper functions.
class ZyreNode {
    private {
        SharedResource _node;
        ZyreGroup[string] _groups;
        Duration _evasiveTimeout = 5000.msecs;
        Duration _silentTimeout = 5000.msecs;
        Duration _expiredTimeout = 3000.msecs;
        Duration _interval = 1000.msecs;
        int _port = 5670;
        string _iface = "";
        bool _verbose = false;
        bool _started = false;
    }

    @property inout(zyre_t)** handle() inout @trusted pure nothrow {
        return cast(typeof(return)) _node.handle;

    }

    @property inout(zyre_t)* unsafeHandle() inout @trusted pure nothrow {
        return cast(typeof(return)) *handle;
    }

    @property bool valid() {
        DEBUG!"valid check (%d %d)"(handle != null, unsafeHandle != null);
        if (handle != null) {
            if (unsafeHandle != null) {
                return true;
            }
        }
        return false;
    }

    @property ZyreList peers() in {
        assert(valid, "should be valid");
    } do {
        ZyreList l = theAllocator.make!ZyreList(zyre_peers(unsafeHandle));
        return l;
    }

    @property string uuid() in {
        assert(valid, "should be valid");
    } do {
        const(char)* uuid = zyre_uuid(unsafeHandle);
        return uuid.fromStringz.idup;
    }

    @property string name() in {
        assert(valid, "should be valid");
    } do {
        const(char)* name = zyre_name(unsafeHandle);
        return name.fromStringz.idup;
    }

    @property string name(string name) in {
        assert(valid, "should be valid");
    } do {
        zyre_set_name(unsafeHandle, name.toStringz);
        return name;
    }

    @property zsock_t* socket() in {
        assert(valid, "should be valid");
    } do {
        return zyre_socket(unsafeHandle);
    }

    extern(C) void setHeader(string name, string format, ...) in {
        assert(valid, "should be valid");
    } do {
        import core.stdc.stdarg;
        va_list args;
        va_start(args, format);
        zyre_set_header(unsafeHandle, name.toStringz, format.toStringz, args);
        va_end(args);
    }

    bool start() in {
        assert(valid, "should be valid");
    } do {
        int status = zyre_start(unsafeHandle);
        if (status == 0) {
            _started = true;
        }
        return _started;
    }

    void stop() in {
        assert(valid, "should be valid");
        assert(_started, "should have started");
    } do {
        zyre_stop(unsafeHandle);
    }

    void print() in {
        assert(valid, "should be valid");
    } do {
        zyre_print(unsafeHandle);
    }

    @property ZyreGroup[string] joinedGroups() in {
        assert(valid, "should be valid");
    } do {
        return _groups;
    }

    ZyreGroup joinGroup(string name) {
        ZyreGroup g = theAllocator.make!ZyreGroup(this, name);
        _groups[name] = g;
        return g;
    }

    ZyreList getKnownGroups() in {
        assert(valid, "should be valid");
    } do {
        ZyreList l = theAllocator.make!(ZyreList)(zyre_peer_groups(unsafeHandle));
        return l;
    }

    ZyreList getPeersInGroup(string name) in {
        assert(valid, "should be valid");
    } do {
        ZyreList l = theAllocator.make!(ZyreList)(zyre_peers_by_group(unsafeHandle, name.toStringz));
        return l;
    }

    ZyreMessage!(true) recv() in {
        assert(valid, "should be valid");
    } do {
        zmsg_t* msg = zyre_recv(unsafeHandle);
        if (msg == null) {
            throw new Exception("interrupted");
        }
        ZyreMessage!(true) m = theAllocator.make!(ZyreMessage!(true))(msg);
        return m;
    }

    import zyre.event;
    ZyreEvent recvEvent() in {
        assert(valid, "should be valid");
    } do {
        zyre_event_t* evt = zyre_event_new(unsafeHandle);
        if (evt == null) {
            throw new Exception("interrupted");
        }
        ZyreEvent e = theAllocator.make!(ZyreEvent)(this, evt);
        return e;
    }

    import core.stdc.stdarg;
    int whisper(string peer, ZyreMessage!(true) msg) in {
        assert(valid, "should be valid");
        assert(msg.valid, "message should be valid");
    } do {
        return zyre_whisper(unsafeHandle, peer.toStringz, msg.handle);
    }

    extern(C) int whisper(string peer, string format, ...) in {
        assert(valid, "should be valid");
    } do {
        va_list args;
        va_start(args, format);
        int status = zyre_whispers(unsafeHandle, peer.toStringz, format.toStringz, args);
        va_end(args);

        return status;

    }

    int shout(string group, ZyreMessage!(true) msg) in {
        assert(valid, "should be valid");
        assert(msg.valid, "message should be valid");
    } do {
        return zyre_shout(unsafeHandle, group.toStringz, msg.handle);
    }

    extern(C) int shout(string group, string format, ...) in {
        assert(valid, "should be valid");
    } do {
        va_list args;
        va_start(args, format);
        int status = zyre_shouts(unsafeHandle, group.toStringz, format.toStringz, args);
        va_end(args);

        return status;

    }

    /// Factory functions that use the custom allocator
    static ZyreNode withName(string name) {
        ZyreNode n = theAllocator.make!ZyreNode(name);
        return n;
    }

    static ZyreNode withUUID() {
        ZyreNode n = theAllocator.make!ZyreNode("");
        return n;
    }

    this(string name) {
        static Exception release(shared(void)* ptr) @trusted nothrow {
            zyre_t** n = cast(zyre_t**)ptr;
            if (n == null) {
                return new Exception("did not expect safe pointer to be freed");
            }
            if (*n != null) {
                zyre_stop(*n);
            }
            zyre_destroy(n);
            theAllocator.dispose(n);
            return null;
        }
        DEBUG!"initializing new node (name: %s)"(name);
        zyre_t** safePtr = theAllocator.make!(zyre_t*)();
        assert(safePtr != null, "allocation failed");
        import std.string;
        if (name.length == 0) {
            *safePtr = zyre_new(null);
        } else { 
            *safePtr = zyre_new(name.toStringz);
        }
        assert(*safePtr != null, "initialization failed");
        _node = SharedResource(cast(shared)safePtr, &release);
    }

    ~this() {
        DEBUG!"release!";
        foreach(g; _groups) {
            DEBUG!"releasing group %s"(g.name);
            theAllocator.dispose(g);
        }

        _node.forceRelease();
    }
}
