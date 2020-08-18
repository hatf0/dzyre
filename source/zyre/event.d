module zyre.event;
import zyre.generated;
import zyre.resource;
import zyre.logger;
import zyre.message;
import zyre.node : ZyreNode;
import std.string : fromStringz;

enum EventType : const(char)[] {
    ENTER = "ENTER",
    EXIT = "EXIT",
    JOIN = "JOIN",
    LEAVE = "LEAVE",
    EVASIVE = "EVASIVE",
    WHISPER = "WHISPER",
    SHOUT = "SHOUT",
    SILENT = "SILENT",
    STOP = "STOP",
    INVALID = "INVALID"
}

class ZyreEvent {
    private {
        SharedResource _event;
        ZyreNode _node;
        EventType _evtType;
    }

    @property inout(zyre_event_t)** handle() inout @trusted pure nothrow {
        return cast(typeof(return)) _event.handle;
    }

    @property inout(zyre_event_t)* unsafeHandle() inout @trusted pure nothrow {
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

    @property EventType type() {
        return _evtType;
    }

    @property string peerName() in {
        assert(valid, "must be valid");
    } do {
        return zyre_event_peer_name(unsafeHandle).fromStringz.idup;
    }

    @property string peerId() in {
        assert(valid, "must be valid");
    } do {
        return zyre_event_peer_uuid(unsafeHandle).fromStringz.idup;
    }

    @property string peerAddr() in {
        assert(valid, "must be valid");
    } do {
        return zyre_event_peer_addr(unsafeHandle).fromStringz.idup;
    }

    @property void* headers() in {
        assert(valid, "must be valid");
    } do {
        assert(0, "stub");
    }

    @property string group() in {
        assert(valid, "must be valid");
    } do {
        assert(0, "stub");
    }

    @property ZyreMessage!(false) messageNoCopy() in {
        assert(valid, "must be valid");
    } do {
        zmsg_t* msg = zyre_event_msg(unsafeHandle);
        assert(msg != null, "message should not be null");

        ZyreMessage!(false) m = theAllocator.make!(ZyreMessage!(false))(msg);
        return m;
    }

    @property ZyreMessage!(true) message() in {
        assert(valid, "must be valid");
    } do {
        zmsg_t* msg = zyre_event_get_msg(unsafeHandle);
        assert(msg != null, "message should not be null");

        ZyreMessage!(true) m = theAllocator.make!(ZyreMessage!(true))(msg);
        return m;
    }

    void print() in {
        assert(valid, "must be valid");
    } do {
        zyre_event_print(unsafeHandle);
    }

    this(ZyreNode node, zyre_event_t* evt) {
        assert(evt != null, "event should not be null");
        _node = node;

        static Exception release(shared(void)* ptr) @trusted nothrow {
            zyre_event_t** n = cast(zyre_event_t**)ptr;
            if (n == null) {
                return new Exception("did not expect safe pointer to be freed");
            }
            zyre_event_destroy(n);
            theAllocator.dispose(n);
            return null;
        }

        zyre_event_t** safePtr = theAllocator.make!(zyre_event_t*)();
        assert(safePtr != null, "memory allocation failed");
        *safePtr = evt;
        _event = SharedResource(cast(shared)safePtr, &release);

        import std.traits : EnumMembers;
        const(char)[] etype = zyre_event_type(evt).fromStringz;
        switch (etype) {
            static foreach(i, member; EnumMembers!(EventType)) {
                case member:
                    _evtType = member;
                    return; // quick break-out
            }

            default:
                _evtType = EventType.INVALID;
        }
    }

    ~this() {
        _event.forceRelease();
    }
}
