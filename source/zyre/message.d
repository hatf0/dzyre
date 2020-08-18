module zyre.message;
import zyre.generated;
import zyre.resource;
import zyre.logger;
import std.experimental.allocator : theAllocator, make, dispose;

class ZyreMessage(bool owner) {
    private {
        SharedResource _msg;
    }

    @property inout(zmsg_t)** handle() inout @trusted pure nothrow {
        return cast(typeof(return)) _msg.handle;

    }
    @property inout(zmsg_t)* unsafeHandle() inout @trusted pure nothrow {
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

    @property int signal() in {
        assert(valid, "should be valid");
    } do {
        return zmsg_signal(unsafeHandle);
    }

    @property size_t length() in {
        assert(valid, "should be valid");
    } do {
        return zmsg_size(unsafeHandle);
    }

    @property size_t contentLength() in {
        assert(valid, "should be valid");
    } do {
        return zmsg_content_size(unsafeHandle);
    }

    ZyreMessage dup() in {
        assert(valid, "should be valid");
    } do {
        zmsg_t* msg = zmsg_dup(unsafeHandle);
        if (msg == null) {
            throw new Exception("failed to duplicate");
        }
        return theAllocator.make!(ZyreMessage)(msg);
    }

    void print() in {
        assert(valid, "should be valid");
    } do {
        zmsg_print(unsafeHandle);
    }

    // Ownership is toggleable (i.e ZyreMessage!(false)(msg); )
    this(zmsg_t* msg) {
        assert(msg != null, "message should not be null");
        assert(zmsg_is(msg), "should look like a message");
        static Exception release(shared(void)* ptr) @trusted nothrow {
            zmsg_t** n = cast(zmsg_t**)ptr;
            if (n == null) {
                return new Exception("did not expect safe pointer to be freed");
            }
            static if (owner) {
                zmsg_destroy(n);
            }
            theAllocator.dispose(n);
            return null;
        }

        zmsg_t** safePtr = theAllocator.make!(zmsg_t*)();
        assert(safePtr != null, "memory allocation failed");
        *safePtr = msg;
        _msg = SharedResource(cast(shared)safePtr, &release);
    }

    import std.stdio : File;
    this(File f) {
        zmsg_t* msg = zmsg_load(cast(FILE*)f.getFP());

        if (msg == null) {
            throw new Exception("could not read message");
        }
        this(msg);
    }

    this(string path) {
        // load
        import std.path : buildNormalizedPath, expandTilde;
        File f = File(path.expandTilde.buildNormalizedPath); 
        this(f);
        f.close();
    }

    this(zframe_t* frame) {
        zmsg_t* msg = zmsg_decode(frame);
        if (msg == null) {
            throw new Exception("could not decode message");
        }
        this(msg);
    }

    this() {
        this(zmsg_new());
    }
}

