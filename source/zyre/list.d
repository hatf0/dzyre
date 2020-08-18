module zyre.list;
import zyre.generated;
import zyre.resource;
import zyre.logger;
import std.experimental.allocator : theAllocator, make, dispose;

// lifetime of a zlist_t object is handled by this
class ZyreList {
    private {
        SharedResource _list;
    }

    @property inout(zlist_t)** handle() inout @trusted pure nothrow {
        return cast(typeof(return)) _list.handle;

    }
    @property inout(zlist_t)* unsafeHandle() inout @trusted pure nothrow {
        return cast(typeof(return)) *handle;
    }

    @property bool valid() const {
        DEBUG!"valid check (%d %d)"(handle != null, unsafeHandle != null);
        if (handle != null) {
            if (unsafeHandle != null) {
                return true;
            }
        }
        return false;
    }

    @property size_t size() const in {
        assert(valid, "list should be valid");
    } do {
        return zlist_size(cast(zlist_t*)unsafeHandle);
    }

    ZyreList dup() in {
        assert(valid, "list should be valid");
    } do {
        ZyreList t = theAllocator.make!(ZyreList)(zlist_dup(unsafeHandle));
        return t;
    }

    void purge() in {
        assert(valid, "list should be valid");
    } do {
        zlist_purge(unsafeHandle);
    }

    bool push(void* ptr) in {
        assert(valid, "list should be valid");
    } do {
        if (zlist_push(unsafeHandle, ptr) == 0) {
            return true;
        }
        return false;
    }

    void remove(void* ptr) in {
        assert(valid, "list should be valid");
    } do {
        zlist_remove(unsafeHandle, ptr);
    }

    // alias for pop to enable foreach
    void* popFront() {
        return pop();
    }

    void* front() {
        return first();
    }

    // helper function
    bool empty() const { 
        return size == 0;
    }

    // first, last, next, head, tail, item, pop all have the same exact signature
    // avoid writing them out (smh, boilerplate), define them in one go
    static foreach(listMethod; ["first", "last", "next", "head", "tail", "item", "pop"]) {
        mixin("void* " ~ listMethod ~ "() in { 
                assert(valid, \"list should be valid\"); 
              } do {
                return zlist_" ~ listMethod ~ "(unsafeHandle);
              }");
    }

    this(zlist_t* list) {
        assert(list != null, "list should not be null");

        static Exception release(shared(void)* ptr) @trusted nothrow {
            zlist_t** p = cast(zlist_t**)ptr;
            assert(p != null, "our managed pointer should never null");
            // ideally, this would never happen because we should manage the entire lifecycle of the list
            assert(*p != null, "list lifetime should be managed by us");
            zlist_destroy(p);
            theAllocator.dispose(p);
            return null;
        }

        zlist_t** _p = theAllocator.make!(zlist_t*)(); 
        assert(_p != null, "allocation failed");
        *_p = list; 
        _list = SharedResource(cast(shared)_p, &release);
    }

    this() {
        zlist_t* l = zlist_new();
        this(l);
    }

    ~this() {
        DEBUG!"list release";
        _list.forceRelease();
    }
}


