module zyre.group;
import zyre.generated;
import zyre.resource;
import zyre.logger;
import zyre.list;
import zyre.node : ZyreNode;
import std.string : toStringz;

class ZyreGroup {
    private {
        ZyreNode _node;
        string _name;
        bool _joined;
    }

    @property ZyreList peers() in {
        assert(_node.valid, "node should be valid");
        assert(_joined, "should be joined to a group"); 
    } do {
        ZyreList l = theAllocator.make!ZyreList(zyre_peers_by_group(_node.unsafeHandle, _name.toStringz));
        return l;
    }

    @property string name() {
        return _name;
    }

    this(ZyreNode zyreNode, string group_name) {
        _node = zyreNode;
        _name = group_name;

        assert(zyreNode.valid, "node must be valid before joining a group");

        if (zyre_join(_node.unsafeHandle, group_name.toStringz) != 0) {
            throw new Exception("could not join zyre group");
        }
        _joined = true;
    }

    ~this() {
        if (_joined) {
            DEBUG!"group (name: %s) going away"(_name);
            assert(_node.valid, "node should've stayed valid?");

            if (zyre_leave(_node.unsafeHandle, name.toStringz) != 0) {
                throw new Exception("could not leave joined zyre group?");
            }
        }
    }
}

