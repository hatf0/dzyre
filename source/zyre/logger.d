module zyre.logger;
import zyre.generated;
import std.datetime; 
import std.traits;
import core.thread;

enum Verbosity {
    Debug = 0,
    Info = 1,
    Notice = 2,
    Warning = 3,
    Error = 4,
};

import std.array, std.format;
static shared Logger _zyreLogger;

void INFO(string format, string file = __MODULE__, int line = __LINE__, A...)(lazy A args) @trusted {
    if (_zyreLogger.__minVerbosity <= Verbosity.Info) {
        auto msg = appender!string;
        formattedWrite(msg, format, args);
        _zyreLogger.log(Verbosity.Info, msg.data, file, line);
    }
}

void DEBUG(string format, string file = __MODULE__, int line = __LINE__, A...)(lazy A args) @trusted {
    if (_zyreLogger.__minVerbosity <= Verbosity.Debug) {
        auto msg = appender!string;
        formattedWrite(msg, format, args);
        _zyreLogger.log(Verbosity.Debug, msg.data, file, line);
    }
}

void ERROR(string format, string file = __MODULE__, int line = __LINE__, A...)(lazy A args) @trusted {
    if (_zyreLogger.__minVerbosity <= Verbosity.Error) {
        auto msg = appender!string;
        formattedWrite(msg, format, args);
        _zyreLogger.log(Verbosity.Error, msg.data, file, line);
    }
}

void NOTICE(string format, string file = __MODULE__, int line = __LINE__, A...)(lazy A args) @trusted {
    if (_zyreLogger.__minVerbosity <= Verbosity.Notice) {
        auto msg = appender!string;
        formattedWrite(msg, format, args);
        _zyreLogger.log(Verbosity.Notice, msg.data, file, line);
    }
}

void WARNING(string format, string file = __MODULE__, int line = __LINE__, A...)(lazy A args) @trusted {
    if (_zyreLogger.__minVerbosity <= Verbosity.Warning) {
        auto msg = appender!string;
        formattedWrite(msg, format, args);
        _zyreLogger.log(Verbosity.Warning, msg.data, file, line);
    }
}

class Logger {
    private {
        string _infoPath;
        string _warningPath;
        string _errorPath;
        string _debugPath;
        Verbosity __minVerbosity;
    }

    @property Verbosity minVerbosity() shared {
        return __minVerbosity;
    }

    @property Verbosity minVerbosity(Verbosity _min) shared {
        __minVerbosity = _min;
        return _min;
    }
    
    void log(Verbosity v, string message, string file = __MODULE__, int line = __LINE__) shared {
        import std.stdio;
        import std.conv : to;
        import std.string;
        import std.datetime;
        if (minVerbosity <= v) {
            static foreach(i, lvl; EnumMembers!Verbosity) {
                if (v == lvl) {
                    mixin ("zsys_" ~ __traits(identifier, EnumMembers!Verbosity[i]).toLower() ~ "(\"[%s:%d] %s\", file.toStringz, line, message.toStringz);");
                }
            }
        }
    }

    this(Verbosity _minVerbosity = Verbosity.Info, string info = "", string warning = "", string error = "", string debug_ = "") shared {
        minVerbosity = _minVerbosity;
        _infoPath = info;
        _warningPath = warning;
        _errorPath = error;
        _debugPath = debug_;
    }

    shared static this() {
        zsys_init();
        _zyreLogger = new shared(Logger)();
        import core.exception;
        core.exception.assertHandler = &assertHandler;
    }
    
    shared static ~this() {
        zsys_shutdown();
        destroy(_zyreLogger);
    }
}

import core.stdc.stdlib : abort;
import core.thread;
import core.time;

void assertHandler(string file, ulong line, string message) nothrow {
    try { 
        ERROR!"ASSERT: %s at %s:%d"(message, file, line);
        abort();
    } catch(Exception e) {

    }
}
