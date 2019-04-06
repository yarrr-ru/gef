"""
This script is the server-side of the XML-RPC defined for gef for
BinaryNinja.
It will spawn a threaded XMLRPC server from your current BN session
making it possible for gef to interact with Binary Ninja.

To install this script as a plugin:
$ ln -sf /path/to/gef/binja_gef.py ~/.binaryninja/plugins/binaryninja_gef.py

Then run it from Binary Ninja:
- open a disassembly session
- click "Tools" -> "gef : start/stop server"

If all went well, you will see something like
[+] Creating new thread for XMLRPC server: Thread-1
[+] Starting XMLRPC server: 0.0.0.0:1337
[+] Registered 10 functions.

@_hugsy_
"""

from binaryninja import *

from SimpleXMLRPCServer import SimpleXMLRPCRequestHandler, SimpleXMLRPCServer, list_public_methods
import threading, string, inspect, xmlrpclib, copy

HOST, PORT = "0.0.0.0", 1337
DEBUG = True
HL_NO_COLOR = enums.HighlightStandardColor.NoHighlightColor
HL_BP_COLOR = enums.HighlightStandardColor.RedHighlightColor
HL_CUR_INSN_COLOR = enums.HighlightStandardColor.GreenHighlightColor

_breakpoints = set()
srv = None


PAGE_SZ = 0x1000


def dbg(x):
    if DEBUG:
        log_info("[*] {}".format(x))
    return


def ok(x):
    log_info("[+] {}".format(x))
    return


def expose(f):
    f.exposed = True
    return f


def is_exposed(f):
    return getattr(f, 'exposed', False)


def ishex(s):
    return s.startswith("0x") or s.startswith("0X")


class Gef:
    """
    Top level class where exposed methods are declared.
    """

    def __init__(self, server, bv, *args, **kwargs):
        self.server = server
        self.view = bv
        self.base = self.view.start
        self.text_base = self.view.sections[".text"].start
        self._version = ("Binary Ninja", core_version)
        self.old_bps = set()
        self.runtime_info = {
            "path": "",
            "is_pie": False,
            "pc": 0,
            "page_base": 0,
            "text_base": 0,
        }
        self.pc = 0
        return


    def _dispatch(self, method, params):
        """
        Plugin dispatcher
        """
        func = getattr(self, method)
        if not is_exposed(func):
            raise NotImplementedError('Method "%s" is not exposed' % method)

        dbg("Executing %s%s" % (method, params))
        return func(*params)


    def _listMethods(self):
        """
        Class method listing (required for introspection API).
        """
        m = []
        for x in list_public_methods(self):
            if x.startswith("_"): continue
            if not is_exposed( getattr(self, x) ): continue
            m.append(x)
        return m


    def _methodHelp(self, method):
        """
        Method help (required for introspection API).
        """
        f = getattr(self, method)
        return inspect.getdoc(f)


    def get_va(self, offset, convert_to_int=True):
        if convert_to_int:
            offset = long(offset, 16) if ishex(offset) else long(offset)
        va = offset
        if self.runtime_info["is_pie"]:
            va += self.text_base
        return va


    def get_offset(self, address, convert_to_int=True):
        if convert_to_int:
            address = long(address, 16) if ishex(address) else long(address)
        offset = address
        if self.runtime_info["is_pie"]:
            offset -= self.runtime_info["text_base"] - self.runtime_info["page_base"]
        return address


    @expose
    def shutdown(self):
        """ shutdown() => None
        Cleanly shutdown the XML-RPC service.
        Example: binaryninja-interact shutdown
        """
        self.server.server_close()
        ok("XMLRPC server stopped")
        setattr(self.server, "shutdown", True)
        return

    @expose
    def version(self):
        """ version() => None
        Return a tuple containing the tool used and its version
        Example: binaryninja-interact version
        """
        return self._version

    @expose
    def jump(self, address):
        """ jump(int addr) => None
        Move the EA pointer to the address pointed by `addr`.
        Example: binaryninja-interact jump 0x4049de
        """
        # convert to offset from text base
        off = self.get_offset(address, convert_to_int=True)
        addr = self.get_va(off, convert_to_int=False)
        dbg("set cursor to %#x (+%#x)" % (addr, off))
        return self.view.file.navigate(self.view.file.view, addr)

    @expose
    def makecomm(self, address, comment):
        """ makecomm(int addr, string comment) => None
        Add a comment at the location `address`.
        Example: binaryninja-interact makecomm 0x40000 "Important call here!"
        """
        off = self.get_offset(address)
        addr = self.get_va(off)
        start_addr = self.view.get_previous_function_start_before(addr)
        func = self.view.get_function_at(start_addr)
        return func.set_comment(addr, comment)

    @expose
    def setcolor(self, address, color='0xff0000'):
        """ setcolor(int addr [, int color]) => None
        Set the location pointed by `address` with `color`.
        Example: binaryninja-interact setcolor 0x40000 0xff0000
        """
        off = self.get_offset(address, True)
        addr = self.get_va(off, False)
        color = long(color, 16) if ishex(color) else long(color)
        R,G,B = (color >> 16)&0xff, (color >> 8)&0xff, (color&0xff)
        color = highlight.HighlightColor(red=R, blue=G, green=B)
        return hl(self.view, addr, color)

    @expose
    def collectruntimeinfo(self, _type, _value):
        """ collectprocessinfo(_type, _value) => None
        This is an internal function which is automatically used by GEF.
        Do not use it from the command line.
        """
        if _type == "pc":                     _value = long(_value, 16)
        elif _type == "page_base":            _value = long(_value, 16)
        elif _type == "text_base":            _value = long(_value, 16)
        dbg("setting runtime_info['{}'] : {}".format(_type, _value))
        self.runtime_info[_type] = _value
        return

    @expose
    def synchronize(self, off, added, removed):
        """ synchronize(off, added, removed) => None
        Synchronize debug info with gef. This is an internal function which is
        automatically used by GEF if ida-interact.sync_cursor setting is True.
        It is not recommended using it from the command line.
        """
        global _breakpoints

        cur_pc = self.pc            # the current value of $PC stored by Binja
        new_pc = self.get_va(off)   # the new value of $PC sent by GDB
        dbg("cur_pc=%#x , new_pc=%#x" % (cur_pc, new_pc))

        # unhighlight the current instruction
        if cur_pc:
            hl(self.view, cur_pc, HL_NO_COLOR)

        # color the new one
        hl(self.view, new_pc, HL_CUR_INSN_COLOR)

        # update the current instruction
        self.pc = new_pc

        dbg("pre-gdb-add-breakpoints: %s" % (added,))
        dbg("pre-gdb-del-breakpoints: %s" % (removed,))
        dbg("pre-binja-breakpoints: %s" % (_breakpoints))

        bp_added = [ x-self.base for x in _breakpoints if x not in self.old_bps ]
        bp_removed = [ x-self.base for x in self.old_bps if x not in _breakpoints ]

        for bp in added:
            gef_add_breakpoint_to_list(self.view, self.get_va(bp))

        for bp in removed:
            gef_del_breakpoint_from_list(self.view, self.get_va(bp))

        self.old_bps = copy.deepcopy(_breakpoints)

        dbg("post-gdb-add-breakpoints: %s" % (bp_added,))
        dbg("post-gdb-del-breakpoints: %s" % (bp_removed,))
        dbg("post-binja-breakpoints: %s" % (_breakpoints,))

        return [bp_added, bp_removed]


class RequestHandler(SimpleXMLRPCRequestHandler):
    rpc_paths = ("/RPC2",)


class GefRpcServer:
    def __init__(self, bv, host="0.0.0.0", port=1337):
        self.bv = bv
        self.host = host
        self.port = port
        self.url = "http://{:s}:{:d}".format(self.host, self.port)
        self.server = SimpleXMLRPCServer(
            (self.host, self.port),
            requestHandler=RequestHandler,
            logRequests=False,
            allow_none=True
        )
        self.serve_forever = self.server.serve_forever
        self.list_methods = self.server.system_listMethods
        self.handle_request = self.server.handle_request
        self.register_instance = self.server.register_instance
        self.register_function = self.server.register_function
        self.register_introspection_functions = self.server.register_introspection_functions
        self.is_running = False
        self.register_introspection_functions()
        self.register_instance(Gef(self, self.bv))
        ok("Registered {} functions.".format( len(self.list_methods()) ))
        return

    def start(self):
        self.service = threading.Thread(target=self.start_service)
        self.service.daemon = True
        self.service.start()
        self.is_running = True
        return

    def start_service(self):
        ok("Starting service on {}:{}".format(self.host, self.port))
        while True:
            if hasattr(self, "shutdown") and self.shutdown==True:
                ok("Stopping service")
                break
            self.handle_request()
        return

    def stop(self):
        self.service.join()
        self.service = None
        self.is_running = False
        ok("Server stopped")
        return


class GefRpcClient:
    def __init__(self, url):
        self._xmlrpc_server_proxy = xmlrpclib.ServerProxy(url)
        return

    def __getattr__(self, name):
        return getattr(self._xmlrpc_server_proxy, name)


def hl(bv, addr, color):
    start_addr = bv.get_previous_function_start_before(addr)
    func = bv.get_function_at(start_addr)
    if func is None: return
    func.set_user_instr_highlight(addr, color)
    return


def gef_start_stop(bv):
    global srv

    if srv is None:
        srv = GefRpcServer(bv, HOST, PORT)
        srv.start()

        if srv.is_running:
            create_binja_menu()

        show_message_box(
            "GEF",
            "Service successfully started, you can set up gef to connect to it",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.InformationIcon
        )
        return

    try:
        if srv.is_running:
            # try to stop gently
            cli = GefRpcClient(srv.url)
            cli.shutdown()
    except socket.error:
        pass

    srv.stop()
    show_message_box(
        "GEF",
        "Service successfully stopped",
        MessageBoxButtonSet.OKButtonSet,
        MessageBoxIcon.InformationIcon
    )
    return


def gef_add_breakpoint_to_list(bv, addr):
    global  _breakpoints
    if addr in _breakpoints: return False
    _breakpoints.add(addr)
    ok("Breakpoint %#x added" % addr)
    hl(bv, addr, HL_BP_COLOR)
    return True


def gef_del_breakpoint_from_list(bv, addr):
    global _breakpoints
    if addr not in _breakpoints: return False
    _breakpoints.discard(addr)
    ok("Breakpoint %#x removed" % addr)
    hl(bv, addr, HL_NO_COLOR)
    return True


def create_binja_menu():
    PluginCommand.register_for_address("[gef] add breakpoint",
                                       "Add a breakpoint in gef at the specified location.",
                                       gef_add_breakpoint_to_list)
    PluginCommand.register_for_address("[gef] delete breakpoint",
                                       "Remove a breakpoint in gef at the specified location.",
                                       gef_del_breakpoint_from_list)
    return


PluginCommand.register("Start/stop server GEF interaction",
                       "Start/stop the XMLRPC server for communicating with gef",
                       gef_start_stop)
