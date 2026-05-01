# -*- coding: utf-8 -*-
"""
IDA Runtime / Live Coverage support for Lighthouse.

This module records coverage from IDA Debugger trace events and feeds them
into a normal Lighthouse coverage set named "Runtime Live".

Intended workflow:
  1. Break at main / function / interesting address.
  2. Start Live BB Coverage.
  3. Run / step / hit breakpoint.
  4. Lighthouse updates "Runtime Live".
  5. Snapshot it as input_A / input_B / etc.

Notes:
  - IDA UI normally won't repaint while the debuggee is freely running.
    This means "live" is best understood as:
      * updated on breakpoints / suspend / step events
      * updated when you click Stop / Flush
  - For truly streaming coverage while the process keeps running, implement
    a DynamoRIO client + IPC later.
"""

from __future__ import print_function

import os
import json
import time
import logging
import traceback
import collections

import idaapi
import ida_dbg
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_segment
import ida_name

try:
    import ida_bytes
except Exception:
    ida_bytes = None

from lighthouse.util import lmsg
from lighthouse.util.qt import await_future
from lighthouse.util.disassembler import disassembler
from lighthouse.metadata import metadata_progress

logger = logging.getLogger("Lighthouse.IDA.LiveCoverage")


LIVE_COVERAGE_NAME = "Runtime Live"


#------------------------------------------------------------------------------
# Small helpers
#------------------------------------------------------------------------------

def _badaddr():
    return getattr(ida_idaapi, "BADADDR", idaapi.BADADDR)


def _now_tag():
    return time.strftime("%Y%m%d_%H%M%S")


def _safe_hex(ea):
    try:
        return "0x%X" % int(ea)
    except Exception:
        return str(ea)


def _get_func_name(ea):
    f = ida_funcs.get_func(ea)
    if not f:
        return "UNKNOWN_%X" % ea

    try:
        name = ida_funcs.get_func_name(f.start_ea)
    except Exception:
        name = None

    return name or ("sub_%X" % f.start_ea)


def _seg_name(ea):
    seg = ida_segment.getseg(ea)
    if not seg:
        return ""
    try:
        return ida_segment.get_segm_name(seg) or ""
    except Exception:
        return ""


def _parse_ea(text):
    """
    Parse an address or symbol name from user input.

    Accepts:
      401000
      0x401000
      sub_401000
      main
    """
    if text is None:
        return _badaddr()

    text = str(text).strip()
    if not text:
        return _badaddr()

    # Try symbol / name first.
    ea = ida_name.get_name_ea(_badaddr(), text)
    if ea != _badaddr():
        return ea

    # Try numeric address.
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text, 16)
    except Exception:
        return _badaddr()


def _get_screen_function_range():
    ea = ida_kernwin.get_screen_ea()
    f = ida_funcs.get_func(ea)
    if not f:
        return None
    return (f.start_ea, f.end_ea)


def _option(name, default=0):
    return getattr(ida_dbg, name, default)


#------------------------------------------------------------------------------
# IDA action handler
#------------------------------------------------------------------------------

class _ActionHandler(idaapi.action_handler_t):
    def __init__(self, callback):
        idaapi.action_handler_t.__init__(self)
        self._callback = callback

    def activate(self, ctx):
        try:
            self._callback()
        except Exception:
            text = traceback.format_exc()
            logger.error(text)
            lmsg("[LiveCoverage] action failed:\n%s" % text)
            ida_kernwin.warning("Live Coverage action failed.\n\n%s" % text)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


#------------------------------------------------------------------------------
# Debugger hooks
#------------------------------------------------------------------------------

class _LiveCoverageDbgHooks(ida_dbg.DBG_Hooks):
    def __init__(self, controller):
        ida_dbg.DBG_Hooks.__init__(self)
        self.controller = controller

    def dbg_trace(self, tid, ip):
        """
        Called for step trace. IDA docs say returning 0 logs the trace event;
        returning 1 suppresses it.

        Keep this callback cheap. Do not refresh Lighthouse UI here.
        """
        try:
            self.controller.record_ea(ip, tid=tid, source="dbg_trace")
        except Exception:
            self.controller.remember_error("dbg_trace", traceback.format_exc())

        return 0

    def dbg_bpt(self, tid, bptea):
        try:
            self.controller.poll_trace_buffer(reason="breakpoint")
            self.controller.flush(force=True, reason="breakpoint")
        except Exception:
            self.controller.remember_error("dbg_bpt", traceback.format_exc())

        return 0

    def dbg_suspend_process(self):
        try:
            self.controller.poll_trace_buffer(reason="suspend")
            self.controller.flush(force=True, reason="suspend")
        except Exception:
            self.controller.remember_error("dbg_suspend_process", traceback.format_exc())

    def dbg_step_into(self):
        try:
            self.controller.record_current_ip(source="step_into")
            self.controller.poll_trace_buffer(reason="step_into")
            self.controller.flush(force=True, reason="step_into")
        except Exception:
            self.controller.remember_error("dbg_step_into", traceback.format_exc())

    def dbg_step_over(self):
        try:
            self.controller.record_current_ip(source="step_over")
            self.controller.poll_trace_buffer(reason="step_over")
            self.controller.flush(force=True, reason="step_over")
        except Exception:
            self.controller.remember_error("dbg_step_over", traceback.format_exc())

    def dbg_step_until_ret(self):
        try:
            self.controller.record_current_ip(source="step_until_ret")
            self.controller.poll_trace_buffer(reason="step_until_ret")
            self.controller.flush(force=True, reason="step_until_ret")
        except Exception:
            self.controller.remember_error("dbg_step_until_ret", traceback.format_exc())

    def dbg_run_to(self, pid, tid, ea):
        try:
            self.controller.poll_trace_buffer(reason="run_to")
            self.controller.flush(force=True, reason="run_to")
        except Exception:
            self.controller.remember_error("dbg_run_to", traceback.format_exc())

    def dbg_process_exit(self, pid, tid, ea, exit_code):
        try:
            self.controller.poll_trace_buffer(reason="process_exit")
            self.controller.flush(force=True, reason="process_exit")
            self.controller.stop_trace_only()
        except Exception:
            self.controller.remember_error("dbg_process_exit", traceback.format_exc())

    def dbg_process_detach(self, pid, tid, ea):
        try:
            self.controller.poll_trace_buffer(reason="process_detach")
            self.controller.flush(force=True, reason="process_detach")
            self.controller.stop_trace_only()
        except Exception:
            self.controller.remember_error("dbg_process_detach", traceback.format_exc())


#------------------------------------------------------------------------------
# Runtime coverage controller
#------------------------------------------------------------------------------

class RuntimeCoverageController(object):
    """
    Runtime coverage collector for one LighthouseContext.
    """

    def __init__(self, integration, lctx):
        self.integration = integration
        self.lctx = lctx
        self.director = lctx.director
        self.metadata = lctx.metadata

        self.enabled = False
        self.mode = "bblk"

        self.scope_ranges = []
        self.exclude_library = True
        self.exclude_thunk = True
        self.exclude_import_segments = True

        self.pending_addresses = set()
        self.seen_addresses = set()

        self.covered_functions = collections.OrderedDict()

        self.last_trace_qty = 0
        self.last_flush_time = 0.0

        self.flush_interval = 0.25
        self.flush_threshold = 512

        self.events_seen = 0
        self.events_accepted = 0
        self.events_rejected = 0
        self.flush_count = 0

        self.last_errors = collections.deque(maxlen=20)

        self._dbg_hooks = _LiveCoverageDbgHooks(self)
        self._hooks_installed = False

    #--------------------------------------------------------------------------
    # Lifecycle
    #--------------------------------------------------------------------------

    def start(self, mode="bblk", clear=True, scope_ranges=None):
        """
        Start IDA trace and record coverage.

        mode:
          bblk - basic block trace, preferred default
          insn - instruction trace, slower but better for stepping
        """
        self._ensure_metadata()

        self.mode = mode
        self.scope_ranges = list(scope_ranges or [])
        self.enabled = True

        if clear:
            self.clear(create=True)

        self._install_dbg_hooks()

        ida_dbg.clear_trace()
        ida_dbg.set_trace_size(0)  # unlimited trace buffer

        step_opts = (
            _option("ST_OVER_DEBUG_SEG") |
            _option("ST_OVER_LIB_FUNC")
        )

        try:
            ida_dbg.set_step_trace_options(step_opts)
        except Exception:
            self.remember_error("set_step_trace_options", traceback.format_exc())

        if mode == "bblk":
            try:
                ida_dbg.disable_insn_trace()
            except Exception:
                pass

            try:
                ida_dbg.set_bblk_trace_options(0)
            except Exception:
                pass

            ok = ida_dbg.enable_bblk_trace(True)

        elif mode == "insn":
            try:
                ida_dbg.disable_bblk_trace()
            except Exception:
                pass

            try:
                ida_dbg.set_insn_trace_options(0)
            except Exception:
                pass

            ok = ida_dbg.enable_insn_trace(True)
            try:
                ida_dbg.enable_step_trace(True)
            except Exception:
                pass

        else:
            raise ValueError("unsupported live coverage mode: %s" % mode)

        self.last_trace_qty = ida_dbg.get_tev_qty()
        self.last_flush_time = time.time()

        self.director.select_coverage(LIVE_COVERAGE_NAME)
        self.integration.open_coverage_overview()

        if self.scope_ranges:
            scope_str = ", ".join("%s-%s" % (_safe_hex(a), _safe_hex(b)) for a, b in self.scope_ranges)
        else:
            scope_str = "entire database"

        lmsg("[LiveCoverage] started mode=%s ok=%s scope=%s" % (mode, ok, scope_str))
        return ok

    def stop(self):
        """
        Stop trace and flush all pending coverage.
        """
        self.enabled = False
        self.stop_trace_only()
        self.poll_trace_buffer(reason="stop")
        self.flush(force=True, reason="stop")
        lmsg("[LiveCoverage] stopped. accepted=%u pending=%u flushes=%u" % (
            self.events_accepted,
            len(self.pending_addresses),
            self.flush_count,
        ))

    def stop_trace_only(self):
        """
        Disable IDA trace without clearing coverage data.
        """
        try:
            ida_dbg.disable_bblk_trace()
        except Exception:
            pass

        try:
            ida_dbg.disable_insn_trace()
        except Exception:
            pass

        try:
            ida_dbg.disable_step_trace()
        except Exception:
            pass

    def clear(self, create=True):
        """
        Clear the Runtime Live coverage set.
        """
        self.pending_addresses.clear()
        self.seen_addresses.clear()
        self.covered_functions.clear()

        self.events_seen = 0
        self.events_accepted = 0
        self.events_rejected = 0
        self.flush_count = 0
        self.last_trace_qty = ida_dbg.get_tev_qty()

        if self.director.get_coverage(LIVE_COVERAGE_NAME):
            try:
                self.director.delete_coverage(LIVE_COVERAGE_NAME)
            except Exception:
                self.remember_error("delete_live_coverage", traceback.format_exc())

        if create:
            self.director.create_coverage(LIVE_COVERAGE_NAME, [])
            self.director.select_coverage(LIVE_COVERAGE_NAME)
            self.director._notify_coverage_modified()

        lmsg("[LiveCoverage] cleared")

    def terminate(self):
        self.enabled = False
        self.stop_trace_only()

        if self._hooks_installed:
            try:
                self._dbg_hooks.unhook()
            except Exception:
                pass
            self._hooks_installed = False
    def _install_dbg_hooks(self):
        """
        Install IDA debugger hooks once.
        """
        if self._hooks_installed:
            return

        self._dbg_hooks.hook()
        self._hooks_installed = True
        lmsg("[LiveCoverage] debugger hooks installed")
    #--------------------------------------------------------------------------
    # Recording
    #--------------------------------------------------------------------------

    def record_current_ip(self, source="current_ip"):
        try:
            ea = ida_dbg.get_ip_val()
        except Exception:
            ea = _badaddr()

        if ea == _badaddr():
            return

        self.record_ea(ea, tid=ida_dbg.get_current_thread(), source=source)

    def record_ea(self, ea, tid=None, source="unknown"):
        """
        Record one address cheaply.
        """
        if not self.enabled:
            return

        if ea == _badaddr():
            return

        self.events_seen += 1

        if not self._accept_ea(ea):
            self.events_rejected += 1
            return

        self.events_accepted += 1

        self.pending_addresses.add(ea)
        self.seen_addresses.add(ea)
        self._record_function_hit(ea)

        if len(self.pending_addresses) >= self.flush_threshold:
            self.flush(force=False, reason="threshold")

    def poll_trace_buffer(self, reason="poll"):
        """
        Read new IDA trace events since the last poll.

        IDA trace index 0 is newest. If qty increased by N, new events are
        roughly indices [0, N). We process them in reverse so the local
        covered_functions order is closer to execution order.
        """
        if not self.enabled:
            return 0

        try:
            qty = ida_dbg.get_tev_qty()
        except Exception:
            self.remember_error("get_tev_qty", traceback.format_exc())
            return 0

        if qty < self.last_trace_qty:
            # Trace buffer was cleared or truncated.
            self.last_trace_qty = 0

        new_count = qty - self.last_trace_qty
        if new_count <= 0:
            return 0

        processed = 0

        for i in range(new_count - 1, -1, -1):
            try:
                ea = ida_dbg.get_tev_ea(i)
            except Exception:
                continue

            if ea == _badaddr():
                continue

            self.record_ea(ea, tid=None, source="trace_buffer")
            processed += 1

        self.last_trace_qty = qty
        logger.debug("polled %u trace events because %s", processed, reason)
        return processed

    def _record_function_hit(self, ea):
        f = ida_funcs.get_func(ea)
        if not f:
            return

        start = f.start_ea
        item = self.covered_functions.get(start)
        if item is None:
            item = {
                "first_seen": len(self.covered_functions) + 1,
                "ea": start,
                "name": _get_func_name(start),
                "hits": 0,
            }
            self.covered_functions[start] = item

        item["hits"] += 1

    def _accept_ea(self, ea):
        if self.scope_ranges:
            inside = False
            for start, end in self.scope_ranges:
                if start <= ea < end:
                    inside = True
                    break
            if not inside:
                return False

        f = ida_funcs.get_func(ea)
        if f:
            if self.exclude_library and (f.flags & ida_funcs.FUNC_LIB):
                return False

            if self.exclude_thunk and (f.flags & ida_funcs.FUNC_THUNK):
                return False

        if self.exclude_import_segments:
            sname = _seg_name(ea).lower()
            if sname in (".idata", ".plt", ".got", "extern"):
                return False

        return True

    #--------------------------------------------------------------------------
    # Lighthouse mapping
    #--------------------------------------------------------------------------

    def flush(self, force=False, reason="flush"):
        """
        Map pending addresses into the Runtime Live Lighthouse coverage.
        """
        if not self.pending_addresses:
            return False

        now = time.time()
        if not force and (now - self.last_flush_time) < self.flush_interval:
            return False

        live = self._get_or_create_live_coverage()

        # Expand BB start addresses to instruction addresses when possible.
        addresses = self._expand_to_instruction_addresses(self.pending_addresses)

        live.add_addresses(addresses, update=True)
        live.refresh()

        try:
            self.director.select_coverage(LIVE_COVERAGE_NAME)
        except Exception:
            pass

        self.director._notify_coverage_modified()

        try:
            self.lctx.painter.force_repaint()
        except Exception:
            pass

        count = len(self.pending_addresses)
        self.pending_addresses.clear()

        self.flush_count += 1
        self.last_flush_time = now

        lmsg("[LiveCoverage] flush #%u reason=%s added=%u total_seen=%u functions=%u" % (
            self.flush_count,
            reason,
            len(addresses),
            len(self.seen_addresses),
            len(self.covered_functions),
        ))

        return True

    def _expand_to_instruction_addresses(self, addresses):
        """
        Convert BB/event addresses to Lighthouse instruction addresses.

        If an address maps to a known basic block, add every instruction in
        that block. If not, add the raw address so unmapped/unknown execution
        can still be diagnosed later.
        """
        out = set()

        for ea in addresses:
            node = None

            try:
                node = self.metadata.get_node(ea)
            except Exception:
                node = None

            if node:
                try:
                    out.update(node.instructions.keys())
                except AttributeError:
                    out.update(node.instructions)
            else:
                out.add(ea)

        return list(out)

    def _get_or_create_live_coverage(self):
        live = self.director.get_coverage(LIVE_COVERAGE_NAME)
        if live:
            return live

        live = self.director.create_coverage(LIVE_COVERAGE_NAME, [])
        return live

    def snapshot(self, name=None):
        """
        Save Runtime Live as a normal Lighthouse coverage set.
        """
        self.poll_trace_buffer(reason="snapshot")
        self.flush(force=True, reason="snapshot")

        live = self.director.get_coverage(LIVE_COVERAGE_NAME)
        if not live:
            ida_kernwin.warning("Runtime Live coverage does not exist.")
            return None

        if not name:
            name = ida_kernwin.ask_str(
                "runtime_%s" % _now_tag(),
                0,
                "保存 Runtime Live 覆盖率为:"
            )

        if not name:
            return None

        data = dict(live.data)
        coverage = self.director.update_coverage(name, data)
        self.director.select_coverage(name)
        self.director._notify_coverage_modified()

        try:
            self.lctx.painter.force_repaint()
        except Exception:
            pass

        lmsg("[LiveCoverage] snapshot saved as '%s' with %u addresses" % (name, len(data)))
        return coverage

    #--------------------------------------------------------------------------
    # Metadata / diagnostics
    #--------------------------------------------------------------------------

    def _ensure_metadata(self):
        if self.metadata.cached:
            return

        disassembler.show_wait_box("正在构建 Lighthouse 元数据，用于实时覆盖率...")
        try:
            future = self.metadata.refresh_async(progress_callback=metadata_progress)
            self.metadata.go_synchronous()
            await_future(future)
        finally:
            disassembler.hide_wait_box()

    def remember_error(self, where, text):
        item = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "where": where,
            "traceback": text,
        }
        self.last_errors.append(item)
        logger.error("[LiveCoverage] %s\n%s", where, text)

    def debug_status(self):
        live = self.director.get_coverage(LIVE_COVERAGE_NAME)

        status = collections.OrderedDict()
        status["enabled"] = self.enabled
        status["mode"] = self.mode
        status["metadata_cached"] = self.metadata.cached
        status["coverage_name"] = self.director.coverage_name
        status["coverage_names"] = list(self.director.coverage_names)
        status["live_exists"] = bool(live)
        status["live_address_count"] = len(live.data) if live else 0
        status["pending_count"] = len(self.pending_addresses)
        status["seen_count"] = len(self.seen_addresses)
        status["covered_function_count"] = len(self.covered_functions)
        status["events_seen"] = self.events_seen
        status["events_accepted"] = self.events_accepted
        status["events_rejected"] = self.events_rejected
        status["flush_count"] = self.flush_count
        status["last_trace_qty"] = self.last_trace_qty

        try:
            status["ida_trace_qty"] = ida_dbg.get_tev_qty()
        except Exception as e:
            status["ida_trace_qty_error"] = str(e)

        for name in (
            "is_bblk_trace_enabled",
            "is_insn_trace_enabled",
            "is_step_trace_enabled",
        ):
            fn = getattr(ida_dbg, name, None)
            if fn:
                try:
                    status[name] = bool(fn())
                except Exception as e:
                    status[name] = "error: %s" % e

        status["scope_ranges"] = [
            [_safe_hex(a), _safe_hex(b)] for a, b in self.scope_ranges
        ]

        status["covered_functions_first_50"] = [
            {
                "first_seen": item["first_seen"],
                "ea": _safe_hex(item["ea"]),
                "name": item["name"],
                "hits": item["hits"],
            }
            for item in list(self.covered_functions.values())[:50]
        ]

        status["last_errors"] = list(self.last_errors)
        return status

    def dump_debug_status(self):
        status = self.debug_status()

        out_dir = os.path.join(idaapi.get_user_idadir(), "lighthouse")
        try:
            os.makedirs(out_dir)
        except OSError:
            pass

        path = os.path.join(out_dir, "live_coverage_debug_%s.json" % _now_tag())

        with open(path, "w", encoding="utf-8") as f:
            json.dump(status, f, indent=2, ensure_ascii=False)

        lmsg("[LiveCoverage] debug status dumped to: %s" % path)
        ida_kernwin.info("Live Coverage 诊断信息已保存:\n\n%s" % path)
        return path


#------------------------------------------------------------------------------
# Menu / action manager
#------------------------------------------------------------------------------

class LiveCoverageManager(object):
    """
    Installs IDA menu actions and routes them to a RuntimeCoverageController.

    This version tries to install actions under:
      1. Debugger -> Tracing
      2. File -> Load file

    The File menu fallback is intentional because some IDA versions do not
    allow appending to Debugger/Tracing directly.
    """

    ACTION_START_BB = "lighthouse:livecov_start_bb"
    ACTION_START_INSN = "lighthouse:livecov_start_insn"
    ACTION_START_FUNC = "lighthouse:livecov_start_current_function"
    ACTION_START_RANGE = "lighthouse:livecov_start_address_range"
    ACTION_STOP = "lighthouse:livecov_stop"
    ACTION_FLUSH = "lighthouse:livecov_flush"
    ACTION_CLEAR = "lighthouse:livecov_clear"
    ACTION_SNAPSHOT = "lighthouse:livecov_snapshot"
    ACTION_DEBUG_DUMP = "lighthouse:livecov_debug_dump"

    # Try these in order. First one that works will be used per action.
    MENU_ANCHORS = (
        ("Debugger/Tracing/Tracing options...", idaapi.SETMENU_INS),
        ("Debugger/Tracing/Basic block tracing", idaapi.SETMENU_APP),
        ("Debugger/Tracing/Function tracing", idaapi.SETMENU_APP),
        ("File/Load file/", idaapi.SETMENU_APP),
    )

    def __init__(self, integration):
        self.integration = integration
        self._controllers = {}
        self._installed_actions = []
        self._menu_attachments = []

    def install(self):
        self._register_action(
            self.ACTION_START_BB,
            "Lighthouse: 开始实时基本块覆盖率",
            self.start_bb
        )
        self._register_action(
            self.ACTION_START_INSN,
            "Lighthouse: 开始实时指令覆盖率",
            self.start_insn
        )
        self._register_action(
            self.ACTION_START_FUNC,
            "Lighthouse: 跟踪当前函数覆盖率",
            self.start_current_function
        )
        self._register_action(
            self.ACTION_START_RANGE,
            "Lighthouse: 跟踪地址范围覆盖率",
            self.start_address_range
        )
        self._register_action(
            self.ACTION_STOP,
            "Lighthouse: 停止实时覆盖率",
            self.stop
        )
        self._register_action(
            self.ACTION_FLUSH,
            "Lighthouse: 刷新实时覆盖率",
            self.flush
        )
        self._register_action(
            self.ACTION_CLEAR,
            "Lighthouse: 清空实时覆盖率",
            self.clear
        )
        self._register_action(
            self.ACTION_SNAPSHOT,
            "Lighthouse: 保存实时覆盖率快照",
            self.snapshot
        )
        self._register_action(
            self.ACTION_DEBUG_DUMP,
            "Lighthouse: 导出实时覆盖率诊断信息",
            self.debug_dump
        )

        lmsg("[LiveCoverage] menu install finished, actions=%u attachments=%u" % (
            len(self._installed_actions),
            len(self._menu_attachments),
        ))

    def uninstall(self):
        for menu_path, action_name in reversed(self._menu_attachments):
            try:
                idaapi.detach_action_from_menu(menu_path, action_name)
            except Exception:
                pass

        self._menu_attachments = []

        for action_name in reversed(self._installed_actions):
            try:
                idaapi.unregister_action(action_name)
            except Exception:
                pass

        self._installed_actions = []

        for controller in list(self._controllers.values()):
            controller.terminate()

        self._controllers.clear()
        lmsg("[LiveCoverage] menu uninstalled")

    def _register_action(self, action_name, label, callback):
        desc = idaapi.action_desc_t(
            action_name,
            label,
            _ActionHandler(callback),
            None,
            label,
            -1
        )

        try:
            registered = idaapi.register_action(desc)
        except Exception:
            registered = False

        if not registered:
            # If the action already exists from a previous failed reload,
            # unregister and try once more.
            try:
                idaapi.unregister_action(action_name)
            except Exception:
                pass

            registered = idaapi.register_action(desc)

        if not registered:
            lmsg("[LiveCoverage] failed to register action: %s" % action_name)
            return False

        self._installed_actions.append(action_name)

        attached_path = self._attach_action_to_first_working_menu(action_name)

        if not attached_path:
            lmsg("[LiveCoverage] registered but failed to attach menu action: %s" % action_name)
            return False

        lmsg("[LiveCoverage] installed action: %s -> %s" % (label, attached_path))
        return True

    def _attach_action_to_first_working_menu(self, action_name):
        for menu_path, flags in self.MENU_ANCHORS:
            try:
                ok = idaapi.attach_action_to_menu(menu_path, action_name, flags)
            except Exception:
                ok = False

            if ok:
                self._menu_attachments.append((menu_path, action_name))
                return menu_path

        return None

    def _controller(self):
        lctx = self.integration.get_context(None)
        key = lctx.dctx

        controller = self._controllers.get(key)
        if controller is None:
            controller = RuntimeCoverageController(self.integration, lctx)
            self._controllers[key] = controller

        return controller

    #--------------------------------------------------------------------------
    # Actions
    #--------------------------------------------------------------------------

    def start_bb(self):
        self._controller().start(mode="bblk", clear=True)

    def start_insn(self):
        self._controller().start(mode="insn", clear=True)

    def start_current_function(self):
        rng = _get_screen_function_range()
        if not rng:
            ida_kernwin.warning("当前光标不在函数内。")
            return

        start, end = rng
        c = self._controller()
        c.start(mode="bblk", clear=True, scope_ranges=[rng])

        lmsg("[LiveCoverage] current function scope: %s %s-%s" % (
            _get_func_name(start),
            _safe_hex(start),
            _safe_hex(end),
        ))

    def start_address_range(self):
        default = ""

        rng = _get_screen_function_range()
        if rng:
            default = "%X-%X" % (rng[0], rng[1])

        text = ida_kernwin.ask_str(
            default,
            0,
            "输入地址范围，例如 401000-402000 或 main-sub_402000:"
        )

        if not text:
            return

        text = text.replace(",", "-").replace(" ", "")
        if "-" not in text:
            ida_kernwin.warning("格式错误。示例: 401000-402000")
            return

        left, right = text.split("-", 1)
        start = _parse_ea(left)
        end = _parse_ea(right)

        if start == _badaddr() or end == _badaddr() or end <= start:
            ida_kernwin.warning("地址范围无效: %s" % text)
            return

        self._controller().start(mode="bblk", clear=True, scope_ranges=[(start, end)])

    def stop(self):
        self._controller().stop()

    def flush(self):
        c = self._controller()
        c.poll_trace_buffer(reason="manual_flush")
        c.flush(force=True, reason="manual_flush")

    def clear(self):
        self._controller().clear(create=True)

    def snapshot(self):
        self._controller().snapshot()

    def debug_dump(self):
        self._controller().dump_debug_status()