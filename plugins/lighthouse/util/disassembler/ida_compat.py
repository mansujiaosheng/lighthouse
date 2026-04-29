"""
Compatibility helpers for IDA's split IDAPython modules.

Lighthouse historically used the broad ``idaapi`` namespace. Modern IDA
versions, including 9.2+, expose many APIs from dedicated modules instead. This
module keeps the rest of the plugin on its existing call sites while filling in
missing ``idaapi`` attributes from their canonical modules.
"""

import importlib

import idaapi


_ALIASES = {
    "ida_auto": [
        "auto_is_ok",
    ],
    "ida_bytes": [
        "clr_abits",
        "get_flags",
        "get_item_end",
        "is_code",
        "next_head",
        "set_abits",
    ],
    "ida_diskio": [
        "fopenWT",
        "get_user_idadir",
    ],
    "ida_fpro": [
        "eclose",
        "qfclose",
    ],
    "ida_funcs": [
        "get_func",
    ],
    "ida_gdl": [
        "qflow_chart_t",
    ],
    "ida_graph": [
        "NIF_BG_COLOR",
        "NIF_FRAME_COLOR",
        "node_info_t",
        "set_node_info",
    ],
    "ida_hexrays": [
        "hxe_close_pseudocode",
        "hxe_text_ready",
        "install_hexrays_callback",
        "remove_hexrays_callback",
    ],
    "ida_ida": [
        "get_kernel_version",
    ],
    "ida_idaapi": [
        "BADADDR",
        "IDA_SDK_VERSION",
        "PLUGIN_HIDE",
        "PLUGIN_KEEP",
        "PLUGIN_MOD",
        "PLUGIN_PROC",
        "cvar",
        "plugin_t",
    ],
    "ida_idp": [
        "IDB_Hooks",
        "IDP_Hooks",
    ],
    "ida_kernwin": [
        "AST_ENABLE_ALWAYS",
        "BWN_DISASM",
        "BWN_DISASMS",
        "DP_RIGHT",
        "DP_TAB",
        "MFF_FAST",
        "MFF_NOWAIT",
        "MFF_READ",
        "MFF_WRITE",
        "PluginForm",
        "SETMENU_APP",
        "SETMENU_INS",
        "UI_Hooks",
        "action_desc_t",
        "action_handler_t",
        "activate_widget",
        "attach_action_to_menu",
        "attach_action_to_popup",
        "cancel_exec_request",
        "create_empty_widget",
        "cvar",
        "detach_action_from_menu",
        "display_widget",
        "execute_sync",
        "find_widget",
        "free_custom_icon",
        "get_current_widget",
        "get_kernel_version",
        "get_screen_ea",
        "get_widget_title",
        "get_widget_type",
        "is_msg_inited",
        "jumpto",
        "load_custom_icon",
        "refresh_idaview_anyway",
        "register_action",
        "set_dock_pos",
        "unregister_action",
        "warning",
    ],
    "ida_lines": [
        "COLOR_ADDR",
        "COLOR_ADDR_SIZE",
        "COLOR_ON",
    ],
    "ida_loader": [
        "GENFLG_GENHTML",
        "OFILE_LST",
        "gen_file",
    ],
    "ida_name": [
        "SN_NOWARN",
        "get_name",
        "get_short_name",
        "set_name",
    ],
    "ida_nalt": [
        "get_input_file_path",
        "get_imagebase",
        "get_root_filename",
    ],
    "ida_netnode": [
        "netnode",
    ],
    "ida_segment": [
        "getseg",
    ],
}


def _copy_missing(module_name, names):
    try:
        module = importlib.import_module(module_name)
    except ImportError:
        return

    for name in names:
        if hasattr(idaapi, name) or not hasattr(module, name):
            continue
        setattr(idaapi, name, getattr(module, name))


def patch_idaapi():
    for module_name, names in _ALIASES.items():
        _copy_missing(module_name, names)

    if not hasattr(idaapi, "eclose"):
        try:
            ida_fpro = importlib.import_module("ida_fpro")
        except ImportError:
            pass
        else:
            if hasattr(ida_fpro, "qfclose"):
                idaapi.eclose = ida_fpro.qfclose

    if not hasattr(idaapi, "BWN_DISASMS") and hasattr(idaapi, "BWN_DISASM"):
        idaapi.BWN_DISASMS = idaapi.BWN_DISASM

    return idaapi


patch_idaapi()
