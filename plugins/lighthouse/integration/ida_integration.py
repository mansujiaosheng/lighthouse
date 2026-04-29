import json
import os
import shutil
import time
import logging

import idaapi
from lighthouse.util.disassembler.ida_compat import patch_idaapi

from lighthouse.context import LighthouseContext
from lighthouse.integration.drcov_runner import run_drcov_async
from lighthouse.util import lmsg
from lighthouse.util.misc import plugin_resource
from lighthouse.util.qt import QtWidgets, await_future, prompt_string
from lighthouse.util.disassembler import disassembler
from lighthouse.integration.core import LighthouseCore

patch_idaapi()
logger = logging.getLogger("Lighthouse.IDA.Integration")

#------------------------------------------------------------------------------
# Lighthouse IDA Integration
#------------------------------------------------------------------------------

class LighthouseIDA(LighthouseCore):
    """
    Lighthouse UI Integration for IDA Pro.
    """

    def __init__(self):

        # menu entry icons
        self._icon_id_xref = idaapi.BADADDR
        self._icon_id_file = idaapi.BADADDR
        self._icon_id_batch = idaapi.BADADDR
        self._icon_id_generate = idaapi.BADADDR
        self._icon_id_overview = idaapi.BADADDR

        # IDA ui hooks
        self._ui_hooks = UIHooks(self)

        # run initialization
        super(LighthouseIDA, self).__init__()

    def get_context(self, dctx=None, startup=True):
        """
        Get the LighthouseContext object for a given database context.

        NOTE: since IDA can only have one binary / IDB open at a time, the
        dctx (database context) should always be 'None'.
        """
        self.palette.warmup()

        #
        # there should only ever be 'one' disassembler / IDB context at any
        # time for IDA. but if one does not exist yet, that means this is the
        # first time the user has interacted with Lighthouse for this session
        #

        if dctx not in self.lighthouse_contexts:

            # create a new 'context' representing this IDB
            lctx = LighthouseContext(self, dctx)
            if startup:
                lctx.start()

            # save the created ctx for future calls
            self.lighthouse_contexts[dctx] = lctx

        # return the lighthouse context object for this IDB
        return self.lighthouse_contexts[dctx]

    #--------------------------------------------------------------------------
    # IDA Actions
    #--------------------------------------------------------------------------

    ACTION_LOAD_FILE         = "lighthouse:load_file"
    ACTION_LOAD_BATCH        = "lighthouse:load_batch"
    ACTION_GENERATE_COVERAGE = "lighthouse:generate_coverage"
    ACTION_COVERAGE_XREF     = "lighthouse:coverage_xref"
    ACTION_COVERAGE_OVERVIEW = "lighthouse:coverage_overview"

    def _install_load_file(self):
        """
        Install the 'File->Load->Code coverage file...' menu entry.
        """

        # create a custom IDA icon
        icon_path = plugin_resource(os.path.join("icons", "load.png"))
        icon_data = open(icon_path, "rb").read()
        self._icon_id_file = idaapi.load_custom_icon(data=icon_data)

        # describe a custom IDA UI action
        action_desc = idaapi.action_desc_t(
            self.ACTION_LOAD_FILE,                   # The action name
            "代码覆盖率文件...",                     # The action text
            IDACtxEntry(self.interactive_load_file), # The action handler
            None,                                    # Optional: action shortcut
            "加载单个或多个代码覆盖率文件",           # Optional: tooltip
            self._icon_id_file                       # Optional: the action icon
        )

        # register the action with IDA
        result = idaapi.register_action(action_desc)
        if not result:
            RuntimeError("Failed to register load_file action with IDA")

        # attach the action to the File-> dropdown menu
        result = idaapi.attach_action_to_menu(
            "File/Load file/",      # Relative path of where to add the action
            self.ACTION_LOAD_FILE,  # The action ID (see above)
            idaapi.SETMENU_APP      # We want to append the action after ^
        )
        if not result:
            RuntimeError("Failed action attach load_file")

        logger.info("Installed the 'Code coverage file' menu entry")

    def _install_load_batch(self):
        """
        Install the 'File->Load->Code coverage batch...' menu entry.
        """

        # create a custom IDA icon
        icon_path = plugin_resource(os.path.join("icons", "batch.png"))
        icon_data = open(icon_path, "rb").read()
        self._icon_id_batch = idaapi.load_custom_icon(data=icon_data)

        # describe a custom IDA UI action
        action_desc = idaapi.action_desc_t(
            self.ACTION_LOAD_BATCH,                   # The action name
            "批量代码覆盖率...",                      # The action text
            IDACtxEntry(self.interactive_load_batch), # The action handler
            None,                                     # Optional: action shortcut
            "加载并聚合多个代码覆盖率文件",            # Optional: tooltip
            self._icon_id_batch                       # Optional: the action icon
        )

        # register the action with IDA
        result = idaapi.register_action(action_desc)
        if not result:
            RuntimeError("Failed to register load_batch action with IDA")

        # attach the action to the File-> dropdown menu
        result = idaapi.attach_action_to_menu(
            "File/Load file/",      # Relative path of where to add the action
            self.ACTION_LOAD_BATCH, # The action ID (see above)
            idaapi.SETMENU_APP      # We want to append the action after ^
        )
        if not result:
            RuntimeError("Failed action attach load_batch")

        logger.info("Installed the 'Code coverage batch' menu entry")

    def _install_generate_coverage(self):
        """
        Install the 'File->Load->Run and load coverage...' menu entry.
        """

        # create a custom IDA icon
        icon_path = plugin_resource(os.path.join("icons", "load.png"))
        icon_data = open(icon_path, "rb").read()
        self._icon_id_generate = idaapi.load_custom_icon(data=icon_data)

        # describe a custom IDA UI action
        action_desc = idaapi.action_desc_t(
            self.ACTION_GENERATE_COVERAGE,            # The action name
            "运行并加载覆盖率...",                    # The action text
            IDACtxEntry(self.interactive_generate_coverage),
            None,                                     # Optional: action shortcut
            "使用 DynamoRIO drcov 运行当前程序并自动加载覆盖率",
            self._icon_id_generate                    # Optional: the action icon
        )

        # register the action with IDA
        result = idaapi.register_action(action_desc)
        if not result:
            RuntimeError("Failed to register generate_coverage action with IDA")

        # attach the action to the File-> dropdown menu
        result = idaapi.attach_action_to_menu(
            "File/Load file/",
            self.ACTION_GENERATE_COVERAGE,
            idaapi.SETMENU_APP
        )
        if not result:
            RuntimeError("Failed action attach generate_coverage")

        logger.info("Installed the 'Run and load coverage' menu entry")

    def _install_open_coverage_xref(self):
        """
        Install the right click 'Coverage Xref' context menu entry.
        """

        # create a custom IDA icon
        icon_path = plugin_resource(os.path.join("icons", "batch.png"))
        icon_data = open(icon_path, "rb").read()
        self._icon_id_xref = idaapi.load_custom_icon(data=icon_data)

        # describe a custom IDA UI action
        action_desc = idaapi.action_desc_t(
            self.ACTION_COVERAGE_XREF,                # The action name
            "覆盖率交叉引用...",                      # The action text
            IDACtxEntry(self._pre_open_coverage_xref),# The action handler
            None,                                     # Optional: action shortcut
            "列出命中当前地址的覆盖率集合",            # Optional: tooltip
            self._icon_id_xref                        # Optional: the action icon
        )

        # register the action with IDA
        result = idaapi.register_action(action_desc)
        if not result:
            RuntimeError("Failed to register coverage_xref action with IDA")

        self._ui_hooks.hook()
        logger.info("Installed the 'Coverage Xref' menu entry")

    def _install_open_coverage_overview(self):
        """
        Install the 'View->Open subviews->Coverage Overview' menu entry.
        """

        # create a custom IDA icon
        icon_path = plugin_resource(os.path.join("icons", "overview.png"))
        icon_data = open(icon_path, "rb").read()
        self._icon_id_overview = idaapi.load_custom_icon(data=icon_data)

        # describe a custom IDA UI action
        action_desc = idaapi.action_desc_t(
            self.ACTION_COVERAGE_OVERVIEW,            # The action name
            "覆盖率总览",                             # The action text
            IDACtxEntry(self.open_coverage_overview), # The action handler
            None,                                     # Optional: action shortcut
            "打开当前数据库的代码覆盖率总览",          # Optional: tooltip
            self._icon_id_overview                    # Optional: the action icon
        )

        # register the action with IDA
        result = idaapi.register_action(action_desc)
        if not result:
            RuntimeError("Failed to register open coverage overview action with IDA")

        # attach the action to the View-> dropdown menu
        result = idaapi.attach_action_to_menu(
            "View/Open subviews/Hex dump", # Relative path of where to add the action
            self.ACTION_COVERAGE_OVERVIEW, # The action ID (see above)
            idaapi.SETMENU_INS             # We want to insert the action before ^
        )
        if not result:
            RuntimeError("Failed action attach to 'View/Open subviews' dropdown")

        logger.info("Installed the 'Coverage Overview' menu entry")

    def _uninstall_load_file(self):
        """
        Remove the 'File->Load file->Code coverage file...' menu entry.
        """

        # remove the entry from the File-> menu
        result = idaapi.detach_action_from_menu(
            "File/Load file/",
            self.ACTION_LOAD_FILE
        )
        if not result:
            return False

        # unregister the action
        result = idaapi.unregister_action(self.ACTION_LOAD_FILE)
        if not result:
            return False

        # delete the entry's icon
        idaapi.free_custom_icon(self._icon_id_file)
        self._icon_id_file = idaapi.BADADDR

        logger.info("Uninstalled the 'Code coverage file' menu entry")

    def _uninstall_load_batch(self):
        """
        Remove the 'File->Load file->Code coverage batch...' menu entry.
        """

        # remove the entry from the File-> menu
        result = idaapi.detach_action_from_menu(
            "File/Load file/",
            self.ACTION_LOAD_BATCH
        )
        if not result:
            return False

        # unregister the action
        result = idaapi.unregister_action(self.ACTION_LOAD_BATCH)
        if not result:
            return False

        # delete the entry's icon
        idaapi.free_custom_icon(self._icon_id_batch)
        self._icon_id_batch = idaapi.BADADDR

        logger.info("Uninstalled the 'Code coverage batch' menu entry")

    def _uninstall_generate_coverage(self):
        """
        Remove the 'File->Load file->Run and load coverage...' menu entry.
        """

        # remove the entry from the File-> menu
        result = idaapi.detach_action_from_menu(
            "File/Load file/",
            self.ACTION_GENERATE_COVERAGE
        )
        if not result:
            return False

        # unregister the action
        result = idaapi.unregister_action(self.ACTION_GENERATE_COVERAGE)
        if not result:
            return False

        # delete the entry's icon
        idaapi.free_custom_icon(self._icon_id_generate)
        self._icon_id_generate = idaapi.BADADDR

        logger.info("Uninstalled the 'Run and load coverage' menu entry")

    def _uninstall_open_coverage_xref(self):
        """
        Remove the right click 'Coverage Xref' context menu entry.
        """
        self._ui_hooks.unhook()

        # unregister the action
        result = idaapi.unregister_action(self.ACTION_COVERAGE_XREF)
        if not result:
            return False

        # delete the entry's icon
        idaapi.free_custom_icon(self._icon_id_xref)
        self._icon_id_xref = idaapi.BADADDR

        logger.info("Uninstalled the 'Coverage Xref' menu entry")

    def _uninstall_open_coverage_overview(self):
        """
        Remove the 'View->Open subviews->Coverage Overview' menu entry.
        """

        # remove the entry from the View-> menu
        result = idaapi.detach_action_from_menu(
            "View/Open subviews/Hex dump",
            self.ACTION_COVERAGE_OVERVIEW
        )
        if not result:
            return False

        # unregister the action
        result = idaapi.unregister_action(self.ACTION_COVERAGE_OVERVIEW)
        if not result:
            return False

        # delete the entry's icon
        idaapi.free_custom_icon(self._icon_id_overview)
        self._icon_id_overview = idaapi.BADADDR

        logger.info("Uninstalled the 'Coverage Overview' menu entry")

    #--------------------------------------------------------------------------
    # Helpers
    #--------------------------------------------------------------------------

    def _inject_ctx_actions(self, view, popup, view_type):
        """
        Inject context menu entries into IDA's right click menus.

        NOTE: This is only being used for coverage xref at this time, but
        may host additional actions in the future.

        """

        if view_type == idaapi.BWN_DISASMS:

            idaapi.attach_action_to_popup(
                view,
                popup,
                self.ACTION_COVERAGE_XREF,  # The action ID (see above)
                "Xrefs graph from...",      # Relative path of where to add the action
                idaapi.SETMENU_APP          # We want to append the action after ^
            )

    def _pre_open_coverage_xref(self):
        """
        Grab a contextual address before opening the coverage xref dialog.
        """
        self.open_coverage_xref(idaapi.get_screen_ea())

    #--------------------------------------------------------------------------
    # Automatic Coverage Generation
    #--------------------------------------------------------------------------

    def interactive_generate_coverage(self, dctx=None):
        """
        Run the current input file under DynamoRIO drcov and load the result.
        """
        lctx = self.get_context(dctx)

        target_path = self._select_target_executable()
        if not target_path:
            return

        drrun_path = self._find_or_select_drrun_path()
        if not drrun_path:
            return

        ok, target_args = prompt_string(
            "请输入程序运行参数（可留空）:",
            "运行参数",
            ""
        )
        if not ok:
            return

        output_dir = self._drcov_output_dir(lctx, target_path)
        future = lctx.metadata.refresh_async()

        disassembler.show_wait_box("正在运行目标程序并生成覆盖率...")
        run_future = run_drcov_async(
            drrun_path,
            target_path,
            target_args,
            output_dir,
            os.path.dirname(target_path)
        )
        result = await_future(run_future)
        disassembler.hide_wait_box()

        if isinstance(result, Exception):
            lctx.metadata.abort_refresh()
            disassembler.warning("生成覆盖率失败:\n\n%s" % result)
            return

        logs = result["logs"]
        if result["returncode"]:
            lmsg("目标程序返回码: %d" % result["returncode"])

        lmsg("已生成 %u 个 drcov 覆盖率日志:" % len(logs))
        for log_path in logs:
            lmsg(" - %s" % log_path)

        self._load_coverage_filepaths(lctx, logs, future)

    def _config_path(self):
        """
        Return the path to the Lighthouse IDA integration config.
        """
        return os.path.join(
            idaapi.get_user_idadir(),
            "lighthouse_drcov.json"
        )

    def _load_config(self):
        """
        Load persisted local settings.
        """
        try:
            with open(self._config_path(), "r") as fd:
                return json.load(fd)
        except (IOError, ValueError):
            return {}

    def _save_config(self, config):
        """
        Persist local settings.
        """
        try:
            with open(self._config_path(), "w") as fd:
                json.dump(config, fd, indent=2)
        except IOError:
            logger.exception("Failed to save Lighthouse drcov config")

    def _is_64bit_database(self):
        """
        Return True if the current IDB is 64bit.
        """
        try:
            import ida_ida
            return bool(ida_ida.inf_is_64bit())
        except Exception:
            return True

    def _candidate_drrun_paths(self):
        """
        Yield plausible DynamoRIO drrun paths for this machine.
        """
        config = self._load_config()
        configured = config.get("drrun_path")
        if configured:
            yield configured

        for env_name in ("LIGHTHOUSE_DRRUN", "DYNAMORIO_DRRUN"):
            env_path = os.environ.get(env_name)
            if env_path:
                yield env_path

        roots = []
        for env_name in ("DYNAMORIO_HOME", "DYNAMORIO_ROOT"):
            env_path = os.environ.get(env_name)
            if env_path:
                roots.append(env_path)

        plugin_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        roots.append(os.path.join(plugin_dir, "third_party", "dynamorio"))
        roots.append(os.path.join(plugin_dir, "tools", "dynamorio"))

        preferred_bins = ["bin64", "bin32"] if self._is_64bit_database() else ["bin32", "bin64"]
        for root in roots:
            yield os.path.join(root, "drrun.exe")
            for bin_name in preferred_bins:
                yield os.path.join(root, bin_name, "drrun.exe")
            try:
                children = os.listdir(root)
            except OSError:
                children = []
            for child in children:
                child_root = os.path.join(root, child)
                if not os.path.isdir(child_root):
                    continue
                yield os.path.join(child_root, "drrun.exe")
                for bin_name in preferred_bins:
                    yield os.path.join(child_root, bin_name, "drrun.exe")

        which = shutil.which("drrun.exe") or shutil.which("drrun")
        if which:
            yield which

    def _find_or_select_drrun_path(self):
        """
        Locate DynamoRIO's drrun.exe, prompting the user if needed.
        """
        for path in self._candidate_drrun_paths():
            if path and os.path.isfile(path):
                path = os.path.abspath(path)
                config = self._load_config()
                if config.get("drrun_path") != path:
                    config["drrun_path"] = path
                    self._save_config(config)
                return path

        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            None,
            "请选择 DynamoRIO 的 drrun.exe",
            os.path.dirname(self._config_path()),
            "drrun.exe (drrun.exe);;可执行文件 (*.exe);;所有文件 (*.*)"
        )
        if not path:
            disassembler.warning(
                "未找到 drrun.exe。\n\n"
                "请先安装 DynamoRIO，或选择 DynamoRIO 目录下的 bin64\\drrun.exe / bin32\\drrun.exe。"
            )
            return None

        path = os.path.abspath(path)
        if not os.path.isfile(path):
            disassembler.warning("选择的 drrun.exe 不存在:\n\n%s" % path)
            return None

        config = self._load_config()
        config["drrun_path"] = path
        self._save_config(config)
        return path

    def _select_target_executable(self):
        """
        Return the current input executable, prompting if the path is stale.
        """
        target_path = idaapi.get_input_file_path()
        if target_path and os.path.isfile(target_path):
            return os.path.abspath(target_path)

        target_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            None,
            "请选择要运行的目标程序",
            os.getcwd(),
            "可执行文件 (*.exe);;所有文件 (*.*)"
        )
        if not target_path:
            return None
        return os.path.abspath(target_path)

    def _drcov_output_dir(self, lctx, target_path):
        """
        Return a per-run drcov output directory.
        """
        target_name = os.path.splitext(os.path.basename(target_path))[0]
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        return os.path.join(
            disassembler.get_disassembler_user_directory(),
            "lighthouse",
            "drcov",
            "%s_%s" % (target_name, timestamp)
        )

#------------------------------------------------------------------------------
# IDA UI Helpers
#------------------------------------------------------------------------------

class IDACtxEntry(idaapi.action_handler_t):
    """
    A minimal context menu entry class to utilize IDA's action handlers.
    """

    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        """
        Execute the embedded action_function when this context menu is invoked.
        """
        self.action_function()
        return 1

    def update(self, ctx):
        """
        Ensure the context menu is always available in IDA.
        """
        return idaapi.AST_ENABLE_ALWAYS

class UIHooks(idaapi.UI_Hooks):
    """
    Hooks for IDA's UI subsystem.

    At the moment, we are only using these to inject into IDA's right click
    context menus (eg, coverage xrefs)
    """

    def __init__(self, integration):
        self.integration = integration
        super(UIHooks, self).__init__()

    def finish_populating_widget_popup(self, widget, popup):
        """
        A right click menu is about to be shown. (IDA 7.0+)
        """

        #
        # if lighthouse hasn't been used yet, there's nothing to do. we also
        # don't want this event to trigger the creation of a lighthouse
        # context! so we should bail early in this case...
        #

        if not self.integration.lighthouse_contexts:
            return 0

        # inject any of lighthouse's right click context menu's into IDA
        lctx = self.integration.get_context(None)
        if lctx.director.coverage_names:
            self.integration._inject_ctx_actions(widget, popup, idaapi.get_widget_type(widget))

        # must return 0 for ida...
        return 0
