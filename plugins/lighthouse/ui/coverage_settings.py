import logging

from lighthouse.util.qt import *
from lighthouse.util.disassembler import disassembler

logger = logging.getLogger("Lighthouse.UI.Settings")

class TableSettingsMenu(QtWidgets.QMenu):
    """
    A quick-access settings menu for Lighthouse.
    """

    def __init__(self, parent=None):
        super(TableSettingsMenu, self).__init__(parent)
        self._visible_action = None
        self._ui_init_actions()

        self.setToolTipsVisible(True)

    #--------------------------------------------------------------------------
    # QMenu Overloads
    #--------------------------------------------------------------------------

    def event(self, event):
        """
        Hook the QMenu event stream.
        """
        action = self.activeAction()

        # swallow clicks to checkbox/radiobutton actions to keep qmenu open
        if event.type() == QtCore.QEvent.MouseButtonRelease:
            if action and action.isEnabled() and action.isCheckable():
                action.trigger()
                event.accept()
                return True

        # handle any other events as wee normally should
        return super(TableSettingsMenu, self).event(event)

    #--------------------------------------------------------------------------
    # Initialization - UI
    #--------------------------------------------------------------------------

    def _ui_init_actions(self):
        """
        Initialize the menu actions.
        """

        # lighthouse colors
        self._action_change_theme = QtWidgets.QAction("切换主题", None)
        self._action_change_theme.setToolTip("自定义 Lighthouse 颜色和主题")
        self.addAction(self._action_change_theme)
        self.addSeparator()

        # painting
        self._action_force_clear = QtWidgets.QAction("强制清除着色（较慢）", None)
        self._action_force_clear.setToolTip("尝试强制清除数据库中残留的覆盖率着色")
        self.addAction(self._action_force_clear)

        self._action_disable_paint = QtWidgets.QAction("禁用着色", None)
        self._action_disable_paint.setCheckable(True)
        self._action_disable_paint.setToolTip("禁用覆盖率着色子系统")
        self.addAction(self._action_disable_paint)
        self.addSeparator()

        # table actions
        self._action_refresh_metadata = QtWidgets.QAction("重建覆盖率映射", None)
        self._action_refresh_metadata.setToolTip("刷新数据库元数据和覆盖率映射")
        self.addAction(self._action_refresh_metadata)

        self._action_export_html = QtWidgets.QAction("生成 HTML 报告", None)
        self._action_export_html.setToolTip("将覆盖率表导出为 HTML")
        self.addAction(self._action_export_html)

        self._action_hide_zero = QtWidgets.QAction("隐藏 0% 覆盖率", None)
        self._action_hide_zero.setToolTip("隐藏没有覆盖率数据的表项")
        self._action_hide_zero.setCheckable(True)
        self.addAction(self._action_hide_zero)

    def connect_signals(self, controller, lctx):
        """
        Connect UI signals.
        """
        self._action_change_theme.triggered.connect(lctx.core.palette.interactive_change_theme)
        self._action_refresh_metadata.triggered.connect(lctx.director.refresh)
        self._action_hide_zero.triggered[bool].connect(controller._model.filter_zero_coverage)
        self._action_disable_paint.triggered[bool].connect(lambda x: lctx.painter.set_enabled(not x))
        self._action_force_clear.triggered.connect(lctx.painter.force_clear)
        self._action_export_html.triggered.connect(controller.export_to_html)
        lctx.painter.status_changed(self._ui_painter_changed_status)

    #--------------------------------------------------------------------------
    # Signal Handlers
    #--------------------------------------------------------------------------

    @disassembler.execute_ui
    def _ui_painter_changed_status(self, painter_enabled):
        """
        Handle an event from the painter being enabled/disabled.
        """
        self._action_disable_paint.setChecked(not painter_enabled)
