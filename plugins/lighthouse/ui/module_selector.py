import os
import logging

from lighthouse.util import lmsg
from lighthouse.util.qt import *
from lighthouse.util.misc import human_timestamp
from lighthouse.util.python import *

logger = logging.getLogger("Lighthouse.UI.ModuleSelector")

#------------------------------------------------------------------------------
# Coverage Xref Dialog
#------------------------------------------------------------------------------

class ModuleSelector(QtWidgets.QDialog):
    """
    A Qt Dialog to list all the coverage modules in a coverage file.

    This class makes up a rudimentary selector dialog. It does not follow Qt
    'best practices' because it does not need to be super flashy, nor does
    it demand much facetime.
    """

    def __init__(self, target_name, module_names, coverage_file):
        super(ModuleSelector, self).__init__()

        self._target_name = target_name
        self._module_names = module_names
        self._coverage_file = os.path.basename(coverage_file)

        # dialog attributes
        self.selected_name = None

        # configure the widget for use
        self._ui_init()

    @property
    def remember_alias(self):
        return self._checkbox_remember.isChecked()

    @property
    def ignore_missing(self):
        return self._checkbox_ignore_missing.isChecked()

    #--------------------------------------------------------------------------
    # Initialization - UI
    #--------------------------------------------------------------------------

    def _ui_init(self):
        """
        Initialize UI elements.
        """
        self.setWindowTitle("选择匹配当前数据库的模块")
        set_window_flag(self, QtCore.Qt.WindowContextHelpButtonHint, False)
        self.setModal(True)

        self._font = self.font()
        self._font.setPointSizeF(normalize_to_dpi(10))
        self._font_metrics = QtGui.QFontMetricsF(self._font)

        # initialize module selector table
        self._ui_init_header()
        self._ui_init_table()
        self._populate_table()

        # layout the populated UI just before showing it
        self._ui_layout()

    def _ui_init_header(self):
        """
        Initialize the module selector header UI elements.
        """

        description_text = \
        "Lighthouse 无法自动识别该覆盖率文件中的目标模块:<br />" \
        "<br />" \
        "-- <b>目标:</b> {0}<br />" \
        "-- <b>覆盖率文件:</b> {1}<br />" \
        "<br />" \
        "请双击与当前数据库匹配的模块名称。<br />" \
        "如果下表中没有目标二进制文件，请直接关闭此对话框。".format(self._target_name, self._coverage_file)

        self._label_description = QtWidgets.QLabel(description_text)
        self._label_description.setTextFormat(QtCore.Qt.RichText)
        self._label_description.setFont(self._font)
        #self._label_description.setWordWrap(True)

        # a checkbox to save the user selected alias to the database
        self._checkbox_remember = QtWidgets.QCheckBox("在本次会话中记住目标模块别名")
        self._checkbox_remember.setFont(self._font)

        # a checkbox to ignore future 'missing coverage' / select module warnings
        self._checkbox_ignore_missing = QtWidgets.QCheckBox("对剩余覆盖率文件不再显示此对话框")
        self._checkbox_ignore_missing.setFont(self._font)

    def _ui_init_table(self):
        """
        Initialize the module selector table UI elements.
        """
        self._table = QtWidgets.QTableWidget()
        self._table.verticalHeader().setVisible(False)
        self._table.setHorizontalScrollMode(QtWidgets.QAbstractItemView.ScrollPerPixel)
        self._table.horizontalHeader().setFont(self._font)
        self._table.setFont(self._font)

        # Create a simple table / list
        self._table.setColumnCount(1)
        self._table.setHorizontalHeaderLabels(["模块名称"])

        # left align text in column headers
        self._table.horizontalHeaderItem(0).setTextAlignment(QtCore.Qt.AlignLeft)

        # disable bolding of column headers when selected
        self._table.horizontalHeader().setHighlightSections(False)

        # stretch the last column of the table (aesthetics)
        self._table.horizontalHeader().setStretchLastSection(True)

        # make table read only, select a full row by default
        self._table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self._table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)

        # catch double click events on table rows
        self._table.cellDoubleClicked.connect(self._ui_cell_double_click)

    def _populate_table(self):
        """
        Populate the module table with the module names provided to this dialog.
        """
        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(self._module_names))
        for i, module_name in enumerate(self._module_names, 0):
            self._table.setItem(i, 0, QtWidgets.QTableWidgetItem(module_name))
        self._table.resizeRowsToContents()
        self._table.setSortingEnabled(True)

    def _ui_layout(self):
        """
        Layout the major UI elements of the widget.
        """
        layout = QtWidgets.QVBoxLayout()
        #layout.setContentsMargins(0,0,0,0)

        # layout child widgets
        layout.addWidget(self._label_description)
        layout.addWidget(self._table)
        layout.addWidget(self._checkbox_remember)
        layout.addWidget(self._checkbox_ignore_missing)

        # scale widget dimensions based on DPI
        height = int(get_dpi_scale() * 250)
        width = int(get_dpi_scale() * 400)
        self.setMinimumHeight(height)
        self.setMinimumWidth(width)

        # apply the widget layout
        self.setLayout(layout)

    #--------------------------------------------------------------------------
    # Signal Handlers
    #--------------------------------------------------------------------------

    def _ui_cell_double_click(self, row, column):
        """
        A cell/row has been double clicked in the module table.
        """
        self.selected_name = self._table.item(row, 0).text()
        self.accept()
