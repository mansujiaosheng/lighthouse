
#
# this global is used to indicate whether Qt bindings for python are present
# and available for use by Lighthouse.
#

QT_AVAILABLE = False

#------------------------------------------------------------------------------
# PyQt5 <--> PySide2/PySide6 Compatibility
#------------------------------------------------------------------------------
#
#    we use this file to shim/re-alias a few Qt API's to ensure compatibility
#    between the popular Qt frameworks. these shims serve to reduce the number
#    of compatibility checks in the plugin code that consumes them.
#
#    this file was critical for retaining compatibility with Qt4 frameworks
#    used by IDA 6.8/6.95, but it less important now. support for Qt 4 and
#    older versions of IDA (< 7.0) were deprecated in Lighthouse v0.9.0
#

USING_PYQT5 = False
USING_PYSIDE2 = False
USING_PYSIDE6 = False
wrapinstance = None

#
#    TODO/QT: This file is getting pretty gross. this whole shim system
#    should probably get refactored as I really don't want disassembler
#    specific dependencies in here...
#

try:
    import ida_idaapi
    USING_IDA = True
except ImportError:
    USING_IDA = False

IDA_SDK_VERSION = 0
if USING_IDA:
    try:
        IDA_SDK_VERSION = ida_idaapi.IDA_SDK_VERSION
    except AttributeError:
        try:
            import idaapi
            IDA_SDK_VERSION = idaapi.IDA_SDK_VERSION
        except (ImportError, AttributeError):
            IDA_SDK_VERSION = 0

try:
    import binaryninjaui
    USING_NEW_BINJA = "qt_major_version" in binaryninjaui.__dict__ and binaryninjaui.qt_major_version == 6
    USING_OLD_BINJA = not(USING_NEW_BINJA)
except ImportError:
    USING_NEW_BINJA = False
    USING_OLD_BINJA = False

def _install_pyside_aliases():
    """
    Add the small PyQt-style aliases used throughout Lighthouse.
    """
    QtCore.pyqtSignal = QtCore.Signal
    QtCore.pyqtSlot = QtCore.Slot
    QtWidgets.QAction = QtGui.QAction

def _install_exec_aliases():
    """
    Preserve PyQt's exec_() spelling when running on PySide6 / Qt6.
    """
    for class_name in ("QDialog", "QFileDialog", "QInputDialog", "QMenu", "QMessageBox"):
        cls = getattr(QtWidgets, class_name, None)
        if not cls or hasattr(cls, "exec_") or not hasattr(cls, "exec"):
            continue
        try:
            setattr(cls, "exec_", getattr(cls, "exec"))
        except TypeError:
            pass

def qt_exec(widget):
    """
    Execute a Qt dialog/menu with either PyQt5 or PySide6 spelling.
    """
    if hasattr(widget, "exec"):
        return widget.exec()
    return widget.exec_()

def _try_import_pyqt5():
    global QtGui, QtCore, QtWidgets, QT_AVAILABLE, USING_PYQT5, wrapinstance

    try:
        import PyQt5.QtGui as QtGui
        import PyQt5.QtCore as QtCore
        import PyQt5.QtWidgets as QtWidgets
        try:
            import sip
        except ImportError:
            from PyQt5 import sip

        # importing went okay, PyQt5 must be available for use
        QT_AVAILABLE = True
        USING_PYQT5 = True
        wrapinstance = sip.wrapinstance
        _install_exec_aliases()
        return True

    # import failed, PyQt5 is not available
    except ImportError:
        return False

def _try_import_pyside2():
    global QtGui, QtCore, QtWidgets, QT_AVAILABLE, USING_PYSIDE2, wrapinstance

    try:
        import PySide2.QtGui as QtGui
        import PySide2.QtCore as QtCore
        import PySide2.QtWidgets as QtWidgets
        import shiboken2

        # importing went okay, PySide must be available for use
        QT_AVAILABLE = True
        USING_PYSIDE2 = True
        wrapinstance = shiboken2.wrapInstance
        _install_pyside_aliases()
        _install_exec_aliases()
        return True

    # import failed. No Qt / UI bindings available...
    except ImportError:
        return False

def _try_import_pyside6():
    global QtGui, QtCore, QtWidgets, QT_AVAILABLE, USING_PYSIDE6, wrapinstance

    try:
        import PySide6.QtGui as QtGui
        import PySide6.QtCore as QtCore
        import PySide6.QtWidgets as QtWidgets
        import shiboken6

        # importing went okay, PySide must be available for use
        QT_AVAILABLE = True
        USING_PYSIDE6 = True
        wrapinstance = shiboken6.wrapInstance
        _install_pyside_aliases()
        _install_exec_aliases()
        return True

    # import failed. No Qt / UI bindings available...
    except ImportError:
        return False

#------------------------------------------------------------------------------
# IDA Qt Compatibility
#------------------------------------------------------------------------------

if USING_IDA:
    if IDA_SDK_VERSION >= 920:
        _try_import_pyside6()

    if not QT_AVAILABLE:
        _try_import_pyqt5()

    if not QT_AVAILABLE:
        _try_import_pyside6()

#------------------------------------------------------------------------------
# PySide2 Compatibility
#------------------------------------------------------------------------------

# if PyQt5 did not import, try to load PySide2 (Old Binary Ninja / Cutter)
if not QT_AVAILABLE and USING_OLD_BINJA:
    _try_import_pyside2()

#------------------------------------------------------------------------------
# PySide6 Compatibility
#------------------------------------------------------------------------------

# If all else fails, try to load PySide6 (New Binary Ninja)
if not QT_AVAILABLE and USING_NEW_BINJA:
    _try_import_pyside6()
