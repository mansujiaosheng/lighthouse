import glob
import os
import shlex
import shutil
import subprocess
import struct
import tempfile
import threading
import time

try:
    import Queue as queue
except ImportError:
    import queue


class DrcovRunError(RuntimeError):
    pass


PE_MACHINE_X86 = 0x014C
PE_MACHINE_X64 = 0x8664
PE_MACHINE_ARM64 = 0xAA64
WRONG_ARCHITECTURE_TEXT = "wrong architecture"
WINDOWS_DRRUN_UNSAFE_CHARS = ("'", "`")


def makedirs(path):
    """
    Make a fully qualified path if it does not already exist.
    """
    try:
        os.makedirs(path)
    except OSError:
        if not os.path.isdir(path):
            raise


def split_target_args(args):
    """
    Split user supplied target arguments for subprocess execution.
    """
    if not args:
        return []
    return shlex.split(args, posix=(os.name != "nt"))


def has_windows_drrun_unsafe_chars(path):
    """
    Return True if a path contains characters that confuse drrun on Windows.
    """
    return os.name == "nt" and any(ch in path for ch in WINDOWS_DRRUN_UNSAFE_CHARS)


def prepare_drrun_paths(target_path, output_dir):
    """
    Prepare safe paths for drrun while preserving the final output directory.
    """
    if not (has_windows_drrun_unsafe_chars(target_path) or has_windows_drrun_unsafe_chars(output_dir)):
        return target_path, output_dir, None, {}

    shadow_dir = tempfile.mkdtemp(prefix="lighthouse-drcov-")
    shadow_target = os.path.join(shadow_dir, "target.exe")
    shadow_output = os.path.join(shadow_dir, "logs")
    makedirs(shadow_output)

    try:
        os.link(target_path, shadow_target)
    except OSError:
        shutil.copy2(target_path, shadow_target)

    replacements = {
        shadow_target: target_path,
        os.path.basename(shadow_target): os.path.basename(target_path),
    }
    return shadow_target, shadow_output, shadow_dir, replacements


def patch_drcov_log_paths(filepath, replacements):
    """
    Patch shadow paths in text drcov logs back to the original target path.
    """
    if not replacements:
        return

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            data = f.read()
    except TypeError:
        with open(filepath, "r") as f:
            data = f.read()

    for old, new in replacements.items():
        data = data.replace(old, new)
        data = data.replace(old.replace("\\", "/"), new.replace("\\", "/"))

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(data)
    except TypeError:
        with open(filepath, "w") as f:
            f.write(data)


def finalize_drcov_logs(logs, output_dir, shadow_dir, replacements=None):
    """
    Move logs from a safe temporary directory to the requested output directory.
    """
    if not shadow_dir:
        return logs

    makedirs(output_dir)
    moved_logs = []
    for log_path in logs:
        patch_drcov_log_paths(log_path, replacements)
        destination = os.path.join(output_dir, os.path.basename(log_path))
        if os.path.exists(destination):
            root, ext = os.path.splitext(destination)
            destination = "%s_%u%s" % (root, int(time.time()), ext)
        shutil.move(log_path, destination)
        moved_logs.append(destination)

    shutil.rmtree(shadow_dir, ignore_errors=True)
    return moved_logs


def is_64bit_pe(filepath, default=None):
    """
    Return whether a PE file is 64bit, or default if it cannot be detected.
    """
    try:
        with open(filepath, "rb") as f:
            if f.read(2) != b"MZ":
                return default
            f.seek(0x3C)
            pe_offset = struct.unpack("<I", f.read(4))[0]
            f.seek(pe_offset)
            if f.read(4) != b"PE\x00\x00":
                return default
            machine = struct.unpack("<H", f.read(2))[0]
    except (IOError, OSError, struct.error):
        return default

    if machine in (PE_MACHINE_X64, PE_MACHINE_ARM64):
        return True
    if machine == PE_MACHINE_X86:
        return False
    return default


def is_wrong_architecture_error(error):
    """
    Return True if an error came from a DynamoRIO architecture mismatch.
    """
    return WRONG_ARCHITECTURE_TEXT in str(error).lower()


def run_drcov(drrun_path, target_path, target_args, output_dir, working_dir=None, stdin_data=None):
    """
    Run a target under DynamoRIO drcov and return generated log files.
    """
    makedirs(output_dir)
    run_target_path, run_output_dir, shadow_dir, replacements = prepare_drrun_paths(target_path, output_dir)

    before = set(glob.glob(os.path.join(run_output_dir, "drcov*.log")))
    command = [
        drrun_path,
        "-t", "drcov",
        "-dump_text",
        "-logdir", run_output_dir,
        "--",
        run_target_path,
    ] + split_target_args(target_args)

    start_time = time.time()
    try:
        process = subprocess.Popen(
            command,
            cwd=working_dir or os.path.dirname(target_path) or None,
            stdin=subprocess.PIPE if stdin_data else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        output, _ = process.communicate(stdin_data)
    except OSError as e:
        if shadow_dir:
            shutil.rmtree(shadow_dir, ignore_errors=True)
        raise DrcovRunError(str(e))

    after = set(glob.glob(os.path.join(run_output_dir, "drcov*.log")))
    logs = sorted(
        after - before,
        key=lambda path: os.path.getmtime(path)
    )

    if not logs:
        # Some DynamoRIO builds can reuse file names on rapid reruns. Fall back
        # to files modified during this run.
        logs = sorted(
            [
                path for path in after
                if os.path.getmtime(path) >= start_time
            ],
            key=lambda path: os.path.getmtime(path)
        )

    if not logs:
        message = "DynamoRIO 没有生成 drcov 日志。"
        if output:
            message += "\n\n%s" % output[-4000:]
        if shadow_dir:
            shutil.rmtree(shadow_dir, ignore_errors=True)
        raise DrcovRunError(message)

    logs = finalize_drcov_logs(logs, output_dir, shadow_dir, replacements)

    return {
        "command": command,
        "drrun_path": drrun_path,
        "logs": logs,
        "output": output,
        "returncode": process.returncode,
    }


def run_drcov_any(drrun_paths, target_path, target_args, output_dir, working_dir=None, stdin_data=None):
    """
    Try one or more drrun paths, falling back on architecture mismatch.
    """
    if isinstance(drrun_paths, str):
        drrun_paths = [drrun_paths]

    errors = []
    for drrun_path in drrun_paths:
        try:
            return run_drcov(
                drrun_path,
                target_path,
                target_args,
                output_dir,
                working_dir,
                stdin_data
            )
        except DrcovRunError as e:
            errors.append((drrun_path, e))
            if is_wrong_architecture_error(e):
                continue
            raise

    message = "DynamoRIO 无法用可用架构运行目标程序。"
    for drrun_path, error in errors:
        message += "\n\n[%s]\n%s" % (drrun_path, error)
    raise DrcovRunError(message)


def run_drcov_async(drrun_paths, target_path, target_args, output_dir, working_dir=None, stdin_data=None):
    """
    Run DynamoRIO in a worker thread and return a queue future.
    """
    result_queue = queue.Queue()

    def worker():
        try:
            result_queue.put(run_drcov_any(
                drrun_paths,
                target_path,
                target_args,
                output_dir,
                working_dir,
                stdin_data
            ))
        except Exception as e:
            result_queue.put(e)

    thread = threading.Thread(target=worker, name="LighthouseDrcov")
    thread.daemon = True
    thread.start()
    return result_queue
