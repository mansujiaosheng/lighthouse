import glob
import os
import shlex
import subprocess
import threading
import time

try:
    import Queue as queue
except ImportError:
    import queue


class DrcovRunError(RuntimeError):
    pass


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
    return shlex.split(args)


def run_drcov(drrun_path, target_path, target_args, output_dir, working_dir=None):
    """
    Run a target under DynamoRIO drcov and return generated log files.
    """
    makedirs(output_dir)

    before = set(glob.glob(os.path.join(output_dir, "drcov*.log")))
    command = [
        drrun_path,
        "-t", "drcov",
        "-dump_text",
        "-logdir", output_dir,
        "--",
        target_path,
    ] + split_target_args(target_args)

    start_time = time.time()
    try:
        process = subprocess.Popen(
            command,
            cwd=working_dir or os.path.dirname(target_path) or None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        output, _ = process.communicate()
    except OSError as e:
        raise DrcovRunError(str(e))

    after = set(glob.glob(os.path.join(output_dir, "drcov*.log")))
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
        raise DrcovRunError(message)

    return {
        "command": command,
        "logs": logs,
        "output": output,
        "returncode": process.returncode,
    }


def run_drcov_async(drrun_path, target_path, target_args, output_dir, working_dir=None):
    """
    Run DynamoRIO in a worker thread and return a queue future.
    """
    result_queue = queue.Queue()

    def worker():
        try:
            result_queue.put(run_drcov(
                drrun_path,
                target_path,
                target_args,
                output_dir,
                working_dir
            ))
        except Exception as e:
            result_queue.put(e)

    thread = threading.Thread(target=worker, name="LighthouseDrcov")
    thread.daemon = True
    thread.start()
    return result_queue
