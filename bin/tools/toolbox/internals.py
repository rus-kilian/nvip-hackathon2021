import os
import sys
import select
import time
import termios
from colorama import Fore, Style
from colorama.ansi import clear_line
from multiprocessing import Process, Pipe


def colorprint(fgcolor, text, end="\n", prefix=""):
    print(prefix + fgcolor + text + Style.RESET_ALL, end=end)


def redprint(text, end="\n", prefix=""):
    colorprint(Fore.RED, text, end=end, prefix=prefix)


def greenprint(text, end="\n", prefix=""):
    colorprint(Fore.GREEN, text, end=end, prefix=prefix)


def yellowprint(text, end="\n", prefix=""):
    colorprint(Style.BRIGHT + Fore.YELLOW, text, end=end, prefix=prefix)


def blueprint(text, end="\n", prefix=""):
    colorprint(Fore.CYAN, text, end=end, prefix=prefix)


def statusprint(text=""):
    print(clear_line() + "\r" + text, end="")


def abort(text, exitcode=1):
    redprint(text)
    sys.exit(exitcode)


def wait_for_keypress(c2, text, timeout):
    _t = time.time() + timeout
    try:
        while True:
            while not c2.poll():
                _time_remain = _t - time.time()
                if _time_remain < 0:
                    return
                spinner(Fore.YELLOW + text + Style.RESET_ALL, "[%02d]" % _time_remain)
                time.sleep(0.5)
    except KeyboardInterrupt:
        pass


def set_nonblocking():
    old_settings = termios.tcgetattr(sys.stdin)
    new_settings = termios.tcgetattr(sys.stdin)
    new_settings[3] = new_settings[3] & ~(termios.ECHO | termios.ICANON)  # lflags
    new_settings[6][termios.VMIN] = 0  # cc
    new_settings[6][termios.VTIME] = 0  # cc
    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, new_settings)
    return old_settings


def revert_nonblocking(old_settings):
    if old_settings:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)


def _create_char_spinner():
    """Creates a generator yielding a char based spinner."""
    while True:
        for character in "|/-\\":
            yield character


_spinner = _create_char_spinner()


def spinner(label="", prefix=""):
    """Prints label with a spinner.
    When called repeatedly from inside a loop this prints
    a one line CLI spinner.
    """
    _text = "\r"
    if prefix:
        _text += prefix + " "
    _text += label + " " + next(_spinner)
    sys.stdout.write(_text)
    sys.stdout.flush()


def prompt_action(backups, description, action="Restore"):
    if len(backups) == 1:
        backup = backups[0]
        ans = timeout_input(
            "%s %s '%s' ?" % (action, description, backup), hint="(Y/n)"
        )
        if ans == "n":
            backup = None
    else:
        _action = action.lower()
        print("Found several %s for %s:" % (description, _action))
        for idx, val in enumerate(backups):
            print("%d: %s" % (1 + idx, val))
        print(
            "%sn: Do not %s %s"
            % (int((len(backups) / 10) - 1) * " ", _action, description)
        )
        if len(backups) > 9:
            res = input(  # nosec: B322
                "Which %s to %s? (Default=1)" % (description, _action)
            ).strip()
        else:
            res = timeout_input(
                "Which %s to %s?" % (description, _action), hint="Default=1"
            )
        if not res:
            res = 1
        if res == "n":
            return
        try:
            res = int(res)
        except ValueError:
            res = 1
        if res < 1 or res > len(backups) + 1:
            abort("No such %s %d" % (description, res))
        else:
            backup = backups[res - 1]
    return backup


def timeout_input(text, timeout=30, hint="(press RETURN to skip)", end="\n"):
    _input = None
    old_settings = set_nonblocking()
    try:
        c1, c2 = Pipe()
        p = Process(
            target=wait_for_keypress,
            args=(c2, text + " " + hint, timeout),
        )
        p.start()
        _t = time.time() + timeout
        while [sys.stdin]:
            _time_remain = _t - time.time()
            if _time_remain < 0:
                break

            ready = select.select([sys.stdin], [], [], 0.1)[0]
            if not ready:
                time.sleep(0.1)
            else:
                _input = os.read(sys.stdin.fileno(), 1)
                break
        c1.send(None)
        p.terminate()
        revert_nonblocking(old_settings)
        if _input:
            _ans = _input.decode("utf-8").strip()
            print(clear_line() + "\r%s " % text, end="")
            colorprint(_ans, Style.BRIGHT + Fore.WHITE, end=end)
            return _ans
        else:
            blueprint(clear_line() + "\r%s" % text, end=end)
    except KeyboardInterrupt:
        revert_nonblocking(old_settings)
        print("")
        yellowprint("Execution aborted.")
        raise SystemExit(-99)
