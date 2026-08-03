"""The bot must not promise protection it is not providing.

Property under test, in both directions:

  the /start copy mentions group watching  IF AND ONLY IF  main() actually
  registers the group handler.

Guardian mode is off in production (@BotFather has can_join_groups and
can_read_all_group_messages both false), so the shipped /start must say the
bot works in private chat only. This suite is stdlib-only by design, per the
README, so it injects a minimal `telegram` stub when python-telegram-bot is
not importable. The stub records which callbacks main() wires up, which is
the observable we care about.
"""

import importlib
import sys
import tempfile
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[0].parent))

GROUP_WORDS = ("group", "groups")


def _install_telegram_stub():
    """Minimal stand-in for python-telegram-bot, if the real one is absent."""
    try:
        import telegram  # noqa: F401
        import telegram.ext  # noqa: F401
        return
    except Exception:
        pass

    class _Filter:
        def __and__(self, other):
            return self

        def __rand__(self, other):
            return self

        def __invert__(self):
            return self

    class _ChatType:
        PRIVATE = _Filter()
        GROUPS = _Filter()

    filters_mod = types.ModuleType("telegram.ext.filters")
    filters_mod.ChatType = _ChatType
    filters_mod.COMMAND = _Filter()

    class _Handler:
        def __init__(self, *args):
            # CommandHandler(name, cb) / MessageHandler(filter, cb)
            self.callback = args[-1]

    class _Builder:
        def __init__(self):
            self.app = _StubApp()

        def token(self, _t):
            return self

        def post_init(self, fn):
            self.app.post_init = fn
            return self

        def build(self):
            return self.app

    class _StubApp:
        def __init__(self):
            self.handlers = []
            self.post_init = None

        @staticmethod
        def builder():
            return _Builder()

        def add_handler(self, h):
            self.handlers.append(h)

        def run_polling(self):
            self.polled = True

    ext = types.ModuleType("telegram.ext")
    ext.Application = _StubApp
    ext.CommandHandler = _Handler
    ext.MessageHandler = _Handler
    ext.ContextTypes = types.SimpleNamespace(DEFAULT_TYPE=object)
    ext.filters = filters_mod

    tg = types.ModuleType("telegram")
    tg.Update = object
    tg.ext = ext
    constants = types.ModuleType("telegram.constants")
    constants.ParseMode = types.SimpleNamespace(HTML="HTML")
    tg.constants = constants

    sys.modules.setdefault("telegram", tg)
    sys.modules.setdefault("telegram.ext", ext)
    sys.modules.setdefault("telegram.ext.filters", filters_mod)
    sys.modules.setdefault("telegram.constants", constants)


def _load_bot(guardian_env):
    """Import bot.py fresh with SCAMSHIELD_GUARDIAN set to `guardian_env`."""
    import os
    _install_telegram_stub()
    db = Path(tempfile.mkdtemp()) / "test_ioc.db"
    old = {k: os.environ.get(k) for k in
           ("SCAMSHIELD_GUARDIAN", "SCAMSHIELD_TOKEN", "SCAMSHIELD_DB")}
    os.environ["SCAMSHIELD_TOKEN"] = "test:token"
    os.environ["SCAMSHIELD_DB"] = str(db)
    if guardian_env is None:
        os.environ.pop("SCAMSHIELD_GUARDIAN", None)
    else:
        os.environ["SCAMSHIELD_GUARDIAN"] = guardian_env
    sys.modules.pop("bot", None)
    try:
        return importlib.import_module("bot")
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        sys.modules.pop("bot", None)


def _registered_callbacks(mod):
    """Run main() against the stub and return the callbacks it wired up."""
    import telegram.ext as ext
    seen = []
    orig_add = ext.Application.add_handler
    orig_run = ext.Application.run_polling
    # Works against the stub and against real python-telegram-bot alike.
    ext.Application.add_handler = lambda self, h, *a, **k: seen.append(h)
    ext.Application.run_polling = lambda self, *a, **k: None
    try:
        mod.main()
    finally:
        ext.Application.add_handler = orig_add
        ext.Application.run_polling = orig_run
    return [h.callback for h in seen]


class GuardianCopyMatchesBehaviour(unittest.TestCase):

    def test_shipped_default_does_not_advertise_groups(self):
        """Guardian off (production): /start must not mention groups
        as something it watches, and on_group must not be registered."""
        mod = _load_bot(None)
        self.assertFalse(mod.GUARDIAN_ENABLED)
        cbs = _registered_callbacks(mod)
        self.assertNotIn(mod.on_group, cbs,
                         "group handler registered while guardian mode off")
        self.assertIn(mod.on_private, cbs, "shield mode must always be on")
        text = mod.start_text().lower()
        # It may say it does NOT do groups; it must not claim it does.
        self.assertNotIn("add me to a group", text)
        self.assertNotIn("i'll watch it for you", text)
        self.assertTrue(
            "don't monitor groups" in text or "do not monitor groups" in text,
            "/start must state plainly that groups are not covered")

    def test_enabling_guardian_turns_on_both_copy_and_handler(self):
        """The flag moves copy and behaviour together, never one alone."""
        mod = _load_bot("1")
        self.assertTrue(mod.GUARDIAN_ENABLED)
        cbs = _registered_callbacks(mod)
        self.assertIn(mod.on_group, cbs)
        text = mod.start_text().lower()
        self.assertIn("group", text)
        self.assertNotIn("don't monitor groups", text)

    def test_copy_and_handler_never_disagree(self):
        """The invariant itself, stated once, checked in both states."""
        for env in (None, "0", "1"):
            with self.subTest(SCAMSHIELD_GUARDIAN=env):
                mod = _load_bot(env)
                cbs = _registered_callbacks(mod)
                handler_on = mod.on_group in cbs
                text = mod.start_text().lower()
                claims_groups = any(
                    p in text for p in ("add me to a group",
                                        "watch every message there",
                                        "watch it for you"))
                self.assertEqual(
                    claims_groups, handler_on,
                    "/start advertises group protection = %s but the group "
                    "handler is registered = %s" % (claims_groups, handler_on))

    def test_guardian_implementation_is_preserved_not_deleted(self):
        """Turning the mode off must not have gutted the code path."""
        mod = _load_bot(None)
        self.assertTrue(callable(mod.on_group))
        self.assertEqual(mod.POLICY["CONFIRMED_PATTERN"], "delete")

    def test_docstring_and_switch_document_both_botfather_toggles(self):
        """A future reader must be able to find how to turn this on."""
        src = (Path(__file__).resolve().parents[1] / "bot.py").read_text()
        self.assertIn("Allow Groups?", src)
        self.assertIn("Group Privacy", src)
        self.assertIn("SCAMSHIELD_GUARDIAN=1", src)


if __name__ == "__main__":
    unittest.main()
