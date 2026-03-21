"""
gui.py — ncr-cipher desktop GUI (single file, stdlib only, zero extra deps)
Launch: python gui.py
"""
from __future__ import annotations

import os
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk

# ── Try to import ncr_cipher ──────────────────────────────────────────────────
try:
    from ncr_cipher import NCRKey, NCRError, NCRAuthError, NCRFormatError
    _HAS_NCR = True
except ImportError:
    _HAS_NCR = False

# ── Theme colours ─────────────────────────────────────────────────────────────
BG       = "#1e1e2e"
BG2      = "#2a2a3e"
BG3      = "#313145"
FG       = "#cdd6f4"
FG_DIM   = "#7f849c"
ACCENT   = "#89b4fa"
GREEN    = "#a6e3a1"
RED      = "#f38ba8"
YELLOW   = "#f9e2af"
BORDER   = "#45475a"

FONT     = ("Segoe UI", 10) if sys.platform == "win32" else ("SF Pro Text", 10) if sys.platform == "darwin" else ("Ubuntu", 10)
FONT_B   = (FONT[0], 10, "bold")
FONT_SM  = (FONT[0], 9)
FONT_MON = ("Consolas", 9) if sys.platform == "win32" else ("Menlo", 9) if sys.platform == "darwin" else ("DejaVu Sans Mono", 9)

APP_TITLE   = "ncr-cipher  v2.2.0"
MIN_W, MIN_H = 480, 400


# ── Helper widgets ────────────────────────────────────────────────────────────
class DarkEntry(tk.Entry):
    def __init__(self, master, show="", **kw):
        super().__init__(master,
            bg=BG3, fg=FG, insertbackground=FG,
            relief="flat", bd=0, highlightthickness=1,
            highlightbackground=BORDER, highlightcolor=ACCENT,
            font=FONT, show=show, **kw)


class DarkButton(tk.Button):
    def __init__(self, master, **kw):
        kw.setdefault("bg", BG3)
        kw.setdefault("fg", FG)
        kw.setdefault("activebackground", ACCENT)
        kw.setdefault("activeforeground", BG)
        kw.setdefault("relief", "flat")
        kw.setdefault("bd", 0)
        kw.setdefault("padx", 12)
        kw.setdefault("pady", 6)
        kw.setdefault("cursor", "hand2")
        kw.setdefault("font", FONT_B)
        super().__init__(master, **kw)


class FilePickerRow(tk.Frame):
    """Button + label that lets the user pick a file."""
    def __init__(self, master, label: str, save: bool = False, **kw):
        super().__init__(master, bg=BG2, **kw)
        self._path  = tk.StringVar()
        self._save  = save
        self._label = label

        DarkButton(self, text="📂 " + label, width=18,
                   command=self._pick).pack(side="left", padx=(0, 8))
        lbl = tk.Label(self, textvariable=self._path, fg=FG_DIM, bg=BG2,
                       font=FONT_SM, anchor="w", wraplength=280)
        lbl.pack(side="left", fill="x", expand=True)

    def _pick(self):
        if self._save:
            path = filedialog.asksaveasfilename(title=self._label)
        else:
            path = filedialog.askopenfilename(title=self._label)
        if path:
            self._path.set(path)

    @property
    def path(self) -> str:
        return self._path.get()


class PasswordRow(tk.Frame):
    """Label + hidden entry + show/hide toggle."""
    def __init__(self, master, label: str = "Password", **kw):
        super().__init__(master, bg=BG2, **kw)
        tk.Label(self, text=label, fg=FG_DIM, bg=BG2,
                 font=FONT, width=14, anchor="w").pack(side="left")
        self._var   = tk.StringVar()
        self._show  = False
        self._entry = DarkEntry(self, textvariable=self._var, show="●", width=24)
        self._entry.pack(side="left", ipady=4, padx=(0, 4))
        self._btn = DarkButton(self, text="👁", width=3, padx=4,
                               command=self._toggle)
        self._btn.pack(side="left")

    def _toggle(self):
        self._show = not self._show
        self._entry.config(show="" if self._show else "●")

    @property
    def value(self) -> str:
        return self._var.get()

    def clear(self):
        self._var.set("")


# ── Tab base ──────────────────────────────────────────────────────────────────
class BaseTab(tk.Frame):
    def __init__(self, master, status_cb, **kw):
        super().__init__(master, bg=BG2, **kw)
        self._status_cb  = status_cb
        self._busy       = False

    def _set_status(self, msg: str, ok: bool = True):
        self._status_cb(msg, ok)

    def _run_bg(self, fn, *args):
        """Run *fn* in a daemon thread, disable/enable buttons around it."""
        self._busy = True
        self._set_widgets_state("disabled")
        def _worker():
            try:
                fn(*args)
            finally:
                self._busy = False
                self.after(0, lambda: self._set_widgets_state("normal"))
        threading.Thread(target=_worker, daemon=True).start()

    def _set_widgets_state(self, state: str):
        for w in self.winfo_children():
            try:
                w.config(state=state)
            except tk.TclError:
                pass


# ── Keygen tab ────────────────────────────────────────────────────────────────
class KeygenTab(BaseTab):
    def __init__(self, master, status_cb):
        super().__init__(master, status_cb)
        self._build()

    def _build(self):
        pad = {"padx": 16, "pady": 6}

        tk.Label(self, text="Generate a new key file", fg=FG, bg=BG2,
                 font=FONT_B).pack(anchor="w", **pad)

        self._pw1 = PasswordRow(self, label="Password")
        self._pw1.pack(fill="x", **pad)
        self._pw2 = PasswordRow(self, label="Confirm")
        self._pw2.pack(fill="x", **pad)

        self._dest = FilePickerRow(self, "Save key as…", save=True)
        self._dest.pack(fill="x", **pad)

        # N slider
        row = tk.Frame(self, bg=BG2)
        row.pack(fill="x", **pad)
        tk.Label(row, text="Strength (N)", fg=FG_DIM, bg=BG2,
                 font=FONT, width=14, anchor="w").pack(side="left")
        self._n_var = tk.IntVar(value=17)
        tk.Scale(row, from_=14, to=20, orient="horizontal",
                 variable=self._n_var, bg=BG2, fg=FG, troughcolor=BG3,
                 highlightthickness=0, font=FONT_SM,
                 label="log₂(N)").pack(side="left", fill="x", expand=True)

        self._result_var = tk.StringVar()
        tk.Label(self, textvariable=self._result_var, fg=ACCENT, bg=BG2,
                 font=FONT_MON, wraplength=420, justify="left").pack(anchor="w", **pad)

        self._progress = ttk.Progressbar(self, mode="indeterminate")
        self._progress.pack(fill="x", padx=16, pady=(0, 4))

        DarkButton(self, text="⚙  Generate Key", bg=ACCENT, fg=BG,
                   command=self._go).pack(pady=8)

    def _go(self):
        pw1  = self._pw1.value
        pw2  = self._pw2.value
        dest = self._dest.path
        if not pw1:
            self._set_status("Password cannot be empty.", ok=False); return
        if pw1 != pw2:
            self._set_status("Passwords do not match.", ok=False); return
        if not dest:
            self._set_status("Choose a destination for the key file.", ok=False); return

        N = 2 ** self._n_var.get()
        self._progress.start(10)
        self._result_var.set("")

        def _work():
            try:
                key = NCRKey.generate(pw1.encode(), N=N)
                key.save(dest)
                self.after(0, lambda: self._result_var.set(f"→ {dest}"))
                self._set_status(f"Key saved: {Path(dest).name}", ok=True)
            except Exception as exc:
                self._set_status(str(exc), ok=False)
            finally:
                self.after(0, self._progress.stop)

        self._run_bg(_work)


# ── Lock tab ──────────────────────────────────────────────────────────────────
class LockTab(BaseTab):
    def __init__(self, master, status_cb):
        super().__init__(master, status_cb)
        self._build()

    def _build(self):
        pad = {"padx": 16, "pady": 6}
        tk.Label(self, text="Encrypt a file", fg=FG, bg=BG2,
                 font=FONT_B).pack(anchor="w", **pad)

        self._src  = FilePickerRow(self, "File to encrypt")
        self._src.pack(fill="x", **pad)
        self._key  = FilePickerRow(self, "Key file")
        self._key.pack(fill="x", **pad)
        self._pw   = PasswordRow(self, label="Password")
        self._pw.pack(fill="x", **pad)

        self._result_var = tk.StringVar()
        tk.Label(self, textvariable=self._result_var, fg=GREEN, bg=BG2,
                 font=FONT_MON, wraplength=420, justify="left").pack(anchor="w", **pad)

        self._progress = ttk.Progressbar(self, mode="indeterminate")
        self._progress.pack(fill="x", padx=16, pady=(0, 4))

        DarkButton(self, text="🔒  Lock", bg=ACCENT, fg=BG,
                   command=self._go).pack(pady=8)

    def _go(self):
        src = self._src.path
        kf  = self._key.path
        pw  = self._pw.value
        if not src:
            self._set_status("Choose a file to encrypt.", ok=False); return
        if not kf:
            self._set_status("Choose a key file.", ok=False); return
        if not pw:
            self._set_status("Password cannot be empty.", ok=False); return

        self._progress.start(10)
        self._result_var.set("")

        def _work():
            try:
                key = NCRKey.load(kf, pw.encode())
                out = key.encrypt_file(src)
                self.after(0, lambda: self._result_var.set(f"→ {out}"))
                self._set_status(f"Locked → {out.name}", ok=True)
            except NCRAuthError as e:
                self._set_status(f"Auth error: {e}", ok=False)
            except NCRError as e:
                self._set_status(str(e), ok=False)
            except Exception as e:
                self._set_status(str(e), ok=False)
            finally:
                self.after(0, self._progress.stop)

        self._run_bg(_work)


# ── Unlock tab ────────────────────────────────────────────────────────────────
class UnlockTab(BaseTab):
    def __init__(self, master, status_cb):
        super().__init__(master, status_cb)
        self._build()

    def _build(self):
        pad = {"padx": 16, "pady": 6}
        tk.Label(self, text="Decrypt a file", fg=FG, bg=BG2,
                 font=FONT_B).pack(anchor="w", **pad)

        self._src  = FilePickerRow(self, "File to decrypt (.ncr)")
        self._src.pack(fill="x", **pad)
        self._key  = FilePickerRow(self, "Key file")
        self._key.pack(fill="x", **pad)
        self._pw   = PasswordRow(self, label="Password")
        self._pw.pack(fill="x", **pad)

        self._result_var = tk.StringVar()
        tk.Label(self, textvariable=self._result_var, fg=GREEN, bg=BG2,
                 font=FONT_MON, wraplength=420, justify="left").pack(anchor="w", **pad)

        self._progress = ttk.Progressbar(self, mode="indeterminate")
        self._progress.pack(fill="x", padx=16, pady=(0, 4))

        DarkButton(self, text="🔓  Unlock", bg=ACCENT, fg=BG,
                   command=self._go).pack(pady=8)

    def _go(self):
        src = self._src.path
        kf  = self._key.path
        pw  = self._pw.value
        if not src:
            self._set_status("Choose a .ncr file to decrypt.", ok=False); return
        if not kf:
            self._set_status("Choose a key file.", ok=False); return
        if not pw:
            self._set_status("Password cannot be empty.", ok=False); return

        self._progress.start(10)
        self._result_var.set("")

        def _work():
            try:
                key = NCRKey.load(kf, pw.encode())
                out = key.decrypt_file(src)
                self.after(0, lambda: self._result_var.set(f"→ {out}"))
                self._set_status(f"Unlocked → {out.name}", ok=True)
            except NCRAuthError as e:
                self._set_status(f"Auth error: {e}", ok=False)
            except NCRError as e:
                self._set_status(str(e), ok=False)
            except Exception as e:
                self._set_status(str(e), ok=False)
            finally:
                self.after(0, self._progress.stop)

        self._run_bg(_work)


# ── Main App ──────────────────────────────────────────────────────────────────
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.minsize(MIN_W, MIN_H)
        self.configure(bg=BG)
        self._apply_style()
        self._build()

    # ── ttk dark style ────────────────────────────────────────────────────────
    def _apply_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TNotebook",
            background=BG, borderwidth=0)
        style.configure("TNotebook.Tab",
            background=BG3, foreground=FG_DIM,
            padding=[14, 6], font=FONT,
            borderwidth=0)
        style.map("TNotebook.Tab",
            background=[("selected", BG2)],
            foreground=[("selected", FG)])
        style.configure("TProgressbar",
            troughcolor=BG3, background=ACCENT, borderwidth=0, thickness=4)
        style.configure("TFrame", background=BG2)

    # ── Layout ────────────────────────────────────────────────────────────────
    def _build(self):
        # Title bar
        title_bar = tk.Frame(self, bg=BG, pady=8)
        title_bar.pack(fill="x")
        tk.Label(title_bar, text="🔐  " + APP_TITLE, fg=ACCENT, bg=BG,
                 font=(FONT[0], 13, "bold")).pack(side="left", padx=16)

        # Install hint (when ncr_cipher missing)
        if not _HAS_NCR:
            hint = tk.Frame(self, bg=BG3, padx=12, pady=10)
            hint.pack(fill="x", padx=12, pady=4)
            tk.Label(hint,
                     text="⚠  ncr_cipher not installed.\n"
                          "Run:  pip install ncr-cipher",
                     fg=YELLOW, bg=BG3, font=FONT, justify="left").pack()
            return

        # Notebook
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        self._status_var = tk.StringVar(value="Ready.")
        self._status_ok  = True

        for label, cls in [
            ("🔑  Keygen", KeygenTab),
            ("🔒  Lock",   LockTab),
            ("🔓  Unlock", UnlockTab),
        ]:
            frame = cls(nb, self._set_status)
            nb.add(frame, text=label)

        # Status bar
        bar = tk.Frame(self, bg=BG, pady=4)
        bar.pack(fill="x", side="bottom")
        tk.Frame(bar, bg=BORDER, height=1).pack(fill="x")
        self._status_lbl = tk.Label(bar, textvariable=self._status_var,
                                    fg=GREEN, bg=BG, font=FONT_SM,
                                    anchor="w", padx=12)
        self._status_lbl.pack(fill="x")

    def _set_status(self, msg: str, ok: bool = True):
        def _update():
            self._status_var.set(("✓  " if ok else "✗  ") + msg)
            self._status_lbl.config(fg=GREEN if ok else RED)
        self.after(0, _update)


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = App()
    app.mainloop()
