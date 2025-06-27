# gui.py

import tkinter as tk
from tkinter import simpledialog, messagebox
from pathlib import Path

from storage import get_usb_path
from auth import set_master_password_from_string, verify_master_password_from_string
from manager import PasswordManager
from utils import generate_password, copy_to_clipboard

# Silently ignore background callback errors
def _ignore_bg_errors(self, exc, val, tb):
    return
tk.Tk.report_callback_exception = _ignore_bg_errors


class ConfirmDialog(simpledialog.Dialog):
    """
    A dialog that captures hidden input (no echo) for confirming passwords.
    """
    def body(self, master):
        tk.Label(master, text="Confirm new master password:").pack(pady=5)
        self.password = ""
        self.entry = tk.Entry(master, show="", width=30)
        self.entry.pack(pady=5)
        self.entry.focus_set()
        # Capture every keystroke, but ignore Enter here
        self.entry.bind("<Key>", self._on_key)
        return self.entry

    def _on_key(self, event):
        if event.keysym == "BackSpace":
            self.password = self.password[:-1]
        elif len(event.char) == 1:
            self.password += event.char
        # Always clear so nothing is shown
        self.entry.delete(0, tk.END)
        return "break"

    def apply(self):
        # Called by ok(), sets self.result
        self.result = self.password

    def ok(self, event=None):
        try:
            self.entry.unbind("<Return>")
        except Exception:
            pass
        return super().ok(event)    


class LoginWindow:
    """A single-window welcome/login screen"""
    def __init__(self):
        self.result = None
        self.password = ""
        self.root = tk.Tk()
        self.root.title("Fun Password Manager")

        # Determine mode
        usb = get_usb_path()
        self.is_new = not (usb / "master.hash").exists()

        # ----- GIF on white background -----
        img_path = Path(__file__).parent / "welcome.gif"
        self._frames = []
        if img_path.exists():
            idx = 0
            while True:
                try:
                    frame = tk.PhotoImage(
                        file=str(img_path),
                        format=f"gif -index {idx}"
                    )
                except tk.TclError:
                    break
                self._frames.append(frame)
                idx += 1

        if self._frames:
            gif_lab = tk.Label(self.root, image=self._frames[0], bg="white")
            gif_lab.pack(pady=10)
            self._anim_label = gif_lab
            # start animation
            self._after_id = self.root.after(100, self._animate, 1)

        # ----- Prompt label -----
        prompt = (
            "No master password found.\nCREATE a master password:"
            if self.is_new else
            "ENTER your master password:"
        )
        tk.Label(
            self.root,
            text=prompt,
            font=("Segoe UI", 14, "bold"),
            justify="center"
        ).pack(pady=(5,10))

        # ----- Hidden Entry -----
        self.pw_entry = tk.Entry(self.root, show="", width=30)
        self.pw_entry.pack()
        self.pw_entry.focus_set()
        # Build our buffer on every keystroke:
        self.pw_entry.bind("<Key>", self._on_key)
        # Bind Enter (method) on both entry and window
        self.pw_entry.bind("<Return>", self.on_ok)


        # ----- Buttons -----
        btns = tk.Frame(self.root)
        btns.pack(pady=15)
        tk.Button(btns, text="OK",     width=12, command=self.on_ok).pack(side="left", padx=10)
        tk.Button(btns, text="Cancel", width=12, command=self.on_cancel).pack(side="left", padx=10)

        self.root.protocol("WM_DELETE_WINDOW", self.on_cancel)
        self.root.mainloop()

    def _animate(self, ind: int):
        frame = self._frames[ind]
        self._anim_label.configure(image=frame)
        nxt = (ind + 1) % len(self._frames)
        self._after_id = self.root.after(100, self._animate, nxt)

    def _on_key(self, event):
        # Leave Return to its own binding
        if event.keysym in ("Return", "KP_Enter"):
            self.on_ok()
            return "break"
        
        if event.keysym == "BackSpace":
            self.password = self.password[:-1]
        elif event.char and len(event.char) == 1:
            self.password += event.char
        # never echo anything
        self.pw_entry.delete(0, tk.END)
        return "break"

    def on_ok(self, event=None):
        # stop animation
        if hasattr(self, "_after_id"):
            self.root.after_cancel(self._after_id)
        try:
            self.pw_entry.unbind("<Return>")
            self.root.unbind("<Return>")
        except Exception:
            pass

        pw = self.password
        usb = get_usb_path()
        mpw_file = usb / "master.hash"

        # --- First‐run: create master ---
        if self.is_new:
            if not pw:
                messagebox.showerror("Error", "Password cannot be empty.")
                return
            # confirm in a little hidden dialog
            confirm = HiddenEntryDialog(
                self.root,
                "Confirm Password",
                "Confirm new master password:"
            ).result
            if confirm != pw or confirm is None:
                messagebox.showerror("Error", "Passwords did not match.")
                # reset and restart the same window
                self.password = ""
                self.root.destroy()
                return LoginWindow()
            key = set_master_password_from_string(pw)
            messagebox.showinfo("Success", "Master password created.")
            self.result = key

        # --- Unlock flow ---
        else:
            key = verify_master_password_from_string(pw)
            if not key:
                messagebox.showerror("Error", "Incorrect master password.")
                self.password = ""
                self.root.destroy()
                return LoginWindow()
            self.result = key

        self.root.destroy()

    def on_cancel(self, event=None):
        if hasattr(self, "_after_id"):
            self.root.after_cancel(self._after_id)
        try:
            self.pw_entry.unbind("<Return>")
            self.root.unbind("<Return>")
        except Exception:
            pass
        self.result = None
        self.root.destroy()



class EntryDialog(simpledialog.Dialog):
    """Dialog for adding or editing a password entry."""
    def __init__(self, parent, title, entry=None):
        self.entry = entry
        super().__init__(parent, title)

    def body(self, master):
        tk.Label(master, text="Label:").grid(row=0, column=0, sticky="e", padx=4, pady=2)
        self.label_var = tk.StringVar(value=(self.entry.label if self.entry else ""))
        tk.Entry(master, textvariable=self.label_var).grid(row=0, column=1, padx=4, pady=2)

        tk.Label(master, text="Username:").grid(row=1, column=0, sticky="e", padx=4, pady=2)
        self.user_var = tk.StringVar(value=(self.entry.username if self.entry else ""))
        tk.Entry(master, textvariable=self.user_var).grid(row=1, column=1, padx=4, pady=2)

        tk.Label(master, text="Password:").grid(row=2, column=0, sticky="e", padx=4, pady=2)
        self.pwd_var = tk.StringVar()
        pwd_entry = tk.Entry(master, textvariable=self.pwd_var, show="*")
        pwd_entry.grid(row=2, column=1, padx=4, pady=2)

        tk.Label(master, text="Notes:").grid(row=3, column=0, sticky="ne", padx=4, pady=2)
        self.notes_text = tk.Text(master, width=30, height=4)
        self.notes_text.grid(row=3, column=1, padx=4, pady=2)
        if self.entry and self.entry.notes:
            self.notes_text.insert("1.0", self.entry.notes)

        return pwd_entry

    def apply(self):
        label = self.label_var.get().strip()
        user  = self.user_var.get().strip()
        pwd   = self.pwd_var.get() or None
        notes = self.notes_text.get("1.0", "end").strip() or None
        self.result = (label, user, pwd, notes)

class HiddenEntryDialog(simpledialog.Dialog):
    def __init__(self, parent, title, prompt):
        self.prompt = prompt
        self.password = ""
        super().__init__(parent, title)

    def body(self, master):
        tk.Label(master, text=self.prompt).pack(pady=5)
        self.entry = tk.Entry(master, show="", width=30)
        self.entry.pack(pady=5)
        self.entry.focus_set()

        # Capture keystrokes
        self.entry.bind("<Key>", self._on_key)
        

        return self.entry

    def _on_key(self, event):
        if event.keysym in ("Return", "KP_Enter"):
                self.ok()
                return "break"
        if event.keysym == "BackSpace":
            self.password = self.password[:-1]
        elif event.char and len(event.char) == 1:
            self.password += event.char
        
        # Never let Tk echo anything
        self.entry.delete(0, tk.END)
        return "break"

    def apply(self):
        self.result = self.password

    def ok(self, event=None):
        try:
            self.entry.unbind("<Return>")
        except Exception:
            pass
        return super().ok(event)    


class MainWindow(tk.Tk):
    def __init__(self, key):
        super().__init__()
        self.title("USB Password Manager")
        self.key = key
        self.pm = PasswordManager.load(key)
        self.build_ui()

    def build_ui(self):
        toolbar = tk.Frame(self)
        toolbar.pack(fill="x")

        for (text, cmd) in [
            ("Add",      self.add_entry),
            ("View",     self.view_entry),
            ("Update",   self.update_entry),
            ("Delete",   self.delete_entry),
            ("Gen Pass", self.gen_password),
            ("Change MPW", self.change_master)
        ]:
            tk.Button(toolbar, text=text, command=cmd).pack(side="left", padx=2, pady=2)

        self.listbox = tk.Listbox(self, width=50)
        self.listbox.pack(fill="both", expand=True, padx=5, pady=5)
        self.refresh_list()

    def refresh_list(self):
        self.listbox.delete(0, tk.END)
        for e in self.pm.list_entries():
            self.listbox.insert(tk.END, f"{e.label} — {e.username}")

    def add_entry(self):
        dlg = EntryDialog(self, "Add Entry")
        if not getattr(dlg, "result", None):
            return
        label, user, pwd, notes = dlg.result
        self.pm.add_entry(label, user, pwd, notes, self.key)
        self.refresh_list()

    def view_entry(self):
        sel = self.listbox.curselection()
        if not sel:
            return
        e = self.pm.list_entries()[sel[0]]
        pwd = e.get_password()
        copy_to_clipboard(pwd)
        messagebox.showinfo(e.label,
            "Password copied to clipboard."
        )

    def update_entry(self):
        sel = self.listbox.curselection()
        if not sel:
            return
        e = self.pm.list_entries()[sel[0]]
        dlg = EntryDialog(self, "Edit Entry", entry=e)
        if not getattr(dlg, "result", None):
            return
        label, user, pwd, notes = dlg.result
        self.pm.update_entry(sel[0], label, user, pwd, notes, self.key)
        self.refresh_list()

    def delete_entry(self):
        sel = self.listbox.curselection()
        if not sel:
            return
        if messagebox.askyesno("Confirm", "Delete selected entry?"):
            self.pm.delete_entry(sel[0])
            self.refresh_list()

    def gen_password(self):
        length = simpledialog.askinteger("Length", "Password length:", minvalue=8, initialvalue=16)
        if length:
            pwd = generate_password(length)
            copy_to_clipboard(pwd)
            messagebox.showinfo("Generated", f"Password copied ({length} chars)")

    def change_master(self):
        old_key = self.key

        # Prompt for new master
        dlg1 = HiddenEntryDialog(
            self, "Change Master", "Type new master password:"
        )
        pw1 = dlg1.result
        if pw1 is None or pw1 == "":
            return

        # Confirm it
        pw2 = HiddenEntryDialog(
            self, "Confirm New Master", "Confirm new master password:"
        ).result
        if pw2 != pw1 or pw2 is None:
            messagebox.showerror("Error", "Passwords did not match.")
            return

        # Rotate everything
        new_key = set_master_password_from_string(pw1)
        for i, entry in enumerate(self.pm.list_entries()):
            plain = entry.get_password(old_key)
            self.pm.update_entry(i, None, None, plain, None, new_key)

        self.key = new_key
        self.pm.save(new_key)
        messagebox.showinfo("Success", "Master password changed.")

    def on_closing(self):
        self.pm.save(self.key)
        self.destroy()


def run_gui():
    # Launch login + welcome
    login = LoginWindow()
    key = login.result
    if not key:
        return

    # Create main window *after* we have the key
    app = MainWindow(key)
    # Now set size & minimums here to avoid recursion
    app.geometry("800x600")
    app.minsize(600, 400)
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()


if __name__ == "__main__":
    run_gui()
