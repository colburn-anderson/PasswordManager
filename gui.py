# gui.py

import tkinter as tk
from tkinter import simpledialog, messagebox
from pathlib import Path

from storage import get_usb_path
from auth import set_master_password_from_string, verify_master_password_from_string
from manager import PasswordManager
from utils import generate_password, copy_to_clipboard


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
        self.entry.bind("<Return>", lambda e: self.ok())
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


class LoginWindow:
    """
    Handles both first-run (create) and unlock flows,
    with the GIF on white and the rest on grey,
    truly hidden entry, and Enter→OK.
    """
    def __init__(self):
        self.result = None
        self.password = ""
        self.root = tk.Tk()
        self.root.title("Fun Password Manager")

        usb = get_usb_path()
        self.is_new = not (usb / "master.hash").exists()

        # GIF loading (same as before)…
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
            self._anim_label = tk.Label(self.root,
                                        image=self._frames[0],
                                        bg="white")
            self._anim_label.pack(pady=10)
            self._after_id = self.root.after(100, self._animate, 1)

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

        # Hidden password entry
        self.pw_entry = tk.Entry(self.root, show="", width=30)
        self.pw_entry.pack()
        self.pw_entry.focus_set()
        # Bind Enter to OK
        self.pw_entry.bind("<Return>", lambda e: self.on_ok())
        # Capture all other keystrokes
        self.pw_entry.bind("<Key>", self._on_key)

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
        # Let Return go to its binding
        if event.keysym in ("Return", "KP_Enter"):
            return
        if event.keysym == "BackSpace":
            self.password = self.password[:-1]
        elif event.char and len(event.char) == 1:
            self.password += event.char
        self.pw_entry.delete(0, tk.END)
        return "break"

    def on_ok(self, event=None):
        # Cancel animation callbacks
        if hasattr(self, "_after_id"):
            self.root.after_cancel(self._after_id)

        pw = self.password
        usb = get_usb_path()
        mpw_file = usb / "master.hash"

        if self.is_new:
            if not pw:
                messagebox.showerror("Error", "Password cannot be empty.")
                return
            # Use our custom ConfirmDialog
            confirm_dlg = ConfirmDialog(self.root, "Confirm Password")
            confirm = confirm_dlg.result
            # If they cancelled or mismatched, reset and retry
            if confirm is None or confirm != pw:
                messagebox.showerror("Error", "Passwords did not match.")
                self.password = ""
                return
            key = set_master_password_from_string(pw)
            messagebox.showinfo("Success", "Master password created.")
            self.result = key
        else:
            key = verify_master_password_from_string(pw)
            if not key:
                messagebox.showerror("Error", "Incorrect master password.")
                self.password = ""
                return
            self.result = key

        self.root.destroy()

    def on_cancel(self, event=None):
        if hasattr(self, "_after_id"):
            self.root.after_cancel(self._after_id)
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
        pw = e.get_password(self.key)
        copy_to_clipboard(pw)
        messagebox.showinfo(e.label, f"Username: {e.username}\n(Password copied to clipboard)")

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
        pw1 = simpledialog.askstring("Change Master", "New master password:", show="*")
        if not pw1:
            return
        pw2 = simpledialog.askstring("Confirm New Master", "Confirm new password:", show="*")
        if pw1 != pw2:
            messagebox.showerror("Mismatch", "Passwords did not match.")
            return
        new_key = set_master_password_from_string(pw1)
        for i, e in enumerate(self.pm.list_entries()):
            plain = e.get_password(old_key)
            self.pm.update_entry(i, None, None, plain, None, new_key)
        self.key = new_key
        self.pm.save(new_key)
        messagebox.showinfo("Success", "Master password changed and database re-encrypted.")

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
