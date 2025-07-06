import os
import json
from tkinter import ttk
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import tkinter.messagebox as messagebox
import tkinter as tk
from config_manager import create_default_config
import pyperclip


class AuthenticationDialog(tk.Toplevel):
    # Диалоговое окно аутентификации с мастер-паролем
    def __init__(self, parent, title="Аутентификация"):
        super().__init__(parent)
        self.title(title)
        self.transient(parent)
        self.grab_set()
        self.parent = parent

        self.result = None
        self.master_password = None
        self.max_attempts = 3
        self.attempts = 0

        self._setup_ui()
        self._center_window()

        self.protocol("WM_DELETE_WINDOW", self._safe_destroy)
        self.after(100, lambda: self.parent.focus_force())

    def _center_window(self):
        # Центрирует окно на родительском окне
        self.update_idletasks()

        parent_x = self.parent.winfo_x()
        parent_y = self.parent.winfo_y()
        parent_width = self.parent.winfo_width()
        parent_height = self.parent.winfo_height()

        width = self.winfo_width()
        height = self.winfo_height()

        x = parent_x + (parent_width - width) // 2
        y = parent_y + (parent_height - height) // 2

        if parent_width == 1 or parent_height == 1:
            screen_width = self.winfo_screenwidth()
            screen_height = self.winfo_screenheight()
            x = (screen_width - width) // 2
            y = (screen_height - height) // 2

        self.geometry(f"+{x}+{y}")

    def _setup_ui(self):
        # Устанавливает графический интерфейс для ввода мастер-пароля и проверки доступа
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            main_frame, text="Введите мастер-пароль для шифрования/расшифрования:").pack(pady=(0, 10))

        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(
            main_frame,
            textvariable=self.password_var,
            show="*",
            width=30
        )
        self.password_entry.pack(pady=(0, 10), fill=tk.X)
        self.password_entry.focus_force()

        self.attempts_label = ttk.Label(main_frame, text="", foreground="red")
        self.attempts_label.pack(pady=(0, 10), fill=tk.X)

        self.attempts_label = ttk.Label(main_frame, text="", foreground="red")
        self.attempts_label.pack(pady=(0, 10), fill=tk.X)

        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=(10, 0))

        ttk.Button(buttons_frame, text="ОК", command=self._on_ok).pack(
            side=tk.RIGHT, padx=5)
        ttk.Button(buttons_frame, text="Отмена",
                   command=self._on_cancel).pack(side=tk.RIGHT, padx=5)

        self.bind("<Return>", lambda event: self._on_ok())

        self.minsize(300, 150)

        self.show_password_var = tk.BooleanVar(value=False)
        checkbox_frame = ttk.Frame(main_frame)
        checkbox_frame.pack(fill=tk.X, pady=(0, 10))

        self.show_password_var = tk.BooleanVar(value=False)
        self.show_checkbutton = ttk.Checkbutton(
            checkbox_frame,
            text="Показать пароль",
            variable=self.show_password_var,
            command=self._toggle_password_visibility
        )
        self.show_checkbutton.pack(side=tk.LEFT, anchor=tk.W)
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(
            label="Вставить", command=self._paste_from_clipboard)

        self.password_entry.bind("<Button-3>", self._show_context_menu)

    def _toggle_password_visibility(self):
        show = self.show_password_var.get()
        self.password_entry.config(show="" if show else "*")

    def _paste_from_clipboard(self):
        try:
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, pyperclip.paste())
        except Exception as e:
            messagebox.showerror(
                "Ошибка", f"Не удалось вставить из буфера: {str(e)}")

    def _show_context_menu(self, event):
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def _validate_master_password(self, password):
        # Проверяет корректность мастер-пароля
        try:
            if os.path.exists("passwords.json"):
                with open("passwords.json", "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if data:
                        test_item = data[0]
                        fernet = Fernet(self._generate_key(password))
                        fernet.decrypt(test_item["password"].encode())
            return True
        except Exception:
            return False

    def _generate_key(self, password):
        # Генерирует ключ для шифрования на основе мастер-пароля и соли
        with open("salt.bin", "rb") as salt_file:
            salt = salt_file.read()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def _on_ok(self):
        # Обрабатывает нажатие кнопки "ОК"
        password = self.password_var.get()

        if not password:
            messagebox.showerror("Ошибка", "Пароль не может быть пустым")
            return

        self.attempts += 1

        try:
            if self._validate_master_password(password):
                self.master_password = password
                self.result = True
                if self.winfo_exists():
                    self.destroy()
            else:
                remaining = self.max_attempts - self.attempts
                if remaining > 0:
                    self.attempts_label.config(
                        text=f"Неверный пароль. Осталось попыток: {remaining}"
                    )
                    self.password_var.set("")
                    self.password_entry.focus_set()
                else:
                    if self.parent.winfo_exists():
                        self.parent.destroy()
                    self.destroy()
        except Exception as e:
            if self.parent.winfo_exists():
                self.parent.destroy()
            self.destroy()

    def _on_cancel(self):
        # Обрабатывает нажатие кнопки "Отмена"
        self.result = False
        self.destroy()
        self.parent.grab_release()

    def _safe_destroy(self):
        # Безопасное закрытие окна
        self.result = False
        self.destroy()
        self.parent.focus_set()
