import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import pyperclip


class BasePasswordDialog(tk.Toplevel):
    # Суперкласс для диалоговых окон с паролями
    def __init__(self, parent, title):
        super().__init__(parent)
        self.title(title)
        self.transient(parent)
        self.grab_set()
        self.parent = parent
        self.result = None

        self._setup_ui()
        self._center_window()

    def _center_window(self):
        # Центрирование окна относительно родительского окна
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'+{x}+{y}')

    def _setup_ui(self):
        raise NotImplementedError("Subclasses must implement _setup_ui")


class PasswordDialog(BasePasswordDialog):
    # Диалоговое окно для добавления/редактирования пароля
    def __init__(self, parent, title, password_data=None):
        self.password_data = password_data or {
            "description": "",
            "password": "",
            "tags": [],
            "url": ""
        }
        super().__init__(parent, title)
        self._setup_ui()
        self._load_data()

    def _setup_ui(self):
        # Описание
        ttk.Label(self, text="Описание:").grid(
            row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.description_entry = ttk.Entry(self, width=30)
        self.description_entry.grid(
            row=0, column=1, padx=5, pady=5, sticky=tk.EW)

        # Пароль
        ttk.Label(self, text="Пароль:").grid(
            row=1, column=0, padx=5, pady=5, sticky=tk.W)
        password_frame = ttk.Frame(self)
        password_frame.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        self.password_entry = ttk.Entry(password_frame, width=25, show="*")
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.paste_button = ttk.Button(
            password_frame,
            text="Вст.",
            command=self._paste_from_clipboard,
            style="Small.TButton"
        )
        self.paste_button.pack(side=tk.RIGHT, padx=2, ipady=0)
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=2)

        style = ttk.Style()
        style.configure(
            "Small.TButton",
            width=6,
            font=("Arial", 8),
            padding=(1, 1)
        )

        # Теги
        ttk.Label(self, text="Теги:").grid(
            row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.tags_entry = ttk.Entry(self, width=30)
        self.tags_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.EW)

        # URL
        ttk.Label(self, text="URL:").grid(
            row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.url_entry = ttk.Entry(self, width=30)
        self.url_entry.grid(row=3, column=1, padx=5, pady=5, sticky=tk.EW)

        # Чекбокс и кнопки
        self.show_password_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            self,
            text="Показать пароль",
            variable=self.show_password_var,
            command=self._toggle_password_visibility
        ).grid(row=4, column=1, padx=5, pady=5, sticky=tk.E)

        button_frame = ttk.Frame(self)
        button_frame.grid(row=5, column=0, columnspan=2, pady=10)
        ttk.Button(button_frame, text="Сохранить",
                   command=self._save).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Отмена",
                   command=self.destroy).pack(side=tk.RIGHT)

    def _load_data(self):
        """Загружает данные в поля формы."""
        self.description_entry.insert(0, self.password_data["description"])
        self.password_entry.insert(0, self.password_data["password"])
        self.tags_entry.insert(0, ", ".join(self.password_data["tags"]))
        self.url_entry.insert(0, self.password_data["url"])

    def _toggle_password_visibility(self):
        # Показать или скрыть пароль
        show = self.show_password_var.get()
        self.password_entry.config(show="" if show else "*")

    def _paste_from_clipboard(self):
        # Вставить пароль из буфера обмена
        try:
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, pyperclip.paste())
        except Exception as e:
            tk.messagebox.showerror(
                "Ошибка", f"Не удалось вставить из буфера: {str(e)}")

    def _save(self):
        # Сохранение данных пароля
        description = self.description_entry.get()
        password = self.password_entry.get()
        url = self.url_entry.get().strip()
        tags = [tag.strip()
                for tag in self.tags_entry.get().split(",") if tag.strip()]

        if not description or not password:
            tk.messagebox.showerror("Ошибка", "Заполните описание и пароль!")
            return

        if len(password) < 4:
            messagebox.showerror(
                "Ошибка", "Пароль должен быть не короче 4 символов!")
            return
        url = self.url_entry.get()
        self.result = {
            "description": description,
            "password": password,
            "tags": tags,
            "url": url.strip()
        }
        self.destroy()


class ChangeMasterPasswordDialog(tk.Toplevel):
    # Диалоговое окно для смены мастер-пароля
    def __init__(self, parent, password_manager):
        super().__init__(parent)
        self.title("Смена мастер-пароля")
        self.transient(parent)
        self.grab_set()
        self.parent = parent
        self.password_manager = password_manager
        self.result = None

        # Создаем элементы интерфейса
        self._setup_ui()  # Вызываем ПЕРЕД созданием контекстного меню
        self._center_window()

        # Инициализация контекстного меню
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(
            label="Вставить", command=self._paste_from_clipboard)

        # Привязка правого клика к полям
        self.old_password_entry.bind("<Button-3>", self._show_context_menu)
        self.new_password_entry.bind("<Button-3>", self._show_context_menu)
        self.confirm_password_entry.bind("<Button-3>", self._show_context_menu)

    def _center_window(self):
        # Центрирование окна относительно родительского окна
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'+{x}+{y}')

    def _setup_ui(self):
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Поле для текущего пароля
        ttk.Label(
            main_frame, text="Текущий мастер-пароль:").pack(anchor=tk.W, pady=(0, 5))
        self.old_password_var = tk.StringVar()
        self.old_password_entry = ttk.Entry(
            main_frame,
            textvariable=self.old_password_var,
            show="*",
            width=30
        )
        self.old_password_entry.pack(fill=tk.X, pady=(0, 10))

        # Поле для нового пароля
        ttk.Label(
            main_frame, text="Новый мастер-пароль:").pack(anchor=tk.W, pady=(0, 5))
        self.new_password_var = tk.StringVar()
        self.new_password_entry = ttk.Entry(
            main_frame,
            textvariable=self.new_password_var,
            show="*",
            width=30
        )
        self.new_password_entry.pack(fill=tk.X, pady=(0, 10))

        # Поле подтверждения
        ttk.Label(main_frame, text="Подтвердите новый пароль:").pack(
            anchor=tk.W, pady=(0, 5))
        self.confirm_password_var = tk.StringVar()
        self.confirm_password_entry = ttk.Entry(
            main_frame,
            textvariable=self.confirm_password_var,
            show="*",
            width=30
        )
        self.confirm_password_entry.pack(fill=tk.X, pady=(0, 10))

        # Кнопки
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=(10, 0))

        ttk.Button(buttons_frame, text="Сменить пароль",
                   command=self._on_change).pack(side=tk.RIGHT, padx=5)
        ttk.Button(buttons_frame, text="Отмена",
                   command=self._on_cancel).pack(side=tk.RIGHT, padx=5)

    def _on_change(self):
        # Теперь old_password_var доступен
        old_password = self.old_password_var.get()
        new_password = self.new_password_var.get()
        confirm_password = self.confirm_password_var.get()

        if not old_password or not new_password:
            messagebox.showerror("Ошибка", "Все поля должны быть заполнены")
            return

        if new_password != confirm_password:
            messagebox.showerror("Ошибка", "Новые пароли не совпадают")
            return

        success, message = self.password_manager.change_master_password(
            old_password, new_password)
        if success:
            messagebox.showinfo("Успех", message)
            self.result = True
            self.destroy()
        else:
            messagebox.showerror("Ошибка", message)

    def _on_cancel(self):
        # Отмена смены мастер-пароля
        self.result = False
        self.destroy()

    def _show_context_menu(self, event):
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def _paste_from_clipboard(self):
        try:
            widget = self.focus_get()
            if widget in [self.old_password_entry, self.new_password_entry, self.confirm_password_entry]:
                widget.delete(0, tk.END)
                widget.insert(0, pyperclip.paste())
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось вставить: {str(e)}")


class ConfigEditorDialog(BasePasswordDialog):
    # Диалоговое окно для редактирования конфигурации пароля
    def __init__(self, parent, config_data):
        self.config_data = config_data
        super().__init__(parent, "Редактирование конфигурации")

    def _setup_ui(self):
        # Создание интерфейса для редактирования конфигурации пароля
        ttk.Label(self, text="Макс. длина пароля:").grid(
            row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.max_length_entry = ttk.Spinbox(self, from_=8, to=128, width=10)
        self.max_length_entry.grid(
            row=0, column=1, padx=5, pady=5, sticky=tk.W)
        self.max_length_entry.set(
            self.config_data.get("max_password_length", 32))

        ttk.Label(self, text="Длина по умолчанию:").grid(
            row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.default_length_entry = ttk.Spinbox(
            self, from_=4, to=self.config_data.get("max_password_length", 32), width=10)
        self.default_length_entry.grid(
            row=1, column=1, padx=5, pady=5, sticky=tk.W)
        self.default_length_entry.set(
            self.config_data.get("default_length", 18))

        self.use_upper_var = tk.BooleanVar(
            value=self.config_data.get("use_uppercase", True))
        ttk.Checkbutton(self, text="Исп. заглавные буквы", variable=self.use_upper_var).grid(
            row=2, column=0, columnspan=2, padx=5, pady=2, sticky=tk.W)

        self.use_lower_var = tk.BooleanVar(
            value=self.config_data.get("use_lowercase", True))
        ttk.Checkbutton(self, text="Исп. строчные буквы", variable=self.use_lower_var).grid(
            row=3, column=0, columnspan=2, padx=5, pady=2, sticky=tk.W)

        self.use_digits_var = tk.BooleanVar(
            value=self.config_data.get("use_digits", True))
        ttk.Checkbutton(self, text="Исп. цифры", variable=self.use_digits_var).grid(
            row=4, column=0, columnspan=2, padx=5, pady=2, sticky=tk.W)

        self.use_symbols_var = tk.BooleanVar(
            value=self.config_data.get("use_symbols", True))
        ttk.Checkbutton(self, text="Исп. символы", variable=self.use_symbols_var).grid(
            row=5, column=0, columnspan=2, padx=5, pady=2, sticky=tk.W)

        ttk.Label(self, text="Исключенные символы:").grid(
            row=6, column=0, padx=5, pady=5, sticky=tk.W)
        self.excluded_chars_entry = ttk.Entry(self, width=30)
        self.excluded_chars_entry.grid(row=6, column=1, padx=5, pady=5)
        self.excluded_chars_entry.insert(
            0, self.config_data.get("excluded_chars", ""))

        ttk.Label(self, text="Файл для паролей:").grid(
            row=7, column=0, padx=5, pady=5, sticky=tk.W)
        self.pass_file_entry = ttk.Entry(self, width=30)
        self.pass_file_entry.grid(row=7, column=1, padx=5, pady=5)
        self.pass_file_entry.insert(0, self.config_data.get(
            "passwords_file", "passwords.json"))

        button_frame = ttk.Frame(self)
        button_frame.grid(row=8, column=0, columnspan=2, pady=10)

        ttk.Button(button_frame, text="Сохранить",
                   command=self._save).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Отмена",
                   command=self.destroy).pack(side=tk.RIGHT)

    def _save(self):
        # Сохранение изменений в конфигурации пароля
        new_config = {
            "max_password_length": int(self.max_length_entry.get()),
            "default_length": int(self.default_length_entry.get()),
            "use_uppercase": self.use_upper_var.get(),
            "use_lowercase": self.use_lower_var.get(),
            "use_digits": self.use_digits_var.get(),
            "use_symbols": self.use_symbols_var.get(),
            "excluded_chars": self.excluded_chars_entry.get(),
            "passwords_file": self.pass_file_entry.get()
        }

        if new_config["default_length"] > new_config["max_password_length"]:
            messagebox.showerror(
                "Ошибка", "Длина по умолчанию не может превышать максимальную")
            return

        self.config_data.update(new_config)
        self.result = True
        self.destroy()


class RegenerateSaltDialog(tk.Toplevel):
    # Диалоговое окно для обновления криптографической соли
    def __init__(self, parent, password_manager):
        super().__init__(parent)
        self.title("Обновление криптографической соли")
        self.password_manager = password_manager

        # Сначала создаем элементы интерфейса
        self._setup_ui()
        self._center_window()

        # Теперь инициализируем контекстное меню
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(
            label="Вставить", command=self._paste_from_clipboard)

        # Правильное имя поля - password_entry
        self.password_entry.bind("<Button-3>", self._show_context_menu)

    def _center_window(self):
        # Центрирование окна на экране
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'+{x}+{y}')

    def _show_context_menu(self, event):
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def _paste_from_clipboard(self):
        try:
            # Используем правильное имя поля
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, pyperclip.paste())
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось вставить: {str(e)}")

    def _setup_ui(self):
        # Создание интерфейса для обновления криптографической соли
        main_frame = ttk.Frame(self, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            main_frame, text="Введите текущий мастер-пароль:").pack(pady=(0, 10))

        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(  # СОЗДАЕМ ПРАВИЛЬНЫЙ АТРИБУТ
            main_frame,
            textvariable=self.password_var,
            show="*",
            width=30
        )
        self.password_entry.pack(pady=(0, 10))

        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=(10, 0))

        ttk.Button(buttons_frame, text="Обновить",
                   command=self._regenerate).pack(side=tk.RIGHT, padx=5)
        ttk.Button(buttons_frame, text="Отмена",
                   command=self.destroy).pack(side=tk.RIGHT, padx=5)

    def _regenerate(self):
        # Обновление криптографической соли
        password = self.password_var.get()
        if not password:
            messagebox.showerror("Ошибка", "Введите мастер-пароль")
            return

        success, message = self.password_manager.regenerate_salt(password)
        if success:
            messagebox.showinfo("Успех", message)
            self.destroy()
        else:
            messagebox.showerror("Ошибка", message)
