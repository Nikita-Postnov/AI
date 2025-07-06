import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import webbrowser
import pyperclip
import os
import json

from password_generator import PasswordGenerator
from password_manager import PasswordManager
from gui.dialogs import ConfigEditorDialog, PasswordDialog, RegenerateSaltDialog
from .authentication import AuthenticationDialog
from tkinter import filedialog
from password_generator import PasswordGenerator
from config_manager import get_app_dir


class PasswordGeneratorApp:
    def __init__(self, master):
        self.master = master
        master.title("Генератор паролей")
        master.geometry("800x600")
        master.minsize(800, 600)

        self.idle_timer = None
        self.idle_timeout = 120000  # (2 минуты)

        self.setup_activity_tracking()

        if not self._initialize_password_manager():
            return

        self._full_ui_initialization()

    def _full_ui_initialization(self):
        # Создаем экземпляр PasswordManager
        self.password_generator = PasswordGenerator()
        self._setup_styles()
        self._create_tabs()
        self._setup_context_menu()
        self._create_menu()
        self.length_slider.config(
            to=self.password_generator.max_password_length)
        self.schedule_backup()
        self._refresh_password_list()
        self.master.deiconify()

    def _edit_configuration(self):
        # Загрузка текущей конфигурации из файла config.json
        config_path = os.path.join(get_app_dir(), "config.json")

        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
        except Exception as e:
            messagebox.showerror(
                "Ошибка", f"Не удалось загрузить конфигурацию: {str(e)}")
            return

        dialog = ConfigEditorDialog(self.master, config_data)
        dialog.wait_window()

        if getattr(dialog, 'result', False):
            try:
                with open(config_path, 'w', encoding='utf-8') as f:
                    json.dump(config_data, f, indent=4, ensure_ascii=False)

                self.password_generator.load_config()
                self.length_slider.config(
                    to=self.password_generator.max_password_length)
                messagebox.showinfo("Успех", "Конфигурация успешно обновлена!")

            except Exception as e:
                messagebox.showerror(
                    "Ошибка", f"Ошибка сохранения конфигурации: {str(e)}")

    def _export_passwords_txt(self):
        # Открываем диалог выбора пути для сохранения паролей
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Текстовые файлы", "*.txt"), ("Все файлы", "*.*")],
            title="Сохранить пароли в TXT"
        )
        if not file_path:
            return

        success, message = self.password_manager.export_to_txt(file_path)
        if success:
            messagebox.showinfo("Успех", message)
        else:
            messagebox.showerror("Ошибка", message)

    def schedule_backup(self):
        # Запланировать бэкап паролей через 1 час
        self.password_manager.backup_passwords()
        self.master.after(3600000, self.schedule_backup)  # 1 час

    def _initialize_password_manager(self):
        # Создаем экземпляр класса PasswordManager с пустым паролем
        attempts = 3
        while attempts > 0:
            auth_dialog = AuthenticationDialog(self.master)
            auth_dialog.wait_window()

            if not auth_dialog.result:
                if self.master.winfo_exists():
                    self.master.destroy()
                return False

            try:
                self.password_manager = PasswordManager(
                    auth_dialog.master_password)
                self.password_manager.load_passwords()
                self.master.withdraw()
                return True
            except Exception:
                attempts -= 1
                if attempts > 0:
                    messagebox.showwarning(
                        "Ошибка",
                        f"Неверный пароль. Осталось попыток: {attempts}"
                    )
                else:
                    if self.master.winfo_exists():
                        self.master.destroy()
                    return

    def _show_change_master_password(self):
        # Отображаем диалоговое окно для смены мастер-пароля
        from gui.dialogs import ChangeMasterPasswordDialog
        dialog = ChangeMasterPasswordDialog(self.master, self.password_manager)
        dialog.wait_window()

        if dialog.result:
            self._refresh_password_list()

    def _create_default_config(self):
        # Создаем файл конфигурации по умолчанию, если его нет
        config_path = os.path.join(os.path.dirname(
            os.path.abspath(__file__)), "config.json")
        if not os.path.exists(config_path):
            default_config = {
                "max_password_length": 32,
                "default_length": 15,
                "use_uppercase": True,
                "use_lowercase": True,
                "use_digits": True,
                "use_symbols": True,
                "excluded_chars": "1l0Oo|",
                "passwords_file": "passwords.json"
            }
            try:
                with open(config_path, 'w', encoding='utf-8') as f:
                    json.dump(default_config, f, indent=4)
            except Exception as e:
                print(f"Ошибка создания конфигурации: {str(e)}")

    def _setup_styles(self):
        # Настройка стилей для виджетов
        style = ttk.Style()
        style.theme_use("clam")
        style.configure('TButton', font=('Arial', 10))
        style.configure('TLabel', font=('Arial', 10))
        style.configure('TEntry', font=('Arial', 10))
        style.configure('TCheckbutton', font=('Arial', 10))
        style.configure("red.Horizontal.TProgressbar", background='red')
        style.configure("yellow.Horizontal.TProgressbar", background='yellow')
        style.configure("green.Horizontal.TProgressbar", background='green')

        style.configure("Treeview.Cell",
                        borderwidth=1,
                        relief="solid",
                        padding=(5, 2)
                        )
        style.layout("Treeview.Item", [
            ('Treeitem.padding', {
                'sticky': 'nswe',
                'children': [
                    ('Treeitem.indicator', {'side': 'left', 'sticky': ''}),
                    ('Treeitem.image', {'side': 'left', 'sticky': ''}),
                    ('Treeitem.text', {'side': 'left', 'sticky': ''}),
                    ('Treeitem.Cell', {'sticky': 'nswe'})
                ]
            })
        ])

    def _create_tabs(self):
        # Создаем вкладки и настраиваем их содержимое
        if not hasattr(self, 'password_manager'):
            return

        self.tab_control = ttk.Notebook(self.master)
        self.tab_control = ttk.Notebook(self.master)

        self.generator_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.generator_tab, text="Генератор")
        self._setup_generator_tab()

        self.manager_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.manager_tab, text="Менеджер паролей")
        self._setup_manager_tab()

        self.tab_control.pack(expand=1, fill="both")

    def _setup_generator_tab(self):
        # Настройка содержимого вкладки "Генератор"
        settings_frame = ttk.LabelFrame(
            self.generator_tab, text="Настройки генератора", padding=10)
        settings_frame.pack(padx=10, pady=10, fill=tk.BOTH)

        ttk.Label(settings_frame, text="Длина пароля:").grid(
            row=0, column=0, sticky=tk.W, pady=5)
        self.length_var = tk.IntVar(
            value=self.password_generator.password_length)

        length_entry = ttk.Entry(
            settings_frame, textvariable=self.length_var, width=5)
        length_entry.grid(row=0, column=1, sticky=tk.W, pady=5)

        self.length_slider = ttk.Scale(
            settings_frame, from_=4, to=32, orient=tk.HORIZONTAL,
            variable=self.length_var, length=200, command=lambda _: self.length_var.set(int(self.length_slider.get()))
        )
        self.length_slider.grid(row=0, column=2, sticky=tk.W, pady=5, padx=10)

        self.use_uppercase = tk.BooleanVar(
            value=self.password_generator.use_uppercase)
        ttk.Checkbutton(settings_frame, text="Заглавные буквы (A-Z)", variable=self.use_uppercase
                        ).grid(row=1, column=0, columnspan=3, sticky=tk.W)

        self.use_lowercase = tk.BooleanVar(
            value=self.password_generator.use_lowercase)
        ttk.Checkbutton(settings_frame, text="Строчные буквы (a-z)", variable=self.use_lowercase
                        ).grid(row=2, column=0, columnspan=3, sticky=tk.W)

        self.use_digits = tk.BooleanVar(
            value=self.password_generator.use_digits)
        ttk.Checkbutton(settings_frame, text="Цифры (0-9)", variable=self.use_digits
                        ).grid(row=3, column=0, columnspan=3, sticky=tk.W)

        self.use_symbols = tk.BooleanVar(
            value=self.password_generator.use_symbols)
        ttk.Checkbutton(settings_frame, text="Специальные символы (!@#$%)", variable=self.use_symbols
                        ).grid(row=4, column=0, columnspan=3, sticky=tk.W)

        ttk.Label(settings_frame, text="Исключить:").grid(
            row=5, column=0, sticky=tk.W, pady=5)
        self.excluded_chars_var = tk.StringVar(
            value=self.password_generator.excluded_chars)
        ttk.Entry(settings_frame, textvariable=self.excluded_chars_var, width=30
                  ).grid(row=5, column=1, columnspan=2, sticky=tk.W, pady=5)

        ttk.Button(settings_frame, text="Сгенерировать пароль", command=self._generate_password
                   ).grid(row=6, column=0, columnspan=3, pady=10)

        output_frame = ttk.LabelFrame(
            self.generator_tab, text="Сгенерированный пароль", padding=10)
        output_frame.pack(padx=10, pady=10, fill=tk.BOTH)

        self.password_var = tk.StringVar()
        password_entry_frame = ttk.Frame(output_frame)
        password_entry_frame.pack(fill=tk.X)

        self.password_entry = ttk.Entry(
            password_entry_frame, textvariable=self.password_var, width=30)
        self.password_entry.pack(side=tk.LEFT, expand=True, fill=tk.X)
        self.password_entry.config(show="*")

        self.show_password_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            password_entry_frame, text="Показать", variable=self.show_password_var,
            command=lambda: self.password_entry.config(
                show="" if self.show_password_var.get() else "*")
        ).pack(side=tk.RIGHT)

        ttk.Label(output_frame, text="Сложность пароля:").pack(anchor=tk.W)
        self.strength_var = tk.IntVar()
        self.strength_bar = ttk.Progressbar(
            output_frame, orient=tk.HORIZONTAL, length=200,
            mode='determinate', variable=self.strength_var
        )
        self.strength_bar.pack(fill=tk.X, pady=5)

        button_frame = ttk.Frame(output_frame)
        button_frame.pack(fill=tk.X, pady=5)

        ttk.Button(button_frame, text="Копировать",
                   command=self._copy_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Очистить", command=lambda: self.password_var.set(
            "")).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Сохранить",
                   command=self._save_password_dialog).pack(side=tk.LEFT, padx=5)

    def _setup_manager_tab(self):
        # Настройка содержимого вкладки "Менеджер паролей"
        control_frame = ttk.Frame(self.manager_tab, padding=10)
        control_frame.pack(fill=tk.X)

        self.hide_passwords_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            control_frame,
            text="Скрыть пароли",
            variable=self.hide_passwords_var,
            command=self._refresh_password_list
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(control_frame, text="Обновить список",
                   command=self._refresh_password_list).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Добавить новый пароль",
                   command=self._add_new_password).pack(side=tk.LEFT, padx=5)

        ttk.Label(control_frame, text="Поиск:").pack(
            side=tk.LEFT, padx=(10, 0))
        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda *args: self._filter_passwords())
        ttk.Entry(control_frame, textvariable=self.search_var,
                  width=20).pack(side=tk.LEFT, padx=5)

        ttk.Label(control_frame, text="Теги:").pack(side=tk.LEFT, padx=(10, 0))
        self.tag_filter_var = tk.StringVar(value="Все")
        self.tag_filter = ttk.Combobox(
            control_frame, textvariable=self.tag_filter_var, values=["Все"], state="readonly"
        )
        self.tag_filter.pack(side=tk.LEFT, padx=5)
        self.tag_filter.bind("<<ComboboxSelected>>",
                             lambda e: self._filter_passwords())

        list_frame = ttk.Frame(self.manager_tab, padding=10)
        list_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("description", "password", "tags")
        self.password_tree = ttk.Treeview(
            list_frame, columns=columns, show="headings", selectmode="browse")

        headings = {
            "description": "Описание",
            "password": "Пароль",
            "tags": "Теги"
        }

        for col in columns:
            self.password_tree.heading(
                col, text=headings[col], anchor="center")
            if col == "description":
                self.password_tree.column(
                    col, anchor="e", stretch=True, width=150)
            elif col == "password":
                self.password_tree.column(
                    col, anchor="center", stretch=True, width=200)
            else:
                self.password_tree.column(
                    col, anchor="center", stretch=True, width=100)

        vscroll = ttk.Scrollbar(
            list_frame, orient="vertical", command=self.password_tree.yview)
        hscroll = ttk.Scrollbar(
            list_frame, orient="horizontal", command=self.password_tree.xview)
        self.password_tree.configure(
            yscrollcommand=vscroll.set, xscrollcommand=hscroll.set)

        vscroll.pack(side=tk.RIGHT, fill=tk.Y)
        hscroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.password_tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        action_frame = ttk.Frame(self.manager_tab, padding=10)
        action_frame.pack(fill=tk.X)

        ttk.Button(action_frame, text="Копировать",
                   command=self._copy_selected_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Просмотреть",
                   command=self._view_selected_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Редактировать",
                   command=self._edit_selected_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Удалить",
                   command=self._delete_selected_password).pack(side=tk.LEFT, padx=5)

        self._refresh_password_list()
        self.password_tree.bind(
            "<Double-1>", lambda e: self._edit_selected_password())

    def _setup_context_menu(self):
        # Настройка контекстного меню
        self.entry_context_menu = tk.Menu(self.master, tearoff=0)
        self.entry_context_menu.add_command(
            label="Копировать", command=lambda: self._copy_to_clipboard(self.master.focus_get()))
        self.entry_context_menu.add_command(
            label="Вырезать", command=lambda: self._cut_to_clipboard(self.master.focus_get()))
        self.entry_context_menu.add_command(
            label="Вставить", command=lambda: self._paste_from_clipboard(self.master.focus_get()))
        self.entry_context_menu.add_command(
            label="Выбрать всё", command=lambda: self._select_all(self.master.focus_get()))

        self.tree_context_menu = tk.Menu(self.master, tearoff=0)
        self.tree_context_menu.add_command(
            label="Копировать", command=self._copy_selected_password)
        self.tree_context_menu.add_command(
            label="Просмотреть", command=self._view_selected_password)
        self.tree_context_menu.add_command(
            label="Редактировать", command=self._edit_selected_password)
        self.tree_context_menu.add_command(
            label="Удалить", command=self._delete_selected_password)

        self.master.bind("<Button-3>", self._on_right_click)
        self.password_tree.bind("<Button-3>", self._on_tree_right_click)

    def setup_activity_tracking(self):
        # Настройка отслеживания активности пользователя
        def track_activity(event):
            self.reset_inactivity_timer()

        def bind_recursive(widget):
            widget.bind("<Motion>", track_activity)
            widget.bind("<KeyPress>", track_activity)
            for child in widget.winfo_children():
                bind_recursive(child)

        bind_recursive(self.master)
        self.reset_inactivity_timer()

    def reset_inactivity_timer(self, event=None):
        # Сброс таймера неактивности
        if self.idle_timer is not None:
            self.master.after_cancel(self.idle_timer)

        self.idle_timer = self.master.after(
            self.idle_timeout,
            self.lock_application
        )

    def lock_application(self):
        # Заблокировать приложение
        if not hasattr(self, 'password_manager') or not self.password_manager:
            return
        self.master.withdraw()
        auth_window = tk.Toplevel(self.master)
        auth_window.title("Блокировка")
        auth_window.protocol("WM_DELETE_WINDOW", lambda: None)
        auth_window.grab_set()

        auth_window.update_idletasks()
        parent_width = self.master.winfo_width()
        parent_height = self.master.winfo_height()
        parent_x = self.master.winfo_x()
        parent_y = self.master.winfo_y()

        width = auth_window.winfo_width()
        height = auth_window.winfo_height()

        x = parent_x + (parent_width - width) // 2
        y = parent_y + (parent_height - height) // 2
        auth_window.geometry(f"+{x}+{y}")

        auth_dialog = AuthenticationDialog(auth_window)
        auth_dialog.wait_window()

        if auth_dialog.result:
            try:
                self.password_manager = PasswordManager(
                    auth_dialog.master_password)
                self.password_manager.load_passwords()
                self._refresh_password_list()
                auth_window.destroy()
                self.master.deiconify()
            except Exception as e:
                messagebox.showerror(
                    "Ошибка", f"Ошибка разблокировки: {str(e)}")
                self.master.destroy()
        else:
            self.master.destroy()

        self.reset_inactivity_timer()

    def _create_menu(self):
        # Настройка главного меню
        self.menu_bar = tk.Menu(self.master)
        self.master.config(menu=self.menu_bar)
        security_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Безопасность", menu=security_menu)
        security_menu.add_command(
            label="Обновить криптографическую соль",
            command=self._regenerate_salt
        )
        security_menu.add_command(label="Сменить мастер-пароль",
                                  command=self._show_change_master_password)
        security_menu.add_command(label="Заблокировать",
                                  command=lambda: self.lock_application())
        file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Файл", menu=file_menu)
        file_menu.add_command(label="Изменить конфигурацию",
                              command=self._edit_configuration)
        file_menu.add_command(label="Экспорт в TXT",
                              command=self._export_passwords_txt)

        file_menu.add_command(
            label="Импорт из TXT",
            command=self._import_passwords_txt
        )

        file_menu.add_command(
            label="Создать резервную копию", command=self._create_backup)
        file_menu.add_command(
            label="Открыть резервную копию", command=self._open_backup)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.master.destroy)

        help_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Справка", menu=help_menu)
        help_menu.add_command(label="О программе", command=self._show_about)

    def _show_text_context_menu(self, event, menu):
        # Отображение контекстного меню для текстового поля
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _regenerate_salt(self):
        # Обновить криптографическую соль
        dialog = RegenerateSaltDialog(self.master, self.password_manager)
        dialog.wait_window()
        self._refresh_password_list()

    def _open_backup(self):
        # Открыть резервную копию
        backup_dir = os.path.join(os.path.dirname(
            os.path.abspath(__file__)), "..", "backups")
        backup_file = os.path.join(backup_dir, "backup_passwords.bin")

        if not os.path.exists(backup_file):
            messagebox.showerror("Ошибка", f"Файл не найден:\n{backup_file}")
            return

        try:
            with open(backup_file, 'r', encoding='utf-8') as f:
                encrypted_data = f.read()

            backup_passwords = json.loads(encrypted_data)
            decrypted_passwords = []

            for item in backup_passwords:
                try:
                    decrypted_pwd = self.password_manager.decrypt(
                        item["password"])
                    decrypted_item = {
                        "description": item["description"],
                        "password": decrypted_pwd,
                        "tags": item.get("tags", [])
                    }
                    decrypted_passwords.append(decrypted_item)
                except Exception as e:
                    messagebox.showerror(
                        "Ошибка расшифровки",
                        f"Не удалось расшифровать пароль для '{item['description']}': {str(e)}"
                    )
                    return

            text_window = tk.Toplevel(self.master)
            text_window.title("Резервная копия (расшифровано)")

            text = tk.Text(text_window, wrap=tk.WORD)
            text.pack(fill=tk.BOTH, expand=True)

            formatted_data = json.dumps(
                decrypted_passwords, indent=4, ensure_ascii=False)
            text.insert(tk.END, formatted_data)

            context_menu = tk.Menu(text_window, tearoff=0)
            context_menu.add_command(label="Копировать",
                                     command=lambda: self._copy_from_text_widget(text))

            text.bind("<Button-3>",
                      lambda e: self._show_text_context_menu(e, context_menu))

        except Exception as e:
            messagebox.showerror(
                "Ошибка", f"Не удалось обработать файл: {str(e)}")

    def _copy_from_text_widget(self, text_widget):
        # Копирование выделенного текста из виджета текста
        try:
            selected = text_widget.get("sel.first", "sel.last")
            self.master.clipboard_clear()
            self.master.clipboard_append(selected)
        except tk.TclError:
            pass

    def _create_backup(self):
        # Создать резервную копию паролей
        success, message = self.password_manager.backup_passwords()
        if success:
            messagebox.showinfo("Успех", message)
        else:
            messagebox.showerror("Ошибка", message)

    def _show_about(self):
        # Отображение окна информации о программе
        messagebox.showinfo(
            "О программе",
            "Менеджер паролей с шифрованием\n\n"
        )

    def _import_passwords_txt(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Выберите файл для импорта"
        )

        if not file_path:
            return

        try:
            # Показать превью файла
            with open(file_path, 'r', encoding='utf-8') as f:
                preview = f.read(1000)

            if not messagebox.askyesno("Подтверждение",
                                       f"Импортировать пароли из файла?\n\nПревью:\n{preview[:200]}..."):
                return

            success, message = self.password_manager.import_from_txt(file_path)
            if success:
                messagebox.showinfo("Успех", message)
                self._refresh_password_list()
            else:
                messagebox.showerror("Ошибка", message)

        except Exception as e:
            messagebox.showerror(
                "Ошибка", f"Не удалось прочитать файл: {str(e)}")

    def _generate_password(self):
        # Генерация нового пароля
        self.password_generator.password_length = int(self.length_var.get())
        self.password_generator.use_uppercase = self.use_uppercase.get()
        self.password_generator.use_lowercase = self.use_lowercase.get()
        self.password_generator.use_digits = self.use_digits.get()
        self.password_generator.use_symbols = self.use_symbols.get()
        self.password_generator.excluded_chars = self.excluded_chars_var.get().replace(' ', '')

        new_password = self.password_generator.generate_password()
        self.password_var.set(new_password)
        self._update_strength_bar(new_password)

    def _update_strength_bar(self, password):
        # Обновление шкалы сложности пароля
        score = self.password_generator.evaluate_password_strength(password)
        self.strength_var.set(score)

        if score < 40:
            self.strength_bar.config(style="red.Horizontal.TProgressbar")
        elif score < 70:
            self.strength_bar.config(style="yellow.Horizontal.TProgressbar")
        else:
            self.strength_bar.config(style="green.Horizontal.TProgressbar")

    def _copy_password(self):
        # Копирование пароля в буфер обмена
        password = self.password_var.get()
        if password:
            pyperclip.copy(password)
            messagebox.showinfo("Успешно", "Пароль скопирован в буфер обмена!")
        else:
            messagebox.showerror("Ошибка", "Нет пароля для копирования.")

    def _save_password_dialog(self):
        # Отображение диалогового окна для сохранения пароля
        password = self.password_var.get()
        if not password:
            messagebox.showerror("Ошибка", "Сначала сгенерируйте пароль!")
            return

        initial_data = {
            "password": password,
            "description": "",
            "tags": []
        }

        dialog = PasswordDialog(self.master, "Сохранение пароля", initial_data)
        dialog.wait_window()

        if hasattr(dialog, 'result') and dialog.result:
            data = dialog.result
            if not data["description"]:
                messagebox.showerror("Ошибка", "Заполните описание!")
                return

            self.password_manager.add_password(
                data["password"], data["description"], data.get("tags", []), data.get("url", ""))
            messagebox.showinfo("Успешно", "Пароль сохранен!")
            self._refresh_password_list()

    def _add_new_password(self):
        # Добавление нового пароля с помощью диалогового окна
        dialog = PasswordDialog(self.master, "Добавить новый пароль")
        dialog.wait_window()

        if hasattr(dialog, 'result') and dialog.result:
            data = dialog.result
            self.password_manager.add_password(
                data["password"], data["description"], data.get("tags", []), data.get("url", ""))
            self._refresh_password_list()

    def _refresh_password_list(self):
        # Обновление списка сохраненных паролей
        self.password_tree.delete(*self.password_tree.get_children())

        passwords = self.password_manager.get_all_passwords()

        for idx, pwd in enumerate(passwords):
            pwd_copy = pwd.copy()
            if self.hide_passwords_var.get():
                pwd_copy["password"] = "••••••••"

            self.password_tree.insert(
                "",
                tk.END,
                iid=str(idx),
                values=(
                    pwd_copy["description"],
                    pwd_copy["password"],
                    ", ".join(pwd.get("tags", []))
                )
            )

        self._update_tag_filter_options()
        self._filter_passwords()

    def _update_tag_filter_options(self):
        # Обновление списка доступных тегов для фильтрации паролей
        tags = set()
        for pwd in self.password_manager.get_all_passwords():
            tags.update(pwd.get("tags", []))

        all_tags = ["Все"] + sorted(tags)
        self.tag_filter["values"] = all_tags
        self.tag_filter.config(width=max(10, max(len(str(tag))
                               for tag in all_tags) + 2 if all_tags else 10))

    def _filter_passwords(self):
        # Фильтрация сохраненных паролей по поисковому запросу и выбранному тегу
        search_term = self.search_var.get().lower()
        selected_tag = self.tag_filter_var.get()

        self.password_tree.delete(*self.password_tree.get_children())

        passwords = self.password_manager.get_all_passwords()

        for idx, pwd in enumerate(passwords):
            tags = [t.lower() for t in pwd.get("tags", [])]

            match_search = (
                not search_term or
                search_term in pwd["description"].lower() or
                search_term in pwd["password"].lower() or
                any(search_term in tag for tag in tags)
            )

            match_tag = (selected_tag == "Все" or selected_tag.lower() in tags)

            if match_search and match_tag:
                display_password = "••••••••••••••••••••••••••••••••••••••••••••••••••••••••" if self.hide_passwords_var.get(
                ) else pwd["password"]

                self.password_tree.insert(
                    "",
                    tk.END,
                    iid=str(idx),
                    values=(
                        pwd["description"],
                        display_password,
                        ", ".join(pwd.get("tags", []))
                    ))

    def _get_selected_password_index(self):
        # Получение индекса выбранного пароля в дереве паролей
        selection = self.password_tree.selection()
        return int(selection[0]) if selection else None

    def _copy_selected_password(self):
        # Копирование выбранного пароля в буфер обмена
        index = self._get_selected_password_index()
        if index is None:
            messagebox.showerror("Ошибка", "Выберите пароль для копирования.")
            return

        pwd = self.password_manager.get_password(index)
        if pwd:
            pyperclip.copy(pwd["password"])
            messagebox.showinfo("Успешно", "Пароль скопирован в буфер обмена!")

    def _view_selected_password(self):
        index = self._get_selected_password_index()
        if index is None:
            messagebox.showerror("Ошибка", "Выберите пароль для просмотра.")
            return

        pwd = self.password_manager.get_password(index)
        if pwd:
            dialog = PasswordDialog(self.master, "Просмотр пароля", pwd)
            dialog.paste_button.pack_forget()
            dialog.paste_button.destroy()
            dialog.password_entry.config(state="readonly")
            dialog.description_entry.config(state="readonly")
            dialog.tags_entry.config(state="readonly")
            dialog.url_entry.config(state="readonly")

            # Удаляем стандартные кнопки
            for child in dialog.winfo_children():
                if isinstance(child, ttk.Button):
                    child.destroy()

            # Добавляем кнопку "Открыть ссылку" в отдельную строку
            url = pwd.get("url", "")
            if url.startswith(("http://", "https://")):
                link_frame = ttk.Frame(dialog)
                link_frame.grid(row=5, column=0, columnspan=2,
                                pady=10, sticky="ew")

                ttk.Button(
                    link_frame,
                    text="Открыть ссылку",
                    command=lambda: webbrowser.open(url),
                    cursor="hand2"
                ).pack(side=tk.TOP, fill=tk.X)

            # Добавляем кнопку закрытия
            ttk.Button(
                dialog,
                text="Закрыть",
                command=dialog.destroy
            ).grid(row=6, column=0, columnspan=2, pady=10, sticky="ew")

    def _edit_selected_password(self):
        # Редактирование выбранного пароля с помощью диалогового окна
        index = self._get_selected_password_index()
        if index is None:
            messagebox.showerror(
                "Ошибка", "Выберите пароль для редактирования.")
            return

        pwd = self.password_manager.get_password(index)
        if pwd:
            dialog = PasswordDialog(self.master, "Редактировать пароль", pwd)
            dialog.wait_window()

            if hasattr(dialog, 'result') and dialog.result:
                data = dialog.result
                self.password_manager.update_password(
                    index, data["password"], data["description"], data.get("tags", []), data.get("url", ""))
                self._refresh_password_list()

    def _delete_selected_password(self):
        # Удаление выбранного пароля
        index = self._get_selected_password_index()
        if index is None:
            messagebox.showerror("Ошибка", "Выберите пароль для удаления.")
            return

        if messagebox.askyesno("Подтверждение", "Вы уверены, что хотите удалить этот пароль?"):
            if self.password_manager.delete_password(index):
                messagebox.showinfo("Успех", "Пароль удален.")
                self._refresh_password_list()
            else:
                messagebox.showerror("Ошибка", "Не удалось удалить пароль.")

    def _copy_to_clipboard(self, widget):
        # Копирование выбранного текста в буфер обмена
        if widget.selection_present():
            self.master.clipboard_clear()
            self.master.clipboard_append(widget.selection_get())

    def _cut_to_clipboard(self, widget):
        # Вырезание выбранного текста и копирование в буфер обмена
        if widget.selection_present():
            self._copy_to_clipboard(widget)
            widget.delete("sel.first", "sel.last")

    def _paste_from_clipboard(self, widget):
        # Вставка текста из буфера обмена в виджет
        try:
            text = self.master.clipboard_get()
            if widget.selection_present():
                widget.delete("sel.first", "sel.last")
            widget.insert(tk.INSERT, text)
        except:
            pass

    def _select_all(self, widget):
        # Выделение всего текста в виджете
        widget.select_range(0, tk.END)
        widget.icursor(tk.END)

    def _on_right_click(self, event):
        # Обработка правого клика на виджетах Entry и Treeview
        widget = event.widget
        if isinstance(widget, (tk.Entry, ttk.Entry)):
            self.entry_context_menu.tk_popup(event.x_root, event.y_root)

    def _on_tree_right_click(self, event):
        # Обработка правого клика на виджете Treeview
        item = self.password_tree.identify_row(event.y)
        if item:
            self.password_tree.selection_set(item)
            self.tree_context_menu.tk_popup(event.x_root, event.y_root)
