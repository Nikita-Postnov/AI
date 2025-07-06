import os
import json
import re
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import tkinter.messagebox as messagebox
from cryptography.fernet import Fernet, InvalidToken
from config_manager import get_app_dir


class PasswordManager:
    # Класс для управления зашифрованными паролями
    def __init__(self, master_password=None):
        self.master_password = master_password
        self.passwords = []
        self.key = None
        self.salt = None
        self._create_default_config()
        self.load_config()
        if self.master_password:
            self._initialize_encryption()
        self.load_passwords()

    def backup_passwords(self):
        # Создает резервную копию всех паролей
        backup_dir = os.path.join(os.path.dirname(
            os.path.abspath(__file__)), "backups")
        backup_filename = os.path.join(
            backup_dir, "backup_passwords.bin")

        os.makedirs(backup_dir, exist_ok=True)

        try:
            data = json.dumps(self.passwords, indent=4, ensure_ascii=False)
            with open(backup_filename, 'w', encoding='utf-8') as backup_file:
                backup_file.write(data)
            return True, f"Резервная копия создана: {backup_filename}"
        except Exception as e:
            return False, f"Ошибка резервного копирования: {str(e)}"

    def regenerate_salt(self, master_password):
        # Генерация новой соли
        new_salt = os.urandom(16)

        # Сохранение временной резервной копии
        backup_passwords = self.get_all_passwords()

        try:
            # Обновление соли
            with open("salt.bin", "wb") as salt_file:
                salt_file.write(new_salt)
            self.salt = new_salt

            # Пересоздание ключа с новой солью
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(master_password.encode())
            self.key = base64.urlsafe_b64encode(key)

            # Перешифрование всех паролей
            self.passwords = []
            for item in backup_passwords:
                self.add_password(
                    item["password"], item["description"], item.get("tags", []))

            return True, "Соль успешно обновлена. Все пароли перешифрованы."

        except Exception as e:
            # Восстановление из резервной копии при ошибке
            self.passwords = backup_passwords
            return False, f"Ошибка обновления соли: {str(e)}"

    def _initialize_encryption(self):
        # Инициализирует шифрование данных с использованием мастер-пароля
        if not os.path.exists("salt.bin"):
            self.salt = os.urandom(16)
            with open("salt.bin", "wb") as salt_file:
                salt_file.write(self.salt)
        else:
            with open("salt.bin", "rb") as salt_file:
                self.salt = salt_file.read()
        # Создаем ключ для шифрования с использованием мастер-пароля
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(self.master_password.encode())
        self.key = base64.urlsafe_b64encode(key)

    def encrypt(self, data):
        # Шифрует данные с использованием мастер-пароля
        fernet = Fernet(self.key)
        return fernet.encrypt(data.encode()).decode()

    def decrypt(self, encrypted_data):
        # Расшифровывает данные с использованием мастер-пароля
        fernet = Fernet(self.key)
        return fernet.decrypt(encrypted_data.encode()).decode()

    def load_config(self):
        # Загружает конфигурацию и имя файла с паролями
        config_path = os.path.join(get_app_dir(), "config.json")
        print(f"Config path: {config_path}")
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    if "passwords_file" in config:
                        self.filename = config["passwords_file"]
                    else:
                        self.filename = os.path.join(os.path.dirname(
                            os.path.abspath(__file__)), "passwords.json")
            except Exception as e:
                print(f"Ошибка загрузки конфигурации: {str(e)}")
                self.filename = os.path.join(os.path.dirname(
                    os.path.abspath(__file__)), "passwords.json")
        else:
            self.filename = os.path.join(os.path.dirname(
                os.path.abspath(__file__)), "passwords.json")

    def add_password(self, password, description, tags=None, url=None):
        encrypted_password = self.encrypt(password)
        self.passwords.append({
            "password": encrypted_password,
            "description": description.strip(),
            "tags": tags or [],
            "url": url.strip() if url else "",  # Добавляем URL
            "encrypted": True
        })
        self._save_passwords()
        return True

    def _create_default_config(self):
        # Создает конфигурацию по умолчанию, если она не существует
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

    def update_password(self, index, password, description, tags=None, url=None):
        if 0 <= index < len(self.passwords):
            encrypted_password = self.encrypt(password)
            self.passwords[index] = {
                "password": encrypted_password,
                "description": description,
                "tags": tags or [],
                "url": url.strip() if url else "",  # Добавляем URL
                "encrypted": True
            }
            self._save_passwords()
            return True
        return False

    def export_to_txt(self, filename):
        try:
            decrypted_passwords = self.get_all_passwords()
            with open(filename, 'w', encoding='utf-8') as f:
                for pwd in decrypted_passwords:
                    f.write(f"Описание: {pwd['description']}\n")
                    f.write(f"Пароль: {pwd['password']}\n")
                    f.write(f"Теги: {', '.join(pwd['tags'])}\n")
                    f.write(f"URL: {pwd.get('url', '')}\n")  # Новая строка
                    f.write("-" * 40 + "\n")
            return True, "Пароли успешно экспортированы"
        except Exception as e:
            return False, f"Ошибка экспорта: {str(e)}"

    def import_from_txt(self, filename):
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read().strip()

            # Улучшенное разделение на блоки
            password_blocks = []
            current_block = []

            for line in content.split('\n'):
                line = line.strip()
                if line.startswith('-----') or line == '':
                    if current_block:
                        password_blocks.append('\n'.join(current_block))
                        current_block = []
                else:
                    current_block.append(line)

            if current_block:
                password_blocks.append('\n'.join(current_block))

            imported_data = []
            for block in password_blocks:
                password_info = {"description": "", "password": "", "tags": []}
                lines = block.strip().split('\n')

                for line in lines:
                    line = line.strip()
                    if not line:
                        continue

                    # Более гибкий парсинг данных
                    if ':' in line:
                        key_part, value_part = line.split(':', 1)
                        key = key_part.strip().lower()
                        value = value_part.strip()

                        if key.startswith('опис'):
                            password_info['description'] = value
                        elif key.startswith('парол'):
                            password_info['password'] = value
                        elif key.startswith('url'):
                            password_info['url'] = value
                        elif key.startswith('тег'):
                            tags = [t.strip() for t in re.split(
                                r'[,;]', value) if t.strip()]
                            password_info['tags'] = tags

                # Проверяем минимальные требования
                if password_info['description'] and password_info['password']:
                    imported_data.append(password_info)
                else:
                    print(f"Пропущен неполный блок: {block[:50]}...")

            if not imported_data:
                return False, "Не удалось найти валидные пароли в файле"

            # Добавляем все пароли
            imported_count = 0
            existing_descriptions = {p['description'] for p in self.passwords}

            for item in imported_data:
                if item['description'] in existing_descriptions:
                    print(f"Пропущен дубликат: {item['description']}")
                    continue

                encrypted_password = self.encrypt(item['password'])
                self.passwords.append({
                    "password": encrypted_password,
                    "description": item['description'],
                    "tags": item.get('tags', []),
                    "encrypted": True
                })
                imported_count += 1

            self._save_passwords()
            return True, f"Успешно импортировано {imported_count} паролей"

        except Exception as e:
            return False, f"Ошибка импорта: {str(e)}"

    def delete_password(self, index):
        # Удаляет пароль из списка паролей
        if 0 <= index < len(self.passwords):
            del self.passwords[index]
            self._save_passwords()
            return True
        return False

    def get_password(self, index):
        if 0 <= index < len(self.passwords):
            item = self.passwords[index]
            try:
                return {
                    "password": self.decrypt(item["password"]),
                    "description": item["description"],
                    "tags": item.get("tags", []),
                    "url": item.get("url", "")
                }
            except:
                return {"error": "Неверный мастер-пароль для расшифровки"}
        return None

    def get_all_passwords(self):
        return [{
            "password": self.decrypt(p["password"]),
            "description": p["description"],
            "tags": p.get("tags", []),
            "url": p.get("url", "")
        } for p in self.passwords]

    def load_passwords(self):
        # Загружает список паролей из файла
        if os.path.exists(self.filename):
            try:
                with open(self.filename, "r", encoding="utf-8") as f:
                    self.passwords = json.load(f)

                if self.passwords:
                    test_item = self.passwords[0]
                    self.decrypt(test_item["password"])

                if self.key and any(not p.get("encrypted", False) for p in self.passwords):
                    self._migrate_old_passwords()

            except (InvalidToken, json.JSONDecodeError):
                self.passwords = []
            except Exception:
                self.passwords = []

    def _save_passwords(self):
        data = [{
            "password": p["password"],
            "description": p["description"],
            "tags": p.get("tags", []),
            "url": p.get("url", ""),
            "encrypted": True
        } for p in self.passwords]

        try:
            with open(self.filename, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
                self.backup_passwords()
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка сохранения: {str(e)}")

    def _migrate_old_passwords(self):
        # Мигрирует старые пароли в зашифрованный формат
        migrated = False
        for item in self.passwords:
            if not item.get("encrypted", False):
                try:
                    item["password"] = self.encrypt(item["password"])
                    item["encrypted"] = True
                    migrated = True
                except Exception as e:
                    messagebox.showerror("Ошибка шифрования",
                                         f"Не удалось зашифровать пароль для '{item['description']}': {str(e)}")

        if migrated:
            self._save_passwords()
            messagebox.showinfo(
                "Миграция", "Существующие пароли были успешно зашифрованы")

    def change_master_password(self, old_password, new_password):
        # Изменяет мастер-пароль
        if old_password != self.master_password:
            return False, "Неверный текущий мастер-пароль"

        decrypted_passwords = []
        try:
            for item in self.passwords:
                decrypted_password = self.decrypt(item["password"]) if item.get(
                    "encrypted", False) else item["password"]
                decrypted_passwords.append({
                    "password": decrypted_password,
                    "description": item["description"],
                    "tags": item.get("tags", [])
                })
        except Exception as e:
            return False, f"Ошибка расшифровки паролей: {str(e)}"

        self.master_password = new_password
        self._initialize_encryption()

        self.passwords = []
        for item in decrypted_passwords:
            self.add_password(item["password"],
                              item["description"], item["tags"])

        return True, "Мастер-пароль успешно изменен"
