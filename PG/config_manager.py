import os
import json
import sys


def get_app_dir():
    # Возвращает путь к директории исполняемого файла (main.py)
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(sys.argv[0]))


def create_default_config():
    # Создает конфигурационный файл по умолчанию, если он отсутствует
    config_path = os.path.join(get_app_dir(), "config.json")

    if not os.path.exists(config_path):
        default_config = {
            "salt_file": "salt.bin",
            "max_password_length": 32,
            "default_length": 18,
            "use_uppercase": True,
            "use_lowercase": True,
            "use_digits": True,
            "use_symbols": True,
            "excluded_chars": "O0DQl1I|i!S5Z2B8G6CGceaouvwxX",
            "passwords_file": "passwords.json"
        }
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(default_config, f, indent=4)
        except Exception as e:
            print(f"Ошибка создания конфигурации: {str(e)}")
