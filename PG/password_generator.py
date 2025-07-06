import string
import random
import re
import json
import os
from config_manager import create_default_config
from config_manager import get_app_dir


class PasswordGenerator:
    # Класс для генерации паролей
    def __init__(self):
        self.password_length = 15
        self.use_uppercase = True
        self.use_lowercase = True
        self.use_digits = True
        self.use_symbols = True
        self.excluded_chars = ''
        self.load_config()

    def load_config(self):
        # Загружает конфигурацию из файла config.json
        config_path = os.path.join(get_app_dir(), "config.json")
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    if "max_password_length" in config:
                        self.max_password_length = config["max_password_length"]
                    if "default_length" in config:
                        self.password_length = config["default_length"]
                    if "use_uppercase" in config:
                        self.use_uppercase = config["use_uppercase"]
                    if "use_lowercase" in config:
                        self.use_lowercase = config["use_lowercase"]
                    if "use_digits" in config:
                        self.use_digits = config["use_digits"]
                    if "use_symbols" in config:
                        self.use_symbols = config["use_symbols"]
                    if "excluded_chars" in config:
                        self.excluded_chars = config["excluded_chars"]
            except Exception as e:
                print(f"Ошибка загрузки конфигурации: {str(e)}")
        else:
            self.max_password_length = 32
            create_default_config()
            self.load_config()

    def generate_password(self):
        # Генерирует пароль на основе текущих настроек
        char_sets = []
        if self.use_uppercase:
            char_sets.append(string.ascii_uppercase)
        if self.use_lowercase:
            char_sets.append(string.ascii_lowercase)
        if self.use_digits:
            char_sets.append(string.digits)
        if self.use_symbols:
            char_sets.append(string.punctuation)

        if not char_sets:
            return ""

        charset = ''.join(char_sets)
        for char in self.excluded_chars:
            charset = charset.replace(char, '')

        if not charset:
            return ""

        password = []
        for char_set in char_sets:
            valid_chars = ''.join(
                c for c in char_set if c not in self.excluded_chars)
            if valid_chars:
                password.append(random.choice(valid_chars))

        remaining_length = max(0, self.password_length - len(password))
        if remaining_length > 0:
            password += random.choices(charset, k=remaining_length)

        random.shuffle(password)
        return ''.join(password)

    def evaluate_password_strength(self, password):
        # Оценивает сложность пароля на основе различных критериев
        score = 0

        if len(password) >= 8:
            score += 10
        if len(password) >= 12:
            score += 10
        if len(password) >= 16:
            score += 10

        if re.search(r'[A-Z]', password):
            score += 10
        if re.search(r'[a-z]', password):
            score += 10
        if re.search(r'[0-9]', password):
            score += 10
        if re.search(r'[^A-Za-z0-9]', password):
            score += 10

        if not re.search(r'(.)\1\1', password):
            score += 10

        unique_chars = len(set(password))
        score += min(20, unique_chars * 2)

        if (re.search(r'[A-Z].*[0-9]|[0-9].*[A-Z]', password) and
                re.search(r'[a-z].*[0-9]|[0-9].*[a-z]', password)):
            score += 10

        return min(100, score)
