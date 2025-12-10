import os
import subprocess
import unittest
import tempfile
import shutil

class TestCliApp(unittest.TestCase):
    def setUp(self):
        # Создаем временную директорию и переходим в нее,
        # чтобы тесты не модифицировали реальные файлы.
        self.test_dir = tempfile.mkdtemp()
        self.old_cwd = os.getcwd()
        os.chdir(self.test_dir)
        # Формируем абсолютный путь к файлу cli.py,
        # предполагая, что он находится в родительской директории тестов.
        self.cli_path = os.path.join(os.path.dirname(__file__), '..', 'cli.py')

    def tearDown(self):
        # Возвращаемся в исходную директорию и удаляем временную.
        os.chdir(self.old_cwd)
        shutil.rmtree(self.test_dir)

    def run_cli(self, args):
        """
        Запускает CLI-приложение с заданными аргументами и возвращает результат выполнения.
        """
        cmd = ['python', self.cli_path] + args
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result

    def test_gen_keys(self):
        """Тестирует генерацию ключей."""
        result = self.run_cli(['gen_keys'])
        self.assertIn("Keys generated successfully", result.stdout)
        # Проверяем, что директория keys существует и файлы с ключами созданы.
        self.assertTrue(os.path.isdir('keys'))
        self.assertTrue(os.path.isfile(os.path.join('keys', 'private_key.pem')))
        self.assertTrue(os.path.isfile(os.path.join('keys', 'public_key.pem')))

    def test_encrypt_decrypt(self):
        """Проверяет корректность шифрования и дешифрования."""
        # Сначала генерируем ключевую пару.
        self.run_cli(['gen_keys'])
        original_message = "Привет, как у тебя дела?!"
        # Шифруем сообщение, используя наш же публичный ключ в качестве peer-key.
        result_encrypt = self.run_cli([
            'encrypt',
            '--peer-key', os.path.join('keys', 'public_key.pem'),
            '--message', original_message
        ])
        self.assertIn("Message ecnrypted and saved to encrypted_message.bin", result_encrypt.stdout)
        # Проверяем, что файл с зашифрованным сообщением создан.
        self.assertTrue(os.path.isfile("encrypted_message.bin"))

        # Дешифруем сообщение.
        result_decrypt = self.run_cli([
            'decrypt',
            '--peer-key', os.path.join('keys', 'public_key.pem'),
            '--file', 'encrypted_message.bin'
        ])
        self.assertIn(f"Decrypted message: {original_message}", result_decrypt.stdout)

    def test_encrypt_missing_message_argument(self):
        """Проверяет, что при отсутствии обязательного аргумента --message выводится ошибка."""
        # Генерируем ключи, чтобы файл публичного ключа существовал.
        self.run_cli(['gen_keys'])
        result = self.run_cli([
            'encrypt',
            '--peer-key', os.path.join('keys', 'public_key.pem')
        ])
        self.assertIn("the following arguments are required: --message", result.stderr)

if __name__ == '__main__':
    unittest.main()
