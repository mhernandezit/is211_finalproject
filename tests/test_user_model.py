import unittest
from models import User

class UserModelTestCase(unittest.TestCase):
    def test_password_setter(self):
        u = User(password = 'test')
        self.assertTrue(u.password_hash is not None)

    def test_no_