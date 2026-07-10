import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestVaultEndToEnd(unittest.TestCase):
    """
    End-to-end test exercising register -> login -> add -> list -> search ->
    edit -> delete -> export -> import, against a temporary database file so
    it never touches the real storage/vault.db.
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_vault.db")

        # Point settings at a throwaway DB before importing modules that read it
        from config import settings
        settings.DB_PATH = self.db_path

        from database import database
        database.init_db()

        from auth import register, login
        from auth.session import Session

        self.register = register
        self.login = login
        self.Session = Session
        self.database = database

    def test_full_workflow(self):
        self.register.register_user("alice", "Str0ng!Passw0rd", "Str0ng!Passw0rd")

        session = self.Session()
        self.login.login("alice", "Str0ng!Passw0rd", session)
        self.assertTrue(session.is_active)

        from manager import vault, search as search_mod, export as export_mod, import_data as import_mod

        entry_id = vault.add_credential(session, "GitHub", "alice@example.com", "S3cretPW!", "personal account")
        entries = vault.list_credentials(session)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].service, "GitHub")
        self.assertEqual(entries[0].password, "S3cretPW!")

        results = search_mod.search_credentials(session, "git")
        self.assertEqual(len(results), 1)

        vault.update_credential(session, entry_id, "GitHub", "alice@example.com", "NewPW!23", "updated")
        updated = vault.get_credential(session, entry_id)
        self.assertEqual(updated.password, "NewPW!23")

        backup_path = os.path.join(self.tmpdir, "backup.spm")
        export_mod.export_vault(session, "BackupPass!1", backup_path)
        self.assertTrue(os.path.exists(backup_path))

        vault.delete_credential(session, entry_id)
        self.assertEqual(len(vault.list_credentials(session)), 0)

        imported = import_mod.import_vault(session, "BackupPass!1", backup_path)
        self.assertEqual(imported, 1)
        self.assertEqual(len(vault.list_credentials(session)), 1)

        session.destroy()
        self.assertFalse(session.is_active)

    def test_login_wrong_password_fails(self):
        self.register.register_user("bob", "AnotherStr0ng!Pw", "AnotherStr0ng!Pw")
        session = self.Session()
        with self.assertRaises(self.login.LoginError):
            self.login.login("bob", "WrongPassword!1", session)


if __name__ == "__main__":
    unittest.main()
