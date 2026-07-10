#!/usr/bin/env python3
"""
Secure Password Manager - CLI entry point.

Workflow:
  Start -> Login/Register -> Verify Master Password -> Derive Encryption Key
        -> Unlock Vault -> Manage Credentials -> Encrypt Updates
        -> Save to Database -> Close Application -> Destroy Encryption Key
"""

import getpass
import sys

from database import database
from auth import register as register_mod
from auth import login as login_mod
from auth.session import Session
from manager import vault, search as search_mod, export as export_mod, import_data as import_mod
from crypto import random_generator


def pause():
    input("\nPress Enter to continue...")


def prompt_master_password(prompt="Master password: "):
    return getpass.getpass(prompt)


# ---------------------------------------------------------------------------
# Screens
# ---------------------------------------------------------------------------

def screen_register():
    print("\n=== Register New Vault ===")
    username = input("Choose a username: ").strip()
    pw1 = prompt_master_password("Choose a master password: ")
    pw2 = prompt_master_password("Confirm master password: ")
    try:
        register_mod.register_user(username, pw1, pw2)
        print(f"\nVault created for '{username}'. You can now log in.")
    except register_mod.RegistrationError as e:
        print(f"\nRegistration failed: {e}")
    pause()


def screen_login(session: Session) -> bool:
    print("\n=== Login ===")
    username = input("Username: ").strip()
    pw = prompt_master_password()
    try:
        login_mod.login(username, pw, session)
        print(f"\nWelcome, {session.username}. Vault unlocked.")
        return True
    except login_mod.LoginError as e:
        print(f"\nLogin failed: {e}")
        return False
    finally:
        pause()


def screen_add_credential(session: Session):
    print("\n=== Add Credential ===")
    service = input("Service/website name: ").strip()
    username = input("Username/email for this service: ").strip()

    use_gen = input("Generate a secure password automatically? (y/n): ").strip().lower()
    if use_gen == "y":
        length_raw = input("Password length [default 20]: ").strip()
        length = int(length_raw) if length_raw else 20
        password = random_generator.generate_password(length=length)
        print(f"Generated password: {password}")
    else:
        password = prompt_master_password("Password to store: ")

    notes = input("Notes (optional, press Enter to skip): ").strip() or None

    entry_id = vault.add_credential(session, service, username, password, notes)
    print(f"\nSaved '{service}' (entry #{entry_id}), encrypted with AES-256-GCM.")
    pause()


def _print_entries(entries):
    if not entries:
        print("\n(no entries found)")
        return
    print(f"\n{'ID':<5}{'Service':<25}{'Username':<30}")
    print("-" * 60)
    for e in entries:
        print(f"{e.id:<5}{e.service:<25}{e.username:<30}")


def screen_list_credentials(session: Session):
    print("\n=== Your Credentials ===")
    entries = vault.list_credentials(session)
    _print_entries(entries)

    if entries:
        choice = input("\nEnter an ID to view full details (or press Enter to go back): ").strip()
        if choice.isdigit():
            entry = vault.get_credential(session, int(choice))
            if entry:
                print(f"\nService : {entry.service}")
                print(f"Username: {entry.username}")
                print(f"Password: {entry.password}")
                print(f"Notes   : {entry.notes or '-'}")
                print(f"Created : {entry.created_at}")
                print(f"Updated : {entry.updated_at}")
            else:
                print("Entry not found.")
    pause()


def screen_search(session: Session):
    print("\n=== Search Credentials ===")
    query = input("Search service name: ").strip()
    results = search_mod.search_credentials(session, query)
    _print_entries(results)
    pause()


def screen_edit_credential(session: Session):
    print("\n=== Edit Credential ===")
    entry_id_raw = input("Entry ID to edit: ").strip()
    if not entry_id_raw.isdigit():
        print("Invalid ID.")
        pause()
        return
    entry_id = int(entry_id_raw)
    entry = vault.get_credential(session, entry_id)
    if entry is None:
        print("Entry not found.")
        pause()
        return

    print(f"Leave blank to keep current value.")
    service = input(f"Service [{entry.service}]: ").strip() or entry.service
    username = input(f"Username [{entry.username}]: ").strip() or entry.username
    new_pw = prompt_master_password("New password (blank to keep current): ")
    password = new_pw if new_pw else entry.password
    notes = input(f"Notes [{entry.notes or '-'}]: ").strip() or entry.notes

    vault.update_credential(session, entry_id, service, username, password, notes)
    print("Entry updated.")
    pause()


def screen_delete_credential(session: Session):
    print("\n=== Delete Credential ===")
    entry_id_raw = input("Entry ID to delete: ").strip()
    if not entry_id_raw.isdigit():
        print("Invalid ID.")
        pause()
        return
    entry_id = int(entry_id_raw)
    confirm = input("Are you sure? This cannot be undone. (y/n): ").strip().lower()
    if confirm == "y":
        if vault.delete_credential(session, entry_id):
            print("Entry deleted.")
        else:
            print("Entry not found.")
    pause()


def screen_generate_password():
    print("\n=== Password Generator ===")
    length_raw = input("Length [default 20]: ").strip()
    length = int(length_raw) if length_raw else 20
    pw = random_generator.generate_password(length=length)
    print(f"\nGenerated password: {pw}")
    pause()


def screen_export(session: Session):
    print("\n=== Export Encrypted Backup ===")
    output_path = input("Output file path [default storage/backup.spm]: ").strip() or "storage/backup.spm"
    backup_pw1 = prompt_master_password("Backup password (can differ from master password): ")
    backup_pw2 = prompt_master_password("Confirm backup password: ")
    if backup_pw1 != backup_pw2:
        print("Backup passwords do not match. Aborting.")
        pause()
        return
    path = export_mod.export_vault(session, backup_pw1, output_path)
    print(f"\nEncrypted backup written to: {path}")
    pause()


def screen_import(session: Session):
    print("\n=== Import Encrypted Backup ===")
    input_path = input("Backup file path: ").strip()
    backup_pw = prompt_master_password("Backup password: ")
    try:
        count = import_mod.import_vault(session, backup_pw, input_path)
        print(f"\nImported {count} entries into your vault.")
    except (import_mod.ImportError_, FileNotFoundError) as e:
        print(f"\nImport failed: {e}")
    pause()


# ---------------------------------------------------------------------------
# Menus
# ---------------------------------------------------------------------------

def main_menu():
    print("\n" + "=" * 40)
    print("   SECURE PASSWORD MANAGER")
    print("=" * 40)
    print("1. Login")
    print("2. Register")
    print("3. Exit")
    return input("Choose an option: ").strip()


def vault_menu(session: Session):
    print("\n" + "=" * 40)
    print(f"   VAULT - {session.username}")
    print("=" * 40)
    print("1. Add credential")
    print("2. List / view credentials")
    print("3. Search credentials")
    print("4. Edit credential")
    print("5. Delete credential")
    print("6. Generate a random password")
    print("7. Export encrypted backup")
    print("8. Import encrypted backup")
    print("9. Logout")
    return input("Choose an option: ").strip()


def vault_loop(session: Session):
    actions = {
        "1": screen_add_credential,
        "2": screen_list_credentials,
        "3": screen_search,
        "4": screen_edit_credential,
        "5": screen_delete_credential,
    }
    while True:
        try:
            choice = vault_menu(session)
            if choice in actions:
                actions[choice](session)
            elif choice == "6":
                screen_generate_password()
            elif choice == "7":
                screen_export(session)
            elif choice == "8":
                screen_import(session)
            elif choice == "9":
                print("\nLogging out and destroying encryption key from memory...")
                session.destroy()
                break
            else:
                print("Invalid option.")
        except RuntimeError as e:
            # Raised by Session.key when session expired
            print(f"\n{e}")
            session.destroy()
            break


def main():
    database.init_db()
    session = Session()

    while True:
        choice = main_menu()
        if choice == "1":
            if screen_login(session):
                vault_loop(session)
        elif choice == "2":
            screen_register()
        elif choice == "3":
            if session.is_active:
                session.destroy()
            print("\nGoodbye. Encryption key destroyed. Application closed.")
            sys.exit(0)
        else:
            print("Invalid option.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted. Application closed.")
        sys.exit(0)
