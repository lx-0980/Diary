import os, shutil, datetime

def backup_database():
    db_file = "diary.db"
    backup_dir = "backups"
    os.makedirs(backup_dir, exist_ok=True)
    if os.path.exists(db_file):
        ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        shutil.copy(db_file, os.path.join(backup_dir, f"diary_backup_{ts}.db"))
        print("✅ Backup created:", os.path.join(backup_dir, f"diary_backup_{ts}.db"))
