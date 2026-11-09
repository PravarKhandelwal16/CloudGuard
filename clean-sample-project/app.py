from config import config
from database import db_manager
from services import calculate_statistics, normalize_text


def run_application():
    print(f"Starting {config.app_name} on port {config.port} ({config.environment})...")
    conn = db_manager.get_connection()
    print("Database connection status:", conn.get("status"))

    sample_data = [12.5, 18.2, 24.1, 9.8, 15.6]
    stats = calculate_statistics(sample_data)
    print("Calculated summary statistics:", stats)

    sample_input = "  Hello   CloudGuard   Secure   Architecture!  "
    clean_input = normalize_text(sample_input)
    print("Normalized text:", clean_input)


if __name__ == "__main__":
    run_application()

