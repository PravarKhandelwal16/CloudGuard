import os
import zipfile
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def package_directory(source_dir_name: str, output_zip_name: str):
    source_dir = BASE_DIR / source_dir_name
    output_zip = BASE_DIR / output_zip_name
    print(f"Archiving {source_dir} -> {output_zip}...")
    with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(source_dir):
            for file in files:
                full_path = Path(root) / file
                rel_path = full_path.relative_to(source_dir)
                zf.write(full_path, arcname=str(rel_path).replace("\\", "/"))
    print(f"Successfully generated {output_zip} ({output_zip.stat().st_size} bytes)")


if __name__ == "__main__":
    package_directory("sample-project", "sample-project.zip")
    package_directory("clean-sample-project", "clean-sample-project.zip")
