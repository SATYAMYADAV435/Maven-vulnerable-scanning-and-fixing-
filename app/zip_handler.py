import os
import zipfile
import tempfile
import shutil
from typing import List, Optional, Tuple
from pathlib import Path


class ZipSecurityError(Exception):
    """Raised when a ZIP file violates security rules (zip-slip, bomb, disallowed extensions)."""
    pass


class SafeZipExtractor:
    """Safely extracts ZIP archives, mitigating zip-slip, zip-bombs, and unwanted files."""

    def __init__(
        self,
        max_uncompressed_bytes: int = 50 * 1024 * 1024,  # 50 MB
        max_file_count: int = 1000,
        allowed_extensions: Optional[List[str]] = None,
    ):
        self.max_uncompressed_bytes = max_uncompressed_bytes
        self.max_file_count = max_file_count
        self.allowed_extensions = set(
            ext.lower()
            for ext in (
                allowed_extensions
                or [".xml", ".java", ".properties", ".yaml", ".yml", ".json", ".md", ".txt"]
            )
        )

    def extract_to_temp(self, zip_source: str | bytes) -> Tuple[str, List[str]]:
        """
        Extracts ZIP contents to a new temporary directory after thorough validation.
        Returns:
            (temp_dir_path, list_of_extracted_relative_files)
        Raises:
            ZipSecurityError: on zip-slip, zip bomb, or corrupted archive.
        """
        target_temp_dir = tempfile.mkdtemp(prefix="mvn_scan_")

        try:
            if isinstance(zip_source, bytes):
                import io
                zfile = zipfile.ZipFile(io.BytesIO(zip_source))
            else:
                if not os.path.isfile(zip_source):
                    raise ZipSecurityError(f"ZIP file not found: {zip_source}")
                zfile = zipfile.ZipFile(zip_source)

            with zfile:
                # 1. Inspect all entries before extraction
                entries = zfile.infolist()
                if len(entries) > self.max_file_count:
                    raise ZipSecurityError(
                        f"Archive contains {len(entries)} files, exceeding limit of {self.max_file_count}."
                    )

                total_uncompressed_size = 0
                for info in entries:
                    total_uncompressed_size += info.file_size
                    if total_uncompressed_size > self.max_uncompressed_bytes:
                        raise ZipSecurityError(
                            f"Total uncompressed size exceeds limit of {self.max_uncompressed_bytes // (1024*1024)} MB."
                        )

                    # Zip-Slip check: verify no path traversal
                    filename = info.filename
                    if filename.startswith("/") or filename.startswith("\\"):
                        raise ZipSecurityError(f"Absolute path in archive forbidden: {filename}")

                    # Check for '..' components in path
                    norm_path = os.path.normpath(filename)
                    parts = Path(norm_path).parts
                    if ".." in parts:
                        raise ZipSecurityError(f"Path traversal ('..') detected: {filename}")

                # 2. Extract allowed files safely
                extracted_files: List[str] = []
                target_base = os.path.abspath(target_temp_dir)

                for info in entries:
                    if info.is_dir():
                        continue

                    # Extension check
                    _, ext = os.path.splitext(info.filename)
                    if ext.lower() not in self.allowed_extensions:
                        continue

                    # Safe resolved destination path check
                    dest_path = os.path.abspath(os.path.join(target_base, info.filename))
                    if not dest_path.startswith(target_base + os.sep) and dest_path != target_base:
                        raise ZipSecurityError(f"Zip slip escape detected: {info.filename}")

                    # Create parent directory and write file
                    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                    with zfile.open(info) as src, open(dest_path, "wb") as dst:
                        shutil.copyfileobj(src, dst)

                    extracted_files.append(os.path.relpath(dest_path, target_base))

            return target_temp_dir, extracted_files

        except Exception as e:
            # Clean up on failure
            if os.path.exists(target_temp_dir):
                shutil.rmtree(target_temp_dir, ignore_errors=True)
            if isinstance(e, ZipSecurityError):
                raise
            raise ZipSecurityError(f"Failed to extract ZIP safely: {str(e)}") from e

    @staticmethod
    def cleanup(temp_dir: str):
        """Safely delete temporary extraction directory."""
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
