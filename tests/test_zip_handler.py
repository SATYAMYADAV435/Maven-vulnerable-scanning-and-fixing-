import io
import zipfile
import pytest
from app.zip_handler import SafeZipExtractor, ZipSecurityError


def create_in_memory_zip(file_dict: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in file_dict.items():
            zf.writestr(name, content)
    return buf.getvalue()


def test_safe_zip_extraction():
    extractor = SafeZipExtractor()
    zip_bytes = create_in_memory_zip({
        "pom.xml": "<project></project>",
        "src/main/java/Main.java": "public class Main {}",
        "malicious.exe": "binary content",  # Disallowed extension
    })

    temp_dir, files = extractor.extract_to_temp(zip_bytes)
    try:
        assert "pom.xml" in files
        assert any("Main.java" in f for f in files)
        assert not any("malicious.exe" in f for f in files)
    finally:
        extractor.cleanup(temp_dir)


def test_zip_slip_path_traversal_rejected():
    extractor = SafeZipExtractor()
    zip_bytes = create_in_memory_zip({
        "../../etc/passwd": "root:x:0:0",
    })

    with pytest.raises(ZipSecurityError) as exc_info:
        extractor.extract_to_temp(zip_bytes)
    assert "traversal" in str(exc_info.value).lower() or "forbidden" in str(exc_info.value).lower()


def test_zip_bomb_file_count_rejected():
    extractor = SafeZipExtractor(max_file_count=5)
    files = {f"file_{i}.txt": "content" for i in range(10)}
    zip_bytes = create_in_memory_zip(files)

    with pytest.raises(ZipSecurityError) as exc_info:
        extractor.extract_to_temp(zip_bytes)
    assert "limit" in str(exc_info.value).lower()


def test_zip_bomb_size_rejected():
    extractor = SafeZipExtractor(max_uncompressed_bytes=100)
    zip_bytes = create_in_memory_zip({
        "large_file.txt": "A" * 200,
    })

    with pytest.raises(ZipSecurityError) as exc_info:
        extractor.extract_to_temp(zip_bytes)
    assert "uncompressed size" in str(exc_info.value).lower()
