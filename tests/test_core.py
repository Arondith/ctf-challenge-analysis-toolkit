import base64
import io
import zipfile

from backend.main import (
    detect_flags,
    identify,
    safe_archive_path,
    zip_children,
    carve,
    decode_children,
)


def test_h4g_flag():
    result = detect_flags(
        b"hello H4G{unit_test_flag} world"
    )

    assert any(
        flag == "H4G{unit_test_flag}"
        for flag, confidence in result
    )


def test_ctf_flag():
    result = detect_flags(
        b"CTF{unit_test_flag}"
    )

    assert result


def test_png_detection():
    kind, mime = identify(
        b"\x89PNG\r\n\x1a\n" + b"A" * 20,
        "test.png",
    )

    assert kind == "png"


def test_archive_paths():
    assert safe_archive_path(
        "folder/flag.txt"
    )

    assert not safe_archive_path(
        "../flag.txt"
    )

    assert not safe_archive_path(
        "/etc/passwd"
    )


def test_zip_extract():

    buffer = io.BytesIO()

    with zipfile.ZipFile(
        buffer,
        "w",
    ) as z:

        z.writestr(
            "flag.txt",
            "H4G{zip_test}",
        )

    result = zip_children(
        buffer.getvalue()
    )

    assert result

    assert result[0][1] == (
        b"H4G{zip_test}"
    )


def test_carving():

    buffer = io.BytesIO()

    with zipfile.ZipFile(
        buffer,
        "w",
    ) as z:

        z.writestr(
            "flag.txt",
            "H4G{carving_test}",
        )

    payload = (
        b"\x89PNG\r\n\x1a\n"
        + b"A" * 40
        + buffer.getvalue()
    )

    result = carve(
        payload
    )

    assert result


def test_base64_decode():

    encoded = base64.b64encode(
        b"H4G{recursive_decode_test}"
    )

    result = decode_children(
        encoded
    )

    assert any(
        b"H4G{recursive_decode_test}"
        in child[1]
        for child in result
    )
