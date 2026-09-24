from src.whitespace_watermark import WhitespaceWatermark


def test_whitespace_watermark_round_trip():
    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<< /Type /Catalog >>\n"
        b"endobj\n"
        b"%%EOF\n"
    )

    method = WhitespaceWatermark()
    watermarked = method.add_watermark(pdf, secret="hello", key="mykey")
    recovered = method.read_secret(watermarked, key="mykey")

    assert recovered == "hello"
