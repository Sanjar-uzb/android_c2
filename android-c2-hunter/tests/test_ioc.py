from hunter.detection.ioc import load_ioc_file


def test_load_ioc_file():
    data = "# comment\n8.8.8.8\n1.1.1.1\n"
    path = 'tmp_iocs.txt'
    with open(path, 'w', encoding='utf-8') as handle:
        handle.write(data)
    try:
        values = load_ioc_file(path)
        assert '8.8.8.8' in values
        assert '1.1.1.1' in values
    finally:
        import os
        os.remove(path)
