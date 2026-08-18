def load_rules():
    return {
        "suspicious_ports": {4444, 5555, 1337, 31337, 12345, 6667},
        "common_ports": {53, 80, 123, 443, 853, 8080, 8443, 5228, 5229, 5230},
    }
