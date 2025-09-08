import platform

def detect_os():
    system = platform.system()
    print(f"Detected system: {system}")
    return system
