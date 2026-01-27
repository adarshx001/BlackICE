import hashlib

def generate_sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()

