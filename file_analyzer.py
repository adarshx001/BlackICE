import os
import math
import mimetypes

def calculate_entropy(file_bytes):
    if not file_bytes:
        return 0.0

    byte_counts = [0] * 256
    for b in file_bytes:
        byte_counts[b] += 1

    entropy = 0.0
    file_len = len(file_bytes)

    for count in byte_counts:
        if count == 0:
            continue
        p = count / file_len
        entropy -= p * math.log2(p)

    return round(entropy, 2)


def analyze_file(file_path, original_name):
    size_bytes = os.path.getsize(file_path)
    size_kb = round(size_bytes / 1024, 2)

    mime_type, _ = mimetypes.guess_type(original_name)
    mime_type = mime_type or "unknown"

    with open(file_path, "rb") as f:
        file_bytes = f.read()
        hex_preview = file_bytes[:256].hex()

    entropy = calculate_entropy(file_bytes)

    results = []

    if file_bytes[:2] == b"PK":
        results.append("File signature matches ZIP format")

    if entropy > 7.5:
        results.append("High entropy detected – possible encryption")

    if size_bytes > 5 * 1024 * 1024:
        results.append("Large file size – review before opening")

    return {
        "name": original_name,
        "size_kb": size_kb,
        "mime": mime_type,
        "entropy": entropy,
        "results": results,
        "hex_preview": hex_preview
    }
