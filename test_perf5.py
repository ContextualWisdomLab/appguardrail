import time
import re

content = "Some random text content " * 1000 + "vulnerable"
finditer = re.compile("vulnerable").finditer
search = re.compile("vulnerable").search

# Benchmark search+finditer with match
start = time.time()
for _ in range(100000):
    if search(content):
        for match in finditer(content):
            pass
print(f"search+finditer (match): {time.time() - start:.4f}s")

# Benchmark finditer only with match
start = time.time()
for _ in range(100000):
    for match in finditer(content):
        pass
print(f"finditer (match): {time.time() - start:.4f}s")
