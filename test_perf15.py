import time
import string

printable_set = set(string.printable)

def is_printable_generator(text):
    return all(c in printable_set for c in text)

def is_printable_fast(text):
    return text.isprintable()

text = "a" * 1000

start = time.time()
for _ in range(100000):
    is_printable_generator(text)
print(f"Gen: {time.time() - start:.4f}s")

start = time.time()
for _ in range(100000):
    is_printable_fast(text)
print(f"Fast: {time.time() - start:.4f}s")
