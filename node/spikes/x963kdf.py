import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF
from cryptography.hazmat.backends import default_backend

def test():
    target = b'Hello World'
    algo = hashes.SHA256()
    output_len = 32
    sharedinfo = b"ANSI X9.63 Example"
    backend = default_backend()

    xkdf = X963KDF(
        algorithm=algo,
        length=output_len,
        sharedinfo=sharedinfo,
        backend=backend
    )
    key = xkdf.derive(target)
    xkdf = X963KDF(
        algorithm=algo,
        length=output_len,
        sharedinfo=sharedinfo,
        backend=backend
    )
    xkdf.verify(target, key)
    print (key.hex())
