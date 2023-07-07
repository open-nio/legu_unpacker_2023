#pip install pycryptodomex
#pip install hexdump

from Cryptodome.Cipher import ChaCha20
import hexdump

data=("A"*0x200).encode()
key=("B"*0x20).encode()
nonce=("cccccccc").encode()

out=ChaCha20.new(key=key, nonce=nonce).encrypt(data)

hexdump.hexdump(out)