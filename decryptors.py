from __future__ import annotations
from itertools import cycle
from typing import Callable, Optional
from Cryptodome.Cipher import ChaCha20

class Decryptor:
    def decrypt(self, data: bytes, password: bytes) -> bytes:
        raise NotImplementedError()
    @classmethod
    def from_decrypt_and_keyderive(cls, decrypt:Callable[[bytes,bytes],bytes], keyderive:Callable[[bytes],bytes]):
        class DecryptorImpl(Decryptor):
            def decrypt(self, data: bytes, password: bytes) -> bytes:
                return decrypt(data, keyderive(password))
        return DecryptorImpl()
    
    @classmethod
    def try_all(cls, decryptors:list[Decryptor], test_decryption_suceeded:Callable[[bytes],bool]):
        class DecryptorImpl(Decryptor):
            def __init__(self) -> None:
                self.decryptors=decryptors
                self.working_decryptor:Optional[Decryptor]=None
                super().__init__()
            def decrypt(self, data: bytes, password: bytes) -> bytes:
                
                if self.working_decryptor is not None:
                    return self.working_decryptor.decrypt(data, password)
                
                for d in self.decryptors:
                    try:
                        decryption = d.decrypt(data, password)
                        if test_decryption_suceeded(decryption):
                            self.working_decryptor=d
                            return decryption
                    except: continue
                raise RuntimeError("No decryptor worked")
        return DecryptorImpl()

def key_derivation_v20(password: bytes) -> bytes:
    XOR_WITH = b'ix&trw1Vcl<u-oltlSK=m0z9p.+tsFbj'
    return bytes(x1 ^ x2 for x1, x2 in zip(XOR_WITH, password+password))
    
    

def key_derivation_v31(password: bytes) -> bytes:
    """
    Derive the encryption key used for ChaCha20 in version 31
    """
    # The 16 bytes of the password are xored with a hardcoded value
    XOR_WITH_FIRST_STEP = b"^o0o7ql]m8y5:+1m"
    step_1 = bytes(x1 ^ x2 for x1, x2 in zip(XOR_WITH_FIRST_STEP, password[:16]))

    # The key consists of the previous value repeated and then xored with a hardcoded value
    XOR_WITH_SECOND_STEP = b"^cHc7Ql]diso:+2m~nTcA&3a7|?GB1z@"
    return bytes(x1 ^ x2 for x1, x2 in zip(XOR_WITH_SECOND_STEP, step_1+step_1))

def key_derivation_v15_v18(password: bytes) -> bytes:
    """
    Routine to derive the decryption key used in XTEA
    """
    KEY  = b"^hHc7Ql]N9Z4:+1m~nTcA&3a7|?GB1z@"
    return bytes(x1 ^ x2 for x1, x2 in zip(KEY, cycle(password)))

V31_NONCE = b'nzbnhgaf'
V20_NONCE = b'nzanhgaf'

def get_decrypt_chacha_with_nonce(nonce):
    def decrypt_chacha(buff: bytes, key: bytes) -> bytes:
        return ChaCha20.new(key=key, nonce=nonce).decrypt(buff)
    return decrypt_chacha

def decrypt_xtea(buff: bytes, key: bytes):
    limit = len(buff) & 0xFFFFFFF8
    aligned_buff = list(int.from_bytes(buff[i:i+4], byteorder='little') for i in range(0, limit, 4))
    key_as_u32 = [int.from_bytes(key[i:i+4], byteorder='little') for i in range(0, len(key), 4)]
    nb_round = 3
    xtea_decrypt(key_as_u32, aligned_buff, len(aligned_buff)*4, nb_round)
    uncrypted = [val.to_bytes(4, byteorder='little') for val in aligned_buff] + [val.to_bytes(1, byteorder='little') for val in buff[limit:]]
    return b''.join(uncrypted)


def xtea_decrypt(key, buf, ilen, nb_round):
    count = ilen // 8
    key_off = (ilen & 8) // 4
    DELTA = 0x9e3779b9
    UINT32_MASK = 0xFFFFFFFF

    key_0 = key[key_off] & UINT32_MASK
    key_1 = key[key_off + 1] & UINT32_MASK

    for i in range(0, count * 2, 2):
        buf[i] ^= key_0
        buf[i + 1] ^= key_1

        sum = DELTA * nb_round
        temp0 = buf[i] & UINT32_MASK
        temp1 = buf[i + 1] & UINT32_MASK

        for _ in range(nb_round):
            temp1 = (temp1 - ((key[2] + ((temp0 << 4) & UINT32_MASK)) ^ (key[3] + ((temp0 >> 5) & UINT32_MASK)) ^ (temp0 + sum))) & UINT32_MASK
            temp0 = (temp0 - ((key[0] + ((temp1 << 4) & UINT32_MASK)) ^ (key[1] + ((temp1 >> 5) & UINT32_MASK)) ^ (temp1 + sum))) & UINT32_MASK
            sum -= DELTA

        buf[i] = temp0
        buf[i + 1] = temp1
    return 0

decryptor_v15_v18 = Decryptor.from_decrypt_and_keyderive(decrypt_xtea, key_derivation_v15_v18)
decryptor_v20 = Decryptor.from_decrypt_and_keyderive(get_decrypt_chacha_with_nonce(V20_NONCE), key_derivation_v20)
decryptor_v31 = Decryptor.from_decrypt_and_keyderive(get_decrypt_chacha_with_nonce(V31_NONCE), key_derivation_v31)

def test_nrv2d_decompression(buffer:bytes)->bool:
    if len(buffer)>=0x200:
        try:
            ucl.nrv2d_decompress(buffer[:0x200], 0x4000)
        except Exception as e:
            return "-201" in str(e) #indicates that the decryption was working up until it hit the end of the buffer, so presumably it's correct
        
    else: #since the buffer is small we'll just try to decrypt the whole thing
        try:
            ucl.nrv2d_decompress(buffer, 0x4000)
        except: return False
    return True
    
decryptor_unknown_version = Decryptor.try_all([decryptor_v15_v18, decryptor_v20, decryptor_v31], test_nrv2d_decompression) 

decryptors_by_version = {
    "4.1.0.15":decryptor_v15_v18,
    "4.1.0.18":decryptor_v15_v18,
    "4.1.0.20":decryptor_v20,
    "4.1.0.31":decryptor_v31,
}