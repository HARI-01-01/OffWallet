from .protocol import ShadowProtocol

class SessionChannel:
    """
    Shadow Protocol v1 - Encrypted Session Channel (Python)
    """
    def __init__(self, sid: str, k_own_to_peer: bytes, k_peer_to_own: bytes):
        self.sid = sid
        self.k_own_to_peer = k_own_to_peer
        self.k_peer_to_own = k_peer_to_own
        self.send_seq = 0
        self.recv_seq = 0

    def seal(self, msg_type: int, payload: bytes) -> bytes:
        aad = self.sid.encode() + bytes([msg_type & 0xFF])
        ciphertext = ShadowProtocol.encrypt(self.k_own_to_peer, self.send_seq, aad, payload)
        self.send_seq += 1
        return ciphertext

    def open(self, msg_type: int, ciphertext: bytes) -> bytes:
        aad = self.sid.encode() + bytes([msg_type & 0xFF])
        plaintext = ShadowProtocol.decrypt(self.k_peer_to_own, self.recv_seq, aad, ciphertext)
        self.recv_seq += 1
        return plaintext

    @staticmethod
    def derive(ss: bytes, transcript_hash: bytes, sid: str, is_payer: bool) -> 'SessionChannel':
        prk = ShadowProtocol.hkdf(ss, transcript_hash, "shadow/v1/session-prk", 32)
        k_a2b = ShadowProtocol.hkdf(prk, b'', ShadowProtocol.TAG_KEY_A2B, 32)
        k_b2a = ShadowProtocol.hkdf(prk, b'', ShadowProtocol.TAG_KEY_B2A, 32)

        if is_payer:
            return SessionChannel(sid, k_a2b, k_b2a)
        else:
            return SessionChannel(sid, k_b2a, k_a2b)
