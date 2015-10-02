from __future__ import unicode_literals

import binascii
import struct
from base64 import urlsafe_b64encode, urlsafe_b64decode

from pymacaroons.utils import convert_to_bytes
from pymacaroons.serializers.base_serializer import BaseSerializer
from pymacaroons.exceptions import MacaroonSerializationException


class CompressedSerializer(BaseSerializer):
    def serialize(self, macaroon):
        combined = struct.pack("!32s", binascii.unhexlify(macaroon.signature_bytes))
        combined += _packetize(macaroon.location)
        combined += _packetize(macaroon.identifier)

        for caveat in macaroon.caveats:
            combined += _packetize(caveat._caveat_id)

            if caveat._verification_key_id and caveat._location:
                combined += _packetize(caveat._verification_key_id)
                combined += _packetize(caveat._location)
            else:
                combined += _packetize("")
                combined += _packetize("")

        return urlsafe_b64encode(
            combined.encode("zlib")
        ).decode('ascii').rstrip('=')

    def deserialize(self, serialized):
        from pymacaroons.macaroon import Macaroon
        from pymacaroons.caveat import Caveat

        macaroon = Macaroon()

        serialized = urlsafe_b64decode(convert_to_bytes(
            serialized + "=" * (-len(serialized) % 4)
        ))

        serialized = serialized.decode("zlib")

        macaroon.signature = binascii.hexlify(serialized[:32])
        serialized = serialized[32:]

        macaroon.location, serialized = _depacketize(serialized)
        macaroon.identifier, serialized = _depacketize(serialized)

        while serialized:
            cid, serialized = _depacketize(serialized)
            c = Caveat(caveat_id=cid)

            vid, serialized = _depacketize(serialized)
            cl, serialized = _depacketize(serialized)

            if vid and cl:
                c.verification_key_id = vid
                c.location = cl

            macaroon.caveats.append(c)

        return macaroon


def _packetize(data):
    encoded_data = data.encode("UTF-8")
    packet_size = len(encoded_data)

    if packet_size > 65535:
        raise MacaroonSerializationException(
            'Packet too long for serialization. '
        )

    packet = struct.pack(
        "!H%ds" % len(encoded_data),
        len(encoded_data),
        encoded_data
    )
    return packet


def _depacketize(packet):
    length, = struct.unpack("!H", packet[:2])
    value = packet[2:2+length].decode("UTF-8")
    return value, packet[2+length:]
