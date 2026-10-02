"""Synthetic primary hives only: no user identifiers, secrets or real evidence."""

import struct


STAMP = 116444736000000000  # 1970-01-01 UTC, synthetic.
RUN = "Microsoft\\Windows\\CurrentVersion\\Run"


def integer(raw, offset, value, fmt="<I"):
    struct.pack_into(fmt, raw, offset, value)


def checksum(raw):
    value = 0
    for offset in range(0, 0x1FC, 4):
        value ^= struct.unpack_from("<I", raw, offset)[0]
    integer(raw, 0x1FC, 1 if value == 0 else 0xFFFFFFFE if value == 0xFFFFFFFF else value)


def string(text):
    return (text + "\0").encode("utf-16le")


def multi(items):
    return ("\0".join(items) + "\0\0").encode("utf-16le")


class Builder:
    def __init__(self, hive_type="SOFTWARE", minor=5, index="li", compressed=True):
        self.raw = bytearray(0x1000)
        self.hive_type, self.minor, self.index, self.compressed = (
            hive_type,
            minor,
            index,
            compressed,
        )
        self.position, self.bin_start, self.bin_end = 0x1000, 0, 0x1000
        self.offsets = {}
        self.data_offsets = {}
        self.root = {"name": "ROOT", "children": {}, "values": []}
        self.key_count = 0

    def finish_bin(self):
        remaining = self.bin_end - self.position
        if remaining:
            assert remaining >= 8 and remaining % 8 == 0
            integer(self.raw, self.position, remaining, "<i")
        self.position = self.bin_end

    def allocate(self, payload):
        size = (len(payload) + 4 + 7) // 8 * 8
        if self.position + size > self.bin_end:
            self.finish_bin()
            pages = (size + 0x20 + 0xFFF) // 0x1000
            self.bin_start = len(self.raw)
            self.bin_end = self.bin_start + pages * 0x1000
            self.raw.extend(bytes(pages * 0x1000))
            self.raw[self.bin_start : self.bin_start + 4] = b"hbin"
            integer(self.raw, self.bin_start + 4, self.bin_start - 0x1000)
            integer(self.raw, self.bin_start + 8, pages * 0x1000)
            self.position = self.bin_start + 0x20
        pointer = self.position - 0x1000
        integer(self.raw, self.position, -size, "<i")
        self.raw[self.position + 4 : self.position + 4 + len(payload)] = payload
        self.position += size
        return pointer

    def add(self, path, name, kind, data, inline=None):
        node = self.root
        for part in path.split("\\") if path else ():
            node = node["children"].setdefault(part, {"name": part, "children": {}, "values": []})
        node["values"].append((name, kind, data, inline))

    def names(self, name):
        compressed = self.compressed and name.isascii()
        return name.encode("ascii") if compressed else name.encode("utf-16le"), compressed

    def value(self, path, row):
        name, kind, data, inline = row
        inline = len(data) <= 4 if inline is None else inline
        encoded, compressed = self.names(name)
        payload = bytearray(20 + len(encoded))
        payload[:2] = b"vk"
        integer(payload, 2, len(encoded), "<H")
        integer(payload, 4, len(data) | (0x80000000 if inline else 0))
        if inline:
            assert len(data) <= 4
            payload[8 : 8 + len(data)] = data
        elif data:
            if self.minor == 5 and len(data) > 0x3FD8:
                segments = [
                    self.allocate(data[i : i + 0x3FD8]) for i in range(0, len(data), 0x3FD8)
                ]
                pointers = self.allocate(b"".join(struct.pack("<I", p) for p in segments))
                data_pointer = self.allocate(struct.pack("<2sHI", b"db", len(segments), pointers))
                self.data_offsets[(path, name)] = {
                    "db": data_pointer,
                    "list": pointers,
                    "segments": segments,
                }
            else:
                data_pointer = self.allocate(data)
                self.data_offsets[(path, name)] = {"data": data_pointer}
            integer(payload, 8, data_pointer)
        integer(payload, 12, kind)
        integer(payload, 16, int(compressed), "<H")
        payload[20:] = encoded
        pointer = self.allocate(payload)
        self.offsets[(path, name)] = pointer
        return pointer

    def keys(self, node, path, parent, security):
        self.key_count += 1
        encoded, compressed = self.names(node["name"])
        payload = bytearray(76 + len(encoded))
        payload[:2] = b"nk"
        integer(payload, 2, (4 if parent is None else 0) | (32 if compressed else 0), "<H")
        integer(payload, 4, STAMP, "<Q")
        integer(payload, 16, 0xFFFFFFFF if parent is None else parent)
        integer(payload, 0x1C, 0xFFFFFFFF)
        integer(payload, 0x20, 0xFFFFFFFF)
        integer(payload, 0x28, 0xFFFFFFFF)
        integer(payload, 0x2C, security)
        integer(payload, 0x30, 0xFFFFFFFF)
        integer(payload, 0x48, len(encoded), "<H")
        payload[76:] = encoded
        pointer = self.allocate(payload)
        self.offsets[path] = pointer
        children = [
            (self.keys(child, path + ("\\" if path else "") + name, pointer, security), name)
            for name, child in node["children"].items()
        ]
        values = [self.value(path, row) for row in node["values"]]
        offset = 0x1004 + pointer
        if children:
            style = "li" if self.index == "ri" else self.index
            entries = bytearray()
            for child, name in children:
                entries += struct.pack("<I", child)
                if style == "lf":
                    entries += name[:4].encode("ascii").ljust(4, b"\0")
                elif style == "lh":
                    hash_value = 0
                    for char in name.upper():
                        hash_value = (hash_value * 37 + ord(char)) & 0xFFFFFFFF
                    entries += struct.pack("<I", hash_value)
            listing = self.allocate(struct.pack("<2sH", style.encode(), len(children)) + entries)
            if self.index == "ri":
                listing = self.allocate(struct.pack("<2sHI", b"ri", 1, listing))
            integer(self.raw, offset + 0x14, len(children))
            integer(self.raw, offset + 0x1C, listing)
        if values:
            listing = self.allocate(b"".join(struct.pack("<I", v) for v in values))
            integer(self.raw, offset + 0x24, len(values))
            integer(self.raw, offset + 0x28, listing)
        return pointer

    def build(self):
        descriptor = bytes((1, 0)) + struct.pack("<H", 0x8000) + bytes(16)
        security = self.allocate(
            struct.pack("<2sHIIII", b"sk", 0, 0, 0, 0, len(descriptor)) + descriptor
        )
        integer(self.raw, 0x1004 + security + 4, security)
        integer(self.raw, 0x1004 + security + 8, security)
        root = self.keys(self.root, "", None, security)
        integer(self.raw, 0x1004 + security + 12, self.key_count)
        self.finish_bin()
        self.raw[:4] = b"regf"
        integer(self.raw, 4, 1)
        integer(self.raw, 8, 1)
        integer(self.raw, 12, STAMP, "<Q")
        integer(self.raw, 20, 1)
        integer(self.raw, 24, self.minor)
        integer(self.raw, 32, 1)
        integer(self.raw, 36, root)
        integer(self.raw, 40, len(self.raw) - 0x1000)
        integer(self.raw, 44, 1)
        header_name = {"NTUSER": "NTUSER.DAT", "USRCLASS": "UsrClass.dat"}.get(
            self.hive_type, self.hive_type
        ).encode("utf-16le")
        assert len(header_name) <= 64
        self.raw[48 : 48 + len(header_name)] = header_name
        checksum(self.raw)
        return bytes(self.raw)


def example(kind=1, data=None, **options):
    builder = Builder(**options)
    builder.add(
        RUN, "Demo", kind, string('"C:\\Synthetic\\app.exe" --review') if data is None else data
    )
    return builder.build(), builder
