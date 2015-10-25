
__author__ = 'immesys'

import gzip
import json
import cStringIO
import base64
from elftools.elf.elffile import ELFFile

class InvalidCellFileException(Exception):
    pass

class SLCell(object):

    FLASH_BASE = 0x10000
    PAYLOAD_LENGTH = 0x70000
    mandatory_fields = [
        "maintainer_name",
        "repository_url",
        "version",
      #  "build_number",
        "build_date",
        "changeset_id",
   ##     "binary_hash",
        "short_name",
        "description",
        "tool_versions",
    #    "build_host"
        #"variant_consts",
        #"ximage"
    ]
    def __init__(self):
        self._cellobj = {}
        self._rawimage = None
        self.elfcontents = ""

    def save(self, filename):
        binrep = json.dumps(self._cellobj, indent=2, sort_keys=True)
        fl = gzip.GzipFile(filename, "wb")
        fl.write(binrep)
        fl.close()

  #  def __getattr__(self, item):
  #      if item in object.__getattribute__(self,"_cellobj"):
  #          return object.__getattribute__(self,"_cellobj")[item]
  #      else:
  #          raise AttributeError("key %s not found" % item)
#
  #  def __setattr__(self, key, value):
  #      if key in object.__getattribute__(self,"_cellobj"):
  #          object.__getattribute__(self,"_cellobj")[key] = value
  #      else:
  #          raise AttributeError("key %s not found" % key)

    def _procelf(self):
        rf = cStringIO.StringIO(self.elfcontents)
        f = ELFFile(rf)
        filemap = []
        floor = SLCell.FLASH_BASE
        for segment in f.iter_segments():
            if len(segment.data()) == 0:
                continue
            binaddr = segment["p_paddr"] - floor
            if binaddr < 0:
                raise InvalidCellFileException("File contains addresses before payload area")
            end = binaddr + len(segment.data())
            if end >= SLCell.PAYLOAD_LENGTH:
                raise InvalidCellFileException("File contains addresses after payload area: \nend = 0x%08x" % end)
            if end >= len(filemap):
                filemap += ["\xFF"]*(end-len(filemap) + 1)
            for d in segment.data():
                filemap[binaddr] = d
                binaddr += 1
        self._rawimage = "".join(filemap)
        #Here we would check for variants
        self._cellobj["variant_consts"] = []

    def locate_symbol(self, name):
        rf = cStringIO.StringIO(self.elfcontents)
        f = ELFFile(rf)
        symtab = f.get_section_by_name(".symtab")
        if not symtab:
            raise InvalidCellFileException("ELF has been stripped!")
        sloc = None
        for s in symtab.iter_symbols():
            if s.name == name:
                sloc = s.entry.st_value
                break
        return sloc

    def add_asset(self, address, name, isexternal, assetstr):
        lst = self._cellobj["eassets" if isexternal else "iassets"]
        body = base64.b64encode(assetstr)
        lst.append({"name":name, "address":address,
                    "length":len(assetstr),"contents":body})

    def get_iasset(self, idx):
        return base64.b64decode(self._cellobj["iassets"][idx])

    def get_easset(self, idx):
        return base64.b64decode(self._cellobj["eassets"][idx])

    def list_iassets(self):
        def cv(o):
            rv = o.copy()
            rv["contents"] = base64.b64decode(o["contents"])
            return rv
        return [(i, cv(self._cellobj["iassets"][i]))
                for i in xrange(len(self._cellobj["iassets"]))]

    def list_eassets(self):
        def cv(o):
            rv = o.copy()
            rv["contents"] = base64.b64decode(o["contents"])
            return rv
        return [(i, cv(self._cellobj["eassets"][i]))
                for i in xrange(len(self._cellobj["eassets"]))]

    def get_raw_image(self):
        return self._rawimage

    def get_hex_image(self):
        ximage = ""
        addr = SLCell.FLASH_BASE
        for bcs in self._rawimage:
            if addr % 0x20 == 0:
                if len(ximage) > 0:
                    ximage += "\n"
                ximage += "0x{:05x} :".format(addr)
            elif addr % 0x08 == 0x00:
                ximage += " " #double space at 16
            ximage += " {:02x}".format(ord(bcs))
            addr += 1
        return ximage

    def set_elf(self, elf_filename):
        with open(elf_filename,"rb") as rf:
            contents = rf.read()
            self._cellobj["xelf"] = base64.b64encode(contents)
            self.elfcontents = contents
            self._procelf()

    @staticmethod
    def generate(params, elf):
        rv = SLCell()
        for f in SLCell.mandatory_fields:
            if f not in params:
                raise ValueError("Mandatory field %s not in parameters" % f)
        for f in params:
            rv._cellobj[f] = params[f]
        rv.set_elf(elf)

        #unspecified
        rv._cellobj["iassets"] = []
        rv._cellobj["eassets"] = []
        return rv

    @staticmethod
    def load(filename):
        self = SLCell()
        f = gzip.GzipFile(filename,"rb")
        contents = f.read()
        f.close()
        self._cellobj = json.loads(contents)
        for f in SLCell.mandatory_fields:
            if f not in self._cellobj:
                raise InvalidCellFileException("Missing field %s", f)
        if "xelf" not in self._cellobj:
            raise InvalidCellFileException("Missing ELF body")
        self.elfcontents = base64.b64decode(self._cellobj["xelf"])
        self._procelf()
        return self

    # @property
    # def bin_image(self):
    #     if self._rawimage is not None:
    #         return self._rawimage
    #
    #
    #     raw = ""
    #     for line in self._cellobj["ximage"]:
    #         line = line.strip()
    #         line = line[:line.find(":")]
    #         if len(line) == 0:
    #             continue
    #         vals = [chr(int(x,16) for line.split())]
    #         raw += vals
    #     self._rawimage = raw
    #     return raw
    #
    # @bin_image.setter
    # def bin_image(self, value):
    #     self._rawimage = value
    #     ximage = ""
    #     addr = SLCell.FLASH_BASE
    #     for bcs in value:
    #         if addr % 0x20 == 0:
    #             if len(ximage) > 0:
    #                 ximage += "\n"
    #             ximage += "0x{:05x} :".format(addr)
    #         ximage += " {:02x}".format(ord(bcs))
    #     self._cellobj["ximage"] = ximage


