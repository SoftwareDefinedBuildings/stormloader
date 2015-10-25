#!/usr/bin/env python

#import serial
import argparse
import sys
import struct
import crcmod
import time
import pylibftdi
pylibftdi.USB_PID_LIST.append(0x6015)
from pylibftdi._base import FtdiError

# TODO come up with a resync that does not inject a 00 into the stream if we were in 
# escape mode. Do this by replacing the serial write with something that logs what the
# last sent byte was.

#define ESCAPE_CHAR 0xFC //This was chosen as it is infrequent in .bin files

EC = "\xFC"
CMD_PING      = "\x01"
CMD_INFO      = "\x03"
CMD_ID        = "\x04"
CMD_RESET     = "\x05"
CMD_EPAGE     = "\x06"
CMD_WPAGE     = "\x07"
CMD_XEBLOCK   = "\x08"
CMD_XWPAGE    = "\x09"
CMD_CRCRX     = "\x10"
CMD_RRANGE    = "\x11"
CMD_XRRANGE   = "\x12"
CMD_SATTR     = "\x13"
CMD_GATTR     = "\x14"
CMD_CRCIF     = "\x15"
CMD_CRCEF     = "\x16"
CMD_XEPAGE    = "\x17"
CMD_XFINIT    = "\x18"
CMD_CLKOUT    = "\x19"

RES_OVERFLOW  = "\x10"
RES_PONG      = "\x11"
RES_BADADDR   = "\x12"
RES_INTERROR  = "\x13"
RES_BADARGS   = "\x14"
RES_OK        = "\x15"
RES_UNKNOWN   = "\x16"
RES_XFTIMEOUT = "\x17"
RES_XFEPE     = "\x18"
RES_CRCRX     = "\x19"
RES_RRANGE    = "\x20"
RES_XRRANGE   = "\x21"
RES_GATTR     = "\x22"
RES_CRCIF     = "\x23"
RES_CRCXF     = "\x24"
RES_INFO      = "\x25"

syncstr = "\x00"+EC+CMD_RESET

class StormloaderException(Exception):
    pass

class CommsTimeoutException(StormloaderException):
    pass

class BadnessException(StormloaderException):
    pass

class StrangenessException(StormloaderException):
    pass

class BL_OverflowException(StormloaderException):
    pass

class BL_BaddAddressException(StormloaderException):
    pass

class BL_InternalErrorException(StormloaderException):
    pass

class BL_BadArgumentsException(StormloaderException):
    pass

class BL_UnknownCommandException(StormloaderException):
    pass

class BL_ExternalFlashTimeoutException(StormloaderException):
    pass

class BL_ExternalFlashProgramErrorException(StormloaderException):
    pass

FLASH_FLOOR   = 65536
FLASH_CEILING = 524287
XFLASH_FLOOR   = 524288
XFLASH_CEILING = 8388607
class StormLoader(object):

    #Duplicated for ease of use
    FLASH_FLOOR   = 65536
    FLASH_CEILING = 524287
    XFLASH_FLOOR   = 524288
    XFLASH_CEILING = 8388607

    def __init__(self, device=None):
        self.devid = device
        self.serial_mode = None
        self.dev = None
        self.dev = pylibftdi.serial_device.SerialDevice() #TODO fix device id
        self.dev.baudrate = 117200
        self.crcfunc = crcmod.mkCrcFun(0x104c11db7, initCrc=0, xorOut=0xFFFFFFFF)

    def _ser_serialmode(self):
        return
        if self.serial_mode != "serial":
            self.dev = pylibftdi.serial_device.SerialDevice() #TODO fix device id
            self.dev.baudrate = 117200
            self.serial_mode = "serial"

    # def _ser_bbmode(self):
    #     if self.serial_mode != "bitbang":
    #         self.dev = pylibftdi.BitBangDevice(self.devid)
    #         self.serial_mode = "bitbang"

    def _ser_write(self, val):
        self._ser_serialmode()
        rv = self.dev.write(val)
        if rv != len(val):
            raise BadnessException("Could not write full packet")

    def _ser_flush(self):
        self._ser_serialmode()
        try:
            self.dev.flush()
        except FtdiError as e:
            print "got ftdi error on flush, ignoring"

    def _ser_read(self, length, timeout=None):
        #print "new read"
        if timeout is None:
            timeout = 5
        self._ser_serialmode()
        sleeps = [0.001, 0.01, 0.1, 0.1, 0.2, 0.2, 0.2, 0.4, 0.6, 1]
        then = time.time()
        rv = self.dev.read(length)
        #print "read so far: ", len(rv), repr(rv)
        while len(rv) != length and time.time() - then < timeout:
            sl = sleeps[0] if len(sleeps) > 0 else 1
            time.sleep(sl)
            sleeps = sleeps[1:]
            rv += self.dev.read(length - len(rv))
            #print "read so far: ", len(rv), repr(rv)
        return rv

    def do_cmd(self, payload, cmd, expected, dosync=True, timeout=None):
        nt = timeout if timeout is not None else 3
        if dosync:
            self._ser_write(syncstr)
        time.sleep(0.0001) #don't remove this. it breaks EVERYTHING
        self._ser_flush()
        if len(payload) > 0:
            payload = payload.replace(EC,EC+EC)
            self._ser_write(payload)
        self._ser_write(EC)
        self._ser_write(cmd)
        rv = self._ser_read(2, timeout)
        if len(rv) != 2:
            #print "actual rv: ", repr(rv)
            raise CommsTimeoutException("Bored now...")
        if rv[0] != EC:
            raise StrangenessException("Expected a start of frame symbol")
        if rv[1] == RES_OVERFLOW:
            raise BL_OverflowException("YO! WTF Bro??")
        if rv[1] == RES_BADADDR:
            raise BL_BaddAddressException("C8H10N4O2 > 9000")
        if rv[1] == RES_INTERROR:
            raise BL_InternalErrorException("I'm a leaf on the... ")
        if rv[1] == RES_BADARGS:
            raise BL_BadArgumentsException("Trust me, I'm a professional")
        if rv[1] == RES_XFTIMEOUT:
            raise BL_ExternalFlashTimeoutException("Wasn't me.")
        if rv[1] == RES_XFEPE:
            raise BL_ExternalFlashProgramErrorException("Achievement get!")
        got = ""
        in_escape = False
        # while len(got) < expected:
        #     nxt = self._ser_read(expected-len(got))
        #     for n in nxt:
        #         if in_escape and n == EC:
        #             got += EC
        #         elif not in_escape and n == EC:
        #             in_escape = True
        #         elif in_escape and n != EC:
        #             raise StrangenessException("Unexpected start of frame")
        #         else:
        #             got += n

        while len(got) < expected:
            cr = self._ser_read(1, timeout)
            if len(cr) == 0:
                raise CommsTimeoutException("Read timeout after %d bytes, expected %d" % (len(got), expected))
            if cr[0] == EC:
                cr2 = self._ser_read(1, timeout)
                if len(cr2) == 0:
                    raise CommsTimeoutException("HEY! I'm (still) talking at you!")
                if cr2 == EC:
                    got += EC
                else:
                    raise StrangenessException("Unexpected start of frame")
            else:
                got += cr
        return rv[1], got

    def raw_read_buffer(self):
        return self._ser_read(80,0.5)

    def raw_read_noblock_buffer(self):
        rv = self.dev.read(80)
        return rv

    def raw_write(self, content):
        rv = self._ser_write(content)
        return rv

    def c_ping(self, timeout=None):
        code, _ = self.do_cmd("", CMD_PING, 0, timeout=timeout)
        if code != RES_PONG:
            raise BadnessException()

    def c_info(self):
        rv, body = self.do_cmd("", CMD_INFO, 192)
        if rv != RES_INFO:
            raise BadnessException()
        ln = ord(body[0])
        return body[1:ln+1]

    def c_id(self):
        pass

    def c_epage(self, address):
        assert address % 512 == 0
        pkt = struct.pack("<I", address)
        rv, _ = self.do_cmd(pkt, CMD_EPAGE, 0)
        if rv != RES_OK:
            raise BadnessException()

    def c_wpage(self, address, contents):
        assert len(contents) == 512
        assert address % 512 == 0
        if isinstance(contents, list):
            contents = "".join([chr(x) for x in contents])
        pkt = struct.pack("<I",address) + contents
        rv, _ = self.do_cmd(pkt, CMD_WPAGE, 0)
        if rv != RES_OK:
            raise BadnessException()

    def c_clkout(self):
        rv = self.do_cmd("", CMD_CLKOUT, 0)

    def c_xeblock(self, address):
        assert address % 2048 == 0
        pkt = struct.pack("<I", address)
        rv, _ = self.do_cmd(pkt, CMD_XEBLOCK, 0)
        if rv != RES_OK:
            raise BadnessException()

    def c_xwpage(self, address, contents):
        assert len(contents) == 256
        assert address % 256 == 0
        assert address >= XFLASH_FLOOR
        assert address <= XFLASH_CEILING
        if isinstance(contents, list):
            contents = "".join([chr(x) for x in contents])
        pkt = struct.pack("<I", address) + contents
        rv, _ = self.do_cmd(pkt, CMD_XWPAGE, 0)
        if rv != RES_OK:
            raise BadnessException()

    def c_crcrx(self):
        rv, pkt = self.do_cmd("", CMD_CRCRX, 6, dosync=False)
        if rv != RES_CRCRX:
            raise BadnessException()
        return struct.unpack("<HI",pkt)

    def c_rrange(self, address, length):
        assert length < 2047
        assert address >= 0
        assert address + length <= FLASH_CEILING + 1
        txpkt = struct.pack("<IH", address, length)
        rv, pkt = self.do_cmd(txpkt, CMD_RRANGE, length)
        if rv != RES_RRANGE:
            raise BadnessException()
        if len(pkt) != length:
            raise BadnessException()
        return pkt

    def c_xrrange(self, address, length):
        assert length < 2047
        assert address >= 0
        assert address <= XFLASH_CEILING
        txpkt = struct.pack("<IH", address, length)
        rv, pkt = self.do_cmd(txpkt, CMD_XRRANGE, length)
        if rv != RES_XRRANGE:
            raise BadnessException()
        if len(pkt) != length:
            raise BadnessException()
        return pkt

    def c_sattr(self, idx, key, val):
        assert idx >= 0
        assert idx < 16
        assert len(key) <= 8
        assert not "\x00" in key
        assert len(val) <= 55
        if isinstance(val, list):
            val = "".join([chr(x) for x in val])
        key += "\x00"*(8-len(key))
        txpkt = chr(idx) + key + chr(len(val)) + val
        rv, _ = self.do_cmd(txpkt, CMD_SATTR, 0)
        if rv != RES_OK:
            raise BadnessException()

    def c_gattr(self, idx, aslist=False):
        assert idx >= 0
        assert idx < 16
        rv, pkt = self.do_cmd(chr(idx), CMD_GATTR, 64)
        if rv != RES_GATTR:
            raise BadnessException()
        nlidx = pkt[:8].find("\x00")
        if nlidx != -1:
            key = pkt[:nlidx]
        else:
            key = pkt[:8]
        vlen = ord(pkt[8])
        if vlen == 255:
            return '', '' if not aslist else []
        assert vlen <= 55
        val = pkt [9:9+vlen]
        return key, val if not aslist else [ord(c) for c in val]

    def c_crcif(self, address, length):
        assert address >= 0
        assert address + length <= FLASH_CEILING + 1
        rv, pkt = self.do_cmd(struct.pack("<II", address, length), CMD_CRCIF, 4)
        if rv != RES_CRCIF:
            raise BadnessException()
        return struct.unpack("<I",pkt)[0]

    def c_crcef(self, address, length):
        assert address >= 0
        assert address + length <= XFLASH_CEILING + 1
        rv, pkt = self.do_cmd(struct.pack("<II", address, length), CMD_CRCEF, 4)
        if rv != RES_CRCXF:
            raise BadnessException()
        return struct.unpack("<I",pkt)[0]

    def c_xepage(self, address):
        assert address >= XFLASH_FLOOR
        assert address <= XFLASH_CEILING
        assert address % 256 == 0
        rv, _ = self.do_cmd(struct.pack("<I", address), CMD_XEPAGE, 0)
        if rv != RES_OK:
            raise BadnessException()

    def c_xfinit(self):
        rv, _ = self.do_cmd("", CMD_XFINIT, 0)

    def crc32(self, msg, init=0):
        if isinstance(msg, list):
            msg = "".join([chr(i) for i in msg])
        return self.crcfunc(msg, init)

    def read_extended_irange(self, address, length, progress=None, aslist=False):
        assert address >= 0
        assert address + length <= FLASH_CEILING + 1
        assert length > 0
        rvl = []
        while length > 0:
            if progress is not None:
                progress(length)
            rvl.append(self.c_rrange(address, min(length, 1024)))
            length -= 1024
            address += 1024
        rv = "".join(rvl)
        if aslist:
            return [ord(c) for c in rv]
        return rv

    def read_extended_xrange(self, address, length, progress=None, aslist=False):
        assert address >= 0
        assert address + length <= XFLASH_CEILING + 1
        assert length > 0
        rvl = []
        while length > 0:
            if progress is not None:
                progress(length)
            rvl.append(self.c_xrrange(address, min(length, 1024)))
            length -= 1024
            address += 1024
        rv = "".join(rvl)
        if aslist:
            return [ord(c) for c in rv]
        return rv

    def write_extended_irange(self, address, contents, progress=None):
        assert address >= FLASH_FLOOR
        assert address + len(contents) <= FLASH_CEILING + 1
        assert address % 512 == 0
        assert len(contents) > 0
        if isinstance(contents, list):
            contents = "".join([chr(x) for x in contents])
        if len(contents) % 512 != 0:
            contents += "\xFF"*(512 - (len(contents)%512))
        left = len(contents)
        while left > 0:
            if progress is not None:
                progress(left)
            self.c_wpage(address, contents[:512])
            address += 512
            contents = contents[512:]
            left -= 512

    def write_extended_xrange(self, address, contents, progress=None):
        assert address >= XFLASH_FLOOR
        assert address + len(contents) <= XFLASH_CEILING + 1
        assert address % 256 == 0
        assert len(contents) > 0
        if isinstance(contents, list):
            contents = "".join([chr(x) for x in contents])
        if len(contents) % 256 != 0:
            contents += "\xFF"*(256 - len(contents)%256)
        left = len(contents)
        while left > 0:
            if progress is not None:
                progress(left)
            self.c_xwpage(address, contents[:256])
            address += 256
            contents = contents[256:]
            left -= 256

    def set_reset(self, v):
        #TODO make this more parameterized. This is hacked for the chair boards
        self._ser_serialmode()
        self.dev.dtr = 1 if v else 0 #True is 1 is low

    def set_blmodepin(self, v):
        self._ser_serialmode()
        self.dev.rts = 1 if v else 0 #True is 1 is low
       
    def enter_bootload_mode(self):
        self.set_reset(True)
        self.set_blmodepin(True)
        self.set_reset(False)
        time.sleep(0.1)
        self.dev.flush()
        for i in xrange(30):
            try:
                self.c_ping(timeout=0.1)
                break
            except Exception as e:
                pass
        else:
            raise CommsTimeoutException("Could not enter bootload mode")
            
    def enter_payload_mode(self):
        self.set_reset(True)
        self.set_blmodepin(False)
        time.sleep(0.01)
        self.dev.flush()
        self.set_reset(False)
            



