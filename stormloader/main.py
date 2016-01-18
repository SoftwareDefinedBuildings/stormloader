#!/usr/bin/env python
# This file is part of StormLoader.
#
# StormLoader is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# StormLoader is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with StormLoader.  If not, see <http://www.gnu.org/licenses/>.
#
#
__author__ = 'Michael Andersen <m.andersen@cs.berkeley.edu>'

from sl_cell import SLCell, InvalidCellFileException
import sl_api
import configobj
import os.path
import datetime
import argparse
import sys
import time
import socket
import requests
import base64
import subprocess
import json
import tempfile
import fcntl

def loadconfigs(args, subsect):
    args = vars(args)
    rv = {}
    def _pcf(cf):
        if "global" in cf:
            for k in cf["global"]:
                rv[k] = cf["global"][k]
        if subsect in cf:
            for k in cf[subsect]:
                rv[k] = cf[subsect][k]
    #Load user default preferences
    try:
        home = os.path.expanduser("~")
        cf = configobj.ConfigObj(os.path.join(home,".stormloader"), file_error=True)
        _pcf(cf)
    except IOError:
        pass

    #Load current directory preferences
    try:
        cf = configobj.ConfigObj(".stormloader")
        _pcf(cf)
    except IOError:
        pass

    #Load preferences from arguments
    if args["config"] is not None:
        try:
            cf = configobj.ConfigObj(args.config, file_error=True)
            _pcf(cf)
        except IOError:
            pass

    for k in rv:
        args[k] = rv[k]

    return args

def act_ping(args):
    args = loadconfigs(args, "ping")
    sl = sl_api.StormLoader(args.get("tty", None))
    sl.enter_bootload_mode()
    try:
        sl.c_ping()
    except sl_api.StormloaderException as e:
        print "Device did not respond:",e
        sys.exit(1)
    if args["verbose"]:
        print "Device responded"
        sys.exit(0)

def act_trace(args):
    args = loadconfigs(args, "trace")
    port = args.get("port","2332")
    host = args.get("target","localhost")
    raw = False
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    def pack_raw(b):
        if len(b) <= 1:
            return b
        h = ord(b[0])
        itm = h >> 3
        lf = h & 0b11
        if lf == 0:
            #slip
            return b[1:]
        if lf == 1:
            print ("[%d] 0x%02x" % (itm, ord(b[1])))
            return b[2:]
        if lf == 2:
            if len(b) < 3:
                return b
            print ("[%d] 0x%04x" % (itm, ord(b[1]) + (ord(b[2]) << 8)))
            return b[3:]
        if lf == 3:
            if len(b) < 5:
                return b
            print ("[%d] 0x%08x" % (itm, ord(b[1]) + (ord(b[2]) << 8) + (ord(b[3]) << 16) + (ord(b[4]) << 24)))
            return b[5:]
    def pack_interlaced(b):
        if len(b) <= 1:
            return b
        h = ord(b[0])
        itm = h >> 3
        lf = h & 0b11
        if lf == 0:
            #slip
            return b[1:]
        if lf == 1:
            if itm == 0:
                sys.stdout.write("\033[33;1m")
                sys.stdout.write(b[1])
                sys.stdout.write("\033[0m")
                sys.stdout.flush()
            elif itm == 1:
                sys.stdout.write("\033[32;1m[{:02x}]\033[0m".format(ord(b[1])))
                sys.stdout.flush()
            return b[2:]
        if lf == 2:
            if len(b) < 3:
                return b
            sys.stdout.write("\033[32;1m[{:04x}]\033[0m".format(ord(b[1]) + (ord(b[2]) << 8)))
            sys.stdout.flush()
            return b[3:]
        if lf == 3:
            if len(b) < 5:
                return b
            sys.stdout.write("\033[32;1m[{:08x}]\033[0m".format(ord(b[1]) + (ord(b[2]) << 8) + (ord(b[3]) << 16) + (ord(b[4]) << 24)))
            sys.stdout.flush()
            return b[5:]
    if raw:
        pack = pack_raw
    else:
        pack = pack_interlaced

    while True:
        buf = ""
        try:
            s.connect((host, port))
            s.settimeout(2)

            while True:
                try:
                    dat = s.recv(32)
                    buf += dat
                    buf = pack(buf)
                    while len(buf) > 5:
                        buf = pack(buf)
                except socket.timeout as te:
                    pass

        except socket.error as e:
            print "Socket error: " + str(e)
            print "Trying again in 5s"
            time.sleep(5)

def act_flashall(args):
    devices = sl_api.StormLoader.list_devices()
    print "Found: ", " ".join(devices)
    for dev in devices:
        print ">>> Programming: "+dev
        act_flash(args, ftdi_device_id=dev)
        print

def act_flash(args, ftdi_device_id=None):
    try:
        args = loadconfigs(args, "flash")
        sl = sl_api.StormLoader(args.get("tty", None), device_id=ftdi_device_id)
        sl.enter_bootload_mode()
        then = time.time()
        cell = SLCell.load(args["sdb"])
        img = cell.get_raw_image()
        sl.write_extended_irange(cell.FLASH_BASE, img)
        now = time.time()
        if args["verbose"]:
            print "Wrote %d bytes in %.3f seconds" %(len(img), now-then)
        expected_crc = sl.crc32(img)
        written_crc = sl.c_crcif(cell.FLASH_BASE, len(img))
        if expected_crc != written_crc:
            print "CRC failure: expected 0x%04x, got 0x%04x" % (expected_crc, written_crc)
            sys.exit(1)
        elif args["verbose"]:
            print "CRC pass"
        sl.enter_payload_mode()
    except sl_api.StormloaderException as e:
        print "Fatal error:", e
        sys.exit(1)

def act_delta(args):
    args = loadconfigs(args, "flashdelta")
    sl = sl_api.StormLoader(args.get("tty", None))
    sl.enter_bootload_mode()

    newcell = SLCell.load(args["newimg"])
    newimg = newcell.get_raw_image()

    def full_flash():
        then = time.time()

        #write the whole img
        sl.write_extended_irange(SLCell.FLASH_BASE, newimg)
        expected_crc = sl.crc32(newimg)
        written_crc = sl.c_crcif(SLCell.FLASH_BASE, len(newimg))
        if expected_crc != written_crc:
            print "CRC failure: expected 0x%04x, got 0x%04x" % (expected_crc, written_crc)
            sys.exit(1)
        elif args["verbose"]:
            print "CRC pass"
        sl.enter_payload_mode()
        if args["verbose"]:
            print "Written and verified in %.2f seconds" % (time.time() - then)
        return

    #We also permit an empty file to be specified as the old image
    #this represents null

    if not (os.path.exists(args["oldimg"]) and os.path.isfile(args["oldimg"])) or os.stat(args["oldimg"]).st_size == 0:
        if args["verbose"]:
            print "Old image is empty, doing full flash"
        full_flash()
        return

    oldcell = SLCell.load(args["oldimg"])
    oldimg = oldcell.get_raw_image()

    oldimgcrc = sl.crc32(oldimg)
    actualcrc = sl.c_crcif(sl.FLASH_FLOOR, len(oldimg))

    if oldimgcrc != actualcrc:
        print "Actual contents do not match expected image, this will take longer"
        full_flash()
        return

    if len(newimg) % 512 != 0:
            newimg += "\xFF"*(512 - (len(newimg)%512))

    if len(oldimg) < len(newimg):
        old_end = len(oldimg) &~ 511
        start_address = (sl.FLASH_FLOOR + old_end)
        sl.write_extended_irange(start_address, newimg[old_end:])
        oldimg = oldimg[:old_end]
        oldimg += newimg[old_end:]

    assert len(oldimg) >= len(newimg)

    def fix_difference():
        for idx in xrange(len(newimg)):
            if oldimg[idx] != newimg[idx]:
                page_address = idx &~511
                real_address = page_address + oldcell.FLASH_BASE
                if args["verbose"]:
                    print "Changed page at 0x%08x" % real_address
                sl.c_wpage(real_address, newimg[page_address:page_address+512])
               # oldimg[page_address:page_address+512] = newimg[page_address:page_address+512]
                newoldimg = oldimg[:page_address] + newimg[page_address:page_address+512] + \
                            oldimg[page_address + 512:]
                return (True, newoldimg)
        return (False, oldimg)

    then = time.time()
    for i in xrange(len(oldimg)+1):
        changes, oldimg = fix_difference()
        if not changes:
            expected_crc = sl.crc32(newimg)
            written_crc = sl.c_crcif(oldcell.FLASH_BASE, len(newimg))
            if expected_crc != written_crc:
                print "CRC failure: expected 0x%04x, got 0x%04x" % (expected_crc, written_crc)
                sys.exit(1)
            elif args["verbose"]:
                print "CRC pass"
            print "Written and verified in %.2f seconds" % (time.time() - then)
            break
    else:
        raise sl.StormloaderException("Delta algorithm bug detected")
    sl.enter_payload_mode()

def act_calibrate(args):
    args = loadconfigs(args, "calibrate")
    coarse = args["coarse"]
    fine = args["fine"]
    try:
        page = [0x69, 0xC0, 0xFF, 0xEE, 0x00, coarse, 0x00, fine] + ([0xFF]*(512-8))
        sl = sl_api.StormLoader(args.get("tty", None))
        sl.enter_bootload_mode()
        sl.c_wpage(0xfe00, page)
        sl.enter_payload_mode()
    except sl_api.StormloaderException as e:
        print "Fatal error:", e
        sys.exit(1)

def act_clkout(args):
    sl = sl_api.StormLoader(args.get("tty", None))
    sl.enter_bootload_mode()
    sl.c_clkout()

def act_programall_kernel_payload(args):
    devices = sl_api.StormLoader.list_devices()
    print "Found: ", " ".join(devices)
    for dev in devices:
        print ">>> Programming: "+dev
        act_program_kernel_payload(args, ftdi_device_id=dev)
        print

def act_program_kernel_payload(args, ftdi_device_id=None):
    try:
        eximage = open(".cached_payload","r").read()
    except:
        eximage = None
    try:
        args = loadconfigs(args, "program")
        params = {}
        params["maintainer_name"] = "UNKNOWN"
        params["repository_url"] ="UNKNOWN"
        params["version"] = "UNKNOWN"
        params["build_date"] = str(datetime.datetime.now())
        params["changeset_id"] = "UNKNOWN"
        params["description"] = "UNKNOWN"
        params["short_name"] = "UNKNOWN"
        params["tool_versions"] = []
        cell = SLCell.generate(params, args["elf"])
        img = cell.get_raw_image()[0x40000:] #was 0x4...

        sl = sl_api.StormLoader(args.get("tty", None), device_id=ftdi_device_id)
        sl.enter_bootload_mode()
        print "Probing payload ELF for entry point..."
        _start = cell.locate_symbol("_start")
        if _start != None:
            print "Located _start at 0x%06x" % _start
            print "Setting entrypoint attribute"
            sl.c_sattr(1,"_start", [_start & 0xFF, (_start >> 8) & 0xFF, (_start >> 16) & 0xFF, (_start >> 24) & 0xFF ])
        else:
            print "Could not locate _start! This payload will not boot!"

        def wfull():
            print "Writing full payload..."
            idx = 0
            retries = 0
            then = time.time()
            while idx < len(img):
                endslice = idx + 0x200
                if endslice > len(img):
                    endslice = len(img)
                sl.write_extended_irange(0x50000 + idx, img[idx:endslice])
                expected_crc = sl.crc32(img[idx:endslice])
                written_crc = sl.c_crcif(0x50000 + idx, endslice-idx)
                if (expected_crc != written_crc):
                    #print ("expected page: ")
                    a = (" ".join("%02x" % ord(c) for c in img[idx:endslice]))
                    #print a
                    rpage = sl.read_extended_irange(0x50000 + idx, 0x200)
                    #print ("got page: ")
                    b = (" ".join("%02x" % ord(c) for c in rpage))
                    #print b
                    print ("slice crc mismatch at 0x%x"%(0x50000 + idx))
                    print "mismatches in bytes: ", [i/3 for i in xrange(len(b)) if a[i] != b[i]]
                    #sl.c_epage(0x50000+idx)

                    retries += 1
                    if (retries == 5):
                        print("hit max retries")
                        print("aborting. please report")
                        sys.exit(1)
                else:
                    retries = 0
                    idx += 0x200
            now = time.time()
            expected_crc = sl.crc32(img)
            written_crc = sl.c_crcif(0x50000, len(img))
            print "Image is 0x%x bytes long" % (len(img))
            if expected_crc != written_crc:
                print "CRC failure: expected 0x%04x, got 0x%04x" % (expected_crc, written_crc)
                sys.exit(1)
            print "Wrote and verified %d bytes in %.3f seconds" %(len(img), now-then)

        if eximage != None:
            excrc = sl.crc32(eximage)
            realcrc = sl.c_crcif(0x50000, len(eximage))
            if excrc != realcrc:
                print "Payload cached contents do not match (this will take longer)"
                wfull()
            else:
                newimg = img
                oldimg = eximage
                if len(newimg) % 512 != 0:
                        newimg += "\xFF"*(512 - (len(newimg)%512))

                if len(oldimg) < len(newimg):
                    old_end = len(oldimg) &~ 511
                    start_address = (0x50000 + old_end)
                    sl.write_extended_irange(start_address, newimg[old_end:])
                    oldimg = oldimg[:old_end]
                    oldimg += newimg[old_end:]

                assert len(oldimg) >= len(newimg)

                def fix_difference():
                    for idx in xrange(len(newimg)):
                        if oldimg[idx] != newimg[idx]:
                            page_address = idx &~511
                            real_address = page_address + 0x50000
                            if args["verbose"]:
                                print "Changed page at 0x%08x" % real_address
                            sl.c_wpage(real_address, newimg[page_address:page_address+512])
                           # oldimg[page_address:page_address+512] = newimg[page_address:page_address+512]
                            newoldimg = oldimg[:page_address] + newimg[page_address:page_address+512] + \
                                        oldimg[page_address + 512:]
                            return (True, newoldimg)
                    return (False, oldimg)

                then = time.time()
                for i in xrange(len(oldimg)+1):
                    changes, oldimg = fix_difference()
                    if not changes:
                        expected_crc = sl.crc32(newimg)
                        written_crc = sl.c_crcif(0x50000, len(newimg))
                        if expected_crc != written_crc:
                            print "CRC failure: expected 0x%04x, got 0x%04x" % (expected_crc, written_crc)
                            sys.exit(1)
                        elif args["verbose"]:
                            print "CRC pass"
                        print "Written and verified in %.2f seconds" % (time.time() - then)
                        break
                else:
                    raise sl.StormloaderException("Delta algorithm bug detected")
        else:
            print "No cached contents (this will take longer)"
            wfull()
        with open(".cached_payload","w") as f:
            f.write(img)

        sl.enter_payload_mode()
    except sl_api.StormloaderException as e:
        print "Fatal error:", e
        sys.exit(1)

def act_flash_assets(args):
    try:
        args = loadconfigs(args, "assetflash")
        sl = sl_api.StormLoader(args.get("tty", None))
        sl.enter_bootload_mode()
        then = time.time()
        cell = SLCell.load(args["sdb"])
        for i, a in cell.list_iassets():
            body = a["contents"]
            if args["verbose"]:
                print "writing %s to iflash @ 0x%x (%d : 0x%x bytes)... " %\
                      (a["name"],a["address"],a["length"],a["length"]),
                sys.stdout.flush()
            sl.write_extended_irange(a["address"], body)
            if args["verbose"]:
                print "ok"
        for i, a in cell.list_eassets():
            body = a["contents"]
            if args["verbose"]:
                print "writing %s to xflash @ 0x%x (%d : 0x%x bytes)... " %\
                      (a["name"],a["address"],a["length"],a["length"]),
                sys.stdout.flush()
            sl.write_extended_xrange(a["address"], body)
            ecrc = sl.crc32(body)
            rcrc = sl.c_crcef(a["address"], a["length"])
            if ecrc != rcrc:
                print "CRC FAIL! (expected 0x%08x, got 0x%08x" % (ecrc, rcrc)
                sys.exit(1)
            if args["verbose"]:
                print "ok"
        now = time.time()
        if args["verbose"]:
            print "%.2f seconds" % (now-then)
        sl.enter_payload_mode()

    except sl_api.StormloaderException as e:
        print "Fatal error:", e
        sys.exit(1)

def act_tailall(args):
    devices = sl_api.StormLoader.list_devices()
    print "Found: ", " ".join(devices)
    args = loadconfigs(args, "tail")
    devices_sl = [sl_api.StormLoader(args.get("tty", None), device_id=dev) for dev in devices]
    io = args.get("interactive", False)
    if not args["noreset"]:
        for sl in devices_sl:
            sl.enter_payload_mode()
    print "[SLOADER] Attached to", " ".join(devices)
    device_buffers = {devid: "" for devid in devices}
    try:
        while True:
            for sl in devices_sl:
                sep = '\n\033[95m['+sl.device_id+']\033[0m  ' if args["prefix"] else '\n'
                c = sl.raw_read_noblock_buffer()
                if len(c) > 0:
                    alllines = c.split('\n')
                    toprint = sep.join(alllines[:-1]) # all but last
                    leftover = alllines[-1]
                    sys.stdout.flush()
                    sys.stdout.write(sep + device_buffers[sl.device_id] + toprint)
                    device_buffers[sl.device_id] = leftover
                    sys.stdout.flush()
                if io:
                    try:
                        input = sys.stdin.read()
                        if len(input) > 0:
                            for sl in devices_sl:
                                sl.raw_write(input)
                    except IOError:
                        pass


    except KeyboardInterrupt:
        sys.exit(0)

def act_tail(args):
    args = loadconfigs(args, "tail")
    sl = sl_api.StormLoader(args.get("tty", None))
    io = args.get("interactive", False)
    if io:
        fd = sys.stdin.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    if not args["noreset"]:
        sl.enter_payload_mode()
    print "[SLOADER] Attached"
    try:
        while True:
            c = sl.raw_read_noblock_buffer()
            if len(c) > 0:
                sys.stdout.write(c)
                sys.stdout.flush()
            if io:
                try:
                    input = sys.stdin.read()
                    if len(input) > 0:
                        sl.raw_write(input)
                except IOError:
                    pass


    except KeyboardInterrupt:
        sys.exit(0)

def _add_asset(cell, args):
    isexternal = not args["internal"]
    if args["addr"] is not None:
        addr = int(args["addr"],0)
    else:
        addrs = [x[1]["address"] + x[1]["length"]
                     for x in (cell.list_eassets() if isexternal else
                               cell.list_iassets())]
        if len(addrs) == 0:
            addr = sl_api.XFLASH_FLOOR if isexternal else sl_api.FLASH_FLOOR
        elif isexternal:
            addr = (max(addrs) + 256) &~ 255
        elif not isexternal:
            addr = (max(addrs) + 512) &~ 511

    f = open(args["asset"],"r")

    body = f.read()
    f.close()
    name = args["name"]
    name = args["asset"] if name is None else name
    cell.add_asset(addr, name, isexternal, body)

def act_add_asset(args):
    args = loadconfigs(args, "assetadd")
    cell = SLCell.load(args["sdb"])
    _add_asset(cell, args)
    cell.save(args["sdb"])

def act_list_assets(args):
    args = loadconfigs(args, "assetlist")
    cell = SLCell.load(args["sdb"])
    iassets = cell.list_iassets()
    eassets = cell.list_eassets()
    def pr_assets_human(assets):
        print " # Address   Length  Name"
        for (i, a) in assets:
            print "{:>2d} 0x{:07x} 0x{:05x} {}".format(i, a["address"], a["length"], a["name"])
    def pr_assets_header(assets):
        s1s = []
        s2s = []
        s3s = []
        for (i, a) in assets:
            s1s.append(("#define ASSET_{}_NAME".format(a["name"].upper()),
                        "\"{}\"".format(a["name"])))
            s2s.append(("#define ASSET_{}_ADDR".format(a["name"].upper()),
                        "0x{:07x}".format(a["address"])))
            s3s.append(("#define ASSET_{}_LEN".format(a["name"].upper()),
                        "0x{:05x}".format(a["length"])))
        longest = max(len(i[0]) for i in (s1s+s2s+s3s))
        for i in s1s+s2s+s3s:
            print ("{:<%ds} {}" % longest).format(*i)

    if len(iassets) > 0:
        print "Internal flash assets"
        if not args["header"]:
            pr_assets_human(iassets)
        else:
            pr_assets_header(iassets)
    else:
        print "No internal flash assets"
    print ""
    if len(eassets) > 0:
        print "External flash assets"
        if not args["header"]:
            pr_assets_human(eassets)
        else:
            pr_assets_header(eassets)
    else:
        print "No external flash assets"

def act_hexdump(args):
    args = loadconfigs(args, "hexdump")
    cell = SLCell.load(args["sdb"])
    print cell.get_hex_image()

def act_factoryinit(args):
    args = loadconfigs(args, "factoryinit")
    sl = sl_api.StormLoader(args.get("tty", None))
    sl.c_xfinit()

def act_sattr(args):
    args = loadconfigs(args, "sattr")
    if args["hex"]:
        val = ""
        for i in range(len(args["value"])/2):
            val += chr(int(args["value"][i*2:(i+1)*2],16))
    else:
        val = args["value"]
    sl = sl_api.StormLoader(args.get("tty", None))
    sl.enter_bootload_mode()
    sl.c_sattr(args["index"],args["key"], val)

def act_gattr(args):
    args = loadconfigs(args, "gattr")
    sl = sl_api.StormLoader(args.get("tty", None))
    sl.enter_bootload_mode()
    for i in range(16):
        k, val = sl.c_gattr(i, True)
        print "%s => %s" % (k, " ".join("{:02x}".format(kk) for kk in val))

def act_pack(args):
    args = loadconfigs(args, "pack")
    params = {}
    def cnn(v):
        if args[v] is None:
            print "Expected '%s' argument for sdb packing" % v
            sys.exit(1)
        return args[v]

    params["maintainer_name"] = cnn("maintainer")
    params["repository_url"] = args.get("repository","UNKNOWN")
    params["version"] = cnn("version")
    params["build_date"] = str(datetime.datetime.now())
    params["changeset_id"] = args.get("changeset","UNKNOWN")
    params["description"] = cnn("description")
    params["short_name"] = cnn("name")
    params["tool_versions"] = []
    if args["tool"] is None: args["tool"] = []
    for tl in args["tool"]:
        try:
            tool, version = tl.split("=")
            params["tool_versions"].append((tool, version))
        except ValueError:
            print "Invalid tool version specification '%s'. " % tl
            print "Expected 'toolname=version'"
            sys.exit(1)


    cell = SLCell.generate(params, args["elf"])
    oname = args.get("outfile", params["short_name"]+".sdb")

    if args["assetlist"] is not None:
        f = open(args["assetlist"],"r")
        for l in f.readlines():
            l = l.strip()
            if len(l) == 0 or l.startswith("#"): continue
            la = l.split()
            if len(la) != 4:
                print "Asset manifest syntax is <i/x> <addr/*> <name> <filename>"
                print "got: ", repr(la)
                sys.exit(1)
            intex, addr, name, filename = la
            if intex not in ["i","x"]:
                print "Incorrect location specifier for flash asset: allowed 'i' or 'x'"
                sys.exit(1)
            _add_asset(cell, {"internal": intex == "i", "name": name, "asset": filename, "addr": None if addr == "*" else addr})


    cell.save(oname)

def act_register(args):
    args = loadconfigs(args, "register")
    out = subprocess.check_output(["gpg","--export",args["key"]])
    if out == "":
        print "Could not find key in user's default gpg keyring"
        sys.exit(1)
    key = out
    r = requests.post("http://cloud.storm.rocks/register", data=json.dumps({
        "namespace":args["namespace"],
        "email":args["email"],
        "key":base64.b64encode(key)
    }))
    rv = json.loads(r.text)
    if rv["status"] != "success":
        print "Failed to register namespace:",rv["message"]
    else:
        print "Namespace registered"

def act_publish(args):
    args = loadconfigs(args, "publish")
    try:
        namespace, name = args["name"].split(":",1)
    except:
        print "Expected name of the form namespace:name"
    sigfilename = tempfile.mktemp()
    try:
        out = subprocess.check_output(["gpg","-u",args["key"],"--output",sigfilename,"--detach-sign",args["sdb"]])
    except:
        print "Failed to sign"
    with open(args["sdb"]) as sdbf:
        with open(sigfilename) as sigfile:
            req = {"signature":base64.b64encode(sigfile.read()),
                   "namespace":namespace,
                   "name":name,
                   "sdb":base64.b64encode(sdbf.read())}
            r = requests.post("http://cloud.storm.rocks/publish",data=json.dumps(req))
            rv = json.loads(r.text)
            if rv["status"] != "success":
                print "Failed to publish:",rv["message"]
            else:
                print "Published as ",rv["link"]

def act_cloudflash(args):
    args = loadconfigs(args, "cloudflash")
    imgl = args["image"].split(":", 1)
    if len(imgl) != 2:
        print "bad image descriptor, expected ns:name"
    ithen = time.time()
    if args["verbose"]:
        print "Downloading image ",
        sys.stdout.flush()
    r = requests.get("http://cloud.storm.rocks/r/"+imgl[0]+"/"+imgl[1])
    if args["verbose"]:
        print "done (%.3f seconds)" %(time.time() - ithen)
    if len(r.content) == 0:
        print "Could not download image"
        sys.exit(1)
    with tempfile.NamedTemporaryFile() as ntf:
        try:
            ntf.write(r.content)
            ntf.flush()
            sl = sl_api.StormLoader(args.get("tty", None))
            sl.enter_bootload_mode()
            then = time.time()
            try:
                cell = SLCell.load(ntf.name)
            except:
                print "SDB image is corrupt"
                sys.exit(1)
            img = cell.get_raw_image()
            sl.write_extended_irange(cell.FLASH_BASE, img)
            now = time.time()
            if args["verbose"]:
                print "Wrote %d bytes in %.3f seconds" %(len(img), now-then)
            expected_crc = sl.crc32(img)
            written_crc = sl.c_crcif(cell.FLASH_BASE, len(img))
            if expected_crc != written_crc:
                print "CRC failure: expected 0x%04x, got 0x%04x" % (expected_crc, written_crc)
                sys.exit(1)
            elif args["verbose"]:
                print "CRC pass"
            sl.enter_payload_mode()
        except sl_api.StormloaderException as e:
            print "Fatal error:", e
            sys.exit(1)



def act_borderconfig(args):
    args = loadconfigs(args, "borderconfig")
    def _pack_ipv4_addr(addr):
        """packs IPv4 address e.g. 10.4.10.1 into a stringified uint32"""
        return bytearray(map(int, addr.split(".")))

    if args["sample"]:
        print """[main]
mesh-ip6-prefix=2001:470:4112:2::
remote-tunnel-addr=10.4.10.3
local-tunnel-addr=10.4.10.2
local-netmask=255.255.255.0
local-gateway-addr=10.4.10.1
"""
        sys.exit(0)

    # setup to write values
    sl = sl_api.StormLoader(args["tty"])
    sl.enter_bootload_mode()
    if args["config"]:
        if args["verbose"]:
            print "Loading config from", args["config"]
        from ConfigParser import SafeConfigParser
        cparser = SafeConfigParser()
        cparser.read(args["config"])
        args["mesh_ip6_prefix"] = cparser.get('main', 'mesh-ip6-prefix')
        args["remote_tunnel_addr"] = cparser.get('main', 'remote-tunnel-addr')
        args["local_tunnel_addr"] = cparser.get('main', 'local-tunnel-addr')
        args["local_netmask"] = cparser.get('main', 'local-netmask')
        args["local_gateway_addr"] = cparser.get('main', 'local-gateway-addr')

    if args["verbose"]:
        print "Loading attributes"
    # load prefix unaltered
    sl.c_sattr(2, "meshpfx", args["mesh_ip6_prefix"])
    sl.c_sattr(3, "remtun", _pack_ipv4_addr(args["remote_tunnel_addr"]))
    sl.c_sattr(4, "loctun",  _pack_ipv4_addr(args["local_tunnel_addr"]))
    sl.c_sattr(5, "locmask", _pack_ipv4_addr(args["local_netmask"]))
    sl.c_sattr(6, "locgate", _pack_ipv4_addr(args["local_gateway_addr"]))
    if args["verbose"]:
        print "Attributes loaded. Resetting..."
    sl.enter_payload_mode()

def act_moteconfig(args):
    args = loadconfigs(args, "moteconfig")
    # setup to write values
    sl = sl_api.StormLoader(args["tty"])
    sl.enter_bootload_mode()
    if args["verbose"]:
        print "Loading [meshpfx] =", args["prefix"]
    sl.c_sattr(2, "meshpfx", args["prefix"])

    router = "fe80::212:6d02:0:"+args["router"]
    if args["verbose"]:
        print "Loading [router addr] =",router
    sl.c_sattr(7, "border", router)
    sl.enter_payload_mode()

def act_burnfuses(args):
    args = loadconfigs(args, "burnfuses")
    sl = sl_api.StormLoader(args["tty"])
    sl.enter_bootload_mode()
    val = 0x00000000
    if not args["wdt"]:
        val |= 1
    if args["bor"]:
        val |= 0x580 | (36 << 1) #BOR at 2.77 volts (20%)
    sl.c_wuser([val & 0xFF, (val >> 8) & 0xFF, (val >> 16) & 0xFF, 0, 0, 0, 0, 0])
    sl.enter_payload_mode()

def entry():
    parser = argparse.ArgumentParser(description="StormLoader tool")
    parser.add_argument("-D","--tty",action="store",default="/dev/ttyUSB0")
    parser.add_argument("-C","--config", action="store", default=None)
    parser.add_argument("-V", "--verbose",action="store_true")
    sp = parser.add_subparsers()

    p_ping = sp.add_parser("ping")

    p_ping.set_defaults(func=act_ping)

    p_flash = sp.add_parser("flash")
    p_flash.set_defaults(func=act_flash)
    p_flash.add_argument("sdb", action="store",help="The storm drop binary to flash")

    p_flashall = sp.add_parser("flashall", help="Flashes ALL attached motes matching USB PIDs 0x60{01,14,15}")
    p_flashall.set_defaults(func=act_flashall)
    p_flashall.add_argument("sdb", action="store",help="The storm drop binary to flash")

    p_pack = sp.add_parser("pack", help="Create a Storm Drop Binary file (SDB)")
    p_pack.set_defaults(func=act_pack)
    p_pack.add_argument("elf", action="store",help="The ELF file")
    p_pack.add_argument("-m","--maintainer",action="store")
    p_pack.add_argument("-r","--repository",action="store")
    p_pack.add_argument("-v","--version",action="store")
    p_pack.add_argument("-b","--buildnumber",action="store")
    p_pack.add_argument("-c","--changeset",action="store")
    p_pack.add_argument("-n","--name",action="store")
    p_pack.add_argument("-d","--description",action="store")
    p_pack.add_argument("-o","--outfile",action="store")
    p_pack.add_argument("-t","--tool",action="append")
    p_pack.add_argument("-a","--assetlist", action="store")

    p_hexdump = sp.add_parser("hexdump")
    p_hexdump.set_defaults(func=act_hexdump)
    p_hexdump.add_argument("sdb", action="store", help="the storm drop binary to dump")

    p_assetadd = sp.add_parser("assetadd")
    p_assetadd.set_defaults(func=act_add_asset)
    p_assetadd.add_argument("sdb", action="store", help="the sdb file to add to")
    p_assetadd.add_argument("asset", action="store", help="the binary asset file to add")
    p_assetadd.add_argument("addr", action="store", nargs="?", default=None,
                            help="the address to store it in, if omitted place after previous assets")
    p_assetadd.add_argument("name", action="store", nargs="?", default=None,
                            help="the name of the asset, if omitted the filename is used")
    p_assetadd.add_argument("-i", "--internal", action="store_true",
                            help="store asset in internal flash (the default is external)")

    p_assetlist = sp.add_parser("assetlist")
    p_assetlist.set_defaults(func=act_list_assets)
    p_assetlist.add_argument("sdb", action="store", help="the sdb file to inspect")
    p_assetlist.add_argument("-d","--header", action="store_true", help="print as a C header")

    p_assetflash = sp.add_parser("assetflash")
    p_assetflash.set_defaults(func=act_flash_assets)
    p_assetflash.add_argument("sdb", action="store", help="the sdb file to read assets from")

    p_tail = sp.add_parser("tail")
    p_tail.set_defaults(func=act_tail)
    p_tail.add_argument("-n","--noreset", action="store_true" ,help="don't reset the device")
    p_tail.add_argument("-i","--interactive", action="store_true", help="attach stdin to device")

    p_tailall = sp.add_parser("tailall")
    p_tailall.set_defaults(func=act_tailall)
    p_tailall.add_argument("-n","--noreset", action="store_true" ,help="don't reset the device")
    p_tailall.add_argument("-i","--interactive", action="store_true", help="attach stdin to device")
    p_tailall.add_argument("-p","--prefix", action="store_true", help="Prefix all lines of output with the node's identifier")

    p_factoryinit = sp.add_parser("factoryinit")
    p_factoryinit.set_defaults(func=act_factoryinit)

    p_delta = sp.add_parser("flashdelta")
    p_delta.set_defaults(func=act_delta)
    p_delta.add_argument("oldimg", help="the sdb file that was last used to program the device")
    p_delta.add_argument("newimg", help="the new sdb file to program")

    p_payload = sp.add_parser("program", help="program an ELF to the payload section")
    p_payload.set_defaults(func=act_program_kernel_payload)
    p_payload.add_argument("elf", action="store", help="The payload ELF to program")

    p_payloadall = sp.add_parser("programall", help="Programs ALL attached motes matching USB PIDs 0x60{01,14,15}")
    p_payloadall.set_defaults(func=act_programall_kernel_payload)
    p_payloadall.add_argument("elf", action="store", help="The payload ELF to program")

    p_trace = sp.add_parser("trace")
    p_trace.set_defaults(func=act_trace)
    p_trace.add_argument("-p","--port", action="store", default=2332, type=int)
    p_trace.add_argument("-t","--target", action="store", default="localhost", type=str)

    p_sattr = sp.add_parser("sattr")
    p_sattr.set_defaults(func=act_sattr)
    p_sattr.add_argument("index", action="store", type=int)
    p_sattr.add_argument("key", action="store")
    p_sattr.add_argument("value", action="store")
    p_sattr.add_argument("-x","--hex", action="store_true")

    p_gattr = sp.add_parser("gattr")
    p_gattr.set_defaults(func=act_gattr)

    p_register = sp.add_parser("register")
    p_register.set_defaults(func=act_register)
    p_register.add_argument("namespace", action="store")
    p_register.add_argument("email", action="store")
    p_register.add_argument("key", action="store")

    p_publish = sp.add_parser("publish")
    p_publish.set_defaults(func=act_publish)
    p_publish.add_argument("sdb", action="store")
    p_publish.add_argument("name", action="store")
    p_publish.add_argument("key", action="store")

    p_cloudflash = sp.add_parser("cloudflash")
    p_cloudflash.set_defaults(func=act_cloudflash)
    p_cloudflash.add_argument("image", action="store")

    p_borderconfig = sp.add_parser("borderconfig", help="Configures the border router with these settings, then restarts")
    p_borderconfig.set_defaults(func=act_borderconfig)
    p_borderconfig.add_argument("-mesh-ip6-prefix", default="", action="store",
        help="IPv6 /64 prefix of the mesh network for this border router, e.g. 2001:470:1234:2::")
    p_borderconfig.add_argument("-remote-tunnel-addr", default="", action="store",
        help="IPv4 address of the remote tunnel, e.g. 10.4.10.33")
    p_borderconfig.add_argument("-local-tunnel-addr", default="", action="store",
        help="IPv4 address of the local tunnel (the border router's address), e.g. 10.4.10.31")
    p_borderconfig.add_argument("-local-netmask", default="", action="store",
        help="Netmask of the border router's ipv4 network, e.g. 255.255.255.0")
    p_borderconfig.add_argument("-local-gateway-addr", default="", action="store",
        help="IPv4 address of the local gateway for the border router's ipv4 network, e.g. 10.4.10.1")
    p_borderconfig.add_argument("-configfile", action="store", default=None, help="path to the .ini config file with key=val of the command line options for border config")
    p_borderconfig.add_argument("-sample", action="store_true", default=False, help="Output a sample configuration file to stdout. Config is used for 'sload borderconfig -c <configfile.ini>'")

    p_moteconfig = sp.add_parser("moteconfig", help="Configure networking for a non-border mote")
    p_moteconfig.set_defaults(func=act_moteconfig)
    p_moteconfig.add_argument("prefix", default=None, action="store",
        help="IPv6 /64 prefix of the mesh network for this mote, e.g. 2001:470:1234:2::")
    p_moteconfig.add_argument("router", default=None, action="store",
        help="NodeID of the border router for this mote in a one-hop network, e.g. f00d")

    p_burnfuses = sp.add_parser("burnfuses", help="Burn the fuses")
    p_burnfuses.set_defaults(func=act_burnfuses)
    p_burnfuses.add_argument("-w","--wdt", action="store_true", default=False, help="Enable the WDT by default on startup (default false)")
    p_burnfuses.add_argument("-b","--bor", action="store_true", default=False, help="Enable the 3.3V BOR (default false)")

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    entry()
