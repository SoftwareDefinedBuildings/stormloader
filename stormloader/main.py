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

def act_flash(args):
    try:
        args = loadconfigs(args, "flash")
        sl = sl_api.StormLoader(args.get("tty", None))
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

def act_tail(args):
    args = loadconfigs(args, "tail")
    sl = sl_api.StormLoader(args.get("tty", None))
    if not args["noreset"]:
        sl.enter_payload_mode()
    print "[SLOADER] Attached"
    try:
        while True:

            c = sl.raw_read_noblock_buffer()
            if len(c) > 0:
                sys.stdout.write(c)
                sys.stdout.flush()
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

    p_pack = sp.add_parser("pack")
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

    p_factoryinit = sp.add_parser("factoryinit")
    p_factoryinit.set_defaults(func=act_factoryinit)

    p_delta = sp.add_parser("flashdelta")
    p_delta.set_defaults(func=act_delta)
    p_delta.add_argument("oldimg", help="the sdb file that was last used to program the device")
    p_delta.add_argument("newimg", help="the new sdb file to program")

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

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    entry()

