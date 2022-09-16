#!/usr/bin/python3
# -*- encoding: utf-8 -*-

import time
import argparse
import subprocess
import sys
import sqlite3
from manuf import manuf
import base64
from lru import LRU
import signal
import struct
import threading
import queue
import os.path
from yaml import load as yaml_load
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

NAME = 'probemon'
DESCRIPTION = "a command line tool for logging 802.11 probe requests"
VERSION = '0.7.2'

MANUF_FILE = './manuf'
MAX_QUEUE_LENGTH = 1024 # just in case
MAX_ELAPSED_TIME = 60 # seconds
MAX_VENDOR_LENGTH = 25
MAX_SSID_LENGTH = 15

# read config variable from config.yaml file
with open('config.yaml', 'r') as f:
    cfg_doc = f.read()
config = yaml_load(cfg_doc, Loader=Loader)

class Colors:
    red = '\033[31m'
    green = '\033[32m'
    yellow = '\033[33m'
    blue = '\033[34m'
    magenta = '\033[35m'
    cyan = '\033[36m'
    endc = '\033[0m'
    bold = '\033[1m'
    underline = '\033[4m'

class MyCache:
    def __init__(self, size):
        self.mac = LRU(size)
        self.ssid = LRU(size)
        self.vendor = LRU(size)

def print_fields(fields):
    if fields[1] in config['knownmac']:
        fields[1] = '%s%s%s%s' % (Colors.bold, Colors.red, fields[1], Colors.endc)
    # convert time to iso
    fields[0] = time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(fields[0  ]))
    # strip mac vendor string to MAX_VENDOR_LENGTH chars, left padded with space
    vendor = fields[2]
    if len(vendor) > MAX_VENDOR_LENGTH:
        vendor = vendor[:MAX_VENDOR_LENGTH-3]+ '...'
    else:
        vendor = vendor.ljust(MAX_VENDOR_LENGTH)
    # do the same for ssid
    ssid = fields[3]
    if len(ssid) > MAX_SSID_LENGTH:
        ssid = ssid[:MAX_SSID_LENGTH-3]+ '...'
    else:
        ssid = ssid.ljust(MAX_SSID_LENGTH)
    fields[2] = vendor
    fields[3] = ssid
    print('%s\t%s\t%s\t%s\t%d' % tuple(fields))

class MyQueue:
    def __init__(self, max_size=0):
        self.queue = queue.Queue(max_size)

    def append(self, fields):
        self.queue.put(fields)

    def commit(self, stdout, conn, c):
        while not self.queue.empty():
            fields = self.queue.get()
            date, mac, ssid, rssi = fields
            # look up vendor from OUI value in MAC address
            vendor = vendor_db.get_manuf_long(mac)
            if vendor is None:
                vendor = 'UNKNOWN'
            fields.insert(2, vendor)
            try:
                insert_into_db(fields, conn, c)
            except sqlite3.OperationalError as e:
                del fields[2]
                # re-insert in queue to process it later
                self.queue.put(fields)
                print(f'Error: {e}')
            if stdout:
                print_fields(fields)

# globals
cache = MyCache(128)
queue = MyQueue(MAX_QUEUE_LENGTH)
vendor_db = None
start_ts = time.monotonic()
lock = threading.Lock()
event = threading.Event()

def sig_handler(signum, frame):
    event.set()

def process_queue(queue, args):
    global start_ts

    conn = sqlite3.connect(args.db)
    c = conn.cursor()
    init_db(conn, c)

    while True:
        with lock:
            queue.commit(args.stdout, conn, c)
        now = time.monotonic()
        if now - start_ts > MAX_ELAPSED_TIME or event.is_set():
            start_ts = now
            try:
                conn.commit()
            except sqlite3.OperationalError as e:
                print(f'Error: {e}')
            if event.is_set():
                conn.close()
                break
        time.sleep(1)

def parse_rssi(packet):
    # parse dbm_antsignal from radiotap header
    # borrowed from python-radiotap module
    radiotap_header_fmt = '<BBHI'
    radiotap_header_len = struct.calcsize(radiotap_header_fmt)
    version, pad, radiotap_len, present = struct.unpack_from(radiotap_header_fmt, packet)

    start = radiotap_header_len
    bits = [int(b) for b in bin(present)[2:].rjust(32, '0')]
    bits.reverse()
    if bits[5] == 0:
        return 0

    while present & (1 << 31):
        present, = struct.unpack_from('<I', packet, start)
        start += 4
    offset = start
    if bits[0] == 1:
        offset = (offset + 8 -1) & ~(8-1)
        offset += 8
    if bits[1] == 1:
        offset += 1
    if bits[2] == 1:
        offset += 1
    if bits[3] == 1:
        offset = (offset + 2 -1) & ~(2-1)
        offset += 4
    if bits[4] == 1:
        offset += 2
    dbm_antsignal, = struct.unpack_from('<b', packet, offset)
    return dbm_antsignal

def insert_into_db(fields, conn, c):
    global cache

    date, mac, vendor, ssid, rssi = fields
    try:
        vendor_id = cache.vendor[vendor]
    except KeyError as k:
        c.execute('select id from vendor where name=?', (vendor,))
        row = c.fetchone()
        if row is None:
            c.execute('insert into vendor (name) values(?)', (vendor,))
            c.execute('select id from vendor where name=?', (vendor,))
            row = c.fetchone()
        vendor_id = row[0]
        cache.vendor[vendor] = vendor_id

    try:
        mac_id = cache.mac[mac]
    except KeyError as k:
        c.execute('select id from mac where address=?', (mac,))
        row = c.fetchone()
        if row is None:
            c.execute('insert into mac (address,vendor) values(?, ?)', (mac, vendor_id))
            c.execute('select id from mac where address=?', (mac,))
            row = c.fetchone()
        mac_id = row[0]
        cache.mac[mac] = mac_id

    try:
        ssid_id = cache.ssid[ssid]
    except KeyError as k:
        c.execute('select id from ssid where name=?', (ssid,))
        row = c.fetchone()
        if row is None:
            c.execute('insert into ssid (name) values(?)', (ssid,))
            c.execute('select id from ssid where name=?', (ssid,))
            row = c.fetchone()
        ssid_id = row[0]
        cache.ssid[ssid] = ssid_id

    c.execute('insert into probemon values(?, ?, ?, ?)', (date, mac_id, ssid_id, rssi))

def build_packet_cb(ignored):
    def packet_callback(packet):
        try:
            rssi = packet.dBm_AntSignal
        except AttributeError as a:
            # parse headers to get RSSI value, scapy version below 2.4.2
            rssi = parse_rssi(buffer(str(packet)))

        try:
            ssid = packet.info.decode('utf-8')
        except AttributeError as a:
            ssid = ''
        except UnicodeDecodeError as u:
            # encode the SSID in base64 because it will fail
            # to be inserted into the db otherwise
            ssid = 'b64_%s' % base64.b64encode(packet.info).decode()
        fields = [packet.time, packet.addr2, ssid, rssi]

        if packet.addr2 not in ignored and not event.is_set():
            with lock:
                queue.append(fields)

    return packet_callback

def init_db(conn, c):
    # create tables if they do not exist
    sql = '''create table if not exists vendor(
        id integer not null primary key,
        name text
        );'''
    c.execute(sql)
    sql = '''create table if not exists mac(
        id integer not null primary key,
        address text,
        vendor integer,
        foreign key(vendor) references vendor(id)
        );'''
    c.execute(sql)
    sql = '''create table if not exists ssid(
        id integer not null primary key,
        name text
        );'''
    c.execute(sql)
    sql = '''create table if not exists probemon(
        date float,
        mac integer,
        ssid integer,
        rssi integer,
        foreign key(mac) references mac(id),
        foreign key(ssid) references ssid(id)
        );'''
    c.execute(sql)
    sql = 'create index if not exists idx_probemon_date on probemon(date);'
    c.execute(sql)
    conn.commit()

    sql = 'pragma synchronous = normal;'
    c.execute(sql)
    sql = 'pragma temp_store = 2;' # to store temp table and indices in memory
    c.execute(sql)
    sql = 'pragma journal_mode = off;' # disable journal for rollback (we don't use this)
    c.execute(sql)
    sql = 'pragma foreign_keys = on;' # explcilty turn that on to be effective
    c.execute(sql)
    conn.commit()

def check_event(packet):
    return event.is_set()

def switch_channel(interface, channel):
    cmd = f'iw dev {interface} set channel {channel}'
    try:
        subprocess.check_call(cmd.split(' '))
    except subprocess.CalledProcessError as c:
        print(f'Error: failed to switch to channel {channel} for interface {interface}', file=sys.stderr)
        sys.exit(1)

def main():
    if args.channel != 0:
        # sniff on specified channel
        switch_channel(args.interface, args.channel)

    update_vdb = False
    global vendor_db
    if not os.path.isfile(MANUF_FILE):
        update_vdb = True
    if update_vdb:
        print('Updating and loading manuf file')
    else:
        print('Loading manuf file')
    vendor_db = manuf.MacParser(manuf_name='./manuf', update=update_vdb)

    # use a detached thread to process the queue and exit faster packet callback
    pq = threading.Thread(target=process_queue, args=(queue, args), daemon=True)
    pq.start()

    print(f':: Started listening to probe requests on channel {args.channel} on interface {args.interface}')
    print('Hit CTRL-C to exit')
    try:
        sniff(iface=args.interface, prn=build_packet_cb(config['ignored']),
            store=0, filter='type mgt subtype probe-req', stop_filter=check_event)
    except Scapy_Exception as se:
        print(f'Error: {se}', file=sys.stderr)
        sys.exit(1)
    except OSError as o:
        print(f"Error: {args.interface} interface not found", file=sys.stderr)
        sys.exit(1)
    finally:
        event.set()
    print('Exiting...')
    time.sleep(7) # default sqlite connect timeout + 2

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('-c', '--channel', default=1, type=int, help="the channel to listen on")
    parser.add_argument('-d', '--db', default='probemon.db', help="database file name to use")
    parser.add_argument('-i', '--interface', help="the capture interface to use")
    parser.add_argument('-I', '--ignore', action='append', help="mac address to ignore")
    parser.add_argument('-s', '--stdout', action='store_true', default=False, help="also log probe request to stdout")
    parser.add_argument('-v', '--version', action='store_true', default=False, help="show version and exit")
    args = parser.parse_args()

    if args.version:
        print(f"{NAME} {VERSION}\n© 2018-2020 solsTiCe d'Hiver, GPL 3 licensed")
        sys.exit(1)

    if not args.interface:
        print('Error: argument -i/--interface is required', file=sys.stderr)
        sys.exit(1)

    if args.ignore is not None:
        config['ignored'] = args.ignore

    # only import scapy here to avoid delay if error in argument parsing
    print('Loading scapy...')
    from scapy.all import sniff
    from scapy.error import Scapy_Exception

    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGQUIT, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)

    main()

# vim: set et ts=4 sw=4:
