from flask import Flask, request, make_response, jsonify, g, render_template
from flask_caching import Cache
from datetime import datetime, timedelta
import sqlite3
import time
import sys
from pathlib import Path
import tempfile
import atexit
import probe_pb2
from yaml import load as yaml_load
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

sys.path.insert(0, '..')
from stats import is_local_bit_set, build_sql_query, median
# read config variable from config.yaml file
try:
    with open('config.yaml', 'r') as f:
        cfg_doc = f.read()
    config = yaml_load(cfg_doc, Loader=Loader)
    config['merged'] = tuple(m[:8] for m in config['merged'])
except FileNotFoundError as e:
    print('Warning: config.yaml not found, skipping', file=sys.stderr)
    config = {'knownmac': tuple(), 'merged': tuple()}

CWD = Path(__file__).resolve().parent
DATABASE = Path.joinpath(CWD, 'probemon.db')

# temp dir for flask cache files
TMPDIR = tempfile.TemporaryDirectory(prefix='mapot-cache-').name

# cleanup temp cache dir on exit
def cleanup():
    for f in Path(TMPDIR).glob('*'):
        f.unlink()
    Path(TMPDIR).rmdir()

atexit.register(cleanup)

class InvalidUsage(Exception):
    status_code = 400

    def __init__(self, message, status_code=None, payload=None):
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return rv

def create_app():
    app = Flask(__name__)

    cache = Cache(config={'CACHE_TYPE': 'FileSystemCache', 'CACHE_DIR': TMPDIR})
    cache.init_app(app)

    def get_db():
        db = getattr(g, '_database', None)
        if db is None:
            db = g._database = sqlite3.connect(f'file:{DATABASE}?mode=ro', uri=True)
        return db

    @app.teardown_appcontext
    def close_connection(exception):
        db = getattr(g, '_database', None)
        if db is not None:
            db.close()

    @app.route('/')
    @app.route('/index.html')
    def index():
        return render_template('index.html.j2')

    @app.route('/api/stats/days')
    @cache.cached(timeout=43200, query_string=True) # 12 hours
    def days():
        cur = get_db().cursor()
        # to store temp table and indices in memory
        sql = 'pragma temp_store = 2;'
        cur.execute(sql)
        macs = request.args.getlist('macs')

        if macs is None:
            # return list of days with probes in db
            try:
                sql = 'select date from probemon'
                sql_args = ()
                cur.execute(sql, sql_args)
            except sqlite3.OperationalError as e:
                return jsonify({'status': 'error', 'message': 'sqlite3 db is not accessible'}), 500

            days = set()
            for row in cur.fetchall():
                t = time.strftime('%Y-%m-%d', time.localtime(row[0]))
                days.add(t)
            days = sorted(list(days))
            missing = []
            last = datetime.strptime(days[-1], '%Y-%m-%d')
            day = datetime.strptime(days[0], '%Y-%m-%d')
            while day != last:
                d = day.strftime('%Y-%m-%d')
                if d not in days:
                    missing.append(d)
                day += timedelta(days=1)
            data = {'first': days[0], 'last': days[-1], 'missing': missing}
            return jsonify(data)
        else:
            # check if stats table is available
            try:
                cur.execute('select count(*) from sqlite_master where type=? and name=?', ('table', 'stats'))
            except sqlite3.OperationalError as e:
                return jsonify({'status': 'error', 'message': 'sqlite3 db is not accessible'}), 500
            if cur.fetchone()[0] == 1:
            # return day-by-day stats for macs
                params = ','.join(['?']*len(macs))
                sql = f'''select mac.id, address from mac
                    inner join vendor on vendor.id=mac.vendor
                    where address in ({params});'''
                cur.execute(sql, macs)
                mac_ids = {}
                for row in cur.fetchall():
                    mac_ids[row[0]] = row[1]
                data = []
                for m in list(mac_ids.keys()):
                    md = []
                    ssids = set()
                    sql = 'select date, first_seen, last_seen, count, min, max, avg, med, ssids from stats where mac_id=? order by date;'
                    cur.execute(sql, (m,))
                    for d, first, last, count, rmin, rmax, ravg, rmed, ssid in cur.fetchall():
                        first = time.mktime(time.strptime(f'{d}T{first}', '%Y-%m-%dT%H:%M:%S'))*1000
                        last = time.mktime(time.strptime(f'{d}T{last}', '%Y-%m-%dT%H:%M:%S'))*1000
                        md.append({'day':d.replace('-', ''), 'count':count,
                            'last': last, 'first': first, 'min': rmin, 'max': rmax, 'avg': ravg, 'median': rmed})
                        ssids = ssids.union(ssid.split(','))
                    ssids = sorted(list(ssids))
                    if '' in ssids:
                        ssids.remove('')
                    data.append({'mac': mac_ids[m], 'days': md, 'ssids': ssids})
                return jsonify(data)
            else:
                params = ','.join(['?']*len(macs))
                sql = f'''select date,mac.address,rssi,ssid.name from probemon
                 inner join ssid on ssid.id=probemon.ssid
                 inner join mac on mac.id=probemon.mac
                 where mac.address in ({params})'''
                sql_args = macs
                cur.execute(sql, sql_args)
                # WARNING: this is copy-pasted from stats.py
                stats = {}
                for row in cur.fetchall():
                    if row[1] not in list(stats.keys()):
                        stats[row[1]] = {'ssids': set()}
                    stats[row[1]]['ssids'].add(row[3])
                    day = time.strftime('%Y%m%d', time.localtime(row[0]))
                    if day in stats[row[1]]:
                        smd = stats[row[1]][day]
                        smd['rssi'].append(row[2])
                        if row[0] > smd['last']:
                            smd['last'] = row[0]
                        if row[0] < smd['first']:
                            smd['first'] = row[0]
                    else:
                        stats[row[1]][day] = {'rssi': [row[2]], 'first': row[0], 'last': row[0]}

                data = []
                for mac in list(stats.keys()):
                    md = []
                    for d in sorted(stats[mac].keys()):
                        if d == 'ssids':
                            continue
                        rssi = stats[mac][d]['rssi']
                        md.append({'day':d, 'count':len(rssi),
                            'last': int(stats[mac][d]['last']*1000), 'first': int(stats[mac][d]['first']*1000),
                            'min': min(rssi), 'max': max(rssi), 'avg': sum(rssi)//len(rssi), 'median': median(rssi)})
                    ssids = list(stats[mac]['ssids'])
                    if '' in ssids:
                        ssids.remove('')
                    data.append({'mac': mac, 'days': md, 'ssids': ssids})
                return jsonify(data)

    @app.route('/api/stats/timestamp')
    @cache.cached(timeout=60)
    def timestamp():
        '''returns latest modification time of the db'''
        ts = Path(DATABASE).stat().st_mtime
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))
        return jsonify({'timestamp': timestamp})

    @app.route('/api/stats')
    @cache.cached(timeout=60, query_string=True)
    def stats():
        '''returns stats for given macs between timestamp'''
        after = request.args.get('after')
        if after is not None:
            try:
                after = time.mktime(time.strptime(after, '%Y-%m-%dT%H:%M:%S'))
            except ValueError as v:
                raise InvalidUsage('Invalid after parameter')
        before = request.args.get('before')
        if before is not None:
            try:
                before = time.mktime(time.strptime(before, '%Y-%m-%dT%H:%M:%S'))
            except ValueError as v:
                raise InvalidUsage('Invalid before parameter')
        macs = request.args.getlist('macs')
        rssi, zero, day = None, False, False

        cur = get_db().cursor()
        # to store temp table and indices in memory
        sql = 'pragma temp_store = 2;'
        cur.execute(sql)

        sql, sql_args = build_sql_query(after, before, macs, rssi, zero, day)
        try:
            cur.execute(sql, sql_args)
        except sqlite3.OperationalError as e:
            return jsonify({'status': 'error', 'message': 'sqlite3 db is not accessible'}), 500

        # gather stats about each mac, same code as in stats.py
        # TODO: just import that
        macs = {}
        for row in cur.fetchall():
            mac = row[1]
            if is_local_bit_set(mac):
                # create virtual mac for LAA mac address
                mac = 'LAA'
            if mac not in macs:
                macs[mac] = {'vendor': row[2], 'ssid': [], 'rssi': [], 'last': row[0], 'first':row[0]}
            d = macs[mac]
            if row[3] != '' and row[3] not in d['ssid']:
                d['ssid'].append(row[3])
            if row[0] > d['last']:
                d['last'] = row[0]
            if row[0] < d['first']:
                d['first'] = row[0]
            if row[4] != 0:
                d['rssi'].append(row[4])

        # sort on frequency of appearence of a mac
        tmp = [(k,len(v['rssi'])) for k,v in macs.items()]
        tmp = [m for m,_ in reversed(sorted(tmp, key=lambda k:k[1]))]

        data = []
        # dump our stats
        for m in tmp:
            v = macs[m]
            first = time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(v['first']))
            last = time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(v['last']))
            t = {'mac': m, 'vendor': v['vendor'], 'ssids': sorted(v['ssid']), 'first': first, 'last': last}
            rssi = v['rssi']
            if rssi != []:
                t.update({'rssi': {'count': len(rssi), 'min': min(rssi), 'max': max(rssi),
                 'avg': sum(rssi)/len(rssi), 'median': int(median(rssi))}})
            data.append(t)

        return jsonify(data)

    @app.route('/api/probes')
    @cache.cached(timeout=60, query_string=True)
    def probes():
        '''returns list of probe requests for given macs between timestamps'''
        after = request.args.get('after')
        if after is not None:
            try:
                after = time.mktime(time.strptime(after, '%Y-%m-%dT%H:%M:%S'))
            except ValueError as v:
                raise InvalidUsage('Invalid after parameter')
        before = request.args.get('before')
        if before is not None:
            try:
                before = time.mktime(time.strptime(before, '%Y-%m-%dT%H:%M:%S'))
            except ValueError as v:
                raise InvalidUsage('Invalid before parameter')
        rssi = request.args.get('rssi')
        if rssi is not None:
            try:
                rssi = int(rssi)
            except ValueError as v:
                raise InvalidUsage('Invalid rssi value')

        macs = request.args.get('macs')
        zero = request.args.get('zero')
        today = request.args.get('today')
        output = request.args.get('output', default='json')

        cur = get_db().cursor()
        # to store temp table and indices in memory
        sql = 'pragma temp_store = 2;'
        cur.execute(sql)

        now = time.time()
        sql, sql_args = build_sql_query(after, before, macs, rssi, zero, today)
        try:
            cur.execute(sql, sql_args)
        except sqlite3.OperationalError as e:
            return jsonify({'status': 'error', 'message': 'sqlite3 db is not accessible'}), 500

        vendor = {}
        ts = {}
        if after is not None:
            starting_ts = int(after*1000)
        elif today:
            starting_ts = int((now-24*60*60)*1000)
        else:
            sql = 'select date from probemon order by date limit 1;'
            c.execute(sql)
            starting_ts = int(c.fetchone()[0]*1000)
        # extract data from db
        for t, mac, vs, ssid, rssi in cur.fetchall():
            #t = time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(t))
            d = (int(t*1000-starting_ts), int(rssi), ssid)
            if is_local_bit_set(mac) and not(mac in config['knownmac'] or mac[:8] in config['merged']):
                mac = 'LAA'
            if mac not in ts.keys():
                ts[mac] = [d]
                vendor[mac] = vs
            else:
                ts[mac].append(d)

        data = []
        # recollection
        for m in ts.keys():
            if m == 'LAA' or m.startswith(config['merged']):
                continue # will deal with them later
            known = m in config['knownmac']
            ssids = list(set(f[2] for f in ts[m]))
            t = {'mac':m, 'known': known, 'vendor': vendor[m], 'ssids': ssids, 'starting_ts': starting_ts,
                'probereq': [{'ts': f[0], 'rssi':f[1], 'ssid': ssids.index(f[2])} for f in ts[m]]}
            if len(t['probereq']) > 3:
                data.append(t)
        data.sort(key=lambda x:len(x['probereq']), reverse=True)
        # LAA
        if 'LAA' in ts.keys():
            ssids = list(set(f[2] for f in ts['LAA']))
            t = {'mac':'LAA', 'vendor': u'UNKNOWN', 'ssids': ssids, 'starting_ts': starting_ts,
                'probereq': [{'ts': f[0], 'rssi':f[1], 'ssid': ssids.index(f[2])} for f in ts['LAA']]}
            data.append(t)
        # MERGED
        for m in config['merged']:
            mm = [ma for ma in ts.keys() if ma.startswith(m)]
            p = []
            for n in mm:
                p.extend(ts[n])
            ssids = list(set(f[2] for f in p))
            if len(p) == 0:
                continue
            p.sort(key=lambda x: x[0])
            t = {'mac':m, 'vendor': u'UNKNOWN', 'ssids': ssids, 'starting_ts': starting_ts,
                'probereq': [{'ts': f[0], 'rssi':f[1], 'ssid': ssids.index(f[2])} for f in p]}
            data.append(t)

        if output == 'json':
            resp = make_response(jsonify(data))
        elif output == 'protobuf':
            res = probe_pb2.MyData()
            for t in data:
                p = res.probes.add()
                p.mac = t['mac']
                p.vendor = t['vendor']
                p.starting_ts = t['starting_ts']
                for s in t['ssids']:
                    sl = p.ssids.add()
                    sl.name = s
                try:
                    p.known = t['known']
                except KeyError as k:
                    p.known = False
                for f in t['probereq']:
                    pr = p.probereq.add()
                    pr.timestamp = f['ts']
                    pr.rssi = f['rssi']
                    pr.ssid = f['ssid']
            resp = make_response(res.SerializeToString())
            resp.headers['Content-Type'] = 'application/x-protobuf'

        if not today:
            resp.headers['Cache-Control'] = 'max-age=21600'
        return resp

    @app.route('/api/probes/latest')
    @cache.cached(timeout=60, query_string=True)
    def latest():
        '''returns latest probe requests'''
        format = request.args.get('format')
        if format is None:
            format = 'text'

        cur = get_db().cursor()
        # to store temp table and indices in memory
        sql = 'pragma temp_store = 2;'
        cur.execute(sql)

        sql = '''select date, mac.address, vendor.name, ssid.name, rssi from probemon
inner join mac on probemon.mac=mac.id
inner join ssid on probemon.ssid=ssid.id
inner join vendor on mac.vendor=vendor.id
order by date desc limit 100'''
        sql_args = None
        try:
            cur.execute(sql)
        except sqlite3.OperationalError as e:
            return jsonify({'status': 'error', 'message': 'sqlite3 db is not accessible'}), 500

        # extract data from db
        text = ''
        for t, mac, vs, ssid, rssi in cur.fetchall():
            t = time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(t))
            d = (t, int(rssi), ssid)
            if is_local_bit_set(mac):
                mac += ' (LAA)'
            text += f'{t}\t{mac}\t{int(rssi)}\t{vs}\n'

        resp = make_response('\n'.join(reversed(text.strip().split('\n'))))
        resp.headers['Content-Type'] = 'text/plain'
        return resp

    @app.route('/api/logs/raw')
    def raw():
        day = request.args.get('day')
        hour = request.args.get('hour')
        if day is None or hour is None:
            return 'missing parameter', 422
        try:
            hour = int(hour)
        except ValueError as v:
            return 'invalid parameter', 400

        c = get_db().cursor()
        # return the raw log with id to avoid too much repeated strings
        start = time.mktime(time.strptime(f'{day}T{hour:02d}:00:00', '%Y-%m-%dT%H:%M:%S'))
        eday = f'{day}T23:59:59' if hour+1 == 24 else f'{day}T{hour+1}:00:00'
        end = time.mktime(time.strptime(eday, '%Y-%m-%dT%H:%M:%S'))
        sql = 'select * from probemon where date >= ? and date <= ? order by date asc;'
        c.execute(sql, (start, end))
        rawlogs = []
        for row in c.fetchall():
            rawlogs.append(row)

        macs = set(m[1] for m in rawlogs)
        mac_ids = {}
        args_list = ','.join(["?"]*len(macs))
        sql = f'''select mac.id,address,vendor.name from mac
            inner join vendor on vendor.id=mac.vendor
            where mac.id in ({args_list});'''
        c.execute(sql, tuple(macs))
        del macs
        for row in c.fetchall():
            mac_ids[row[0]] = (row[1], row[2])

        ssids = set(m[2] for m in rawlogs)
        ssid_ids = {}
        args_list = ','.join(["?"]*len(ssids))
        sql = f'select id,name from ssid where id in ({args_list});'
        c.execute(sql, tuple(ssids))
        del ssids
        for row in c.fetchall():
            ssid_ids[row[0]] = row[1]

        data = {'ssids': ssid_ids, 'macs':mac_ids, 'logs':rawlogs}
        return jsonify(data)

    @app.route('/robots.txt')
    def robot():
        return app.send_static_file('robots.txt')

    @app.errorhandler(InvalidUsage)
    def handle_invalid_usage(error):
        response = jsonify(error.to_dict())
        response.status_code = error.status_code
        return response
    @app.errorhandler(404)
    def error_404(e):
        return render_template('error.html.j2', error=e), 404
    @app.errorhandler(500)
    def error_500(e):
        return render_template('error.html.j2', error=e), 500

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5556, threaded=True, debug=True)
else:
    app = create_app()
