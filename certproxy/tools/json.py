# -*- coding: utf-8 -*-

import simplejson
import re
from datetime import datetime, date, time, timezone, timedelta

re_date = r'(?P<date>(?:[1-9]\d{3}-(?:(?:0[1-9]|1[0-2])-(?:0[1-9]|1\d|2[0-8])|(?:0[13-9]|1[0-2])-(?:29|30)|(?:0[13578]|1[02])-31)|(?:[1-9]\d(?:0[48]|[2468][048]|[13579][26])|(?:[2468][048]|[13579][26])00)-02-29))'
re_hour = r'(?P<hour>(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d)(?:\.(?P<microsecond>\d+))?'
re_tz = r'(?P<tz>Z|[+-][01]\d:[0-5]\d)'


def dumps(obj, **kwargs):
    return simplejson.dumps(obj=obj, cls=JSONEncoder)


def loads(s, **kwargs):
    return simplejson.loads(s=s, cls=JSONDecoder)


class JSONEncoder(simplejson.JSONEncoder):

    def default(self, o):  # pylint: disable=method-hidden
        if isinstance(o, (datetime, date, time)):
            return '@ISO8601 ' + o.isoformat()
        else:
            return super().default(o)


class JSONDecoder(simplejson.JSONDecoder):

    def decode(self, s):
        o = super().decode(s)
        o = self.parseDateTime(o)
        return o

    @staticmethod
    def parseTimeZone(tz):
        if not isinstance(tz, str):
            raise TypeError('String expected')
        
        if tz == 'Z':
            return timezone.utc
        else:
            (h, m) = tz[1:].split(':')
            if tz[0] == '+':
                (h, m) = (int(h), int(m))
            else:
                (h, m) = (-int(h), -int(m))
            return timezone(offset=timedelta(hours=h, minutes=m))

    @staticmethod
    def parseDateTime(o):
        if isinstance(o, str):
            tz = None
            match = re.match('@ISO8601 ' + re_hour + re_tz + '?', o)
            if match:
                if match.group('tz'):
                    tz = JSONDecoder.parseTimeZone(match.group('tz'))
                    o = o[:-len(match.group('tz'))]
                if match.group('microsecond'):
                    return datetime.strptime(o, "@ISO8601 %H:%M:%S.%f").astimezone(tz)
                else:
                    return datetime.strptime(o, "@ISO8601 %H:%M:%S").astimezone(tz)
            else:
                match = re.match('@ISO8601 ' + re_date + '(?:T' + re_hour + re_tz + '?)?', o)
                if match:
                    if match.group('tz'):
                        tz = JSONDecoder.parseTimeZone(match.group('tz'))
                        o = o[:-len(match.group('tz'))]
                    if match.group('hour'):
                        if match.group('microsecond'):
                            return datetime.strptime(o, "@ISO8601 %Y-%m-%dT%H:%M:%S.%f").astimezone(tz)
                        else:
                            return datetime.strptime(o, "@ISO8601 %Y-%m-%dT%H:%M:%S").astimezone(tz)
                    else:
                        return datetime.strptime(o, "@ISO8601 %Y-%m-%d").astimezone(tz).date()
                else:
                    return o
        elif isinstance(o, dict):
            return {k: JSONDecoder.parseDateTime(v) for k, v in o.items()}
        elif isinstance(o, list):
            return map(JSONDecoder.parseDateTime, o)
        else:
            return o


def monkey_patch_requests():
    from requests.models import Response
    oldjson = Response.json

    def newjson(*k, **kw):
        kw['cls'] = JSONDecoder
        return oldjson(*k, **kw)

    Response.json = newjson
