# -*- coding: utf-8 -*-

import json
import re
from datetime import datetime, date, time

re_date = r'(?P<date>(?:[1-9]\d{3}-(?:(?:0[1-9]|1[0-2])-(?:0[1-9]|1\d|2[0-8])|(?:0[13-9]|1[0-2])-(?:29|30)|(?:0[13578]|1[02])-31)|(?:[1-9]\d(?:0[48]|[2468][048]|[13579][26])|(?:[2468][048]|[13579][26])00)-02-29))'
re_hour = r'(?P<hour>(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d)(?:\.(?P<microsecond>\d+))?'
re_tz = r'(?P<tz>Z|[+-][01]\d:[0-5]\d)'


def dumps(obj, **kwargs):
    return json.dumps(obj=obj, cls=JSONEncoder)


def loads(s, **kwargs):
    return json.loads(s=s, cls=JSONDecoder)


class JSONEncoder(json.JSONEncoder):

    def default(self, o):  # pylint: disable=method-hidden
        if isinstance(o, (datetime, date, time)):
            return '@ISO8601 ' + o.isoformat()
        else:
            return super().default(o)


class JSONDecoder(json.JSONDecoder):

    def decode(self, s):
        o = super().decode(s)
        o = self.parseDateTime(o)
        return o

    @staticmethod
    def parseDateTime(o):
        if isinstance(o, str):
            match = re.match('@ISO8601 ' + re_hour + re_tz + '?', o)
            if match:
                if match.group('tz'):
                    raise ValueError('Timezone not supported')
                if match.group('microsecond'):
                    return datetime.strptime(o, "@ISO8601 %H:%M:%S.%f").time()
                else:
                    return datetime.strptime(o, "@ISO8601 %H:%M:%S").time()
            else:
                match = re.match('@ISO8601 ' + re_date + '(?:T' + re_hour + re_tz + '?)?', o)
                if match:
                    if match.group('tz'):
                        raise ValueError('Timezone not supported')
                    if match.group('hour'):
                        if match.group('microsecond'):
                            return datetime.strptime(o, "@ISO8601 %Y-%m-%dT%H:%M:%S.%f")
                        else:
                            return datetime.strptime(o, "@ISO8601 %Y-%m-%dT%H:%M:%S")
                    else:
                        return datetime.strptime(o, "@ISO8601 %Y-%m-%d").date()
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

    def newjson(self, *k, **kw):
        kw['cls'] = JSONDecoder
        return oldjson(self, *k, **kw)
    Response.json = newjson
