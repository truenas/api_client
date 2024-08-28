"""Provides wrappers of the `json` module for handling Python sets and common objects of the `datetime` module.

Specifically, this module allows `datetime.date`, `datetime.time`,
`datetime.datetime`, and `set` objects to be serialized and deserialized in
addition to the types handled by the `json` module (those types are listed
[here](https://docs.python.org/3.11/library/json.html#json.JSONDecoder)).

Example::

    >>> from ejson import dumps, loads
    >>> obj = {'string', 4, date.today(), time(16, 22, 6)}
    >>> serialized = dumps(obj)
    >>> serialized
    {"$set": [4, {"$type": "date", "$value": "2024-07-03"}, "string", {"$time": "16:22:06"}]}
    >>> deserialized = loads(serialized)

"""
import calendar
from datetime import date, datetime, time, timedelta, timezone
import json


class JSONEncoder(json.JSONEncoder):
    """Custom JSON encoder that extends the default encoder to handle more types.

    In addition to the types already supported by `json.JSONEncoder`, this
    encoder adds support for the following types:

    | Python            | JSON                                              |
    | ----------------- | ------------------------------------------------- |
    | datetime.date     | {"$type": "date", "$value": string[YYYY-MM-DD]}   |
    | datetime.datetime | {"$date": number[Total milliseconds since EPOCH]} |
    | datetime.time     | {"$time": string[HH:MM:SS]}                       |
    | set               | {"$set": array[items...]}                         |

    Note: When serializing Python sets, the order that the elements appear in
    the JSON array is undefined.

    """
    def default(self, obj):
        if type(obj) is date:
            return {'$type': 'date', '$value': obj.isoformat()}
        elif type(obj) is datetime:
            if obj.tzinfo is not None:
                obj = obj.astimezone(timezone.utc)
            # Total milliseconds since EPOCH
            return {'$date': int(calendar.timegm(obj.timetuple()) * 1000)}
        elif type(obj) is time:
            return {'$time': str(obj)}
        elif isinstance(obj, set):
            return {'$set': list(obj)}
        return super(JSONEncoder, self).default(obj)


def object_hook(obj: dict):
    """Used when deserializing `date`, `time`, `datetime`, and `set` objects.

    Passed as a kwarg to a JSON deserialization function like `json.dump()`.

    """
    obj_len = len(obj)
    if obj_len == 1:
        if '$date' in obj:
            return datetime.fromtimestamp(obj['$date'] / 1000, tz=timezone.utc) + timedelta(milliseconds=obj['$date'] % 1000)
        if '$time' in obj:
            return time(*[int(i) for i in obj['$time'].split(':')[:4]])  # type: ignore
        if '$set' in obj:
            return set(obj['$set'])
    if obj_len == 2 and '$type' in obj and '$value' in obj:
        if obj['$type'] == 'date':
            return date(*[int(i) for i in obj['$value'].split('-')])
    return obj


def dump(obj, fp, **kwargs):
    """Wraps `json.dump()` and uses the custom `JSONEncoder`.

    Can serialize `date`, `time`, `datetime`, and `set` objects
    to a file-like object.

    """
    return json.dump(obj, fp, cls=JSONEncoder, **kwargs)


def dumps(obj, **kwargs) -> str:
    """Wraps `json.dumps()` and uses the custom `JSONEncoder`.

    Can serialize `date`, `time`, `datetime`, and `set` objects.

    """
    return json.dumps(obj, cls=JSONEncoder, **kwargs)


def loads(obj: str | bytes | bytearray, **kwargs):
    """Wraps `json.loads()` and uses a custom `object_hook` argument.

    Can deserialize `date`, `time`, `datetime`, and `set` objects.

    """
    return json.loads(obj, object_hook=object_hook, **kwargs)
