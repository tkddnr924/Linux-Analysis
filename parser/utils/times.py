from datetime import datetime, timedelta, timezone

_KST = timezone(timedelta(hours=9))

def epoch_to_iso(x: float) -> str:
    dt = datetime.fromtimestamp(float(x), tz=timezone.utc).astimezone(_KST)
    return f"{dt:%Y-%m-%d %H:%M:%S}.{dt.microsecond//1000:03d}"