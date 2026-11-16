"""Conversor deterministico universal de timestamps forenses para UTC estrito."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re

from edrm.shared_kernel.enums import EpochKind
from edrm.shared_kernel.exceptions import InvalidForensicValueError
from edrm.shared_kernel.value_objects import UtcTimestamp

COCOA_EPOCH_OFFSET_SECONDS: int = 978_307_200
QUICKTIME_EPOCH_OFFSET_SECONDS: int = -2_082_844_800

_BR_DATETIME_RE = re.compile(
    r"^(\d{2})/(\d{2})/(\d{4})(?:[ T](\d{2}):(\d{2})(?::(\d{2}))?)?$"
)


def _format_utc_dt(dt_utc: datetime, nanos_rem: int = 0) -> str:
    """Formata um datetime em UTC para ISO-8601 canonico terminado em Z."""
    base = dt_utc.strftime("%Y-%m-%dT%H:%M:%S")
    if nanos_rem > 0:
        millis = nanos_rem // 1_000_000
        if millis > 0:
            return f"{base}.{millis:03d}Z"
    return f"{base}Z"


def from_unix_seconds(raw_seconds: int, raw_label: str = "") -> UtcTimestamp:
    """Converte segundos inteiros Unix (1970-01-01T00:00:00Z) para UtcTimestamp.

    Args:
        raw_seconds: Segundos inteiros desde a epoca Unix 1970.
        raw_label: Texto original encontrado na fonte bruta.

    Returns:
        UtcTimestamp normalizado em UTC.
    """
    if not isinstance(raw_seconds, int) or isinstance(raw_seconds, bool):
        raise InvalidForensicValueError("from_unix_seconds exige int.")
    dt_utc = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=raw_seconds)
    return UtcTimestamp(
        iso_utc=_format_utc_dt(dt_utc),
        epoch_seconds=raw_seconds,
        nanoseconds_remainder=0,
        raw_original=raw_label or str(raw_seconds),
        epoch_kind=EpochKind.UNIX_1970_S,
        tz_declared="UTC",
    )


def from_unix_milliseconds(raw_ms: int, raw_label: str = "") -> UtcTimestamp:
    """Converte milissegundos inteiros Unix (ex.: WhatsApp Android msgstore.db) para UTC.

    Args:
        raw_ms: Milissegundos inteiros desde 1970-01-01T00:00:00Z.
        raw_label: Valor bruto original.

    Returns:
        UtcTimestamp normalizado em UTC com resto em nanosegundos.
    """
    if not isinstance(raw_ms, int) or isinstance(raw_ms, bool):
        raise InvalidForensicValueError("from_unix_milliseconds exige int.")
    sec, rem_ms = divmod(raw_ms, 1000)
    nanos = rem_ms * 1_000_000
    dt_utc = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=sec)
    return UtcTimestamp(
        iso_utc=_format_utc_dt(dt_utc, nanos),
        epoch_seconds=sec,
        nanoseconds_remainder=nanos,
        raw_original=raw_label or str(raw_ms),
        epoch_kind=EpochKind.UNIX_1970_MS,
        tz_declared="UTC",
    )


def from_unix_nanoseconds(raw_ns: int, raw_label: str = "") -> UtcTimestamp:
    """Converte nanosegundos inteiros Unix (ex.: st_mtime_ns) para UtcTimestamp.

    Args:
        raw_ns: Nanosegundos inteiros desde 1970-01-01T00:00:00Z.
        raw_label: Representacao textual original.

    Returns:
        UtcTimestamp exato preservando nanosegundos.
    """
    if not isinstance(raw_ns, int) or isinstance(raw_ns, bool):
        raise InvalidForensicValueError("from_unix_nanoseconds exige int.")
    sec, nanos = divmod(raw_ns, 1_000_000_000)
    dt_utc = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=sec)
    return UtcTimestamp(
        iso_utc=_format_utc_dt(dt_utc, nanos),
        epoch_seconds=sec,
        nanoseconds_remainder=nanos,
        raw_original=raw_label or str(raw_ns),
        epoch_kind=EpochKind.UNIX_1970_S,
        tz_declared="UTC",
    )


def from_cocoa_seconds(cocoa_seconds: int, raw_label: str = "") -> UtcTimestamp:
    """Converte segundos Apple CoreData/Cocoa (2001-01-01 + 978307200s) para UTC.

    Args:
        cocoa_seconds: Segundos inteiros desde 2001-01-01T00:00:00Z (WhatsApp iOS).
        raw_label: Valor bruto original.

    Returns:
        UtcTimestamp normalizado em UTC.
    """
    if not isinstance(cocoa_seconds, int) or isinstance(cocoa_seconds, bool):
        raise InvalidForensicValueError("from_cocoa_seconds exige int.")
    unix_sec = cocoa_seconds + COCOA_EPOCH_OFFSET_SECONDS
    dt_utc = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=unix_sec)
    return UtcTimestamp(
        iso_utc=_format_utc_dt(dt_utc),
        epoch_seconds=unix_sec,
        nanoseconds_remainder=0,
        raw_original=raw_label or str(cocoa_seconds),
        epoch_kind=EpochKind.COCOA_2001_S,
        tz_declared="UTC",
    )


def from_cocoa_nanoseconds(cocoa_ns: int, raw_label: str = "") -> UtcTimestamp:
    """Converte nanosegundos Apple CoreData/iOS (epoca 2001) para UtcTimestamp.

    Args:
        cocoa_ns: Nanosegundos inteiros desde 2001-01-01T00:00:00Z.
        raw_label: Valor bruto original.

    Returns:
        UtcTimestamp normalizado em UTC.
    """
    if not isinstance(cocoa_ns, int) or isinstance(cocoa_ns, bool):
        raise InvalidForensicValueError("from_cocoa_nanoseconds exige int.")
    cocoa_sec, nanos = divmod(cocoa_ns, 1_000_000_000)
    unix_sec = cocoa_sec + COCOA_EPOCH_OFFSET_SECONDS
    dt_utc = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=unix_sec)
    return UtcTimestamp(
        iso_utc=_format_utc_dt(dt_utc, nanos),
        epoch_seconds=unix_sec,
        nanoseconds_remainder=nanos,
        raw_original=raw_label or str(cocoa_ns),
        epoch_kind=EpochKind.COCOA_2001_NS,
        tz_declared="UTC",
    )


def from_quicktime_seconds(qt_seconds: int, raw_label: str = "") -> UtcTimestamp:
    """Converte segundos QuickTime/MP4 (1904-01-01T00:00:00Z) para UtcTimestamp.

    Args:
        qt_seconds: Segundos inteiros desde 1904-01-01T00:00:00Z.
        raw_label: Valor bruto original.

    Returns:
        UtcTimestamp normalizado em UTC.
    """
    if not isinstance(qt_seconds, int) or isinstance(qt_seconds, bool):
        raise InvalidForensicValueError("from_quicktime_seconds exige int.")
    unix_sec = qt_seconds + QUICKTIME_EPOCH_OFFSET_SECONDS
    dt_utc = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=unix_sec)
    return UtcTimestamp(
        iso_utc=_format_utc_dt(dt_utc),
        epoch_seconds=unix_sec,
        nanoseconds_remainder=0,
        raw_original=raw_label or str(qt_seconds),
        epoch_kind=EpochKind.QUICKTIME_1904_S,
        tz_declared="UTC",
    )


def parse_timestamp_to_utc(
    raw_text: str,
    assumed_offset_minutes: int = -180,
) -> UtcTimestamp:
    """Converte strings ISO-8601 ou datas brasileiras (DD/MM/YYYY HH:MM:SS) para UTC.

    Args:
        raw_text: Texto da data/hora extraido do documento ou log.
        assumed_offset_minutes: Fuso assumido em minutos caso nao haja offset explicito
            (padrao -180 para America/Sao_Paulo, marcando EpochKind.LOCAL_ASSUMED).

    Returns:
        UtcTimestamp normalizado em UTC.

    Raises:
        InvalidForensicValueError: Se o formato da data for irreconhecivel.
    """
    cleaned = raw_text.strip()
    if not cleaned:
        raise InvalidForensicValueError("Timestamp vazio nao pode ser convertido.")

    br_match = _BR_DATETIME_RE.match(cleaned)
    if br_match:
        day = int(br_match.group(1))
        month = int(br_match.group(2))
        year = int(br_match.group(3))
        hour = int(br_match.group(4) or "0")
        minute = int(br_match.group(5) or "0")
        second = int(br_match.group(6) or "0")
        tz_local = timezone(timedelta(minutes=assumed_offset_minutes))
        local_dt = datetime(year, month, day, hour, minute, second, tzinfo=tz_local)
        utc_dt = local_dt.astimezone(timezone.utc)
        epoch_s = int((utc_dt - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds())
        sign = "+" if assumed_offset_minutes >= 0 else "-"
        abs_min = abs(assumed_offset_minutes)
        tz_name = f"UTC{sign}{abs_min // 60:02d}:{abs_min % 60:02d}"
        return UtcTimestamp(
            iso_utc=_format_utc_dt(utc_dt),
            epoch_seconds=epoch_s,
            nanoseconds_remainder=0,
            raw_original=cleaned,
            epoch_kind=EpochKind.LOCAL_ASSUMED,
            tz_declared=tz_name,
        )

    iso_candidate = cleaned
    if iso_candidate.endswith("Z"):
        iso_candidate = iso_candidate[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(iso_candidate)
    except ValueError as exc:
        raise InvalidForensicValueError(f"Formato temporal invalido: {raw_text!r}") from exc

    if parsed.tzinfo is None:
        tz_local = timezone(timedelta(minutes=assumed_offset_minutes))
        parsed_aware = parsed.replace(tzinfo=tz_local)
        kind = EpochKind.LOCAL_ASSUMED
        sign = "+" if assumed_offset_minutes >= 0 else "-"
        abs_min = abs(assumed_offset_minutes)
        tz_label = f"UTC{sign}{abs_min // 60:02d}:{abs_min % 60:02d}"
    else:
        parsed_aware = parsed
        kind = EpochKind.ISO8601_OFFSET
        offset_td = parsed_aware.utcoffset() or timedelta(0)
        total_min = int(offset_td.total_seconds()) // 60
        if total_min == 0:
            tz_label = "UTC"
        else:
            sign = "+" if total_min >= 0 else "-"
            abs_min = abs(total_min)
            tz_label = f"UTC{sign}{abs_min // 60:02d}:{abs_min % 60:02d}"

    utc_dt = parsed_aware.astimezone(timezone.utc)
    delta = utc_dt - datetime(1970, 1, 1, tzinfo=timezone.utc)
    epoch_s = delta.days * 86400 + delta.seconds
    nanos = utc_dt.microsecond * 1000
    return UtcTimestamp(
        iso_utc=_format_utc_dt(utc_dt, nanos),
        epoch_seconds=epoch_s,
        nanoseconds_remainder=nanos,
        raw_original=cleaned,
        epoch_kind=kind,
        tz_declared=tz_label,
    )
