"""Objetos de valor imutaveis do nucleo compartilhado EDRM 2.0."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
import hashlib
import json
import re

from edrm.shared_kernel.enums import EpochKind
from edrm.shared_kernel.exceptions import InvalidForensicValueError

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CONTROL_NUMBER_RE = re.compile(r"^CN-\d{8}(?:\.\d{4})*$")
_WIN_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")


def sha256_text(content: str) -> str:
    """Calcula o digest SHA-256 hexadecimal minusculo de uma string UTF-8.

    Args:
        content: Texto de entrada a ser resumido criptograficamente.

    Returns:
        String hexadecimal de 64 caracteres representando o SHA-256.
    """
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def canonical_json_sha256(payload: object) -> tuple[str, str]:
    """Serializa uma estrutura em JSON canonico ordenado e calcula seu SHA-256.

    Args:
        payload: Dicionario, lista ou primitivo compativel com JSON.

    Returns:
        Tupla contendo (json_canonico, sha256_hex).
    """
    serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return serialized, sha256_text(serialized)


@dataclass(frozen=True, slots=True)
class Sha256Hash:
    """Representa um resumo criptografico SHA-256 validado (FIPS 180-4)."""

    hex_digest: str

    def __post_init__(self) -> None:
        normalized = self.hex_digest.strip().lower()
        if not _SHA256_RE.match(normalized):
            raise InvalidForensicValueError(
                f"Digest SHA-256 invalido (esperado 64 hex): {self.hex_digest!r}"
            )
        object.__setattr__(self, "hex_digest", normalized)

    @classmethod
    def from_bytes(cls, raw: bytes) -> Sha256Hash:
        """Cria Sha256Hash diretamente a partir de bytes em memoria.

        Args:
            raw: Sequencia imutavel de bytes.

        Returns:
            Instancia validada de Sha256Hash.
        """
        return cls(hashlib.sha256(raw).hexdigest())


@dataclass(frozen=True, slots=True)
class ByteSize:
    """Tamanho exato em bytes inteiros nao negativos (proibido ponto flutuante)."""

    total_bytes: int

    def __post_init__(self) -> None:
        if not isinstance(self.total_bytes, int) or isinstance(self.total_bytes, bool):
            raise InvalidForensicValueError("ByteSize exige int estrito.")
        if self.total_bytes < 0:
            raise InvalidForensicValueError(f"ByteSize negativo invalido: {self.total_bytes}")


@dataclass(frozen=True, slots=True)
class CentsAmount:
    """Valor monetario exato em centavos inteiros BIGINT (zero ponto flutuante)."""

    cents: int
    currency: str = "BRL"

    def __post_init__(self) -> None:
        if not isinstance(self.cents, int) or isinstance(self.cents, bool):
            raise InvalidForensicValueError("CentsAmount exige int estrito em centavos.")
        if not self.currency or len(self.currency.strip()) != 3:
            raise InvalidForensicValueError(f"Moeda ISO invalida: {self.currency!r}")
        object.__setattr__(self, "currency", self.currency.strip().upper())

    def to_decimal(self) -> Decimal:
        """Converte os centavos inteiros para Decimal exato com duas casas.

        Returns:
            Representacao Decimal exata (cents / 100).
        """
        return (Decimal(self.cents) / Decimal(100)).quantize(Decimal("0.01"))

    def format_brl(self) -> str:
        """Formata o montante monetario no padrao brasileiro deterministico.

        Returns:
            String formatada como 'R$ 1.540,90' ou '-R$ 1.540,90'.
        """
        sign = "-" if self.cents < 0 else ""
        abs_cents = abs(self.cents)
        reais = abs_cents // 100
        centavos = abs_cents % 100
        reais_str = f"{reais:,}".replace(",", ".")
        prefix = "R$" if self.currency == "BRL" else self.currency
        return f"{sign}{prefix} {reais_str},{centavos:02d}"


@dataclass(frozen=True, slots=True)
class MicroDegreesCoord:
    """Coordenada geografica em micrograus inteiros (graus * 1_000_000)."""

    lat_microdeg: int
    lon_microdeg: int

    def __post_init__(self) -> None:
        if not isinstance(self.lat_microdeg, int) or not isinstance(self.lon_microdeg, int):
            raise InvalidForensicValueError("Coordenadas exigem micrograus inteiros.")
        if not (-90_000_000 <= self.lat_microdeg <= 90_000_000):
            raise InvalidForensicValueError(f"Latitude fora do intervalo: {self.lat_microdeg}")
        if not (-180_000_000 <= self.lon_microdeg <= 180_000_000):
            raise InvalidForensicValueError(f"Longitude fora do intervalo: {self.lon_microdeg}")


@dataclass(frozen=True, slots=True)
class UtcTimestamp:
    """Carimbo temporal normalizado em UTC preservando valor bruto e epoca de origem."""

    iso_utc: str
    epoch_seconds: int
    nanoseconds_remainder: int = 0
    raw_original: str = ""
    epoch_kind: EpochKind = EpochKind.ISO8601_OFFSET
    tz_declared: str = "UTC"

    def __post_init__(self) -> None:
        if not isinstance(self.epoch_seconds, int) or isinstance(self.epoch_seconds, bool):
            raise InvalidForensicValueError("epoch_seconds deve ser int.")
        if not (0 <= self.nanoseconds_remainder < 1_000_000_000):
            raise InvalidForensicValueError("nanoseconds_remainder fora de [0, 999999999].")
        if not self.iso_utc.endswith("Z"):
            raise InvalidForensicValueError(f"Timestamp UTC deve terminar em 'Z': {self.iso_utc!r}")


@dataclass(frozen=True, slots=True)
class SafeOsPath:
    """Caminho logico limpo com suporte transparente a caminhos longos Windows \\\\?\\."""

    logical_path: str

    def __post_init__(self) -> None:
        cleaned = self.logical_path.strip()
        if not cleaned:
            raise InvalidForensicValueError("SafeOsPath nao aceita caminho vazio.")
        if cleaned.startswith("\\\\?\\UNC\\"):
            cleaned = "\\\\" + cleaned[8:]
        elif cleaned.startswith("\\\\?\\"):
            cleaned = cleaned[4:]
        object.__setattr__(self, "logical_path", cleaned)

    def to_os_extended(self, is_windows: bool = False) -> str:
        """Retorna caminho estendido \\\\?\\ ou \\\\?\\UNC\\ no Windows quando aplicavel.

        Args:
            is_windows: Indica se o sistema operacional alvo e Windows NTFS.

        Returns:
            String pronta para chamadas de sistema de arquivos sem limite MAX_PATH (260).
        """
        raw = self.logical_path
        looks_windows = is_windows or bool(_WIN_DRIVE_RE.match(raw)) or raw.startswith("\\\\")
        if not looks_windows:
            return raw
        win_norm = raw.replace("/", "\\")
        if len(win_norm) < 248 and not is_windows:
            return win_norm
        if win_norm.startswith("\\\\?\\"):
            return win_norm
        if win_norm.startswith("\\\\"):
            return "\\\\?\\UNC\\" + win_norm[2:]
        if _WIN_DRIVE_RE.match(win_norm):
            return "\\\\?\\" + win_norm
        return win_norm

    def to_sqlite_immutable_uri(self, is_windows: bool = False) -> str:
        """Constroi URI SQLite estritamente somente leitura e imutavel (ISO/IEC 27037).

        Args:
            is_windows: Indica se o caminho provem de ambiente Windows.

        Returns:
            URI no formato 'file:...?mode=ro&immutable=1'.
        """
        raw = self.logical_path.replace("\\", "/")
        if is_windows or _WIN_DRIVE_RE.match(self.logical_path):
            if not raw.startswith("/"):
                raw = "/" + raw
        escaped = (
            raw.replace("%", "%25")
            .replace("?", "%3f")
            .replace("#", "%23")
            .replace(" ", "%20")
        )
        return f"file:{escaped}?mode=ro&immutable=1"


@dataclass(frozen=True, slots=True)
class ControlNumber:
    """Identificador imutavel de cadeia de custodia com genealogia pai-filho."""

    code: str

    def __post_init__(self) -> None:
        normalized = self.code.strip().upper()
        if not _CONTROL_NUMBER_RE.match(normalized):
            raise InvalidForensicValueError(
                f"ControlNumber invalido (esperado CN-00000001[.0001]): {self.code!r}"
            )
        object.__setattr__(self, "code", normalized)

    @classmethod
    def root(cls, sequence: int) -> ControlNumber:
        """Gera um ControlNumber raiz de 8 digitos.

        Args:
            sequence: Inteiro positivo >= 1.

        Returns:
            ControlNumber raiz (ex.: CN-00000001).
        """
        if sequence < 1:
            raise InvalidForensicValueError("Sequencia de ControlNumber deve ser >= 1.")
        return cls(f"CN-{sequence:08d}")

    def child(self, child_index: int) -> ControlNumber:
        """Deriva o ControlNumber filho preservando genealogia documental.

        Args:
            child_index: Indice inteiro positivo >= 1 do item filho.

        Returns:
            ControlNumber filho (ex.: CN-00000001.0001).
        """
        if child_index < 1:
            raise InvalidForensicValueError("Indice filho deve ser >= 1.")
        return ControlNumber(f"{self.code}.{child_index:04d}")

    @property
    def parent_code(self) -> str | None:
        """Retorna o codigo do item pai imediato ou None se for raiz."""
        if "." not in self.code:
            return None
        return self.code.rsplit(".", 1)[0]

    @property
    def is_top_level(self) -> bool:
        """Indica se este ControlNumber e um item raiz (sem ancestral)."""
        return "." not in self.code


@dataclass(frozen=True, slots=True)
class SourceAnchor:
    """Ancora probatoria obrigatoria vinculando qualquer dado extraido a fonte bruta."""

    origin_control_number: str
    origin_path: str
    locator: str
    verbatim_excerpt: str
    captured_at_utc: str
    origin_sha256: str

    def __post_init__(self) -> None:
        ControlNumber(self.origin_control_number)
        Sha256Hash(self.origin_sha256)
        if not self.origin_path.strip():
            raise InvalidForensicValueError("SourceAnchor exige origin_path nao vazio.")
        if not self.locator.strip():
            raise InvalidForensicValueError("SourceAnchor exige locator nao vazio.")
        if not self.captured_at_utc.endswith("Z"):
            raise InvalidForensicValueError("SourceAnchor exige captured_at_utc em UTC ('Z').")

    def to_dict(self) -> dict[str, str]:
        """Converte a ancora para dicionario primitivo serializavel.

        Returns:
            Mapa chave-valor com os 6 atributos probatorios.
        """
        return {
            "origin_control_number": self.origin_control_number,
            "origin_path": self.origin_path,
            "locator": self.locator,
            "verbatim_excerpt": self.verbatim_excerpt,
            "captured_at_utc": self.captured_at_utc,
            "origin_sha256": self.origin_sha256,
        }
