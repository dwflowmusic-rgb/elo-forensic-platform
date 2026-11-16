"""Sensor inteiro de compressibilidade (64 KiB em permille, zero float) para criptografia sem cabecalho."""

from __future__ import annotations

from dataclasses import dataclass
import zlib

from edrm.shared_kernel.enums import MagicSignature

WINDOW_SIZE_BYTES: int = 65_536
WINDOW_OVERLAP_BYTES: int = 1_024
WINDOW_STEP_BYTES: int = WINDOW_SIZE_BYTES - WINDOW_OVERLAP_BYTES
HIGH_ENTROPY_PERMILLE_THRESHOLD: int = 995

KNOWN_COMPRESSED_SIGNATURES: frozenset[MagicSignature] = frozenset(
    {
        MagicSignature.JPEG_IMAGE,
        MagicSignature.PNG_IMAGE,
        MagicSignature.MP4_VIDEO,
        MagicSignature.ZIP_CONTAINER,
        MagicSignature.CELLEBRITE_UFDR_UFDX,
        MagicSignature.RAR_V4_V5,
        MagicSignature.SEVEN_ZIP,
        MagicSignature.GZIP,
        MagicSignature.PDF_DOCUMENT,
    }
)


@dataclass(frozen=True, slots=True)
class CompressibilityProbeResult:
    """Resultado deterministico inteiro da sonda de compressibilidade em janelas de 64 KiB."""

    inspected_bytes: int
    windows_evaluated: int
    min_permille: int
    max_permille: int
    mean_permille: int
    high_entropy_windows: int
    is_headerless_encrypted: bool
    resolved_signature: MagicSignature


def compute_window_permille(raw_window: bytes) -> int:
    """Calcula a razao inteira em milesimos (compressed_len * 1000) // raw_len sem float.

    Args:
        raw_window: Bloco binario a comprimir via zlib nivel 1 deterministico.

    Returns:
        Inteiro em milesimos (permille). Valores >= 995 indicam incompressibilidade/alta entropia.
    """
    raw_len = len(raw_window)
    if raw_len <= 0:
        return 0
    compressed = zlib.compress(raw_window, level=1)
    return (len(compressed) * 1000) // raw_len


def probe_headerless_encryption_bytes(
    raw_bytes: bytes,
    initial_signature: MagicSignature,
) -> CompressibilityProbeResult:
    """Avalia janelas deslizantes de 64 KiB com overlap de 1 KiB para detectar volumes cifrados sem magic bytes.

    Args:
        raw_bytes: Amostra ou conteudo binario do arquivo (>= 64 KiB para ativar classificacao).
        initial_signature: Assinatura de 16 bytes detectada previamente.

    Returns:
        CompressibilityProbeResult com metricas inteiras em permille.
    """
    total_len = len(raw_bytes)
    if total_len < WINDOW_SIZE_BYTES:
        pm = compute_window_permille(raw_bytes) if total_len > 0 else 0
        return CompressibilityProbeResult(
            inspected_bytes=total_len,
            windows_evaluated=1 if total_len > 0 else 0,
            min_permille=pm,
            max_permille=pm,
            mean_permille=pm,
            high_entropy_windows=1 if pm >= HIGH_ENTROPY_PERMILLE_THRESHOLD else 0,
            is_headerless_encrypted=False,
            resolved_signature=initial_signature,
        )

    permilles: list[int] = []
    offset = 0
    while offset + WINDOW_SIZE_BYTES <= total_len:
        win = raw_bytes[offset : offset + WINDOW_SIZE_BYTES]
        permilles.append(compute_window_permille(win))
        offset += WINDOW_STEP_BYTES

    high_cnt = sum(1 for p in permilles if p >= HIGH_ENTROPY_PERMILLE_THRESHOLD)
    mean_pm = sum(permilles) // len(permilles)
    min_pm = min(permilles)
    max_pm = max(permilles)

    is_headerless = (
        initial_signature == MagicSignature.UNKNOWN_BINARY
        and initial_signature not in KNOWN_COMPRESSED_SIGNATURES
        and mean_pm >= HIGH_ENTROPY_PERMILLE_THRESHOLD
        and min_pm >= HIGH_ENTROPY_PERMILLE_THRESHOLD
    )
    resolved = (
        MagicSignature.HEADERLESS_HIGH_ENTROPY_ENCRYPTED
        if is_headerless
        else initial_signature
    )
    return CompressibilityProbeResult(
        inspected_bytes=total_len,
        windows_evaluated=len(permilles),
        min_permille=min_pm,
        max_permille=max_pm,
        mean_permille=mean_pm,
        high_entropy_windows=high_cnt,
        is_headerless_encrypted=is_headerless,
        resolved_signature=resolved,
    )


def filter_compressible_windows_for_bm25(raw_bytes: bytes) -> bytes:
    """Descarta janelas de 64 KiB com permille >= 995 para nao poluir o indice BM25 com lixo pseudoaleatorio.

    Args:
        raw_bytes: Fluxo binario bruto de arquivo desconhecido/corrompido.

    Returns:
        Subconjunto de bytes pertencente apenas as janelas compressiveis (< 995 permille).
    """
    if len(raw_bytes) < WINDOW_SIZE_BYTES:
        if len(raw_bytes) >= 4096 and compute_window_permille(raw_bytes) >= HIGH_ENTROPY_PERMILLE_THRESHOLD:
            return b""
        return raw_bytes

    kept_parts: list[bytes] = []
    offset = 0
    while offset < len(raw_bytes):
        chunk = raw_bytes[offset : offset + WINDOW_SIZE_BYTES]
        if len(chunk) >= 4096 and compute_window_permille(chunk) >= HIGH_ENTROPY_PERMILLE_THRESHOLD:
            offset += WINDOW_SIZE_BYTES
            continue
        kept_parts.append(chunk)
        offset += WINDOW_SIZE_BYTES
    return b"".join(kept_parts)
