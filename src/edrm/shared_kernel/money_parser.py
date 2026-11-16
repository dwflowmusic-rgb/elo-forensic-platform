"""Parser monetario deterministico para centavos inteiros BIGINT (zero ponto flutuante)."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN
import re

from edrm.shared_kernel.exceptions import InvalidForensicValueError
from edrm.shared_kernel.value_objects import CentsAmount

_CURRENCY_PREFIX_RE = re.compile(r"(?:R\$|US\$|BRL|USD|EUR|\$)", re.IGNORECASE)


def parse_money_to_cents(raw_amount: str, currency: str = "BRL") -> CentsAmount:
    """Converte texto monetario (BR '1.540,90', US '1,540.90' ou SIMBA) em CentsAmount.

    Jamais utiliza ponto flutuante binario; opera exclusivamente por analise sintatica
    de digitos e aritmetica Decimal exata convertida para int (BIGINT).

    Args:
        raw_amount: String monetaria bruta constante do extrato, SIMBA, OFX ou auto.
        currency: Codigo ISO de 3 letras da moeda (padrao 'BRL').

    Returns:
        Objeto CentsAmount contendo o valor exato em centavos inteiros.

    Raises:
        InvalidForensicValueError: Quando o texto nao representa quantia monetaria valida
            ou possui fracao sub-centavo nao inteira.
    """
    if not isinstance(raw_amount, str):
        raise InvalidForensicValueError("parse_money_to_cents aceita apenas str.")

    working = raw_amount.strip()
    if not working:
        raise InvalidForensicValueError("Valor monetario vazio.")

    negative = False
    if working.startswith("(") and working.endswith(")"):
        negative = True
        working = working[1:-1].strip()

    working = _CURRENCY_PREFIX_RE.sub("", working).strip()
    if working.endswith("-"):
        negative = True
        working = working[:-1].strip()
    elif working.startswith("-"):
        negative = True
        working = working[1:].strip()
    elif working.startswith("+"):
        working = working[1:].strip()

    working = working.replace(" ", "")
    if not working:
        raise InvalidForensicValueError(f"Valor monetario sem digitos: {raw_amount!r}")

    has_comma = "," in working
    has_dot = "." in working

    if has_comma and has_dot:
        last_comma = working.rfind(",")
        last_dot = working.rfind(".")
        if last_comma > last_dot:
            normalized = working.replace(".", "").replace(",", ".")
        else:
            normalized = working.replace(",", "")
    elif has_comma:
        parts = working.split(",")
        if len(parts) == 2 and len(parts[1]) in (1, 2):
            normalized = parts[0] + "." + parts[1]
        elif all(len(p) == 3 for p in parts[1:]):
            normalized = "".join(parts)
        else:
            raise InvalidForensicValueError(f"Separador decimal ambiguo em: {raw_amount!r}")
    elif has_dot:
        parts = working.split(".")
        if len(parts) == 2 and len(parts[1]) in (1, 2):
            normalized = working
        elif all(len(p) == 3 for p in parts[1:]):
            normalized = "".join(parts)
        else:
            raise InvalidForensicValueError(f"Separador decimal ambiguo em: {raw_amount!r}")
    else:
        normalized = working

    try:
        dec_val = Decimal(normalized)
    except InvalidOperation as exc:
        raise InvalidForensicValueError(f"Quantia monetaria invalida: {raw_amount!r}") from exc

    scaled = (dec_val * Decimal(100)).quantize(Decimal("1"), rounding=ROUND_HALF_EVEN)
    if scaled != dec_val * Decimal(100):
        raise InvalidForensicValueError(
            f"Quantia possui precisao fracionaria sub-centavo nao exata: {raw_amount!r}"
        )

    cents_int = int(scaled)
    if negative:
        cents_int = -abs(cents_int)
    return CentsAmount(cents=cents_int, currency=currency)
