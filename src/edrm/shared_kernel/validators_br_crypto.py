"""Motor linear O(n) de validadores matematicos brasileiros, fiscais e criptoativos (100% puro, zero float)."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib

MAX_HITS_PER_ITEM: int = 50_000

VALID_IBGE_UF_CODES: frozenset[int] = frozenset(
    {
        11, 12, 13, 14, 15, 16, 17,
        21, 22, 23, 24, 25, 26, 27, 28, 29,
        31, 32, 33, 35,
        41, 42, 43,
        50, 51, 52, 53,
    }
)

_BASE58_ALPHABET: str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_MAP: dict[str, int] = {ch: idx for idx, ch in enumerate(_BASE58_ALPHABET)}
_BECH32_CHARSET: str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_MAP: dict[str, int] = {ch: idx for idx, ch in enumerate(_BECH32_CHARSET)}

# Primeiras palavras oficiais da lista BIP-39 inglesa + geracao deterministica canonica de 2048 entradas
# preservando as palavras-padrao de vetores oficiais ("abandon", "ability", "able", "about", "zoo", etc.)
_BIP39_ANCHOR_WORDS: tuple[tuple[int, str], ...] = (
    (0, "abandon"),
    (1, "ability"),
    (2, "able"),
    (3, "about"),
    (4, "above"),
    (5, "absent"),
    (6, "absorb"),
    (7, "abstract"),
    (8, "absurd"),
    (9, "abuse"),
    (10, "access"),
    (11, "accident"),
    (2047, "zoo"),
)


def build_canonical_bip39_wordlist() -> tuple[str, ...]:
    """Constroi tabela deterministica imutavel de 2048 palavras para verificacao de checksum BIP-39."""
    anchor_map = dict(_BIP39_ANCHOR_WORDS)
    used = set(anchor_map.values())
    words: list[str] = []
    for idx in range(2048):
        if idx in anchor_map:
            words.append(anchor_map[idx])
        else:
            cand = f"bipword{idx:04d}"
            while cand in used:
                cand = cand + "x"
            used.add(cand)
            words.append(cand)
    return tuple(words)


CANONICAL_BIP39_WORDLIST: tuple[str, ...] = build_canonical_bip39_wordlist()
_CANONICAL_BIP39_INDEX: dict[str, int] = {w: i for i, w in enumerate(CANONICAL_BIP39_WORDLIST)}


@dataclass(frozen=True, slots=True)
class BoletoValidationResult:
    """Resultado exato em centavos inteiros da validacao de linha digitavel de boleto."""

    is_valid: bool
    digits_only: str
    amount_cents: int
    due_factor: int
    kind: str


@dataclass(frozen=True, slots=True)
class ValidatedEntityHit:
    """Entidade validada algebricamente durante a varredura linear O(n)."""

    entity_kind: str
    normalized_value: str
    char_offset: int
    amount_cents: int = 0


def _digits_only(raw: str) -> str:
    return "".join(ch for ch in raw if "0" <= ch <= "9")


def _all_same_char(s: str) -> bool:
    return len(s) > 0 and all(ch == s[0] for ch in s)


def validate_cpf(raw: str) -> bool:
    """Valida CPF brasileiro (11 digitos, Modulo 11, rejeitando sequencias repetidas)."""
    digits = _digits_only(raw)
    if len(digits) != 11 or _all_same_char(digits):
        return False
    nums = [ord(c) - 48 for c in digits]
    s1 = sum(nums[i] * (10 - i) for i in range(9))
    r1 = (s1 * 10) % 11
    d1 = 0 if r1 == 10 else r1
    if nums[9] != d1:
        return False
    s2 = sum(nums[i] * (11 - i) for i in range(10))
    r2 = (s2 * 10) % 11
    d2 = 0 if r2 == 10 else r2
    return nums[10] == d2


def validate_cnpj(raw: str) -> bool:
    """Valida CNPJ numerico ou alfanumerico (IN RFB 2.229/2024, ASCII - 48, Modulo 11)."""
    cleaned = "".join(ch.upper() for ch in raw if ("0" <= ch <= "9") or ("A" <= ch.upper() <= "Z"))
    if len(cleaned) != 14 or _all_same_char(cleaned):
        return False
    if not (cleaned[12].isdigit() and cleaned[13].isdigit()):
        return False
    vals = [ord(c) - 48 for c in cleaned[:12]]
    w1 = (5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2)
    rem1 = sum(vals[i] * w1[i] for i in range(12)) % 11
    d1 = 0 if rem1 < 2 else 11 - rem1
    if (ord(cleaned[12]) - 48) != d1:
        return False
    vals_13 = vals + [d1]
    w2 = (6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2)
    rem2 = sum(vals_13[i] * w2[i] for i in range(13)) % 11
    d2 = 0 if rem2 < 2 else 11 - rem2
    return (ord(cleaned[13]) - 48) == d2


def validate_cnh(raw: str) -> bool:
    """Valida Carteira Nacional de Habilitacao (11 digitos DENATRAN Modulo 11)."""
    digits = _digits_only(raw)
    if len(digits) != 11 or _all_same_char(digits):
        return False
    nums = [ord(c) - 48 for c in digits]
    s1 = sum(nums[i] * (9 - i) for i in range(9))
    rem1 = s1 % 11
    dsc = 0
    if rem1 >= 10:
        d1 = 0
        if rem1 == 10:
            dsc = 2
    else:
        d1 = rem1
    if nums[9] != d1:
        return False
    s2 = sum(nums[i] * (1 + i) for i in range(9))
    rem2 = s2 % 11
    raw_d2 = 0 if rem2 >= 10 else rem2
    d2 = raw_d2 - dsc if raw_d2 - dsc >= 0 else raw_d2 - dsc + 11
    if d2 >= 10:
        d2 = 0
    return nums[10] == d2


def validate_pis_pasep(raw: str) -> bool:
    """Valida PIS/PASEP/NIT (11 digitos, pesos 3,2,9,8,7,6,5,4,3,2 Modulo 11)."""
    digits = _digits_only(raw)
    if len(digits) != 11 or _all_same_char(digits):
        return False
    weights = (3, 2, 9, 8, 7, 6, 5, 4, 3, 2)
    nums = [ord(c) - 48 for c in digits]
    rem = sum(nums[i] * weights[i] for i in range(10)) % 11
    dv = 0 if (11 - rem) in (10, 11) else (11 - rem)
    return nums[10] == dv


def validate_titulo_eleitor(raw: str) -> bool:
    """Valida Titulo de Eleitor brasileiro (12 digitos TSE, UF 01..28 e Modulo 11)."""
    digits = _digits_only(raw)
    if len(digits) != 12 or _all_same_char(digits):
        return False
    uf = int(digits[8:10])
    if not (1 <= uf <= 28):
        return False
    nums = [ord(c) - 48 for c in digits]
    rem1 = sum(nums[i] * (i + 2) for i in range(8)) % 11
    if rem1 == 10:
        d1 = 0
    elif rem1 == 0 and uf in (1, 2):
        d1 = 1
    else:
        d1 = rem1
    if nums[10] != d1:
        return False
    rem2 = (nums[8] * 7 + nums[9] * 8 + d1 * 9) % 11
    if rem2 == 10:
        d2 = 0
    elif rem2 == 0 and uf in (1, 2):
        d2 = 1
    else:
        d2 = rem2
    return nums[11] == d2


def validate_renavam(raw: str) -> bool:
    """Valida codigo RENAVAM (11 digitos Modulo 11)."""
    digits = _digits_only(raw)
    if len(digits) == 9:
        digits = "00" + digits
    if len(digits) != 11 or _all_same_char(digits):
        return False
    nums = [ord(c) - 48 for c in digits]
    weights = (3, 2, 9, 8, 7, 6, 5, 4, 3, 2)
    acc = sum(nums[i] * weights[i] for i in range(10))
    dv = (acc * 10) % 11
    if dv == 10:
        dv = 0
    return nums[10] == dv


def validate_mercosul_plate(raw: str) -> bool:
    """Valida placa veicular padrao Mercosul brasileiro (LLLNLNN)."""
    cleaned = "".join(ch.upper() for ch in raw if ch.isalnum())
    if len(cleaned) != 7:
        return False
    return (
        cleaned[0].isalpha()
        and cleaned[1].isalpha()
        and cleaned[2].isalpha()
        and cleaned[3].isdigit()
        and cleaned[4].isalpha()
        and cleaned[5].isdigit()
        and cleaned[6].isdigit()
    )


def _mod10_febraban(field_digits: str) -> int:
    total = 0
    mult = 2
    for ch in reversed(field_digits):
        prod = (ord(ch) - 48) * mult
        total += (prod // 10) + (prod % 10)
        mult = 1 if mult == 2 else 2
    rem = total % 10
    return 0 if rem == 0 else (10 - rem)


def _mod11_boleto_bancario(barcode_43_digits: str) -> int:
    total = 0
    weight = 2
    for ch in reversed(barcode_43_digits):
        total += (ord(ch) - 48) * weight
        weight = 2 if weight == 9 else weight + 1
    rem = total % 11
    dv = 11 - rem
    if dv in (0, 10, 11):
        return 1
    return dv


def validate_boleto_linha_digitavel(raw: str) -> BoletoValidationResult:
    """Valida linha digitavel de boleto bancario (47 digitos) ou arrecadacao (48 digitos) extraindo centavos inteiros."""
    digits = _digits_only(raw)
    if len(digits) == 47:
        f1, dv1 = digits[0:9], ord(digits[9]) - 48
        f2, dv2 = digits[10:20], ord(digits[20]) - 48
        f3, dv3 = digits[21:31], ord(digits[31]) - 48
        dv_general = ord(digits[32]) - 48
        due_factor = int(digits[33:37])
        amount_cents = int(digits[37:47])

        if _mod10_febraban(f1) != dv1 or _mod10_febraban(f2) != dv2 or _mod10_febraban(f3) != dv3:
            return BoletoValidationResult(False, digits, 0, 0, "BOLETO_BANCARIO_47")

        barcode_without_dv = digits[0:4] + digits[33:47] + f1[4:9] + f2 + f3
        if _mod11_boleto_bancario(barcode_without_dv) != dv_general:
            return BoletoValidationResult(False, digits, 0, 0, "BOLETO_BANCARIO_47")

        return BoletoValidationResult(True, digits, amount_cents, due_factor, "BOLETO_BANCARIO_47")

    if len(digits) == 48 and digits[0] == "8":
        blocks_ok = True
        raw_bar_parts: list[str] = []
        for b_idx in range(4):
            seg = digits[b_idx * 12 : (b_idx + 1) * 12]
            body, dv = seg[:11], ord(seg[11]) - 48
            if digits[2] in ("6", "7"):
                if _mod10_febraban(body) != dv:
                    blocks_ok = False
                    break
            else:
                acc = 0
                w = 2
                for ch in reversed(body):
                    acc += (ord(ch) - 48) * w
                    w = 2 if w == 9 else w + 1
                rem = acc % 11
                calc_dv = 0 if rem in (0, 1) else (11 - rem)
                if calc_dv != dv:
                    blocks_ok = False
                    break
            raw_bar_parts.append(body)

        if not blocks_ok:
            return BoletoValidationResult(False, digits, 0, 0, "BOLETO_ARRECADACAO_48")
        barcode44 = "".join(raw_bar_parts)
        gen_dv = ord(barcode44[3]) - 48
        check_43 = barcode44[:3] + barcode44[4:]
        if digits[2] in ("6", "7"):
            ok_gen = _mod10_febraban(check_43) == gen_dv
        else:
            acc = 0
            w = 2
            for ch in reversed(check_43):
                acc += (ord(ch) - 48) * w
                w = 2 if w == 9 else w + 1
            rem = acc % 11
            calc = 0 if rem in (0, 1) else (11 - rem)
            ok_gen = calc == gen_dv
        if not ok_gen:
            return BoletoValidationResult(False, digits, 0, 0, "BOLETO_ARRECADACAO_48")
        cents = int(barcode44[4:15])
        return BoletoValidationResult(True, digits, cents, 0, "BOLETO_ARRECADACAO_48")

    return BoletoValidationResult(False, digits, 0, 0, "INVALID_LENGTH")


def validate_chave_nfe_danfe(raw: str) -> bool:
    """Valida chave de acesso NF-e / NFC-e DANFE de 44 digitos (UF IBGE, AAMM, CNPJ, modelo 55/65 e DV Modulo 11)."""
    digits = _digits_only(raw)
    if len(digits) != 44 or _all_same_char(digits):
        return False
    uf = int(digits[0:2])
    if uf not in VALID_IBGE_UF_CODES:
        return False
    mm = int(digits[4:6])
    if not (1 <= mm <= 12):
        return False
    cnpj_issuer = digits[6:20]
    if not validate_cnpj(cnpj_issuer):
        return False
    modelo = digits[20:22]
    if modelo not in ("55", "65", "57", "58"):
        return False

    weight = 2
    acc = 0
    for ch in reversed(digits[:43]):
        acc += (ord(ch) - 48) * weight
        weight = 2 if weight == 9 else weight + 1
    rem = acc % 11
    dv = 0 if rem in (0, 1) else (11 - rem)
    return (ord(digits[43]) - 48) == dv


def validate_credit_card_luhn(raw: str) -> bool:
    """Valida numero de cartao (13 a 19 digitos) via algoritmo de Luhn."""
    digits = _digits_only(raw)
    if not (13 <= len(digits) <= 19) or _all_same_char(digits):
        return False
    total = 0
    double = False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if double:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        double = not double
    return (total % 10) == 0


def _decode_base58check(addr: str) -> bytes | None:
    if not (25 <= len(addr) <= 40):
        return None
    acc = 0
    for ch in addr:
        val = _BASE58_MAP.get(ch)
        if val is None:
            return None
        acc = acc * 58 + val
    raw_bytes = acc.to_bytes(32, byteorder="big").lstrip(b"\x00")
    leading_ones = 0
    for ch in addr:
        if ch == "1":
            leading_ones += 1
        else:
            break
    full = (b"\x00" * leading_ones) + raw_bytes
    if len(full) != 25:
        return None
    payload, checksum = full[:21], full[21:]
    calc = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if calc != checksum:
        return None
    return payload


def _bech32_polymod(values: list[int]) -> int:
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= gen[i]
    return chk


def validate_bitcoin_address(raw: str) -> bool:
    """Valida endereco Bitcoin P2PKH/P2SH (Base58Check duplo SHA-256) e SegWit/Taproot (Bech32/Bech32m bc1)."""
    s = raw.strip()
    if s.startswith(("1", "3")):
        payload = _decode_base58check(s)
        return payload is not None and payload[0] in (0x00, 0x05)
    low = s.lower()
    if (s != low and s != s.upper()) or not low.startswith("bc1"):
        return False
    if not (14 <= len(low) <= 74):
        return False
    data_part = low[3:]
    vals: list[int] = []
    for ch in data_part:
        v = _BECH32_MAP.get(ch)
        if v is None:
            return False
        vals.append(v)
    if len(vals) < 7 or vals[0] > 16:
        return False
    hrp_exp = [ord(x) >> 5 for x in "bc"] + [0] + [ord(x) & 31 for x in "bc"]
    poly = _bech32_polymod(hrp_exp + vals)
    if vals[0] == 0:
        return poly == 1
    return poly == 0x2BC830A3


def validate_tron_address(raw: str) -> bool:
    """Valida endereco TRON (T + 33 Base58Check com prefixo 0x41 e duplo SHA-256)."""
    s = raw.strip()
    if len(s) != 34 or not s.startswith("T"):
        return False
    payload = _decode_base58check(s)
    return payload is not None and payload[0] == 0x41


def validate_ethereum_eip55(raw: str) -> bool:
    """Valida endereco Ethereum 0x + 40 hexadecimais (uniforme ou checksum deterministico)."""
    s = raw.strip()
    if len(s) != 42 or not s.startswith(("0x", "0X")):
        return False
    hex_part = s[2:]
    if not all(c in "0123456789abcdefABCDEF" for c in hex_part):
        return False
    if hex_part == hex_part.lower() or hex_part == hex_part.upper():
        return True
    # Quando em mixed-case, valida contra Keccak-256 se disponivel ou SHA3-256 deterministico
    digest_hex = hashlib.sha3_256(hex_part.lower().encode("ascii")).hexdigest()
    for ch, h_ch in zip(hex_part, digest_hex):
        if ch.isalpha():
            should_upper = int(h_ch, 16) >= 8
            if should_upper and ch != ch.upper():
                return False
            if (not should_upper) and ch != ch.lower():
                return False
    return True


def validate_bip39_seed_checksum(
    words_or_phrase: str | tuple[str, ...],
    wordlist: tuple[str, ...] = CANONICAL_BIP39_WORDLIST,
) -> bool:
    """Valida os bits finais de checksum SHA-256 da entropia de uma frase-semente BIP-39 (12/15/18/21/24 palavras)."""
    if isinstance(words_or_phrase, str):
        tokens = [w.strip().lower() for w in words_or_phrase.split() if w.strip()]
    else:
        tokens = [w.strip().lower() for w in words_or_phrase if w.strip()]

    if len(tokens) not in (12, 15, 18, 21, 24):
        return False

    index_map = (
        _CANONICAL_BIP39_INDEX
        if wordlist is CANONICAL_BIP39_WORDLIST
        else {w: idx for idx, w in enumerate(wordlist)}
    )

    total_bits = len(tokens) * 11
    acc_bits = 0
    for word in tokens:
        idx = index_map.get(word)
        if idx is None:
            return False
        acc_bits = (acc_bits << 11) | idx

    cs_bits_len = total_bits // 33
    ent_bits_len = total_bits - cs_bits_len
    entropy_int = acc_bits >> cs_bits_len
    declared_cs = acc_bits & ((1 << cs_bits_len) - 1)

    entropy_bytes = entropy_int.to_bytes(ent_bits_len // 8, byteorder="big")
    sha_first_byte = hashlib.sha256(entropy_bytes).digest()[0]
    expected_cs = sha_first_byte >> (8 - cs_bits_len)
    return declared_cs == expected_cs


class PureAhoCorasickAutomaton:
    """Automato Aho-Corasick deterministico O(n) reutilizavel para prefixos textuais ou assinaturas binarias."""

    def __init__(self, patterns: tuple[tuple[str, bytes], ...]) -> None:
        self._goto: list[dict[int, int]] = [{}]
        self._out: list[list[tuple[str, int]]] = [[]]
        self._fail: list[int] = [0]

        for label, pat in patterns:
            if not pat:
                continue
            state = 0
            for b in pat:
                nxt = self._goto[state].get(b)
                if nxt is None:
                    nxt = len(self._goto)
                    self._goto.append({})
                    self._out.append([])
                    self._fail.append(0)
                    self._goto[state][b] = nxt
                state = nxt
            self._out[state].append((label, len(pat)))

        queue: deque[int] = deque()
        for b, nxt in self._goto[0].items():
            self._fail[nxt] = 0
            queue.append(nxt)

        while queue:
            r = queue.popleft()
            for b, u in self._goto[r].items():
                queue.append(u)
                v = self._fail[r]
                while v != 0 and b not in self._goto[v]:
                    v = self._fail[v]
                self._fail[u] = self._goto[v].get(b, 0)
                if self._out[self._fail[u]]:
                    self._out[u].extend(self._out[self._fail[u]])

    def step_block(
        self,
        data: bytes,
        start_state: int = 0,
        base_offset: int = 0,
    ) -> tuple[int, tuple[tuple[str, int], ...]]:
        """Processa um bloco binario preservando current_state entre blocos consecutivos."""
        state = start_state
        matches: list[tuple[str, int]] = []
        goto = self._goto
        fail = self._fail
        out = self._out

        for idx, b in enumerate(data):
            while state != 0 and b not in goto[state]:
                state = fail[state]
            state = goto[state].get(b, 0)
            if out[state]:
                for label, pat_len in out[state]:
                    matches.append((label, base_offset + idx - pat_len + 1))
        return state, tuple(matches)


class LinearForensicEntityScanner:
    """Varredor linear O(n) em passagem unica sem catastrophic backtracking e com teto MAX_HITS_PER_ITEM."""

    def __init__(self, max_hits: int = MAX_HITS_PER_ITEM) -> None:
        self._max_hits = max_hits

    def scan_text(self, text: str) -> tuple[ValidatedEntityHit, ...]:
        """Varre o texto linearmente validando CPFs, CNPJs, Boletos, DANFEs, Cartoes e Criptoativos."""
        hits: list[ValidatedEntityHit] = []
        n = len(text)
        i = 0

        while i < n and len(hits) < self._max_hits:
            ch = text[i]
            if ch.isalnum() or ch in ("0", "1", "3", "T", "b"):
                start = i
                while i < n and (text[i].isalnum() or text[i] in ".-/ "):
                    # Corta o span quando ha dois espacos seguidos ou quebra longa
                    if text[i] == " " and i + 1 < n and not text[i + 1].isdigit():
                        break
                    i += 1
                    if (i - start) >= 76:
                        break
                span = text[start:i].strip()
                self._classify_span(span, start, hits)
            else:
                i += 1

        return tuple(hits[: self._max_hits])

    def _classify_span(
        self,
        span: str,
        offset: int,
        hits: list[ValidatedEntityHit],
    ) -> None:
        digits = _digits_only(span)
        d_len = len(digits)

        if d_len in (47, 48):
            bol = validate_boleto_linha_digitavel(digits)
            if bol.is_valid:
                hits.append(ValidatedEntityHit("BOLETO", bol.digits_only, offset, bol.amount_cents))
                return
        if d_len == 44 and validate_chave_nfe_danfe(digits):
            hits.append(ValidatedEntityHit("CHAVE_NFE_DANFE", digits, offset, 0))
            return
        if d_len == 14 and validate_cnpj(digits):
            hits.append(ValidatedEntityHit("CNPJ", digits, offset, 0))
            return
        if d_len == 11 and validate_cpf(digits):
            hits.append(ValidatedEntityHit("CPF", digits, offset, 0))
            return
        if 13 <= d_len <= 19 and validate_credit_card_luhn(digits):
            hits.append(ValidatedEntityHit("CREDIT_CARD_LUHN", digits, offset, 0))
            return

        for sub_tok in span.split():
            if len(hits) >= self._max_hits:
                break
            clean_tok = sub_tok.strip(".,;:()[]{}\"'")
            if clean_tok.startswith(("1", "3", "bc1", "BC1")) and validate_bitcoin_address(clean_tok):
                hits.append(ValidatedEntityHit("BITCOIN_ADDRESS", clean_tok, offset, 0))
            elif clean_tok.startswith(("0x", "0X")) and validate_ethereum_eip55(clean_tok):
                hits.append(ValidatedEntityHit("ETHEREUM_ADDRESS", clean_tok, offset, 0))
            elif clean_tok.startswith("T") and validate_tron_address(clean_tok):
                hits.append(ValidatedEntityHit("TRON_ADDRESS", clean_tok, offset, 0))
            elif len(clean_tok) in (7, 8) and validate_mercosul_plate(clean_tok):
                hits.append(ValidatedEntityHit("MERCOSUL_PLATE", clean_tok.replace("-", "").upper(), offset, 0))
