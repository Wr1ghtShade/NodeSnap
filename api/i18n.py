"""NodeSnap - Internationalisation (FR / EN)."""
import json
import logging
from pathlib import Path
from typing import Dict

log = logging.getLogger("nodesnap.i18n")

I18N_DIR = Path(__file__).parent.parent / "i18n"
SUPPORTED = ("fr", "en")
DEFAULT = "fr"
COOKIE_NAME = "nodesnap_lang"

_translations: Dict[str, Dict[str, str]] = {}


def load_translations() -> None:
    """Charge tous les fichiers JSON de traduction en mémoire (idempotent)."""
    for lang in SUPPORTED:
        path = I18N_DIR / f"{lang}.json"
        if not path.exists():
            log.warning(f"Fichier de traduction manquant : {path}")
            _translations[lang] = {}
            continue
        try:
            _translations[lang] = json.loads(path.read_text(encoding="utf-8"))
            log.info(f"i18n : {lang} chargé ({len(_translations[lang])} clés)")
        except Exception as e:
            log.error(f"Échec chargement {path} : {e}")
            _translations[lang] = {}


def t(key: str, lang: str = DEFAULT, **kwargs) -> str:
    """Retourne la traduction d'une clé. Fallback : FR puis la clé brute.
    Les kwargs servent au formatage {placeholder} dans la chaîne."""
    table = _translations.get(lang, {})
    value = table.get(key)
    if value is None and lang != DEFAULT:
        value = _translations.get(DEFAULT, {}).get(key)
    if value is None:
        return key
    if kwargs:
        try:
            return value.format(**kwargs)
        except (KeyError, IndexError, ValueError):
            return value
    return value


def get_lang(request) -> str:
    """Récupère la langue préférée depuis le cookie. Fallback : DEFAULT."""
    lang = request.cookies.get(COOKIE_NAME, DEFAULT)
    if lang not in SUPPORTED:
        return DEFAULT
    return lang
