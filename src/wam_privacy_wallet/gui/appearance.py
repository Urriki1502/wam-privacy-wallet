"""Native REGTEST visual appearance.

Only changes presentation. No network, location API, filesystem configuration,
wallet authority or Core process is touched by the day/night scheduler.
"""
from __future__ import annotations

from datetime import datetime

VALID_MODES = ("auto", "light", "dark")


def resolved_appearance(mode: str, local_time: datetime) -> str:
    """Auto chooses daylight for 06:00 <= local clock < 18:00.

    This is a time-of-day preference, not an astronomical sunrise forecast.
    The timezone comes from the operating system at each timer refresh; if
    the user's clock or timezone changes, the next tick follows it.
    """
    if (type(mode) is not str or mode not in VALID_MODES
            or type(local_time) is not datetime
            or local_time.tzinfo is None or local_time.utcoffset() is None):
        raise ValueError("APPEARANCE_SCOPE_DENIED")
    if mode != "auto":
        return mode
    return "light" if 6 <= local_time.hour < 18 else "dark"


def appearance_colors(mode: str) -> dict[str, str]:
    if mode == "light":
        return {
            "background": "#F3F6FB", "surface": "#FFFFFF", "surface_alt": "#EAF1F8",
            "text": "#15253B", "muted": "#586A80", "border": "#D9E3EF",
            "accent": "#087B73", "accent_hover": "#07665F",
            "on_accent": "#FFFFFF", "selection": "#DDF4F0",
            "warning": "#7E520F", "warn_surface": "#FFF4DD",
        }
    if mode == "dark":
        return {
            "background": "#0B1424", "surface": "#152239", "surface_alt": "#1C2C45",
            "text": "#F3F7FF", "muted": "#AFC0D5", "border": "#31415B",
            "accent": "#55CDBD", "accent_hover": "#83E6D7",
            "on_accent": "#09201E", "selection": "#244D51",
            "warning": "#F6CF86", "warn_surface": "#3A3023",
        }
    raise ValueError("APPEARANCE_SCOPE_DENIED")


def appearance_stylesheet(mode: str) -> str:
    c = appearance_colors(mode)
    # Explicit selectors: security hold labels remain verbatim and visible.
    return f"""
        QMainWindow, QWidget#WalletRoot {{
            background-color: {c['background']};
            color: {c['text']};
        }}
        QLabel {{
            color: {c['text']};
            background: transparent;
        }}
        QLabel#WalletMark {{
            background: {c['accent']};
            color: {c['on_accent']};
            border-radius: 15px;
            min-width: 36px;
            min-height: 36px;
            max-width: 36px;
            max-height: 36px;
            font-weight: 800;
            font-size: 21px;
        }}
        QLabel#WalletBrand {{
            font-size: 20px;
            font-weight: 750;
        }}
        QLabel#WalletSubtitle {{
            color: {c['muted']};
            font-size: 11px;
        }}
        QLabel#WalletWarning {{
            color: {c['warning']};
            background: {c['warn_surface']};
            border: 1px solid {c['border']};
            border-radius: 9px;
            padding: 8px 12px;
            font-weight: 650;
        }}
        QLabel#PageTitle {{
            font-size: 20px;
            font-weight: 700;
            margin-bottom: 4px;
        }}
        QLabel#TimezoneLabel {{
            color: {c['muted']};
            font-size: 10px;
        }}
        QWidget#WalletHeader, QWidget#WalletCard {{
            background: {c['surface']};
            border: 1px solid {c['border']};
            border-radius: 12px;
        }}
        QListWidget {{
            background: {c['surface']};
            color: {c['text']};
            border: 1px solid {c['border']};
            border-radius: 12px;
            padding: 8px 5px;
            outline: none;
            font-size: 13px;
        }}
        QListWidget::item {{
            padding: 10px 9px;
            min-height: 28px;
            border-radius: 8px;
            margin: 2px;
        }}
        QListWidget::item:selected {{
            color: {c['text']};
            background: {c['selection']};
            font-weight: 650;
        }}
        QListWidget::item:hover:!selected {{
            background: {c['surface_alt']};
        }}
        QStackedWidget, QStackedWidget > QWidget {{
            background: {c['surface']};
            border-radius: 12px;
        }}
        QPushButton {{
            color: {c['text']};
            background: {c['surface_alt']};
            border: 1px solid {c['border']};
            border-radius: 8px;
            padding: 8px 13px;
            font-weight: 600;
        }}
        QPushButton:hover {{
            background: {c['selection']};
            border-color: {c['accent']};
        }}
        QPushButton:disabled {{
            color: {c['muted']};
            background: {c['background']};
            border-color: {c['border']};
        }}
        QPushButton#ModeButton {{
            background: {c['accent']};
            color: {c['on_accent']};
            border: none;
        }}
        QPushButton#ModeButton:hover {{
            background: {c['accent_hover']};
        }}
        QLineEdit, QSpinBox, QComboBox, QPlainTextEdit {{
            background: {c['surface']};
            color: {c['text']};
            border: 1px solid {c['border']};
            border-radius: 7px;
            padding: 6px 9px;
            selection-background-color: {c['accent']};
            selection-color: {c['on_accent']};
        }}
        QLineEdit:focus, QSpinBox:focus, QComboBox:focus {{
            border: 1px solid {c['accent']};
        }}
        QCheckBox {{
            color: {c['text']};
            spacing: 7px;
        }}
    """
