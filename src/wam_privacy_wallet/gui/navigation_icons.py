"""Small native vector navigation icons drawn by Qt, no external images/fonts."""
from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPen, QPixmap


def navigation_icon(index: int, color: str) -> QIcon:
    if type(index) is not int or not 0 <= index <= 8:
        raise ValueError("NAV_ICON_SCOPE_DENIED")
    ink = QColor(color)
    if not ink.isValid():
        raise ValueError("NAV_ICON_COLOR_DENIED")
    canvas = QPixmap(40, 40)
    canvas.fill(Qt.GlobalColor.transparent)
    p = QPainter(canvas)
    try:
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        p.setPen(QPen(ink, 2.2, Qt.PenStyle.SolidLine,
                      Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
        p.setBrush(Qt.BrushStyle.NoBrush)
        def line(x1, y1, x2, y2):
            p.drawLine(QPointF(x1, y1), QPointF(x2, y2))

        if index == 0:  # Dashboard
            for x, y in ((9, 9), (22, 9), (9, 22), (22, 22)):
                p.drawRoundedRect(QRectF(x, y, 9, 9), 2, 2)
        elif index == 1:  # Local node links
            for x, y in ((8, 9), (23, 9), (16, 25)):
                p.drawEllipse(QRectF(x, y, 8, 8))
            line(16, 13, 23, 13)
            line(12, 17, 19, 25)
            line(27, 17, 23, 25)
        elif index == 2:  # Receive
            p.drawRoundedRect(QRectF(9, 24, 22, 7), 2, 2)
            line(20, 8, 20, 22)
            line(14, 16, 20, 22)
            line(26, 16, 20, 22)
        elif index == 3:  # History
            p.drawEllipse(QRectF(9, 9, 22, 22))
            line(20, 13, 20, 21)
            line(20, 21, 26, 24)
        elif index == 4:  # Coins
            p.drawEllipse(QRectF(10, 10, 20, 20))
            p.drawEllipse(QRectF(15, 15, 10, 10))
            line(20, 6, 20, 9)
        elif index == 5:  # Send
            line(8, 20, 30, 20)
            line(23, 13, 30, 20)
            line(23, 27, 30, 20)
            line(11, 13, 11, 27)
        elif index == 6:  # Backup / recovery
            p.drawRoundedRect(QRectF(10, 19, 20, 13), 3, 3)
            line(14, 19, 14, 14)
            p.drawArc(QRectF(14, 7, 12, 13), 5 * 16, 170 * 16)
            line(26, 11, 26, 17)
        elif index == 7:  # Privacy shield
            from PySide6.QtGui import QPainterPath
            path = QPainterPath(QPointF(20, 7))
            path.lineTo(30, 12)
            path.lineTo(29, 23)
            path.quadTo(27, 29, 20, 33)
            path.quadTo(13, 29, 11, 23)
            path.lineTo(10, 12)
            path.closeSubpath()
            p.drawPath(path)
            line(16, 20, 19, 23)
            line(19, 23, 25, 17)
        else:  # Security / diagnostics
            p.drawRoundedRect(QRectF(11, 17, 18, 16), 3, 3)
            p.drawArc(QRectF(15, 8, 10, 18), 0, 180 * 16)
            p.drawEllipse(QRectF(18, 23, 4, 4))
    finally:
        p.end()
    return QIcon(canvas)
