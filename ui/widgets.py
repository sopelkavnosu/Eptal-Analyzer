"""UI-виджеты."""

import os

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QFont, QIcon, QPainter, QPen, QPixmap
from PyQt6.QtSvg import QSvgRenderer
from PyQt6.QtWidgets import QSplashScreen, QWidget

from core.version import __version__

class SpinnerWidget(QWidget):
    # Круговой индикатор загрузки.
    def __init__(self, size=22, parent=None):
        super().__init__(parent)
        self._angle = 0
        self._timer = QTimer(self)
        self._timer.setInterval(80)
        self._timer.timeout.connect(self._rotate)
        self.setFixedSize(size, size)
        self.setVisible(False)

    def start(self):
        self._timer.start()
        self.setVisible(True)

    def stop(self):
        self._timer.stop()
        self.setVisible(False)

    def _rotate(self):
        self._angle = (self._angle + 30) % 360
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = self.rect().adjusted(3, 3, -3, -3)
        pen = QPen(QColor("#3a3a3a"))
        pen.setWidth(3)
        painter.setPen(pen)
        painter.drawEllipse(rect)
        pen = QPen(QColor("#79a7ff"))
        pen.setWidth(3)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        painter.drawArc(rect, int((90 - self._angle) * 16), -120 * 16)
        painter.end()


def load_colored_svg(path, color, size=24):
    renderer = QSvgRenderer(path)
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)

    painter = QPainter(pixmap)
    renderer.render(painter)
    painter.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceIn)
    painter.fillRect(pixmap.rect(), QColor(color))
    painter.end()
    return QIcon(pixmap)


class LogoIniziale(QSplashScreen):
    def __init__(self):
        # Экран загрузки с новым брендингом Eptal-Analyzer и атрибуцией оригинального проекта.
        pixmap = QPixmap(640, 360)
        pixmap.fill(QColor("#1e1e1e"))

        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        logo_path = os.path.join(os.path.dirname(__file__), "assets", "screenLogo.png")
        if os.path.exists(logo_path):
            maxL = 520
            maxA = 170
            logo = QPixmap(logo_path).scaled(
                maxL,
                maxA,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            x = (640 - logo.width()) // 2
            painter.setOpacity(0.22)
            painter.drawPixmap(x, 16, logo)
            painter.setOpacity(1.0)

        painter.setPen(QColor("#ffffff"))
        painter.setFont(QFont("Segoe UI", 34, QFont.Weight.DemiBold))
        painter.drawText(
            pixmap.rect().adjusted(0, 150, 0, 0),
            Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
            "Eptal-Analyzer",
        )

        painter.setPen(QColor("#d6d6d6"))
        painter.setFont(QFont("Segoe UI", 11))
        painter.drawText(
            pixmap.rect().adjusted(0, 210, 0, 0),
            Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
            "Современный анализатор сети",
        )

        painter.setPen(QColor("#d0d0d0"))
        painter.setFont(QFont("Segoe UI", 9))
        painter.drawText(
            pixmap.rect().adjusted(0, 255, 0, 0),
            Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
            "Основано на L0p4Map by HaxL0p4 (оригинал) • GPL-3.0-or-later",
        )

        painter.setPen(QColor("#5a5a5a"))
        painter.setFont(QFont("Segoe UI", 9))
        painter.drawText(
            pixmap.rect().adjusted(0, 305, 0, 0),
            Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
            f"Версия Eptal-Analyzer: v{__version__} • загрузка...",
        )

        painter.setPen(QColor("#3c3c3c"))
        painter.drawRect(0, 0, 639, 359)
        painter.end()

        super().__init__(pixmap)
        self.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint)


