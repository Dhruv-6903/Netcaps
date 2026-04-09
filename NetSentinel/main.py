import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt
from gui.main_window import MainWindow
import os


def main():
    app = QApplication(sys.argv)
    app.setAttribute(Qt.AA_EnableHighDpiScaling, True)

    # Load theme
    theme_path = os.path.join(os.path.dirname(__file__), "gui", "styles", "theme.qss")
    if os.path.exists(theme_path):
        with open(theme_path, "r") as f:
            app.setStyleSheet(f.read())

    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
