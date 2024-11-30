from .base.scroll import BaseScrollWidget


class LibrariesWidget(BaseScrollWidget):
    def __init__(self, parent=None):
        super().__init__("Libraries", parent)
