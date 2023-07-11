# GDPR Checker - Errors.py
# Patrick Thomas pwt5ca
# Created 200204


class SourceDetectorException(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


class DetectorManagerUninitializedException(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)
