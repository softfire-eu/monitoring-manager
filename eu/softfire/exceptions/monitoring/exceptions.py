class _BaseException(Exception):
    def __init__(self, message=None):
        self.message = message


class MonitoringResourceValidationError(_BaseException):
    pass
