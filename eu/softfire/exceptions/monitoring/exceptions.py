class BaseException(Exception):
    def __init__(self, message=None):
        self.message = message

class MonitoringResourceValidationError(BaseException):
	pass