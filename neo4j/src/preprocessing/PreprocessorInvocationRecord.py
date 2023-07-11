from datetime import datetime

class PreprocessorInvocationRecord():
    """Helper class for metadata about preprocessor runs"""

    def log_start(self):
        self.start_time = datetime.now()

    def log_end(self):
        self.end_time = datetime.now()

    def runtime(self):
        """Duration or invocation in ms."""
        delta = self.end_time - self.start_time
        return delta.total_seconds() * 1000

    def __init__(self, start_time=0, end_time=0):
        self.start_time = start_time
        self.end_time = end_time
    

