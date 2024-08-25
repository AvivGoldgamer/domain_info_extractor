## Custom exception for database interactions
class TransactionError(Exception):
    """Custom exception for transaction errors."""

    def __init__(self, message="Transaction failed"):
        self.message = message
        super().__init__({self.message})
        
## Custom exception for process interactions
class ProcessError(Exception):
    """Custom exception for Processing errors."""

    def __init__(self, message="Process failed"):
        self.message = message
        super().__init__({self.message})
