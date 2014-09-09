class MacaroonException(Exception):
    pass


class MacaroonInitException(MacaroonException):
    pass


class MacaroonVerificationFailedException(MacaroonException):
    pass


class MacaroonInvalidSignatureException(MacaroonVerificationFailedException):
    pass


class MacaroonUnmetCaveatException(MacaroonVerificationFailedException):
    pass
