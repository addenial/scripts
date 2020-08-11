class credentials(object):
    def __init__(self, domain, username, plaintext_password, hashed_password):
        self.domain = domain
        self.username = username
        self.plaintext_password = plaintext_password
        self.hashed_password = hashed_password

    @property
    def domain(self):
        return self._domain
    @domain.setter
    def domain(self, value):
        self._domain = value

    @property
    def username(self):
        return self._username
    @username.setter
    def username(self, value):
        self._username = value

    @property
    def plaintext_password(self):
        return self._plaintext_password
    @plaintext_password.setter
    def plaintext_password(self, value):
        self._plaintext_password = value

    @property
    def hashed_password(self):
        return self._hashed_password
    @hashed_password.setter
    def hashed_password(self, value):
        self._hashed_password = value
