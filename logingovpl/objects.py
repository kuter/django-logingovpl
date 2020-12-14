class LoginGovPlUser:
    """Login.gov.pl user object."""

    def __init__(self, first_name, last_name, date_of_birth, pesel):
        """Init method.

        Args:
            first_name (str): first name
            last_name (str): last name
            date_of_birth (str): date of birth
            pesel (str): Polish identify number
        """
        self.first_name = first_name
        self.last_name = last_name
        self.date_of_birth = date_of_birth
        self.pesel = pesel
