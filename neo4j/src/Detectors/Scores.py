# GDPR Checker - Scores.py
# Patrick Thomas pwt5ca
# Created 200723
from PersonalData import PersonalDataMatcher
from enum import Enum
from typing import Any, Dict, Iterable, Optional, Set, Union,List
from NeoHelper import isURLThirdParty,isUrlValid
from Settings import (
    DATA_TYPE_DATABASE, 
    DATA_TYPE_REMOTE, 
    DATA_TYPE_IP,
    DATA_TYPE_ADDRESS,
    DATA_TYPE_BIRTHDAY,
    DATA_TYPE_CITY,
    DATA_TYPE_COUNTRY,
    DATA_TYPE_EMAIL,
    DATA_TYPE_FIRST_NAME,
    DATA_TYPE_LAST_NAME,
    DATA_TYPE_PASSWORD,
    DATA_TYPE_POSTCODE,
    DATA_TYPE_STATE,
    DATA_TYPE_USER,
    DATA_TYPE_USER_META,
    DATA_TYPE_ZIPCODE,
)


PERSONAL_DATA_TYPES = [
    DATA_TYPE_IP,
    DATA_TYPE_ADDRESS,
    DATA_TYPE_BIRTHDAY,
    DATA_TYPE_CITY,
    DATA_TYPE_COUNTRY,
    DATA_TYPE_EMAIL,
    DATA_TYPE_FIRST_NAME,
    DATA_TYPE_LAST_NAME,
    DATA_TYPE_PASSWORD,
    DATA_TYPE_POSTCODE,
    DATA_TYPE_STATE,
    DATA_TYPE_USER,
    DATA_TYPE_USER_META,
    DATA_TYPE_ZIPCODE,
    ]

class ScoreType(Enum):
    CRYPTOGRAPHY = "cryptography"
    STORAGE = "storage"
    TRANSIT = "transit"
    DATABASE = "database"
    API = "api"
    DELETION = "deletion"
    ACTIVATION = "activation"
    RETRIEVAL = "retrieval"
    ERROR = "error"
    NONE = "none"
    WP_USER = 'wp_user'
    VARIABLE = 'variable'
    INPUT = 'user_input'

    def is_storage(self) -> bool:
        """Return if this score is a database or storage node.

        Returns:
            bool: True if the finding is associated with storage. False otherwise.
        """
        return self in (ScoreType.STORAGE, ScoreType.API)

    def is_retrieval(self) -> bool:
        """Return if this score is a database or storage node.

        Returns:
            bool: True if the finding is associated with storage. False otherwise.
        """
        return self is ScoreType.RETRIEVAL

    def is_database(self) -> bool:
        """Return if this score is a database or storage node.

        Returns:
            bool: True if the finding is associated with storage. False otherwise.
        """
        return self is ScoreType.DATABASE

    def is_deletion(self) -> bool:
        return self is ScoreType.DELETION

    def is_source(self) -> bool:
        """Return if this score is a source (supplies data).

        Returns:
            bool: True if the finding is a data source. False otherwise.
        """
        return self.is_retrieval()

    def is_sink(self) -> bool:
        """Return if this score is a sink (saves data).

        Returns:
            bool: True if the finding is a data sink. False otherwise.
        """
        return self.is_storage()


class Score:
    def __init__(
        self,
        value: float,
        categories: Dict[str, Any],
        encryption_method: Optional[str] = None,
        score_type: Optional[ScoreType] = None,
    ):
        """Initialize a new score. Exists as a way to provide background and reasoning with a score.

        Args:
            value (float): A value between 0.0 and 1.0, should represent the number of points assigned to some usage of
                a function.
            categories (Dict[str, bool]): The categories that the score was judged on.
            encryption_method (Optional[str], optional): If the score is being used to judge a usage of encryption, the
                encryption/hash algorithm should be provided for additional information. Defaults to None.
        """
        assert 0.0 <= value <= 1.0
        self.categories: Dict[str, Any] = categories
        self.value = value
        self.encryption_method = encryption_method
        if not score_type:
            score_type = ScoreType.NONE
        self.score_type: ScoreType = score_type

        self.types: Set[str] = set(self.categories.get("data_types", []))

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return f"Score[{self.value * 100:.1f}%]"

    def is_storage(self) -> bool:
        """Return if this node is a database or storage node.

        Returns:
            bool: True if the finding is associated with storage. False otherwise.
        """
        return self.score_type.is_storage() or bool(
            self.categories.get("operations", '') in ["update", "insert"]
        )

    def is_retrieval(self) -> bool:
        """Return if this node is a retrieval node.

        Returns:
            bool: True if the finding is associated with retrieval. False otherwise.
        """
        return self.score_type.is_retrieval() or self.categories.get("operations", '')=='select'

    def is_database(self) -> bool:
        """Return if this node is a database node.

        Returns:
            bool: True if the finding is associated with database. False otherwise.
        """
        return self.score_type.is_database()

    def is_deletion(self) -> bool:
        return self.score_type.is_deletion()

    def is_source(self) -> bool:
        """Return if this score is a source (supplies data).

        Returns:
            bool: True if the finding is a data source. False otherwise.
        """
        return self.is_retrieval() or self.is_input()
    
    def is_input(self) -> bool:
        """Return if this score is a user input node.

        Returns:
            bool: True if the finding is a user input. False otherwise.
        """
        return self.score_type == ScoreType.INPUT

    def is_sink(self) -> bool:
        """Return if this score is a sink (saves data).

        Returns:
            bool: True if the finding is a data sink. False otherwise.
        """
        return self.is_storage()
        
    def is_personal(self) -> bool:
        """
        Returns
            bool: True if one or more data types belong to a personal data category. False otherwise.
        """
        for i in PERSONAL_DATA_TYPES:
            containsAll = True
            for j in i:
                if j not in self.types:
                    containsAll = False
                    break
            if containsAll:
                return True
        return False
    
    def get_data_type(self) -> str:
        if not self.types:
            return ""
        return min(self.types, key=len)

    def get_data_types(self) -> Set[str]:
        return set(self.types)

    def get_data_types_personal(self) -> Set[str]:
        """
        Returns
            list(str): returns a list of personal data types
        """
        personal_data_types = set()
        for i in PERSONAL_DATA_TYPES:
            for j in i:
                if j in self.types:
                    personal_data_types.add(j)
        return list(personal_data_types)

    def store_data_type_info(self, data_type: Union[Iterable[str], str]):
        """Add data type information to the score.

        Args:
            data_type (Union[Iterable[str], str]): Data type to mark this score with.
        """
        if not data_type:
            return
        elif isinstance(data_type, str):
            self.types.add(data_type.lower().strip("[]"))
        else:
            self.types.update([s.lower().strip("[]") for s in data_type])

    def matches_data_type(self, data_type: Union[Iterable[str], str]) -> bool:
        """Test if this score matches any of the data types passed.

        Args:
            data_type (Union[Iterable[str], str]): Data type(s) to test.

        Returns:
            bool: True if the type is returned or modified by this node, false otherwise.
        """
        if isinstance(data_type, str):
            return data_type.lower() in self.types
        else:
            return len(self.get_data_types().intersection([s.lower() for s in data_type])) > 0

    def long_description(self) -> str:
        """Provide a more detailed string containing the score and all categories the score is based on.

        Returns:
            string: A string containing detailed information about the score.
        """
        return f"Score[{self.value * 100:.1f}%, {self.categories}]"

    @staticmethod
    def transit_score(
        is_local: bool,
        uses_ssh: bool,
        supports_ssl_tls: bool,
        is_configured: bool,
        is_configured_elsewhere: bool,
        is_maintained: bool,
    ):
        """Score a usage of some function that involved the transmission of personally identifying information across the Internet.

        Args:
            is_local (bool): Is the data being transmitted to a local sink, like localhost?
            uses_ssh (bool): Is SSH configured for all connections?
            supports_ssl_tls (bool): Does the function support SSL/TLS to be configured and used?
            is_configured (bool): Is SSL/TLS configured to be enabled?
            is_configured_elsewhere (bool): Is SSL/TLS configured in an external file unavailable to the project?
            is_maintained (bool): Is the function maintained?

        Returns:
            Score: A new score with generated categories and a numerical score.
        """
        categories = {
            "is_local": is_local,
            "uses_ssh": uses_ssh,
            "supports_ssl_tls": supports_ssl_tls,
            "is_configured": is_configured,
            "is_configured_elsewhere": is_configured_elsewhere,
            "is_maintained": is_maintained,
        }

        if is_maintained and (
            is_local
            or uses_ssh
            or (supports_ssl_tls and is_configured and not is_configured_elsewhere)
        ):
            score = 1.0
        else:
            score = 0.0

        scorer = Score(score, categories, score_type=ScoreType.TRANSIT)
        return scorer

    @staticmethod
    def store_score(
        from_security_func: bool,
        tde_col_encryption: bool,
        tde_col_configured: bool,
        tde_col_configured_elsewhere: bool,
        is_maintained: bool,
        saves_data: bool = False,
        encryption_method: Optional[str] = None,
    ):
        """Score a usage of some function that writes data onto a disk or some long-term storage medium.

        Args:
            from_security_func (bool): Is the data from some security function like `crypt(...)`?`
            tde_col_encryption (bool): Does the database support transparent data encryption or column encryption?
            tde_col_configured (bool): Is TDE/column encryption enabled?
            tde_col_configured_elsewhere (bool): Is TDE/column encryption enabled in a separate configuration file that
                is unavailable?
            is_maintained (bool): Is the interface or function for storing this data maintained?
            encryption_method (Optional[str], optional): If encryption has been used, the encryption or hash algorithm
                that backs it should be given as a parameter. Defaults to None.

        Returns:
            Score: Generated score based on the parameters.
        """
        categories = {
            "from_security_func": from_security_func,
            "tde_col_encryption": tde_col_encryption,
            "tde_col_configured": tde_col_configured,
            "tde_col_configured_elsewhere": tde_col_configured_elsewhere,
            "is_maintained": is_maintained,
            "saves_data": saves_data,
        }

        if is_maintained and (
            from_security_func
            or (tde_col_encryption and tde_col_configured and not tde_col_configured_elsewhere)
        ):
            score = 1.0
        else:
            score = 0.0

        scorer = Score(
            score,
            categories,
            encryption_method=encryption_method,
            score_type=ScoreType.STORAGE,
        )
        return scorer

    @staticmethod
    def encrypt_score(
        is_state_of_the_art: bool,
        is_maintained: bool,
        encryption_method: Optional[str] = None,
    ):
        """Make a Score for some encryption or hash function.

        Args:
            is_state_of_the_art (bool): Is the encryption or hash function state-of-the-art and has no known
                vulnerabilities? Is it backed by governmental standards?
            is_maintained (bool): Is the algorithm maintained?
            encryption_method (Optional[str], optional): The specific algorithm used should be passed if known. Defaults
                to None.

        Returns:
            Score: Generated score for the encryption usage.
        """
        categories = {
            "is_state_of_the_art": is_state_of_the_art,
            "is_maintained": is_maintained,
        }
        score: float = 1.0 if is_state_of_the_art and is_maintained else 0.0
        scorer = Score(score, categories, encryption_method, score_type=ScoreType.CRYPTOGRAPHY)
        return scorer
    # @staticmethod
    # def database_create_score(
    #     tableName,
    #     fieldNames
    # ):
    #     personalData = PersonalDataMatcher.determine_categories_from_list(fieldNames)
    #     categories = {
    #         'table_name':tableName,
    #         'operations':'create',
    #         'fields':fieldNames,
    #         'data_types':set(personalData)
    #     }
    #     score = 1.0
    #     scorer = Score(
    #         score,
    #         categories,
    #         "",
    #         score_type=ScoreType.DATABASE,
    #     )
    #     return scorer
    @staticmethod
    def database_op_score(
        operation:str,
        tableName:str,
        fieldNames:List[str]
    ):
        personalData = set()
        for f in fieldNames:
            personalData.update(set(PersonalDataMatcher.determine_category(f)))
        categories = {
            'table_name':tableName,
            'operations':operation,
            'fields':fieldNames,
            'data_types':personalData
        }
        score = 1.0
        scorer = Score(
            score,
            categories,
            "",
            score_type=ScoreType.DATABASE,
        )
        return scorer
    @staticmethod
    def database_score(
        storage_score,
        transit_score,
    ):
        """Generate a Score for the usage of a database. This is composed of both a storage Score and a transit Score.

        Args:
            storage_score (Score): A score outputted from Score.storage_score().
            transit_score (Score): A score outputted from Score.transit_score().

        Returns:
            Score: The two scores are merged and returned.
        """
        categories = {}
        for k, v in storage_score.categories.items():
            categories[f"storage_{k}"] = v
        for k, v in transit_score.categories.items():
            categories[f"transit_{k}"] = v
        score = (storage_score.value + transit_score.value) / 2.0
        scorer = Score(
            score,
            categories,
            storage_score.encryption_method,
            score_type=ScoreType.DATABASE,
        )
        scorer.types = DATA_TYPE_DATABASE
        return scorer

    @staticmethod
    def api_score(uses_https: bool, url: List[str]):
        #if any of the possible links is third party, we label the api call as third party
        is_third_party = False
        is_url_unknown = True
        for i in url:
            #print(i)
            if isUrlValid(i):
                is_url_unknown = False
            if isURLThirdParty(i):
                is_third_party = True
                break
        categories = {"uses_https": uses_https, "url": url,"is_third_party":is_third_party,"is_url_unknown":is_url_unknown}
        score: float = 1.0 if uses_https else 0.0
        scorer = Score(score, categories, "https" if uses_https else "", score_type=ScoreType.API)
        scorer.store_data_type_info(DATA_TYPE_REMOTE)
        return scorer
    
    @staticmethod
    def variable_score(varName):
        """Generates a Score for a personal data variable.
        """
        categories = {
            "var": varName,
            "data_types":set(PersonalDataMatcher.determine_category(varName))
        }
        score = 1.0
        scorer = Score(
            score,
            categories,
            "",
            ScoreType.VARIABLE
        )
        return scorer
    @staticmethod
    def user_input_score(personal_types, input_name,input_type,input_value,input_form_id):
        """Generates a Score for an HTML form input with personal data.
        """

        categories = {
            "input_name":input_name,
            "input_type":input_type,
            "value":input_value,
            "form_id":input_form_id,
            "data_types":set(personal_types)
        }
        score = 1.0
        scorer = Score(
            score,
            categories,
            "",
            ScoreType.INPUT
        )
        return scorer
    @staticmethod
    def wp_user_score(code):
        """Generates a Score for creation of a WP_User object.
        """

        categories = {
            "code": code,
            "wordpress": True,
            "data_types":set(DATA_TYPE_USER)
        }
        score = 1.0
        scorer = Score(
            score,
            categories,
            "",
            ScoreType.WP_USER
        )
        return scorer
    @staticmethod
    def error_score():
        """This Score is used when there is some error reading the AST, or some function that is scanned for is
        improperly used (missing arguments, etc.).

        Returns:
            Score: A simple score reflecting that an error occurred.
        """
        categories = {"error": True}
        scorer = Score(0.0, categories)
        return scorer


# Below, static scores are defined for databases


def mysqli_database_score(
    configured: bool,
    from_security_func: bool = False,
    local: bool = False,
    uses_ssh: bool = False,
) -> Score:
    return Score.database_score(
        Score.store_score(
            from_security_func=from_security_func,  # TODO: Assign this intelligently
            tde_col_encryption=True,
            tde_col_configured=False,
            tde_col_configured_elsewhere=True,
            is_maintained=False,
            encryption_method=None,
        ),
        Score.transit_score(
            is_local=local,
            uses_ssh=uses_ssh,  # TODO: Test for this
            supports_ssl_tls=True,
            is_configured=configured,
            is_configured_elsewhere=False,
            is_maintained=True,
        ),
    )


def mysql_database_score(
    configured: bool,
    from_security_func: bool = False,
    local: bool = False,
    uses_ssh: bool = False,
) -> Score:
    return Score.database_score(
        Score.store_score(
            from_security_func=from_security_func,  # TODO: Assign this intelligently
            tde_col_encryption=True,
            tde_col_configured=False,
            tde_col_configured_elsewhere=True,
            is_maintained=False,
            encryption_method=None,
        ),
        Score.transit_score(
            is_local=local,
            uses_ssh=uses_ssh,  # TODO: Test for this
            supports_ssl_tls=True,
            is_configured=configured,
            is_configured_elsewhere=False,
            is_maintained=False,
        ),
    )


# | PDO_CUBRID   | Cubrid (no SSL?)                                                   |
# | PDO_DBLIB    | FreeTDS / Microsoft SQL Server / Sybase (no SSL?)                  |
# | PDO_FIREBIRD | Firebird (no SSL?)                                                 |
# | PDO_IBM      | IBM DB2 (SSL, but configured in separate file)                     |
# | PDO_INFORMIX | IBM Informix Dynamic Server (SSL, but configured in separate file) |
# | PDO_MYSQL    | MySQL 3.x/4.x/5.x (configured in PHP)                              |
# | PDO_OCI      | Oracle Call Interface (separate config file)                       |
# | PDO_ODBC     | ODBC v3 (IBM DB2, unixODBC and win32 ODBC)(separate config file)   |
# | PDO_PGSQL    | PostgreSQL (separate config file)                                  |
# | PDO_SQLITE   | SQLite 3 and SQLite 2 (separate config file)                       |
# | PDO_SQLSRV   | Microsoft SQL Server / SQL Azure (separate config file)            |
# | PDO_4D       | 4D (SSL supported)                                                 |


def pdo_cubrid_database_score(
    from_security_func: bool = False, is_local: bool = False, uses_ssh: bool = False
) -> Score:
    return Score.database_score(
        Score.store_score(
            from_security_func=from_security_func,  # TODO: Assign this intelligently
            tde_col_encryption=False,
            tde_col_configured=False,
            tde_col_configured_elsewhere=True,
            is_maintained=True,
            encryption_method=None,
        ),
        Score.transit_score(
            is_local=is_local,
            uses_ssh=uses_ssh,  # TODO: Test for this
            supports_ssl_tls=False,
            is_configured=False,
            is_configured_elsewhere=False,
            is_maintained=True,
        ),
    )


def pdo_dblib_database_score(
    from_security_func: bool = False, is_local: bool = False, uses_ssh: bool = False
) -> Score:
    return Score.database_score(
        Score.store_score(
            from_security_func=from_security_func,  # TODO: Assign this intelligently
            tde_col_encryption=True,
            tde_col_configured=False,
            tde_col_configured_elsewhere=True,
            is_maintained=True,
            encryption_method=None,
        ),
        Score.transit_score(
            is_local=is_local,
            uses_ssh=uses_ssh,  # TODO: Test for this.
            supports_ssl_tls=False,
            is_configured=False,  # TODO: Test for this.
            is_configured_elsewhere=False,
            is_maintained=True,
        ),
    )


def pdo_firebird_database_score(
    from_security_func: bool = False, is_local: bool = False, uses_ssh: bool = False
) -> Score:
    return Score.database_score(
        Score.store_score(
            from_security_func=from_security_func,  # TODO: Assign this intelligently
            tde_col_encryption=True,  # Supported with extension.
            tde_col_configured=False,
            tde_col_configured_elsewhere=True,
            is_maintained=True,
            encryption_method=None,
        ),
        Score.transit_score(
            is_local=is_local,
            uses_ssh=uses_ssh,  # TODO: Test for this.
            supports_ssl_tls=False,
            is_configured=False,  # TODO: Test for this.
            is_configured_elsewhere=False,
            is_maintained=True,
        ),
    )


def pdo_unsupported_database_score(
    from_security_func: bool = False, is_local: bool = False, uses_ssh: bool = False
) -> Score:
    return Score.database_score(
        Score.store_score(
            from_security_func=from_security_func,  # TODO: Assign this intelligently
            tde_col_encryption=True,
            tde_col_configured=False,
            tde_col_configured_elsewhere=True,
            is_maintained=True,
            encryption_method=None,
        ),
        Score.transit_score(
            is_local=is_local,
            uses_ssh=uses_ssh,  # TODO: Test for this.
            supports_ssl_tls=True,
            is_configured=False,  # TODO: Test for this.
            is_configured_elsewhere=True,
            is_maintained=True,
        ),
    )


def pdo_mysql_database_score(
    configured: bool,
    from_security_func: bool = False,
    is_local: bool = False,
    uses_ssh: bool = False,
) -> Score:
    return Score.database_score(
        Score.store_score(
            from_security_func=from_security_func,  # TODO: Assign this intelligently
            tde_col_encryption=True,
            tde_col_configured=False,
            tde_col_configured_elsewhere=True,
            is_maintained=True,
            encryption_method=None,
        ),
        Score.transit_score(
            is_local=is_local,
            uses_ssh=uses_ssh,  # TODO: Test for this.
            supports_ssl_tls=True,
            is_configured=configured,
            is_configured_elsewhere=False,
            is_maintained=True,
        ),
    )


def pdo_pgsql_database_score(
    configured: bool,
    from_security_func: bool = False,
    is_local: bool = False,
    uses_ssh: bool = False,
) -> Score:
    return Score.database_score(
        Score.store_score(
            from_security_func=from_security_func,  # TODO: Assign this intelligently
            tde_col_encryption=True,
            tde_col_configured=False,
            tde_col_configured_elsewhere=True,
            is_maintained=True,
            encryption_method=None,
        ),
        Score.transit_score(
            is_local=is_local,
            uses_ssh=uses_ssh,  # TODO: Test for this.
            supports_ssl_tls=True,
            is_configured=configured,
            is_configured_elsewhere=False,
            is_maintained=True,
        ),
    )


def pdo_4d_database_score(
    configured: bool,
    from_security_func: bool = False,
    is_local: bool = False,
    uses_ssh: bool = False,
) -> Score:
    return Score.database_score(
        Score.store_score(
            from_security_func=from_security_func,  # TODO: Assign this intelligently
            tde_col_encryption=True,
            tde_col_configured=False,
            tde_col_configured_elsewhere=True,
            is_maintained=True,
            encryption_method=None,
        ),
        Score.transit_score(
            is_local=is_local,
            uses_ssh=uses_ssh,  # TODO: Test for this.
            supports_ssl_tls=True,
            is_configured=configured,
            is_configured_elsewhere=False,
            is_maintained=True,
        ),
    )


def dbplus_database_score(
    from_security_func: bool = False, is_local: bool = False, uses_ssh: bool = False
) -> Score:
    return Score.database_score(
        Score.store_score(
            from_security_func=from_security_func,  # TODO: Assign this intelligently
            tde_col_encryption=True,
            tde_col_configured=False,
            tde_col_configured_elsewhere=True,
            is_maintained=True,
            encryption_method=None,
        ),
        Score.transit_score(
            is_local=is_local,
            uses_ssh=uses_ssh,  # TODO: Test for this.
            supports_ssl_tls=False,
            is_configured=False,
            is_configured_elsewhere=False,
            is_maintained=False,
        ),
    )


def dbase_database_score(
    from_security_func: bool = False, is_local: bool = False, uses_ssh: bool = False
) -> Score:
    return Score.database_score(
        Score.store_score(
            from_security_func=from_security_func,  # TODO: Assign this intelligently
            tde_col_encryption=True,
            tde_col_configured=False,
            tde_col_configured_elsewhere=True,
            is_maintained=True,
            encryption_method=None,
        ),
        Score.transit_score(
            is_local=is_local,
            uses_ssh=uses_ssh,  # TODO: Test for this.
            supports_ssl_tls=False,
            is_configured=False,
            is_configured_elsewhere=False,
            is_maintained=True,
        ),
    )


def filepro_database_score(
    from_security_func: bool = False, is_local: bool = False, uses_ssh: bool = False
) -> Score:
    return Score.database_score(
        Score.store_score(
            from_security_func=from_security_func,  # TODO: Assign this intelligently
            tde_col_encryption=True,
            tde_col_configured=False,
            tde_col_configured_elsewhere=True,
            is_maintained=True,
            encryption_method=None,
        ),
        Score.transit_score(
            is_local=is_local,
            uses_ssh=uses_ssh,  # TODO: Test for this.
            supports_ssl_tls=False,
            is_configured=False,
            is_configured_elsewhere=False,
            is_maintained=False,
        ),
    )


def firebird_database_score(
    from_security_func: bool = False, is_local: bool = False, uses_ssh: bool = False
) -> Score:
    return Score.database_score(
        Score.store_score(
            from_security_func=from_security_func,  # TODO: Assign this intelligently
            tde_col_encryption=True,
            tde_col_configured=True,
            tde_col_configured_elsewhere=True,
            is_maintained=True,
            encryption_method=None,
        ),
        Score.transit_score(
            is_local=is_local,
            uses_ssh=uses_ssh,  # TODO: Test for this.
            supports_ssl_tls=True,
            is_configured=True,
            is_configured_elsewhere=True,
            is_maintained=True,
        ),
    )


def frontbase_database_score(
    from_security_func: bool = False, is_local: bool = False, uses_ssh: bool = False
) -> Score:
    return Score.database_score(
        Score.store_score(
            from_security_func=from_security_func,  # TODO: Assign this intelligently
            tde_col_encryption=False,
            tde_col_configured=False,
            tde_col_configured_elsewhere=False,
            is_maintained=True,
            encryption_method=None,
        ),
        Score.transit_score(
            is_local=is_local,
            uses_ssh=uses_ssh,  # TODO: Test for this.
            supports_ssl_tls=False,
            is_configured=False,
            is_configured_elsewhere=False,
            is_maintained=True,
        ),
    )


def ibm_db2_database_score(
    configured: bool,
    from_security_func: bool = False,
    is_local: bool = False,
    uses_ssh: bool = False,
) -> Score:
    return Score.database_score(
        Score.store_score(
            from_security_func=from_security_func,  # TODO: Assign this intelligently
            tde_col_encryption=True,
            tde_col_configured=False,
            tde_col_configured_elsewhere=True,
            is_maintained=True,
            encryption_method=None,
        ),
        Score.transit_score(
            is_local=is_local,
            uses_ssh=uses_ssh,  # TODO: Test for this.
            supports_ssl_tls=True,
            is_configured=configured,
            is_configured_elsewhere=False,
            is_maintained=True,
        ),
    )


def informix_database_score(
    from_security_func: bool = False, is_local: bool = False, uses_ssh: bool = False
) -> Score:
    return Score.database_score(
        Score.store_score(
            from_security_func=from_security_func,  # TODO: Assign this intelligently
            tde_col_encryption=True,
            tde_col_configured=False,
            tde_col_configured_elsewhere=True,
            is_maintained=True,
            encryption_method=None,
        ),
        Score.transit_score(
            is_local=is_local,
            uses_ssh=uses_ssh,  # TODO: Test for this.
            supports_ssl_tls=True,
            is_configured=False,
            is_configured_elsewhere=True,
            is_maintained=True,
        ),
    )


def ingres_database_score(
    from_security_func: bool = False, is_local: bool = False, uses_ssh: bool = False
) -> Score:
    return Score.database_score(
        Score.store_score(
            from_security_func=from_security_func,  # TODO: Assign this intelligently
            tde_col_encryption=True,
            tde_col_configured=False,
            tde_col_configured_elsewhere=True,
            is_maintained=True,
            encryption_method=None,
        ),
        Score.transit_score(
            is_local=is_local,
            uses_ssh=uses_ssh,  # TODO: Test for this.
            supports_ssl_tls=True,
            is_configured=False,
            is_configured_elsewhere=True,
            is_maintained=True,
        ),
    )


def maxdb_database_score(
    configured: bool,
    from_security_func: bool = False,
    is_local: bool = False,
    uses_ssh: bool = False,
) -> Score:
    return Score.database_score(
        Score.store_score(
            from_security_func=from_security_func,  # TODO: Assign this intelligently
            tde_col_encryption=True,
            tde_col_configured=False,
            tde_col_configured_elsewhere=True,
            is_maintained=True,
            encryption_method=None,
        ),
        Score.transit_score(
            is_local=is_local,
            uses_ssh=uses_ssh,  # TODO: Test for this.
            supports_ssl_tls=True,
            is_configured=configured,
            is_configured_elsewhere=False,
            is_maintained=True,
        ),
    )


def mongo_database_score(
    configured: bool,
    from_security_func: bool = False,
    is_local: bool = False,
    uses_ssh: bool = False,
) -> Score:
    return Score.database_score(
        Score.store_score(
            from_security_func=from_security_func,  # TODO: Assign this intelligently
            tde_col_encryption=True,
            tde_col_configured=False,
            tde_col_configured_elsewhere=True,
            is_maintained=False,
            encryption_method=None,
        ),
        Score.transit_score(
            is_local=is_local,
            uses_ssh=uses_ssh,  # TODO: Test for this.
            supports_ssl_tls=True,
            is_configured=configured,
            is_configured_elsewhere=False,
            is_maintained=False,
        ),
    )


def mongodb_database_score(
    uses_ssl: bool,
    uses_autoencryption: bool,
    from_security_func: bool = False,
    is_local: bool = False,
    uses_ssh: bool = False,
) -> Score:
    return Score.database_score(
        Score.store_score(
            from_security_func=from_security_func,  # TODO: Assign this intelligently
            tde_col_encryption=True,
            tde_col_configured=uses_autoencryption,
            tde_col_configured_elsewhere=False,
            is_maintained=True,
            encryption_method=None,
        ),
        Score.transit_score(
            is_local=is_local,
            uses_ssh=uses_ssh,  # TODO: Test for this.
            supports_ssl_tls=True,
            is_configured=uses_ssl,
            is_configured_elsewhere=False,
            is_maintained=True,
        ),
    )


def msql_database_score(
    from_security_func: bool = False, is_local: bool = False, uses_ssh: bool = False
) -> Score:
    return Score.database_score(
        Score.store_score(
            from_security_func=from_security_func,  # TODO: Assign this intelligently
            tde_col_encryption=False,
            tde_col_configured=False,
            tde_col_configured_elsewhere=False,
            is_maintained=True,
            encryption_method=None,
        ),
        Score.transit_score(
            is_local=is_local,
            uses_ssh=uses_ssh,  # TODO: Test for this.
            supports_ssl_tls=False,
            is_configured=False,
            is_configured_elsewhere=False,
            is_maintained=True,
        ),
    )


def oci8_database_score(
    from_security_func: bool = False, is_local: bool = False, uses_ssh: bool = False
) -> Score:
    return Score.database_score(
        Score.store_score(
            from_security_func=from_security_func,  # TODO: Assign this intelligently
            tde_col_encryption=True,
            tde_col_configured=False,
            tde_col_configured_elsewhere=True,
            is_maintained=True,
            encryption_method=None,
        ),
        Score.transit_score(
            is_local=is_local,
            uses_ssh=uses_ssh,  # TODO: Test for this.
            supports_ssl_tls=True,
            is_configured=False,
            is_configured_elsewhere=True,
            is_maintained=True,
        ),
    )


def paradox_database_score(
    from_security_func: bool = False, is_local: bool = False, uses_ssh: bool = False
) -> Score:
    return Score.database_score(
        Score.store_score(
            from_security_func=from_security_func,  # TODO: Assign this intelligently
            tde_col_encryption=True,
            tde_col_configured=False,
            tde_col_configured_elsewhere=True,
            is_maintained=True,
            encryption_method=None,
        ),
        Score.transit_score(
            is_local=True,
            uses_ssh=uses_ssh,  # TODO: Test for this.
            supports_ssl_tls=False,
            is_configured=False,
            is_configured_elsewhere=False,
            is_maintained=True,
        ),
    )


def postgresql_database_score(
    configured: bool,
    from_security_func: bool = False,
    is_local: bool = False,
    uses_ssh: bool = False,
) -> Score:
    return Score.database_score(
        Score.store_score(
            from_security_func=from_security_func,  # TODO: Assign this intelligently
            tde_col_encryption=True,
            tde_col_configured=False,
            tde_col_configured_elsewhere=True,
            is_maintained=True,
            encryption_method=None,
        ),
        Score.transit_score(
            is_local=is_local,
            uses_ssh=uses_ssh,  # TODO: Test for this.
            supports_ssl_tls=True,
            is_configured=configured,
            is_configured_elsewhere=False,
            is_maintained=True,
        ),
    )


def sqlite_database_score(
    from_security_func: bool = False, is_local: bool = False, uses_ssh: bool = False
) -> Score:
    return Score.database_score(
        Score.store_score(
            from_security_func=from_security_func,  # TODO: Assign this intelligently
            tde_col_encryption=True,
            tde_col_configured=False,
            tde_col_configured_elsewhere=True,
            is_maintained=False,
            encryption_method=None,
        ),
        Score.transit_score(
            is_local=True,
            uses_ssh=uses_ssh,  # TODO: Test for this.
            supports_ssl_tls=False,
            is_configured=False,
            is_configured_elsewhere=False,
            is_maintained=False,
        ),
    )


def sqlite3_database_score(
    configured: bool,
    from_security_func: bool = False,
    is_local: bool = False,
    uses_ssh: bool = False,
) -> Score:
    return Score.database_score(
        Score.store_score(
            from_security_func=from_security_func,  # TODO: Assign this intelligently
            tde_col_encryption=True,
            tde_col_configured=configured,
            tde_col_configured_elsewhere=False,
            is_maintained=True,
            encryption_method=None,
        ),
        Score.transit_score(
            is_local=True,
            uses_ssh=uses_ssh,  # TODO: Test for this.
            supports_ssl_tls=False,
            is_configured=False,
            is_configured_elsewhere=False,
            is_maintained=True,
        ),
    )


def sql_server_database_score(
    uses_ssl: bool,
    uses_col_enc: bool,
    from_security_func: bool = False,
    is_local: bool = False,
    uses_ssh: bool = False,
) -> Score:
    return Score.database_score(
        Score.store_score(
            from_security_func=from_security_func,  # TODO: Assign this intelligently
            tde_col_encryption=True,
            tde_col_configured=uses_col_enc,
            tde_col_configured_elsewhere=False,
            is_maintained=True,
            encryption_method=None,
        ),
        Score.transit_score(
            is_local=is_local,
            uses_ssh=uses_ssh,  # TODO: Test for this.
            supports_ssl_tls=True,
            is_configured=uses_ssl,
            is_configured_elsewhere=False,
            is_maintained=True,
        ),
    )


def sybase_database_score(
    from_security_func: bool = False, is_local: bool = False, uses_ssh: bool = False
) -> Score:
    return Score.database_score(
        Score.store_score(
            from_security_func=from_security_func,  # TODO: Assign this intelligently
            tde_col_encryption=False,
            tde_col_configured=False,
            tde_col_configured_elsewhere=False,
            is_maintained=False,
            encryption_method=None,
        ),
        Score.transit_score(
            is_local=is_local,
            uses_ssh=uses_ssh,  # TODO: Test for this.
            supports_ssl_tls=False,
            is_configured=False,
            is_configured_elsewhere=False,
            is_maintained=False,
        ),
    )


def tokyotyrant_database_score(
    from_security_func: bool = False, is_local: bool = False, uses_ssh: bool = False
) -> Score:
    return Score.database_score(
        Score.store_score(
            from_security_func=from_security_func,  # TODO: Assign this intelligently
            tde_col_encryption=False,
            tde_col_configured=False,
            tde_col_configured_elsewhere=False,
            is_maintained=False,
            encryption_method=None,
        ),
        Score.transit_score(
            is_local=is_local,
            uses_ssh=uses_ssh,  # TODO: Test for this.
            supports_ssl_tls=False,
            is_configured=False,
            is_configured_elsewhere=False,
            is_maintained=False,
        ),
    )
