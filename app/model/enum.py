from enum import Enum
from sqlalchemy.types import SchemaType, TypeDecorator
from sqlalchemy.types import Enum as SQLAlchemyEnum


class EnumType(SchemaType, TypeDecorator):
    def __init__(self, enum, name):
        self.enum = enum
        self.name = name
        members = (member._value_ for member in enum)
        kwargs = {'name': name}
        self.impl = SQLAlchemyEnum(*members, **kwargs)

    def _set_table(self, table, column):
        self.impl._set_table(table, column)

    def copy(self):
        return EnumType(self.enum, self.name)

    def process_bind_param(self, enum_instance, dialect):
        if enum_instance is None:
            return None
        return enum_instance._value_

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return self.enum.fromstring(value)


class DatabaseEnum(Enum):
    def __init__(self, db_repr, label=None):
        self._value_ = db_repr
        self.label = label if label else self.name

    def __lt__(self, other):
        return self._value_ < other._value_

    def __str__(self):
        return self.label

    def __eq__(self, other):
        if not other:
            return False
        if type(other) is str:
            return self.label == other
        return self.name == other.name

    @classmethod
    def as_type(cls, name=None):
        if not name:
            name = "check_{}".format(cls.__name__.lower())
        return EnumType(cls, name)

    @classmethod
    def get_description_mapping(cls):
        return dict((member.name, member.label) for member in cls)

    @classmethod
    def fromstring(cls, name):
        if name is None:
            return None
        return getattr(cls, name, None)


class OrderedDatabaseEnum(DatabaseEnum):
    def __init__(self, label, order):
        super().__init__(db_repr=self.name, label=label)
        self.order = order

    def __lt__(self, other):
        return self.order < other.order


class Status(OrderedDatabaseEnum):
    unknown = 'Unknown', 2
    vulnerable = 'Vulnerable', 1
    testing = 'Testing', 3
    fixed = 'Fixed', 4
    not_affected = 'Not affected', 4

    def open(self):
        return self in (Status.unknown, Status.vulnerable, Status.testing)

    def resolved(self):
        return not self.open()


class Severity(OrderedDatabaseEnum):
    unknown = 'Unknown', 1
    critical = 'Critical', 1
    high = 'High', 2
    medium = 'Medium', 3
    low = 'Low', 4


class Remote(OrderedDatabaseEnum):
    unknown = 'Unknown', 3
    remote = 'Remote', 1
    local = 'Local', 2


class Affected(OrderedDatabaseEnum):
    unknown = 'Unknown', 2
    affected = 'Affected', 1
    not_affected = 'Not Affected', 3
