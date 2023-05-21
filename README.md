async-sqlalchemy-adapter
====
Async SQLAlchemy Adapter for PyCasbin<br>
[![GitHub Actions](https://github.com/pycasbin/async-sqlalchemy-adapter/workflows/build/badge.svg?branch=master)](https://github.com/pycasbin/async-sqlalchemy-adapter/actions)
[![Coverage Status](https://coveralls.io/repos/github/pycasbin/async-sqlalchemy-adapter/badge.svg)](https://coveralls.io/github/pycasbin/async-sqlalchemy-adapter)
[![Version](https://img.shields.io/pypi/v/casbin_async_sqlalchemy_adapter.svg)](https://pypi.org/project/casbin_async_sqlalchemy_adapter/)
[![PyPI - Wheel](https://img.shields.io/pypi/wheel/casbin_async_sqlalchemy_adapter.svg)](https://pypi.org/project/casbin_async_sqlalchemy_adapter/)
[![Pyversions](https://img.shields.io/pypi/pyversions/casbin_async_sqlalchemy_adapter.svg)](https://pypi.org/project/casbin_async_sqlalchemy_adapter/)
[![Download](https://img.shields.io/pypi/dm/casbin_async_sqlalchemy_adapter.svg)](https://pypi.org/project/casbin_async_sqlalchemy_adapter/)
[![License](https://img.shields.io/pypi/l/casbin_async_sqlalchemy_adapter.svg)](https://pypi.org/project/casbin_async_sqlalchemy_adapter/)

Asynchronous SQLAlchemy Adapter is the [SQLAlchemy](https://www.sqlalchemy.org) adapter for [PyCasbin](https://github.com/casbin/pycasbin). With this library, Casbin can load policy from SQLAlchemy supported database or save policy to it.

Based on [Officially Supported Databases](http://www.sqlalchemy.org/), The current supported databases are:

- PostgreSQL
- MySQL
- MariaDB
- SQLite
- Oracle
- Microsoft SQL Server
- Firebird

## Installation

```
pip install casbin_async_sqlalchemy_adapter
```

## Simple Example

```python
import casbin_async_sqlalchemy_adapter
import casbin

adapter = casbin_async_sqlalchemy_adapter.Adapter('sqlite:///test.db')

e = casbin.Enforcer('path/to/model.conf', adapter)

sub = "alice"  # the user that wants to access a resource.
obj = "data1"  # the resource that is going to be accessed.
act = "read"  # the operation that the user performs on the resource.

if e.enforce(sub, obj, act):
    # permit alice to read data1
    pass
else:
    # deny the request, show an error
    pass
```


### Getting Help

- [PyCasbin](https://github.com/casbin/pycasbin)

### License

This project is licensed under the [Apache 2.0 license](LICENSE).
