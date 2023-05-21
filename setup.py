# Copyright 2023 The casbin Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from os import path

from setuptools import setup, find_packages

desc_file = "README.md"

with open(desc_file, "r") as fh:
    long_description = fh.read()

here = path.abspath(path.dirname(__file__))
# get the dependencies and installs
with open(path.join(here, "requirements.txt"), encoding="utf-8") as f:
    all_reqs = f.read().split("\n")

install_requires = [x.strip() for x in all_reqs if "git+" not in x]

setup(
    name="casbin_async_sqlalchemy_adapter",
    author="wrapping-2000",
    author_email="wenpengchen@njust.edu.cn",
    description="Asynchronous SQLAlchemy Adapter for PyCasbin",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/pycasbin/async-sqlalchemy-adapter",
    keywords=[
        "asynccasbin",
        "SQLAlchemy",
        "casbin-adapter",
        "rbac",
        "access control",
        "abac",
        "acl",
        "permission",
    ],
    packages=find_packages(),
    install_requires=install_requires,
    python_requires=">=3.7",
    license="Apache 2.0",
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    data_files=[desc_file],
)
