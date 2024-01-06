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
import warnings
from contextlib import asynccontextmanager
from typing import List

from casbin import persist
from casbin.persist.adapters.asyncio import AsyncAdapter
from sqlalchemy import Column, Integer, String, delete
from sqlalchemy import or_
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()


class CasbinRule(Base):
    __tablename__ = "casbin_rule"

    id = Column(Integer, primary_key=True)
    ptype = Column(String(255))
    v0 = Column(String(255))
    v1 = Column(String(255))
    v2 = Column(String(255))
    v3 = Column(String(255))
    v4 = Column(String(255))
    v5 = Column(String(255))

    def __str__(self):
        arr = [self.ptype]
        for v in (self.v0, self.v1, self.v2, self.v3, self.v4, self.v5):
            if v is None:
                break
            arr.append(v)
        return ", ".join(arr)

    def __repr__(self):
        return '<CasbinRule {}: "{}">'.format(self.id, str(self))


class Filter:
    ptype = []
    v0 = []
    v1 = []
    v2 = []
    v3 = []
    v4 = []
    v5 = []


class Adapter(AsyncAdapter):
    """the interface for Casbin adapters."""

    def __init__(self, engine, db_class=None, filtered=False, warning=True):
        if isinstance(engine, str):
            self._engine = create_async_engine(engine, future=True)
        else:
            self._engine = engine

        if db_class is None:
            db_class = CasbinRule
            if warning:
                warnings.warn(
                    "Using default CasbinRule table, please note the use of the 'Adapter().create_table()' method"
                    " to create the table, and ignore this warning if you are using a custom CasbinRule table.",
                    RuntimeWarning,
                )
        else:
            for attr in (
                "id",
                "ptype",
                "v0",
                "v1",
                "v2",
                "v3",
                "v4",
                "v5",
            ):  # id attr was used by filter
                if not hasattr(db_class, attr):
                    raise Exception(f"{attr} not found in custom DatabaseClass.")
            Base.metadata = db_class.metadata

        self._db_class = db_class
        self.session_local = sessionmaker(
            self._engine, expire_on_commit=False, class_=AsyncSession
        )

        self._filtered = filtered

    @asynccontextmanager
    async def _session_scope(self):
        """Provide an asynchronous transactional scope around a series of operations."""
        async with self.session_local() as session:
            try:
                yield session
                await session.commit()
            except Exception as e:
                await session.rollback()
                raise e

    async def create_table(self):
        """Creates default casbin rule table."""
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def load_policy(self, model):
        """loads all policy rules from the storage."""
        async with self._session_scope() as session:
            lines = await session.execute(select(self._db_class))
            for line in lines.scalars():
                persist.load_policy_line(str(line), model)

    def is_filtered(self):
        return self._filtered

    async def load_filtered_policy(self, model, filter) -> None:
        """loads all policy rules from the storage."""
        async with self._session_scope() as session:
            stmt = select(self._db_class)
            stmt = self.filter_query(stmt, filter)
            result = await session.execute(stmt)
            for line in result.scalars():
                persist.load_policy_line(str(line), model)
            self._filtered = True

    def filter_query(self, stmt, filter):
        for attr in ("ptype", "v0", "v1", "v2", "v3", "v4", "v5"):
            if len(getattr(filter, attr)) > 0:
                stmt = stmt.where(
                    getattr(self._db_class, attr).in_(getattr(filter, attr))
                )
        return stmt.order_by(self._db_class.id)

    async def _save_policy_line(self, ptype, rule):
        async with self._session_scope() as session:
            line = self._db_class(ptype=ptype)
            for i, v in enumerate(rule):
                setattr(line, "v{}".format(i), v)
            session.add(line)

    async def save_policy(self, model):
        """saves all policy rules to the storage."""
        async with self._session_scope() as session:
            stmt = delete(self._db_class)
            await session.execute(stmt)
            for sec in ["p", "g"]:
                if sec not in model.model.keys():
                    continue
                for ptype, ast in model.model[sec].items():
                    for rule in ast.policy:
                        await self._save_policy_line(ptype, rule)
        return True

    async def add_policy(self, sec, ptype, rule):
        """adds a policy rule to the storage."""
        await self._save_policy_line(ptype, rule)

    async def add_policies(self, sec, ptype, rules):
        """adds a policy rules to the storage."""
        for rule in rules:
            await self._save_policy_line(ptype, rule)

    async def remove_policy(self, sec, ptype, rule):
        """removes a policy rule from the storage."""
        async with self._session_scope() as session:
            stmt = delete(self._db_class).where(self._db_class.ptype == ptype)
            for i, v in enumerate(rule):
                stmt = stmt.where(getattr(self._db_class, "v{}".format(i)) == v)
            r = await session.execute(stmt)

        return True if r.rowcount > 0 else False

    async def remove_policies(self, sec, ptype, rules):
        """remove policy rules from the storage."""
        if not rules:
            return
        async with self._session_scope() as session:
            stmt = delete(self._db_class).where(self._db_class.ptype == ptype)
            rules = zip(*rules)
            for i, rule in enumerate(rules):
                stmt = stmt.where(
                    or_(getattr(self._db_class, "v{}".format(i)) == v for v in rule)
                )
            await session.execute(stmt)

    async def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        """removes policy rules that match the filter from the storage.
        This is part of the Auto-Save feature.
        """
        async with self._session_scope() as session:
            stmt = delete(self._db_class).where(self._db_class.ptype == ptype)

            if not (0 <= field_index <= 5):
                return False
            if not (1 <= field_index + len(field_values) <= 6):
                return False
            for i, v in enumerate(field_values):
                if v != "":
                    v_value = getattr(self._db_class, "v{}".format(field_index + i))
                    stmt = stmt.where(v_value == v)
            r = await session.execute(stmt)

        return True if r.rowcount > 0 else False

    async def update_policy(
        self, sec: str, ptype: str, old_rule: List[str], new_rule: List[str]
    ) -> None:
        """
        Update the old_rule with the new_rule in the database (storage).

        :param sec: section type
        :param ptype: policy type
        :param old_rule: the old rule that needs to be modified
        :param new_rule: the new rule to replace the old rule

        :return: None
        """

        async with self._session_scope() as session:
            stmt = select(self._db_class).where(self._db_class.ptype == ptype)

            # locate the old rule
            for index, value in enumerate(old_rule):
                v_value = getattr(self._db_class, "v{}".format(index))
                stmt = stmt.where(v_value == value)

            # need the length of the longest_rule to perform overwrite
            longest_rule = old_rule if len(old_rule) > len(new_rule) else new_rule
            result = await session.execute(stmt)
            old_rule_line = result.scalar_one()

            # overwrite the old rule with the new rule
            for index in range(len(longest_rule)):
                if index < len(new_rule):
                    setattr(old_rule_line, "v{}".format(index), new_rule[index])
                else:
                    setattr(old_rule_line, "v{}".format(index), None)

    async def update_policies(
        self,
        sec: str,
        ptype: str,
        old_rules: List[List[str]],
        new_rules: List[List[str]],
    ) -> None:
        """
        Update the old_rules with the new_rules in the database (storage).

        :param sec: section type
        :param ptype: policy type
        :param old_rules: the old rules that need to be modified
        :param new_rules: the new rules to replace the old rules

        :return: None
        """
        for i in range(len(old_rules)):
            await self.update_policy(sec, ptype, old_rules[i], new_rules[i])

    async def update_filtered_policies(
        self, sec, ptype, new_rules: List[List[str]], field_index, *field_values
    ) -> List[List[str]]:
        """update_filtered_policies updates all the policies on the basis of the filter."""

        filter = Filter()
        filter.ptype = ptype

        # Creating Filter from the field_index & field_values provided
        for i in range(len(field_values)):
            if field_index <= i and i < field_index + len(field_values):
                setattr(filter, f"v{i}", field_values[i - field_index])
            else:
                break

        return await self._update_filtered_policies(new_rules, filter)

    async def _update_filtered_policies(self, new_rules, filter) -> List[List[str]]:
        """_update_filtered_policies updates all the policies on the basis of the filter."""

        async with self._session_scope() as session:
            # Load old policies

            stmt = select(self._db_class).where(self._db_class.ptype == filter.ptype)
            filtered_stmt = self.filter_query(stmt, filter)
            result = await session.execute(filtered_stmt)
            old_rules = result.scalars().all()

            # Delete old policies

            await self.remove_policies("p", filter.ptype, old_rules)

            # Insert new policies

            await self.add_policies("p", filter.ptype, new_rules)

            # return deleted rules

            return old_rules
