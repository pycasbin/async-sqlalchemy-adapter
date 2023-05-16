import asyncio
import os
from casbin_async_sqlalchemy_adapter import Adapter
from casbin_async_sqlalchemy_adapter import Base
from casbin_async_sqlalchemy_adapter import CasbinRule
from casbin_async_sqlalchemy_adapter.adapter import Filter
from unittest import IsolatedAsyncioTestCase
from unittest import TestCase
from unittest import async_case
import casbin
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker
from concurrent.futures import ThreadPoolExecutor
from functools import partial

def get_fixture(path):
    dir_path = os.path.split(os.path.realpath(__file__))[0] + "/"
    return os.path.abspath(dir_path + path)


def get_enforcer():
    engine = create_engine("sqlite://")
    # engine = create_engine('sqlite:///' + os.path.split(os.path.realpath(__file__))[0] + '/test.db', echo=True)
    adapter = Adapter(engine)

    session = sessionmaker(bind=engine)
    Base.metadata.create_all(engine)
    s = session()
    s.query(CasbinRule).delete()
    s.add(CasbinRule(ptype="p", v0="alice", v1="data1", v2="read"))
    s.add(CasbinRule(ptype="p", v0="bob", v1="data2", v2="write"))
    s.add(CasbinRule(ptype="p", v0="data2_admin", v1="data2", v2="read"))
    s.add(CasbinRule(ptype="p", v0="data2_admin", v1="data2", v2="write"))
    s.add(CasbinRule(ptype="g", v0="alice", v1="data2_admin"))
    s.commit()
    s.close()

    return casbin.Enforcer(get_fixture("rbac_model.conf"), adapter)


class TestConfig(IsolatedAsyncioTestCase):
    def test_custom_db_class(self):
        class CustomRule(Base):
            __tablename__ = "casbin_rule2"

            id = Column(Integer, primary_key=True)
            ptype = Column(String(255))
            v0 = Column(String(255))
            v1 = Column(String(255))
            v2 = Column(String(255))
            v3 = Column(String(255))
            v4 = Column(String(255))
            v5 = Column(String(255))
            not_exist = Column(String(255))

        engine = create_engine("sqlite://")
        adapter = Adapter(engine, CustomRule)

        session = sessionmaker(bind=engine)
        Base.metadata.create_all(engine)
        s = session()
        s.add(CustomRule(not_exist="NotNone"))
        s.commit()
        self.assertEqual(s.query(CustomRule).all()[0].not_exist, "NotNone")

    async def test_enforcer_basic(self):
        e = get_enforcer()
        self.assertFalse(e.enforce("alice", "data4", "read"))
        model = e.get_model()
        model.clear_policy()
        model.add_policy("p", "p", ["alice", "data4", "read"])

        self.assertTrue(e.enforce("alice", "data4", "read"))



    async def test_add_policy(self):
        e = get_enforcer()

        self.assertFalse(e.enforce("eve", "data3", "read"))
        self.assertFalse(e.enforce("eve", "data4", "read"))

        model = e.get_model()
        model.clear_policy()
        model.add_policy("p", "p", ["eve", "data3", "read"])
        model.add_policy("p", "p", ["eve", "data4", "read"])

        self.assertTrue(e.enforce("eve", "data3", "read"))
        self.assertTrue(e.enforce("eve", "data4", "read"))

    async def test_add_policies(self):
        e = get_enforcer()

        self.assertFalse(e.enforce("eve", "data3", "read"))
        self.assertFalse(e.enforce("eve", "data4", "read"))
        model = e.get_model()
        model.clear_policy()
        model.add_policies("p", "p", [("eve", "data3", "read"), ("eve", "data4", "read")])

        self.assertTrue(e.enforce("eve", "data3", "read"))
        self.assertTrue(e.enforce("eve", "data4", "read"))


    async def test_save_policy(self):
        e = get_enforcer()
        self.assertFalse(e.enforce("alice", "data4", "read"))

        model = e.get_model()
        model.clear_policy()

        model.add_policy("p", "p", ["alice", "data4", "read"])

        adapter = e.get_adapter()
        adapter.save_policy(model)
        self.assertTrue(e.enforce("alice", "data4", "read"))

    async def test_remove_policy(self):
        e = get_enforcer()
        self.assertFalse(e.enforce("alice", "data4", "read"))

        model = e.get_model()
        model.clear_policy()
        model.add_policy("p", "p", ["alice", "data4", "read"])
        self.assertTrue(e.enforce("alice", "data4", "read"))
        model.remove_policy("p", "p", ["alice", "data4", "read"])
        self.assertFalse(e.enforce("alice", "data4", "read"))

    async def test_remove_policies(self):
        e = get_enforcer()

        self.assertFalse(e.enforce("eve", "data3", "read"))
        self.assertFalse(e.enforce("eve", "data4", "read"))
        model = e.get_model()
        model.clear_policy()
        model.add_policies("p", "p", [("eve", "data3", "read"), ("eve", "data4", "read")])

        self.assertTrue(e.enforce("eve", "data3", "read"))
        self.assertTrue(e.enforce("eve", "data4", "read"))
        model.remove_policies("p", "p", [("eve", "data3", "read"), ("eve", "data4", "read")])

        self.assertFalse(e.enforce("eve", "data3", "read"))
        self.assertFalse(e.enforce("eve", "data4", "read"))

    async def test_remove_filtered_policy(self):
        e = get_enforcer()

        self.assertFalse(e.enforce("eve", "data3", "read"))
        self.assertFalse(e.enforce("eve", "data4", "read"))
        self.assertFalse(e.enforce("alice", "data1", "read"))

        model = e.get_model()
        model.clear_policy()
        model.add_policies("p", "p", [("eve", "data3", "read"), ("eve", "data4", "read"), ("alice", "data1", "read")])

        self.assertTrue(e.enforce("eve", "data3", "read"))
        self.assertTrue(e.enforce("eve", "data4", "read"))
        self.assertTrue(e.enforce("alice", "data1", "read"))

        model.remove_filtered_policy("p", "p", 1, "data1")
        self.assertFalse(e.enforce("alice", "data1", "read"))

        model.remove_filtered_policy("p", "p", 2, "read")
        self.assertFalse(e.enforce("eve", "data3", "read"))
        self.assertFalse(e.enforce("eve", "data4", "read"))
        self.assertFalse(e.enforce("alice", "data1", "read"))

    async def test_str(self):
        rule = CasbinRule(ptype="p", v0="alice", v1="data1", v2="read")
        self.assertEqual(str(rule), "p, alice, data1, read")
        rule = CasbinRule(ptype="p", v0="bob", v1="data2", v2="write")
        self.assertEqual(str(rule), "p, bob, data2, write")
        rule = CasbinRule(ptype="p", v0="data2_admin", v1="data2", v2="read")
        self.assertEqual(str(rule), "p, data2_admin, data2, read")
        rule = CasbinRule(ptype="p", v0="data2_admin", v1="data2", v2="write")
        self.assertEqual(str(rule), "p, data2_admin, data2, write")
        rule = CasbinRule(ptype="g", v0="alice", v1="data2_admin")
        self.assertEqual(str(rule), "g, alice, data2_admin")

    async def test_repr(self):
        rule = CasbinRule(ptype="p", v0="alice", v1="data1", v2="read")
        self.assertEqual(repr(rule), '<CasbinRule None: "p, alice, data1, read">')
        engine = create_engine("sqlite://")

        session = sessionmaker(bind=engine)
        Base.metadata.create_all(engine)
        s = session()

        s.add(rule)
        s.commit()
        self.assertRegex(repr(rule), r'<CasbinRule \d+: "p, alice, data1, read">')
        s.close()

    async def test_filtered_policy(self):
        e = get_enforcer()

        model = e.get_model()
        model.clear_policy()
        model.add_policy("p", "p", ["alice", "data1", "read"])
        model.add_policy("p", "p", ["alice", "data3", "read"])
        model.add_policy("p", "p", ["alice", "data2", "write"])
        model.add_policy("p", "p", ["bob", "data2", "read"])
        model.add_policy("p", "p", ["bob", "data1", "write"])
        model.add_policy("p", "p", ["bob", "data3", "read"])

        print(model.get_filtered_policy("p", "p", 0, "alice"))
        print(model.get_filtered_policy("p", "p", 1, "data1"))
        print(model.get_filtered_policy("p", "p", 2, "read"))

    async def test_update_policy(self):
        e = get_enforcer()
        model = e.get_model()
        model.clear_policy()
        model.add_policy("p", "p", ["alice", "data1", "read"])
        model.add_policy("p", "p", ["alice", "data3", "read"])
        model.add_policy("p", "p", ["alice", "data2", "write"])

        model.update_policy("p", "p", ["alice", "data1", "read"], ["bob", "data2", "read"])
        model.update_policy("p", "p", ["alice", "data3", "read"], ["bob", "data1", "write"])
        model.update_policy("p", "p", ["alice", "data2", "write"], ["bob", "data3", "read"])

        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data3", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertTrue(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data1", "write"))
        self.assertTrue(e.enforce("bob", "data3", "read"))

    async def test_update_policies(self):
        e = get_enforcer()
        model = e.get_model()
        model.clear_policy()

        old_rule_0 = ["alice", "data1", "read"]
        old_rule_1 = ["bob", "data2", "write"]
        old_rule_2 = ["data2_admin", "data2", "read"]
        old_rule_3 = ["data2_admin", "data2", "write"]

        new_rule_0 = ["alice", "data_test", "read"]
        new_rule_1 = ["bob", "data_test", "write"]
        new_rule_2 = ["data2_admin", "data_test", "read"]
        new_rule_3 = ["data2_admin", "data_test", "write"]

        old_rules = [old_rule_0, old_rule_1, old_rule_2, old_rule_3]
        new_rules = [new_rule_0, new_rule_1, new_rule_2, new_rule_3]

        model.add_policies("p", "p", old_rules)
        model.update_policies("p", "p", old_rules, new_rules)

        await e.update_policies(old_rules, new_rules)

        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("alice", "data_test", "read"))

        self.assertFalse(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("bob", "data_test", "write"))

        self.assertFalse(e.enforce("data2_admin", "data2", "read"))
        self.assertTrue(e.enforce("data2_admin", "data_test", "read"))

        self.assertFalse(e.enforce("data2_admin", "data2", "write"))
        self.assertTrue(e.enforce("data2_admin", "data_test", "write"))
