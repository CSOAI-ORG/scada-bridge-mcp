import sys,os
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import server

FRAME="0001 0000 0006 11 06 0001 0003"
def test_parse():
    f=server.parse_modbus(FRAME); assert f.valid; assert f.is_write
def test_govern():
    assert any("62443" in x for x in server.govern_ot(FRAME).frameworks)
def test_bad():
    assert server.parse_modbus("zz").valid is False
