#!/usr/bin/env python3
"""
Industrial SCADA / Modbus / OPC-UA Bridge MCP — CSOAI Layer-0 legacy-bridge family.
Parse OT protocol frames, map to modern telemetry, and govern OT/ICS security.
Sibling of cobol-bridge-mcp. Pairs with NIS2 (critical infrastructure).
Tools: parse_modbus · map_to_modern · govern_ot
"""
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

mcp = FastMCP("SCADA Bridge", instructions="Bridge industrial SCADA/Modbus/OPC-UA (OT) to ONE OS — parse, map, govern (IEC 62443/NIS2).")

MODBUS_FN = {
    1: "Read Coils", 2: "Read Discrete Inputs", 3: "Read Holding Registers",
    4: "Read Input Registers", 5: "Write Single Coil", 6: "Write Single Register",
    15: "Write Multiple Coils", 16: "Write Multiple Registers",
}


class ModbusFrame(BaseModel):
    valid: bool
    transaction_id: Optional[int] = None
    unit_id: Optional[int] = None
    function_code: Optional[int] = None
    function: Optional[str] = None
    start_address: Optional[int] = None
    quantity: Optional[int] = None
    is_write: bool = False
    error: Optional[str] = None


class Governance(BaseModel):
    risk_flags: List[str] = Field(default_factory=list)
    frameworks: List[str] = Field(default_factory=list)
    attestable: bool = True
    note: str = ""


def _hexbytes(h: str) -> bytes:
    h = h.replace(" ", "").replace("0x", "")
    return bytes.fromhex(h)


@mcp.tool()
def parse_modbus(frame_hex: str) -> ModbusFrame:
    """Parse a Modbus TCP frame (hex) → MBAP header + function code + address/quantity."""
    try:
        b = _hexbytes(frame_hex)
    except Exception as e:
        return ModbusFrame(valid=False, error=f"bad hex: {e}")
    if len(b) < 8:
        return ModbusFrame(valid=False, error="frame too short for Modbus TCP")
    tid = int.from_bytes(b[0:2], "big")
    unit = b[6]
    fc = b[7]
    start = int.from_bytes(b[8:10], "big") if len(b) >= 10 else None
    qty = int.from_bytes(b[10:12], "big") if len(b) >= 12 else None
    return ModbusFrame(valid=True, transaction_id=tid, unit_id=unit, function_code=fc,
                       function=MODBUS_FN.get(fc, f"fn{fc}"), start_address=start,
                       quantity=qty, is_write=fc in (5, 6, 15, 16))


@mcp.tool()
def map_to_modern(frame_hex: str) -> Dict[str, Any]:
    """Map a Modbus frame to a modern telemetry/command event for ONE OS."""
    f = parse_modbus(frame_hex)
    return {"source": "Modbus TCP", "device": f.unit_id, "action": f.function,
            "register": f.start_address, "count": f.quantity,
            "kind": "command" if f.is_write else "read", "valid": f.valid}


@mcp.tool()
def govern_ot(frame_hex: str) -> Governance:
    """Governance: OT/ICS security — flag writes to control points, surface IEC 62443 / NIS2 (attestable)."""
    f = parse_modbus(frame_hex)
    flags = []
    if not f.valid:
        flags.append("Malformed frame — drop + alert (OT integrity)")
    if f.is_write:
        flags.append(f"WRITE to control point (unit {f.unit_id}, reg {f.start_address}) — requires authorisation + change window")
    return Governance(risk_flags=flags,
                      frameworks=["IEC 62443 (ICS security)", "NIS2 (critical infrastructure)", "NIST CSF", "Modbus/OPC-UA security"],
                      note="CSOAI governs the bridge: every OT command attestable on the ledger — physical-world actions, signed.")


def main():
    mcp.run()


if __name__ == "__main__":
    main()
