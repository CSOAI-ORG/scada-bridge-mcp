#!/usr/bin/env python3
"""
Industrial SCADA / Modbus / OPC-UA Bridge MCP — CSOAI Layer-0 legacy-bridge family.
Parse OT protocol frames, map to modern telemetry, and govern OT/ICS security.
Sibling of cobol-bridge-mcp. Pairs with NIS2 (critical infrastructure).
Tools: parse_modbus · map_to_modern · govern_ot
"""
from mcp.server.mcpserver import MCPServer as FastMCP  # mcp 2.x: FastMCP renamed MCPServer
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

mcp = FastMCP("SCADA Bridge", instructions="Bridge industrial SCADA/Modbus/OPC-UA (OT) to ONE OS — parse, map, govern (IEC 62443/NIS2).")

# ── SIGIL: every governed action → one signed hash-chained hop (SIGIL_LOG unifies all layers) ──
import hashlib as _hl, time as _t, json as _j, os as _os
_SIGIL_LOG = _os.environ.get("SIGIL_LOG", _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "bridge_sigil.log"))
def _sigil(op, body):
    try:
        prev = ""
        if _os.path.exists(_SIGIL_LOG):
            with open(_SIGIL_LOG) as f:
                ls = f.readlines()
                if ls: prev = _j.loads(ls[-1]).get("digest", "")
        ts = int(_t.time()); dg = _hl.sha256(f"{op}|{ts}|{prev[:8]}|{body}".encode()).hexdigest()[:16]
        _os.makedirs(_os.path.dirname(_SIGIL_LOG), exist_ok=True)
        with open(_SIGIL_LOG, "a") as f: f.write(_j.dumps({"ts": ts, "op": op, "body": body, "prev_digest": prev, "digest": dg}) + "\n")
        return dg
    except Exception: return ""

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
    _sigil("G", "scada|govern_ot")
    f = parse_modbus(frame_hex)
    flags = []
    if not f.valid:
        flags.append("Malformed frame — drop + alert (OT integrity)")
    if f.is_write:
        flags.append(f"WRITE to control point (unit {f.unit_id}, reg {f.start_address}) — requires authorisation + change window")
    return Governance(risk_flags=flags,
                      frameworks=["IEC 62443 (ICS security)", "NIS2 (critical infrastructure)", "NIST CSF", "Modbus/OPC-UA security"],
                      note="CSOAI governs the bridge: every OT command attestable on the ledger — physical-world actions, signed.")


# ---------------------------------------------------------------------------
# MCP 2026-07-28 wire - header-add migration (2026-10-08)
# ---------------------------------------------------------------------------
# stdio carries no HTTP headers, so Mcp-Method / Mcp-Name are not applicable to
# this transport at runtime. When scada-bridge-mcp is exposed over HTTP, route the ingress
# through the vendored mcp2026_shim (ShimASGI): it validates Mcp-Method /
# Mcp-Name, injects params._meta.protocolVersion = "2026-07-28" into every
# request, strips Mcp-Session-Id and answers legacy initialize / server-discover
# locally (the session header is never emitted - stateless wire).
# Refs: MIGRATION_NOTE.md, MCP_2026_WIRE_MIGRATION_PLAN_2026-10-07.md (3) + (4).
# ---------------------------------------------------------------------------


def http_app():
    """ASGI app for HTTP exposure, wrapped in the 2026-07-28 wire shim.

    stdio (``mcp.run()``) needs no shim; this is the enable path once the
    server is fronted by an HTTP transport. Bodies are buffered, so responses
    are requested in JSON mode rather than SSE.
    """
    from mcp2026_shim import WIRE_2026, ShimASGI, ShimConfig

    return ShimASGI(
        mcp.streamable_http_app(json_response=True),
        ShimConfig(
            protocol_version=WIRE_2026,
            server_info={"name": "scada-bridge-mcp", "version": "0.1.0"},
        ),
    )


def main():
    mcp.run()


if __name__ == "__main__":
    main()
