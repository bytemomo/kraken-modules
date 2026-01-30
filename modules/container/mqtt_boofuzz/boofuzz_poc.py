import sys
import json
import io
import os
import sqlite3
from datetime import datetime, timezone
from typing import Union, Any
import click

from boofuzz import *
from boofuzz.constants import DEFAULT_PROCMON_PORT
from boofuzz.utils.debugger_thread_simple import DebuggerThreadSimple
from boofuzz.utils.process_monitor_local import ProcessMonitorLocal


OUTDIR: str = "boofuzz-results"
MODULE_ID = "mqtt-boofuzz"


def build_run_result(
    host: str,
    port: int,
    findings: list[dict[str, Any]],
    logs: list[str],
) -> dict[str, Any]:
    """Build a RunResult structure compatible with kraken's domain.RunResult."""
    return {
        "target": {"host": host, "port": port},
        "findings": findings,
        "logs": logs,
    }


def build_finding(
    finding_id: str,
    success: bool,
    title: str,
    severity: str,
    description: str,
    evidence: dict[str, Any],
    tags: list[str],
    host: str,
    port: int,
) -> dict[str, Any]:
    """Build a Finding structure compatible with kraken's domain.Finding."""
    return {
        "id": finding_id,
        "module_id": MODULE_ID,
        "success": success,
        "title": title,
        "severity": severity,
        "description": description,
        "evidence": evidence,
        "tags": tags,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": {"host": host, "port": port},
    }


def extract_findings_from_db(db_path: str, host: str, port: int) -> tuple[list[dict], list[str]]:
    """Extract crash/failure findings from boofuzz session database."""
    findings = []
    logs = []

    if not os.path.exists(db_path):
        logs.append(f"Session database not found: {db_path}")
        return findings, logs

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, name, index_start, index_end
            FROM cases
            WHERE id IN (SELECT DISTINCT case_id FROM steps WHERE type = 'fail')
        """)
        failed_cases = cursor.fetchall()

        for case_id, case_name, idx_start, idx_end in failed_cases:
            cursor.execute("""
                SELECT description, timestamp
                FROM steps
                WHERE case_id = ? AND type = 'fail'
                ORDER BY timestamp
            """, (case_id,))
            failures = cursor.fetchall()

            for desc, ts in failures:
                finding = build_finding(
                    finding_id=f"FUZZ-FAIL-{case_id}",
                    success=True,
                    title=f"Fuzzing failure in {case_name or 'unknown'}",
                    severity="medium",
                    description=desc or "Test case triggered a failure condition",
                    evidence={
                        "case_id": case_id,
                        "case_name": case_name,
                        "test_index_start": idx_start,
                        "test_index_end": idx_end,
                        "timestamp": ts,
                    },
                    tags=["fuzzing", "mqtt", "failure"],
                    host=host,
                    port=port,
                )
                findings.append(finding)

        cursor.execute("SELECT COUNT(*) FROM cases")
        total_cases = cursor.fetchone()[0]
        logs.append(f"Total test cases executed: {total_cases}")
        logs.append(f"Failed/crashed cases: {len(failed_cases)}")

        conn.close()
    except sqlite3.Error as e:
        logs.append(f"Error reading session database: {e}")

    return findings, logs

def mqtt_varlen_encoder(value):
    n = int.from_bytes(value, byteorder="big", signed=False) if value else 0
    if n < 0 or n > 268_435_455: raise ValueError(f"Remaining Length out of range for MQTT varint: {n}")
    out = bytearray()
    while True:
        encoded = n % 128
        n //= 128
        if n > 0: encoded |= 0x80
        out.append(encoded)
        if n == 0: break
    if len(out) > 4: raise ValueError("MQTT varint produced >4 bytes, which is invalid.")
    return bytes(out)

def build_mqtt_packet(name: str, control_header: Union[int, dict], variable_header_fields=None, payload_fields=None):
    variable_header_fields = variable_header_fields or []
    payload_fields = payload_fields or []

    def build_fields(field_defs):
        elements = []
        for f in field_defs:
            ftype, fname, fval, fuzzable, endian, max_len = f.get("type"), f.get("name"), f.get("value", 0), f.get("fuzzable", True), f.get("endian", "big"), f.get("max_len", None)

            if ftype == "group":
                values, default_value = f.get("values", []), f.get("default_value", None)
                elements.append(Group(name=fname, values=values, default_value=default_value, fuzzable=fuzzable))
            elif ftype == "byte": elements.append(Byte(name=fname, default_value=fval, fuzzable=fuzzable))
            elif ftype == "word": elements.append(Word(name=fname, default_value=fval, endian=endian, fuzzable=fuzzable))
            elif ftype == "string":
                elements.append(Size(name=f"{fname}_len", block_name=fname, length=2, endian=">", fuzzable=False))
                elements.append(String(name=fname, default_value=fval, fuzzable=fuzzable, max_len=max_len))
            elif ftype == "raw": elements.append(Bytes(name=fname, default_value=fval, fuzzable=fuzzable))

        return elements

    if type(control_header) == dict:
        fvalues, fdef, ffuzz = control_header.get("values", None), control_header.get("default_value", None), control_header.get("fuzzable", False)
        if fvalues == None and fdef == None:
            print("[FATAL] At least values or default value has to be specified for the control header")
            exit()
        ch = Group(name="ControlHeader", values=fvalues, default_value=fdef, fuzzable=ffuzz)
    else:
        ch = Byte(name="ControlHeader", default_value=control_header, fuzzable=False)

    return Request(name, children=(
        Block(name="FixedHeader", children=(
            ch,
            Block(name="RemainingLength", children=Size(name="RemainingLengthRaw", block_name="Body", fuzzable=False, length=4, endian=">"), encoder=mqtt_varlen_encoder, fuzzable=False)
        )),
        Block(name="Body", children=(
            Block(name="VariableHeader", children=build_fields(variable_header_fields)),
            Block(name="Payload", children=build_fields(payload_fields))
        ))
    ))

def build_connect_request():
    variable_header = [
        {"type": "string", "name": "ProtocolName", "value": "MQTT", "fuzzable": False},
        {"type": "byte", "name": "ProtocolLevel", "value": 5, "fuzzable": False},
        {"type": "byte", "name": "ConnectFlags", "value": 0x02, "fuzzable": False},
        {"type": "word", "name": "KeepAlive", "value": 60},
        {"type": "byte", "name": "PropertiesLength", "value": 0, "fuzzable": False},
    ]

    payload = [
        {"type": "string", "name": "ClientID", "value": "boofuzz", "max_len": 30}
    ]
    return build_mqtt_packet("MQTT_CONNECT", 0x10, variable_header, payload)

def build_connect_with_auth_request():
    variable_header = [
        {"type": "string", "name": "ProtocolName", "value": "MQTT", "fuzzable": False},
        {"type": "byte", "name": "ProtocolLevel", "value": 5, "fuzzable": False},
        {"type": "byte", "name": "ConnectFlags", "value": 0xC2},
        {"type": "word", "name": "KeepAlive", "value": 60},
        {"type": "byte", "name": "PropertiesLength", "value": 0, "fuzzable": False},
    ]

    payload = [
        {"type": "string", "name": "ClientID", "value": "fuzz_auth_client"},
        {"type": "string", "name": "Username", "value": "fuzzer"},
        {"type": "string", "name": "Password", "value": "password123"}
    ]
    return build_mqtt_packet("MQTT_CONNECT_AUTH", 0x10, variable_header, payload)

def build_connect_with_lwt_request():
    variable_header = [
        {"type": "string", "name": "ProtocolName", "value": "MQTT", "fuzzable": False},
        {"type": "byte", "name": "ProtocolLevel", "value": 5, "fuzzable": False},
        {"type": "byte", "name": "ConnectFlags", "value": 0x2E},
        {"type": "word", "name": "KeepAlive", "value": 60},
        {"type": "byte", "name": "PropertiesLength", "value": 0, "fuzzable": False},
    ]
    payload = [
        {"type": "string", "name": "ClientID", "value": "fuzz_lwt_client"},
        {"type": "string", "name": "WillTopic", "value": "fuzz/lwt"},
        {"type": "string", "name": "WillMessage", "value": "client disconnected"}
    ]
    return build_mqtt_packet("MQTT_CONNECT_LWT", 0x10, variable_header, payload)

def build_publish_request():
    variable_header = [
        {"type": "string", "name": "TopicName", "value": "fuzz/publish"},
        {"type": "byte", "name": "PropertiesLength", "value": 0, "fuzzable": False},
    ]

    payload = [
        {"type": "raw", "name": "Message", "value": b"Publish Test"}
    ]
    return build_mqtt_packet("MQTT_PUBLISH",  0x30, variable_header, payload)

def build_publish_qos1_request():
    variable_header = [
        {"type": "string", "name": "TopicName", "value": "fuzz/qos1"},
        {"type": "word", "name": "PacketIdentifier", "value": 11},
        {"type": "byte", "name": "PropertiesLength", "value": 0, "fuzzable": False},
    ]
    payload = [
        {"type": "raw", "name": "Message", "value": b"QoS 1 Test"}
    ]
    return build_mqtt_packet("MQTT_PUBLISH_QOS1", 0x32, variable_header, payload)

def build_publish_qos2_request():
    variable_header = [
        {"type": "string", "name": "TopicName", "value": "fuzz/qos2"},
        {"type": "word", "name": "PacketIdentifier", "value": 12},
        {"type": "byte", "name": "PropertiesLength", "value": 0, "fuzzable": False},
    ]
    payload = [
        {"type": "raw", "name": "Message", "value": b"QoS 2 Test"}
    ]
    return build_mqtt_packet("MQTT_PUBLISH_QOS2", 0x34, variable_header, payload)

def build_pubrel_request():
    variable_header = [
        {"type": "word", "name": "PacketIdentifier", "value": 12}
    ]
    return build_mqtt_packet("MQTT_PUBREL", 0x62, variable_header)

def build_subscribe_request():
    variable_header = [
        {"type": "word", "name": "PacketIdentifier", "value": 0},
        {"type": "byte", "name": "PropertiesLength", "value": 0, "fuzzable": False},
    ]
    payload = [
        {"type": "string", "name": "TopicFilter", "value": "fuzz/#"},
        {"type": "byte", "name": "SubscriptionOptions", "value": 0x00}
    ]
    return build_mqtt_packet("MQTT_SUBSCRIBE", 0x82, variable_header, payload)

def build_unsubscribe_request():
    variable_header = [
        {"type": "word", "name": "PacketIdentifier", "value": 0},
        {"type": "byte", "name": "PropertiesLength", "value": 0, "fuzzable": False},
    ]
    payload = [
        {"type": "string", "name": "TopicFilter", "value": "fuzz/#"}
    ]
    return build_mqtt_packet("MQTT_UNSUBSCRIBE", 0xA2, variable_header, payload)

def build_pingreq_request():
    return build_mqtt_packet("MQTT_PINGREQ", 0xC0)

def build_disconnect_request():
    variable_header = [
        {"type": "byte", "name": "PropertiesLength", "value": 0, "fuzzable": False},
    ]
    return build_mqtt_packet("MQTT_DISCONNECT", 0xE0, variable_header)


def conn_callback(target, fuzz_data_logger, session, test_case_context, *args, **kwargs):
    """Handle MQTT CONNACK after CONNECT using session.last_recv"""
    try:
        resp = session.last_recv
        if not resp:
            fuzz_data_logger.log_error("No response to CONNECT packet.")
            return

        ctrl_type = resp[0] & 0xF0
        if ctrl_type == 0x20:
            fuzz_data_logger.log_info(f"Received CONNACK: {resp.hex()}")
        else:
            fuzz_data_logger.log_error(f"Unexpected response (expected CONNACK): {resp.hex()}")

    except Exception as e:
        fuzz_data_logger.log_error(f"Error in conn_callback: {e}")


def qos1_callback(target, fuzz_data_logger, session, test_case_context, *args, **kwargs):
    """Handle MQTT PUBACK for QoS1 publish using session.last_recv"""
    try:
        resp = session.last_recv
        if not resp:
            fuzz_data_logger.log_error("No PUBACK received for QoS1 Publish.")
            return

        ctrl_type = resp[0] & 0xF0
        if ctrl_type == 0x40:
            fuzz_data_logger.log_info(f"Received PUBACK: {resp.hex()}")
        else:
            fuzz_data_logger.log_error(f"Unexpected response (expected PUBACK): {resp.hex()}")

    except Exception as e:
        fuzz_data_logger.log_error(f"Error in qos1_callback: {e}")


def qos2_callback(target, fuzz_data_logger, session, test_case_context, *args, **kwargs):
    """Handle MQTT PUBREC -> PUBREL -> PUBCOMP for QoS2 publish using session.last_recv"""
    try:
        resp = session.last_recv
        if not resp:
            fuzz_data_logger.log_error("No PUBREC received for QoS2 Publish.")
            return

        ctrl_type = resp[0] & 0xF0
        if ctrl_type == 0x50:
            fuzz_data_logger.log_info(f"Received PUBREC: {resp.hex()}")

            pubrel = b'\x62\x02\x00\x0C'
            target.send(pubrel)
            fuzz_data_logger.log_info(f"Sent PUBREL: {pubrel.hex()}")

            resp2 = session.last_recv
            if resp2 and (resp2[0] & 0xF0) == 0x70:
                fuzz_data_logger.log_info(f"Received PUBCOMP: {resp2.hex()}")
            else:
                fuzz_data_logger.log_error(f"Expected PUBCOMP, got: {resp2.hex() if resp2 else 'None'}")
        else:
            fuzz_data_logger.log_error(f"Unexpected response (expected PUBREC): {resp.hex()}")

    except Exception as e:
        fuzz_data_logger.log_error(f"Error in qos2_callback: {e}")


def sub_callback(target, fuzz_data_logger, session, test_case_context, *args, **kwargs):
    """Handle MQTT SUBACK using session.last_recv"""
    try:
        resp = session.last_recv
        if not resp:
            fuzz_data_logger.log_error("No SUBACK received.")
            return

        ctrl_type = resp[0] & 0xF0
        if ctrl_type == 0x90:
            fuzz_data_logger.log_info(f"Received SUBACK: {resp.hex()}")
        else:
            fuzz_data_logger.log_error(f"Unexpected response (expected SUBACK): {resp.hex()}")

    except Exception as e:
        fuzz_data_logger.log_error(f"Error in sub_callback: {e}")


def unsub_callback(target, fuzz_data_logger, session, test_case_context, *args, **kwargs):
    """Handle MQTT UNSUBACK using session.last_recv"""
    try:
        resp = session.last_recv
        if not resp:
            fuzz_data_logger.log_error("No UNSUBACK received.")
            return

        ctrl_type = resp[0] & 0xF0
        if ctrl_type == 0xB0:
            fuzz_data_logger.log_info(f"Received UNSUBACK: {resp.hex()}")
        else:
            fuzz_data_logger.log_error(f"Unexpected response (expected UNSUBACK): {resp.hex()}")

    except Exception as e:
        fuzz_data_logger.log_error(f"Error in unsub_callback: {e}")


def ping_callback(target, fuzz_data_logger, session, test_case_context, *args, **kwargs):
    """Handle MQTT PINGRESP using session.last_recv"""
    try:
        resp = session.last_recv
        if not resp:
            fuzz_data_logger.log_error("No PINGRESP received.")
            return

        ctrl_type = resp[0] & 0xF0
        if ctrl_type == 0xD0:
            fuzz_data_logger.log_info("Received PINGRESP")
        else:
            fuzz_data_logger.log_error(f"Unexpected response (expected PINGRESP): {resp.hex()}")

    except Exception as e:
        fuzz_data_logger.log_error(f"Error in ping_callback: {e}")

@click.group()
def cli():
    pass

@click.command()
@click.option('--host', help='Host or IP address of target', prompt=True)
@click.option('--port', type=int, default=1883, help='Network port of target')
@click.option('--test-case-index', help='Test case index', type=str)
@click.option('--test-case-name', help='Name of node or specific test case')
@click.option('--csv-out', help='Output to CSV file')
@click.option('--sleep-between-cases', help='Wait time between test cases (floating point)', type=float, default=0)
@click.option('--procmon-host', help='Process monitor port host or IP')
@click.option('--procmon-port', type=int, default=DEFAULT_PROCMON_PORT, help='Process monitor port')
@click.option('--procmon-start', help='Process monitor start command')
@click.option('--procmon-capture', is_flag=True, help='Capture stdout/stderr from target process upon failure')
@click.option('--tui/--no-tui', help='Enable/disable TUI')
@click.option('--text-dump/--no-text-dump', help='Enable/disable full text dump of logs', default=False)
@click.option('--file-dump/--no-file-dump', help='Enable/disable full dump of logs into a file', default=True)
@click.option('--output-dir', type=str, help='Specify output directory', default="")
@click.argument('target_cmdline', nargs=-1, type=click.UNPROCESSED)
def fuzz(target_cmdline, host, port, test_case_index, test_case_name, csv_out, sleep_between_cases,
         procmon_host, procmon_port, procmon_start, procmon_capture, tui, text_dump, file_dump, output_dir
    ):


    if output_dir == "":
        MASTER_OUTDIR = f"./{OUTDIR}"
    else:
        MASTER_OUTDIR=f"{output_dir}/{OUTDIR}"

    os.makedirs(MASTER_OUTDIR, exist_ok=True)
    LOG_FILEPATH = f"{MASTER_OUTDIR}/fuzz.log"

    fuzz_loggers = []
    if text_dump:
        fuzz_loggers.append(FuzzLoggerText())
    elif tui:
        fuzz_loggers.append(FuzzLoggerCurses())
    elif file_dump:
        fuzz_loggers.append(FuzzLoggerText(file_handle=io.TextIOWrapper(open(LOG_FILEPATH, "wb+"), encoding="utf-8")))
    if csv_out is not None:
        f = open(csv_out, 'w', encoding='utf-8', newline='')
        fuzz_loggers.append(FuzzLoggerCsv(file_handle=f))

    local_procmon = None
    if len(target_cmdline) > 0 and procmon_host is None:
        local_procmon = ProcessMonitorLocal(crash_filename="boofuzz-crash-bin", proc_name=None, pid_to_ignore=None, debugger_class=DebuggerThreadSimple, level=1)

    procmon_options = {}
    if procmon_start is not None:
        procmon_options['start_commands'] = [procmon_start]
    if target_cmdline and len(target_cmdline) > 0:
        procmon_options['start_commands'] = [list(target_cmdline)]
    if procmon_capture:
        procmon_options['capture_output'] = True

    if local_procmon is not None or procmon_host is not None:
        if procmon_host is not None:
            procmon = ProcessMonitor(procmon_host, procmon_port)
        else:
            procmon = local_procmon
        procmon.set_options(**procmon_options)
        monitors = [procmon]
    else:
        procmon = None
        monitors = []

    start = None
    end = None
    fuzz_only_one_case = None
    if test_case_index is None:
        start = 1
    elif "-" in test_case_index:
        start, end = test_case_index.split("-")
        if not start:
            start = 1
        else:
            start = int(start)
        if not end:
            end = None
        else:
            end = int(end)
    else:
        fuzz_only_one_case = int(test_case_index)

    session = Session(
        target=Target(
            connection=TCPSocketConnection(host, port),
            monitors=monitors,
        ),
        fuzz_loggers=fuzz_loggers,
        sleep_time=sleep_between_cases,
        index_start=start,
        index_end=end,
        receive_data_after_fuzz=True,
        db_filename=f"{MASTER_OUTDIR}/session.db"
    )

    connect_req = build_connect_request()
    connect_auth_req = build_connect_with_auth_request()
    connect_lwt_req = build_connect_with_lwt_request()

    publish_req = build_publish_request()
    publish_qos1_req = build_publish_qos1_request()
    publish_qos2_req = build_publish_qos2_request()

    subscribe_req = build_subscribe_request()
    unsubscribe_req = build_unsubscribe_request()

    pubrel_req = build_pubrel_request()

    ping_req = build_pingreq_request()
    disconnect_req = build_disconnect_request()

    session.connect(connect_req)
    session.connect(connect_auth_req)
    session.connect(connect_lwt_req)

    session.connect(connect_req, subscribe_req, callback=conn_callback)
    session.connect(connect_req, unsubscribe_req, callback=conn_callback)
    session.connect(connect_req, publish_req, callback=conn_callback)

    session.connect(connect_req, publish_qos1_req, callback=conn_callback)
    session.connect(connect_req, publish_qos2_req, callback=conn_callback)

    session.connect(connect_req, ping_req, callback=conn_callback)

    session.connect(subscribe_req, unsubscribe_req, callback=sub_callback)
    session.connect(subscribe_req, disconnect_req, callback=sub_callback)

    session.connect(unsubscribe_req, disconnect_req, callback=unsub_callback)
    session.connect(ping_req, disconnect_req, callback=ping_callback)

    session.connect(publish_req, disconnect_req)

    session.connect(publish_qos1_req, disconnect_req, callback=qos1_callback)
    session.connect(publish_qos2_req, disconnect_req, callback=qos2_callback)
    session.connect(connect_auth_req, disconnect_req, callback=conn_callback)
    session.connect(connect_lwt_req, disconnect_req, callback=conn_callback)

    with open(f'./{MASTER_OUTDIR}/fsm.png', 'wb') as file:
        file.write(session.render_graph_graphviz().create_png())

    print(f"Logs will be saved to {LOG_FILEPATH}")


    if fuzz_only_one_case is not None:
        session.fuzz_single_case(mutant_index=fuzz_only_one_case)
    else:
        session.fuzz()

    db_path = f"{MASTER_OUTDIR}/session.db"
    findings, db_logs = extract_findings_from_db(db_path, host, port)

    logs = [f"Fuzzing session completed for {host}:{port}"]
    logs.extend(db_logs)
    logs.append(f"Results saved to {MASTER_OUTDIR}")

    if not findings:
        findings.append(build_finding(
            finding_id="FUZZ-COMPLETE",
            success=False,
            title="Fuzzing completed without crashes",
            severity="info",
            description="The fuzzing session completed without detecting any crashes or failures",
            evidence={"output_dir": MASTER_OUTDIR, "db_path": db_path},
            tags=["fuzzing", "mqtt"],
            host=host,
            port=port,
        ))

    result = build_run_result(host, port, findings, logs)
    print(json.dumps(result))


if __name__ == "__main__":
    cli.add_command(fuzz)
    cli()
