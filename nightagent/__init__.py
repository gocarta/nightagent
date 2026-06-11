# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "netmiko",
# ]
# ///

import argparse
from netmiko import ConnectHandler
import getpass
import re
from time import sleep

HISTORY_LENGTH = 10
REKEY_LEFT_D = "Rekey Left(D)"
BYTES_TX = "Bytes Tx"
PKTS_TX = "Pkts Tx"
BYTES_RX = "Bytes Rx"
PKTS_RX = "Pkts Rx"


class NightAgent:
    def __init__(
        self,
        device_type: str,
        hostname: str,
        username: str,
        password: str,
        secret: str,
        port: int = 22,
        max_exceptions=1_000_000,
    ):
        self.device_type = device_type
        self.hostname = hostname
        self.username = username
        self.password = password
        self.secret = secret
        self.port = port
        self.connection = None
        self.history = {}
        self.max_exceptions = max_exceptions

    def login(self) -> bool:
        try:
            self.connection = ConnectHandler(
                device_type=self.device_type,
                host=self.hostname,
                username=self.username,
                password=self.password,
                secret=self.secret,
            )
            print("[nightagent] logged in")
            self.connection.enable()
            print("[nightagent] entered enable mode")
            sleep(0.5)
            self._disable_paging()
            print("[nightagent] disabled paging")
            return True
        except Exception as e:
            print(f"[nightagent] failed to login: {e}")
            return False

    def logout(self):
        if self.connection:
            try:
                self.connection.disconnect()
                print("[nightagent] logged out and closed SSH connection")
                return True
            except Exception as e:
                print(f"[nightagent] exception while attempting to log out: {e}")
                return False
        else:
            print("[nightagent] you are not logged in, so no need to log out")
            return True

    def _disable_paging(self):
        if self.device_type in [
            "arista_eos",
            "cisco_ios",
            "cisco_nxos",
            "cisco_xe",
            "cisco_xr",
        ]:
            self.connection.send_command("terminal length 0")
        elif self.device_type in ["cisco_asa"]:
            self.connection.send_command("terminal pager 0")
        # elif self.device_type in ["fortinet"]:
        #     self.connection.send_command("config system console\nset output standard\nend")
        elif self.device_type in ["hp_procurve"]:
            self.connection.send_command("no page")
        elif self.device_type in ["juniper_junos"]:
            self.connection.send_command("terminal length 0")
        elif self.device_type in ["paloalto_panos"]:
            self.connection.send_command("set cli pager off")

    def _run_command_on_firewall(self, command: str) -> str:
        if not self.connection:
            raise RuntimeError(
                "[nightagent] can't run command on firewall because you haven't logged in yet"
            )

        print(f'[nightagent] executing command: "{command}"')
        output = self.connection.send_command(command)
        print(f'[nightagent] finished command: "{command}"')
        return output

    def _group_lines(self, lines: list[str]) -> list[list[str]]:
        groups = []
        group = []
        for line in lines:
            if group and not line.startswith("  "):
                groups.append(group)
                group = []
            if line:
                group.append(line)
        if group:
            groups.append(group)
        return groups

    def _get_vpn_session_details(self):
        if not self.connection:
            raise Exception(
                "[nightagent] can't get tunnel stats because you need to log in first"
            )

        output = self._run_command_on_firewall("show vpn-sessiondb detail l2l")

        # match_ikev2 = re.search(f"IKEv2 Tunnels: ([0-9]+)", output)
        # if not match_ikev2:
        #     print(f"[WARN] Could not find number of IKEv2 tunnels")
        #     return False
        # ikev2_tunnels = int(match_ikev2.group(1))

        match = re.search(f"IPsec Tunnels: ([0-9]+)", output)
        if not match:
            print(f"[WARN] Could not find number of IPsec tunnels")
            return False
        ipsec_tunnels = int(match.group(1))

        lines = output.split("\n")

        results = {"IKEv2": [], "IPsec": []}

        groups = self._group_lines(lines)

        for group_lines in groups:
            group_text = "\n".join(group_lines)
            if len(group_lines) > 1 and group_lines[0] == "IPsec:":
                results["IPsec"].append(
                    {
                        "Tunnel ID": re.search(
                            r"Tunnel ID {0,10}: ?([0-9\.]+)", group_text
                        ).group(1),
                        "Rekey Left(D)": int(
                            re.search(
                                r"Rekey Left\(D\): (\d+) K-Bytes", group_text
                            ).group(1)
                        ),
                        "Bytes Tx": int(
                            re.search(r"Bytes Tx {0,10}: ?([0-9]+)", group_text).group(
                                1
                            )
                        ),
                        "Pkts Tx": int(
                            re.search(r"Pkts Tx {0,10}: ?([0-9]+)", group_text).group(1)
                        ),
                        "Bytes Rx": int(
                            re.search(r"Bytes Rx {0,10}: ?([0-9]+)", group_text).group(
                                1
                            )
                        ),
                        "Pkts Rx": int(
                            re.search(r"Pkts Rx {0,10}: ?([0-9]+)", group_text).group(1)
                        ),
                    }
                )

        if len(results["IPsec"]) != ipsec_tunnels:
            raise Exception("[nightagent] invalid parsing of IPsec tunnels")

        return results

    def check_tunnel_health(self) -> bool:
        if not self.connection:
            raise Exception(
                "[nightagent] can't check tunnel health because you need to log in first"
            )

        output = self._run_command_on_firewall("show vpn-sessiondb detail l2l")

        # print("[nightagent] show vpn-sessiondb detail l2l:\n", output)

        indicators = {
            "Rekey Left(D)": r"Rekey Left\(D\): (\d+) K-Bytes",
            "Bytes Tx": r"Bytes Tx {0,10}: ?([0-9]+)",
            "Pkts Tx": r"Pkts Tx {0,10}: ?([0-9]+)",
            "Bytes Rx": r"Bytes Rx {0,10}: ?([0-9]+)",
            "Pkts Rx": r"Pkts Rx {0,10}: ?([0-9]+)",
        }

        for name, pattern in indicators.items():
            matches = re.findall(pattern, output)
            if not matches:
                print(f"[WARN] Could not find indicator: {name}")
                return False

            for match in matches:
                value = int(match)
                if value == 0:
                    print(
                        f"[nightagent] detected unhealthy tunnel because {name} is {value}"
                    )
                    return False

        return True

    def clear_security_associations(self):
        print("[nightagent] clearing IPsec security associations")
        self._run_command_on_firewall("clear crypto ipsec sa")
        print("[nightagent] finished clearing IPsec security associations")

    def monitor(
        self,
        recheck_time: int = 15,
        doublecheck_time: int = 30,
        ask: bool = False,
        log=None,
    ):
        number_of_exceptions = 0
        while True:
            try:
                print(f"[nightagent] sleeping {recheck_time} seconds")
                sleep(recheck_time)

                print("[nightagent] logging in")
                sleep(1)
                self.login()

                details = self._get_vpn_session_details()
                ipsec_tunnels = details["IPsec"]

                new_ipsec_tunnel_ids = tuple(
                    [tunnel["Tunnel ID"] for tunnel in ipsec_tunnels]
                )
                print("[nightagent] IPsec tunnel ids:", ", ".join(new_ipsec_tunnel_ids))

                # check if new tunnel ids, in which case wipe out the previous stats
                old_ipsec_tunnel_ids = tuple(list(self.history.keys()))
                if new_ipsec_tunnel_ids != old_ipsec_tunnel_ids:
                    print(
                        f"[nightagent] tunnel ids changed from {old_ipsec_tunnel_ids} to {new_ipsec_tunnel_ids}"
                    )
                    self.history = dict(
                        [
                            (
                                tid,
                                {
                                    REKEY_LEFT_D: [],
                                    BYTES_TX: [],
                                    PKTS_TX: [],
                                    BYTES_RX: [],
                                    PKTS_RX: [],
                                },
                            )
                            for tid in new_ipsec_tunnel_ids
                        ]
                    )

                for tunnel in details["IPsec"]:
                    tunnel_id = tunnel["Tunnel ID"]
                    self.history[tunnel_id][REKEY_LEFT_D].append(tunnel[REKEY_LEFT_D])
                    self.history[tunnel_id][BYTES_TX].append(tunnel[BYTES_TX])
                    self.history[tunnel_id][PKTS_TX].append(tunnel[PKTS_TX])
                    self.history[tunnel_id][BYTES_RX].append(tunnel[BYTES_RX])
                    self.history[tunnel_id][PKTS_RX].append(tunnel[PKTS_RX])

                    # trim tunnel stats length
                    self.history[tunnel_id][REKEY_LEFT_D] = self.history[tunnel_id][
                        REKEY_LEFT_D
                    ][-1 * HISTORY_LENGTH :]
                    self.history[tunnel_id][BYTES_TX] = self.history[tunnel_id][
                        BYTES_TX
                    ][-1 * HISTORY_LENGTH :]
                    self.history[tunnel_id][PKTS_TX] = self.history[tunnel_id][PKTS_TX][
                        -1 * HISTORY_LENGTH :
                    ]
                    self.history[tunnel_id][BYTES_RX] = self.history[tunnel_id][
                        BYTES_RX
                    ][-1 * HISTORY_LENGTH :]
                    self.history[tunnel_id][PKTS_RX] = self.history[tunnel_id][PKTS_RX][
                        -1 * HISTORY_LENGTH :
                    ]

                # check if any tunnels are not passing traffic
                # in other words, check if any have the same number repeated for any of the key statistics

                for tunnel_id, tunnel_stats in self.history.items():
                    print(
                        f"[nightagent] {tunnel_id}: {BYTES_TX}:",
                        ", ".join(map(str, self.history[tunnel_id][BYTES_TX])),
                    )
                    if (
                        len(tunnel_stats[BYTES_TX]) >= 3
                        and tunnel_stats[BYTES_TX][-1]
                        == tunnel_stats[BYTES_TX][-2]
                        == tunnel_stats[BYTES_TX][-3]
                    ):
                        print(
                            "[nightagent] tunnel is not transmitting bytes, so clear security associations"
                        )
                        if ask is False or input("type yes to proceed").lower() in [
                            "y",
                            "yes",
                        ]:
                            self.clear_security_associations()
                            print(
                                "[nightagent] sleeping 5 minutes to let tunnel rebuild before checking again"
                            )
                            sleep(5 * 60)

                    print(
                        f"[nightagent] {tunnel_id}: {PKTS_TX}:",
                        ", ".join(map(str, self.history[tunnel_id][PKTS_TX])),
                    )
                    if (
                        len(tunnel_stats[PKTS_TX]) >= 3
                        and tunnel_stats[PKTS_TX][-1]
                        == tunnel_stats[PKTS_TX][-2]
                        == tunnel_stats[PKTS_TX][-3]
                    ):
                        print(
                            "[nightagent] tunnel is not transmitting packets, so clear security associations"
                        )
                        if ask is False or input("type yes to proceed").lower() in [
                            "y",
                            "yes",
                        ]:
                            self.clear_security_associations()
                            print(
                                "[nightagent] sleeping 5 minutes to let tunnel rebuild before checking again"
                            )
                            sleep(5 * 60)

                    print(
                        f"[nightagent] {tunnel_id}: {BYTES_RX}:",
                        ", ".join(map(str, self.history[tunnel_id][BYTES_RX])),
                    )
                    if (
                        len(tunnel_stats[BYTES_RX]) >= 3
                        and tunnel_stats[BYTES_RX][-1]
                        == tunnel_stats[BYTES_RX][-2]
                        == tunnel_stats[BYTES_RX][-3]
                    ):
                        print(
                            "[nightagent] tunnel is not receiving bytes, so clear security associations"
                        )
                        if ask is False or input("type yes to proceed").lower() in [
                            "y",
                            "yes",
                        ]:
                            self.clear_security_associations()
                            print(
                                "[nightagent] sleeping 5 minutes to let tunnel rebuild before checking again"
                            )
                            sleep(5 * 60)

                    print(
                        f"[nightagent] {tunnel_id}: {PKTS_RX}:",
                        ", ".join(map(str, self.history[tunnel_id][PKTS_RX])),
                    )
                    if (
                        len(tunnel_stats[PKTS_RX]) >= 3
                        and tunnel_stats[PKTS_RX][-1]
                        == tunnel_stats[PKTS_RX][-2]
                        == tunnel_stats[PKTS_RX][-3]
                    ):
                        print(
                            "[nightagent] tunnel is not receiving packets, so clear security associations"
                        )
                        if ask is False or input("type yes to proceed").lower() in [
                            "y",
                            "yes",
                        ]:
                            self.clear_security_associations()
                            print(
                                "[nightagent] sleeping 5 minutes to let tunnel rebuild before checking again"
                            )
                            sleep(5 * 60)

                print("[nightagent] checking tunnel health")
                sleep(1)
                healthy = self.check_tunnel_health()
                if healthy:
                    print("[nightagent] tunnel is healthy")
                    sleep(1)
                else:
                    print("[nightagent] tunnel is unhealthy")
                    sleep(1)
                    print(
                        f"[nightagent] pausing {doublecheck_time} before double-checking"
                    )
                    sleep(doublecheck_time)
                    healthy = self.check_tunnel_health()
                    if healthy is False:
                        print(
                            "[nightagent] tunnel is still unhealthy, so clear security associations"
                        )
                        if ask is False or input("type yes to proceed").lower() in [
                            "y",
                            "yes",
                        ]:
                            self.clear_security_associations()
                            print(
                                "[nightagent] sleeping 5 minutes to let tunnel rebuild before checking again"
                            )
                            sleep(5 * 60)

                sleep(10)

                print("[nightagent] logging out")
                self.logout()
            except Exception as e:
                print(e)
                number_of_exceptions += 1

                if number_of_exceptions >= self.max_exceptions:
                    print(
                        "[nightagent] hit maximum number of exceptions, so returning from monitor"
                    )
                    return False


def main():
    parser = argparse.ArgumentParser(
        prog="nightagent",
        description="NightAgent - automatically check and fix firewall issues",
    )

    parser.add_argument(
        "--device-type",
        required=False,
        help="Netmiko device_type (e.g. paloalto_panos)",
    )
    parser.add_argument("--hostname", required=False, help="Firewall hostname or IP")
    parser.add_argument("--username", required=False, help="SSH username")
    parser.add_argument("--password", required=False, help="SSH password")
    parser.add_argument("--secret", required=False, help="SSH secret")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")

    # Actions
    subparsers = parser.add_subparsers(dest="command", required=True)

    monitor = subparsers.add_parser(
        "monitor", help="Continuously monitor tunnel health"
    )
    monitor.add_argument(
        "--recheck", type=int, default=15, help="Seconds between checks"
    )
    monitor.add_argument(
        "--doublecheck", type=int, default=60, help="Seconds before re‑check"
    )
    monitor.add_argument(
        "--ask",
        action="store_true",
        help="Ask/prompt before clearing security associations",
    )

    args = parser.parse_args()

    device_type = args.device_type or input("device-type: ")
    hostname = args.hostname or input("hostname: ").strip()
    username = args.username or input("username: ").strip()
    password = args.password or getpass.getpass("password: ")
    secret = args.secret or getpass.getpass("secret: ")

    agent = NightAgent(
        device_type=device_type,
        hostname=hostname,
        username=username,
        password=password,
        secret=secret,
        port=args.port,
    )

    if args.command == "monitor":
        agent.monitor(
            recheck_time=args.recheck,
            doublecheck_time=args.doublecheck,
            ask=args.ask,
        )


if __name__ == "__main__":
    main()
