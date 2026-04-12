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


class NightAgent:
    def __init__(self, device_type: str, hostname: str, username: str, password: str, secret: str, port: int = 22):
        self.device_type = device_type
        self.hostname = hostname
        self.username = username
        self.password = password
        self.secret = secret
        self.port = port
        self.connection = None

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
        if self.device_type in ["arista_eos", "cisco_ios", "cisco_nxos", "cisco_xe", "cisco_xr"]:
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
            raise RuntimeError("[nightagent] can't run command on firewall because you haven't logged in yet")

        print(f'[nightagent] executing command: "{command}"')
        output = self.connection.send_command(command)
        print(f'[nightagent] finished command: "{command}"')
        return output

    def check_tunnel_health(self) -> bool:
        if not self.connection:
            raise Exception("[nightagent] can't check tunnel health because you need to log in first")

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
                    print(f"[nightagent] detected unhealthy tunnel because {name} is {value}")
                    return False

        return True

    def clear_security_associations(self):
        print("[nightagent] clearing IPsec security associations")
        self._run_command_on_firewall("clear crypto ipsec sa")
        print("[nightagent] finished clearing IPsec security associations")

    def monitor(self, recheck_time: int = 15, doublecheck_time: int = 60, ask: bool = False):
        number_of_exceptions = 0
        while True:
            try:
                print(f"[nightagent] sleeping {recheck_time} seconds")
                sleep(recheck_time)

                print("[nightagent] logging in")
                sleep(1)
                self.login()


                print("[nightagent] checking tunnel health")
                sleep(1)
                healthy = self.check_tunnel_health()
                if healthy:
                    print("[nightagent] tunnel is healthy")
                    sleep(1)
                else:
                    print("[nightagent] tunnel is unhealthy")
                    sleep(1)
                    print(f"[nightagent] pausing {doublecheck_time} before double-checking")
                    sleep(doublecheck_time)
                    healthy = self.check_tunnel_health()
                    if healthy is False:
                        print("[nightagent] tunnel is still unhealthy, so clear security associations")
                        if ask is False or input("type yes to proceed").lower() in ["y", "yes"]:
                            self.clear_security_associations()
                            print("[nightagent] sleeping 5 minutes to let tunnel rebuild before checking again")
                            sleep(5 * 60)

                sleep(0.5)

                print("[nightagent] logging out")
                self.logout()
            except Exception as e:
                print(e)
                number_of_exceptions += 1

                if number_of_exceptions >= 3:
                    print("[nightagent] hit maximum number of exceptions, so returning from monitor")
                    return False

def main():
    parser = argparse.ArgumentParser(
        prog="nightagent",
        description="NightAgent - automatically check and fix firewall issues",
    )

    parser.add_argument("--device-type", required=False, help="Netmiko device_type (e.g. paloalto_panos)")
    parser.add_argument("--hostname", required=False, help="Firewall hostname or IP")
    parser.add_argument("--username", required=False, help="SSH username")
    parser.add_argument("--password", required=False, help="SSH password")
    parser.add_argument("--secret", required=False, help="SSH secret")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")

    # Actions
    subparsers = parser.add_subparsers(dest="command", required=True)

    monitor = subparsers.add_parser("monitor", help="Continuously monitor tunnel health")
    monitor.add_argument("--recheck", type=int, default=15, help="Seconds between checks")
    monitor.add_argument("--doublecheck", type=int, default=60, help="Seconds before re‑check")
    monitor.add_argument("--ask", action="store_true", help="Ask/prompt before clearing security associations")

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
