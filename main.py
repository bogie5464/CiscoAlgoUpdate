from netmiko import ConnectHandler
from netmiko import ssh_exception
import getpass
import os
import datetime
import sys
import re

file_name = "ip_list.txt"
enable_hash = "placeholder"


def update_algo(ip: str, admin_password: str, tacacs_user: str, tacacs_password: str) -> bool:
    cisco_dev = {
        "host": ip,
        "username": tacacs_user,
        "password": tacacs_password,
        "device_type": "cisco_ios",
        "secret": "password"  # TODO: can be taken out in production just easier than configuring aaa on test devices

    }

    connection = ConnectHandler(**cisco_dev)
    connection.enable()
    old_users_raw = connection.send_command("sh run | i user ").split("\n")
    connection.config_mode()
    connection.send_command(
        "username lockoutadmin secret 9 $9$7433CNvTm0Ye89$f5zPTiPhCqVzY/q5iknoXQdnGc0NcqQLTnVYTHMGK6U")
    connection.exit_config_mode()
    old_users = list()
    for item in old_users_raw:
        old_users.append(item.split(" ")[1])

    connection.exit_config_mode()
    test_admin = connection.send_command("sh run | i user")
    if "lockoutadmin" in test_admin:
        connection.config_mode()
        for user in old_users:
            output = connection.send_command_timing(f"no user {user}")
            if 'This operation will' in output:
                output += connection.send_command_timing("y")
        connection.send_command(f"user siteadmin algorithm-type scrypt secret {admin_password}")
        connection.exit_config_mode()
        if "siteadmin secret 9" in connection.send_command("sh run | i user"):
            connection.config_mode()
            output = connection.send_command_timing("no user lockoutadmin")
            if 'This operation will' in output:
                output += connection.send_command_timing("y")
            if enable_hash == 'placeholder':
                print("Marshal messed up and forgot to change the enable hash in the script. Go yell at him.")
            else:
                connection.send_command(f"enable secret 9 {enable_hash}")
            connection.exit_config_mode()
            connection.send_command("write")
            return True
        else:
            return False

    else:
        print("Device did not have lockout configured, skipping...")
        return False


def main():
    if not os.path.exists(file_name):
        new_file = open(file_name, "w+")
        new_file.close()
        print("Ip list file did not exist. Created file. Import list of IP's then run again.")
        sys.exit(0)

    try:
        with open(file_name, 'r') as ip_list:
            if bool(re.search('[^0-9.\n]', ip_list.read(), re.M)):
                print(f"Formatting error in {file_name} check that file only contains valid "
                      f"IPv4 addresses separated by new lines")
                sys.exit(1)
            ip_list.seek(0)
            username = getpass.getuser()
            tacacs_password = getpass.getpass(prompt="Enter YOUR TACACS password (will not be shown): ")
            site_password = getpass.getpass(prompt="Enter SITE SPECIFIC siteadmin password (will not be shown): ")
            output_file_name = "{0}.csv".format(datetime.datetime.now().strftime("%m-%d-%y %H%M"))
            output_file = open(output_file_name, "w+")
            output_file.write("IP_ADDR, OPER_SUCCESSFUL\n")
            for line in ip_list:
                for i in range(3):  # Retry Authentication 3 Times before moving on.
                    try:
                        output_file.write(
                            f"{str(line.rstrip())}, {update_algo(str(line), site_password, username, tacacs_password)}\n")
                        print(str(line) + " completed")
                        break
                    except ssh_exception.AuthenticationException:
                        print("Authentication Failure: Try Again\n")
                        username = input("Username: ")
                        tacacs_password = getpass.getpass("Password: ")
                        continue
                    except ssh_exception.NetMikoTimeoutException:
                        print(f"Timeout on device: {str(line)}")
                        output_file.write(f"{str(line.rstrip())}, TIMEOUT\n")
                        break

                else:
                    output_file.write(f"{str(line.rstrip())}, AUTHENTICATION FAILURE\n")
                    break  # For retry authentication

            output_file.close()
    except KeyboardInterrupt:
        print("\nExiting program\n")
        sys.exit(0)


if __name__ == "__main__":
    main()
