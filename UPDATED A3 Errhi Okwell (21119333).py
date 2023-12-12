import paramiko
import difflib
import telnetlib
import pexpect
import time

# Global variables
telnet_ip_address = '192.168.202.136'
telnet_username = 'cisco'
telnet_password = 'cisco123!'
ssh_ip_address = '192.168.202.130'
ssh_username = 'prne'
ssh_password = 'cisco123!'
ssh_password_enable = 'class123!'

def telnet_connect(ip_address, username, password):
    """Establishes a Telnet connection to a given IP address with provided credentials."""
    try:
        tn = telnetlib.Telnet(ip_address)
        tn.read_until(b"Username: ")
        tn.write(username.encode('ascii') + b"\n")
        tn.read_until(b"Password: ")
        tn.write(password.encode('ascii') + b"\n")
        print('--- Success! Connecting via Telnet to:', ip_address)
        tn.write(b"exit\n")
        tn.close()

    except Exception as e:
        print(f'An error occurred during Telnet connection: {str(e)}')

def ssh_connect(ip_address, username, password, password_enable):
    """Establishes an SSH connection to a given IP address with provided credentials."""
    try:
        ssh_session = pexpect.spawn(f'ssh {username}@{ip_address}', encoding='utf-8', timeout=20)
        result = ssh_session.expect(['Password:', pexpect.TIMEOUT, pexpect.EOF])

        if result != 0:
            print('--- FAILURE: Creating SSH session for: ', ip_address)
            exit()

        ssh_session.sendline(password)
        result = ssh_session.expect(['>', pexpect.TIMEOUT, pexpect.EOF])

        if result != 0:
            print('--- FAILURE: Entering SSH password: ', ip_address)
            exit()

        ssh_session.sendline('enable')
        result = ssh_session.expect(['Password: ', pexpect.TIMEOUT, pexpect.EOF])

        if result != 0:
            print('--- FAILURE: Entering enable mode: ', ip_address)
            exit()

        ssh_session.sendline(password_enable)
        result = ssh_session.expect(['#', pexpect.TIMEOUT, pexpect.EOF])

        if result != 0:
            print('--- FAILURE: Entering enable mode after sending password: ', ip_address)
            exit()

        ssh_session.sendline('exit')
        ssh_session.close()

    except Exception as e:
        print(f'An error occurred during SSH connection: {str(e)}')

def compare_configurations(current_config, startup_config):
    """Compares current configuration with the startup configuration."""
    current_lines = current_config.splitlines()
    startup_lines = startup_config.splitlines()
    diff = difflib.unified_diff(current_lines, startup_lines)
    print("\n".join(diff))

def execute_ssh_commands(ssh_client, commands):
    """Executes a list of commands on an SSH session."""
    for command in commands:
        ssh_client.exec_command(command)
        time.sleep(1)

def configure_device(ip_address, username, password, enable_password, commands):
    """Configures a network device with provided commands."""
    device = {
        "device_type": "cisco_ios",
        "ip": ip_address,
        "username": username,
        "password": password,
        "secret": enable_password,
    }

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(**device)
        execute_ssh_commands(ssh, commands)
        ssh.close()
        print("Configuration successful.")
    except paramiko.SSHException as e:
        print(f"SSH error: {str(e)}")

def main():
    """Main function to handle user input and call respective functions."""
    while True:
        print("Welcome to the SSH and Telnet Connection Tool!")
        print("Please select from the following options:")
        print("1. Telnet Connection")
        print("2. SSH Connection")
        print("3. Compare Configurations")
        print("4. Device Configuration")
        print("5. Configure Network Interfaces")
        print("6. Configure Routing Protocol")
        print("7. Configure Access Control Lists")
        print("8. Configure IPSec")
        print("9. Quit")

        choice = input("Enter your choice: ")

        if choice == "1":
            telnet_ip_address = '192.168.202.136'
            telnet_username = 'cisco'
            telnet_password = 'cisco123!'
            telnet_connect(telnet_ip_address, telnet_username, telnet_password)

        elif choice == "2":
            ssh_ip_address = '192.168.202.130'
            ssh_username = 'prne'
            ssh_password = 'cisco123!'
            ssh_password_enable = 'class123!'
            ssh_connect(ssh_ip_address, ssh_username, ssh_password, ssh_password_enable)

        elif choice == "3":
            current_config = "current running configuration text" 
            startup_config = "startup configuration text" 
            compare_configurations(current_config, startup_config)

        elif choice == "4":
            ssh_ip_address  
            ssh_username  
            ssh_password  
            ssh_password_enable  
            commands = [
                "enable",
                f"{ssh_password_enable}",
                "configure terminal",
                "banner motd ^Unauthorized access prohibited!^",
                "line vty 0 4",
                "login local",
                "transport input ssh",
                "exit",
                "service password-encryption",
                "line con 0",
                "login local",
                "transport output ssh",
                "exit",
                "logging buffered 10240 informational",
                "end",
                "write memory",
                "exit",
            ]
            configure_device(ssh_ip_address, ssh_username, ssh_password, ssh_password_enable, commands)

        elif choice == "5":
            ssh_ip_address  
            ssh_username  
            ssh_password  
            ssh_password_enable
            commands = [
                "enable",
                f"{ssh_password_enable}",
                "configure terminal",
                "interface loopback0",
                "ip address 10.0.0.1 255.255.255.255",
                "exit",
                "interface GigabitEthernet0/1",
                "ip address 192.168.1.1 255.255.255.0",
                "exit",
                "end",
                "write memory",
                "exit",
            ]
            configure_device(ssh_ip_address, ssh_username, ssh_password, ssh_password_enable, commands)

        elif choice == "6":
            ssh_ip_address  
            ssh_username 
            ssh_password  
            ssh_password_enable
            print("Please choose a routing protocol: 1. OSPF 2. EIGRP 3. RIP")
            protocol_choice = input("Enter your choice (OSPF/EIGRP/RIP): ").lower()
            
            if protocol_choice == "ospf":
                commands = [
                    "enable",
                    f"{ssh_password_enable}",
                    "configure terminal",
                    "router ospf 1",
                    "network 10.0.0.0 0.255.255.255 area 0",
                    "exit",
                    "end",
                    "write memory",
                    "exit",
                ]
            elif protocol_choice == "eigrp":
                commands = [
                    "enable",
                    f"{ssh_password_enable}",
                    "configure terminal",
                    "router eigrp 100",
                    "network 10.0.0.0",
                    "no auto-summary",
                    "exit",
                    "end",
                    "write memory",
                    "exit",
                ]
            elif protocol_choice == "rip":
                commands = [
                    "enable",
                    f"{ssh_password_enable}",
                    "configure terminal",
                    "router rip",
                    "version 2",
                    "network 10.0.0.0",
                    "no auto-summary",
                    "exit",
                    "end",
                    "write memory",
                    "exit",
                ]
            else:
                print("Invalid choice. Please select OSPF, EIGRP, or RIP.")
                continue
            
            configure_device(ssh_ip_address, ssh_username, ssh_password, ssh_password_enable, commands)

        elif choice == "7":
            ssh_ip_address  
            ssh_username  
            ssh_password  
            ssh_password_enable  
            commands = [
                "enable",
                f"{ssh_password_enable}",
                "configure terminal",
                # Standard ACL 
                "access-list 10 permit 192.168.1.0 0.0.0.255",  #.1
                "access-list 10 deny any",  

                # Extended ACL
                "access-list 100 permit tcp 10.0.0.0 0.255.255.255 any eq 80", 
                "access-list 100 deny ip any any",  

                # Apply the ACL to an interface
                "interface GigabitEthernet0/0",  
                "ip access-group 10 in",  
                "exit",
                
                "interface GigabitEthernet0/1",  
                "ip access-group 100 out",  
                "exit",

                "end",
                "write memory",
                "exit",
            ]
            configure_device(ssh_ip_address, ssh_username, ssh_password, ssh_password_enable, commands)


        elif choice == "8":
            ssh_ip_address 
            ssh_username  
            ssh_password  
            ssh_password_enable
            commands = [
                "enable",
                f"{ssh_password_enable}",
                "configure terminal",
                "crypto isakmp policy 10",
                "encr aes 256",
                "authentication pre-share",
                "group 5",
                "hash sha256",
                "lifetime 3600",
                "exit",
                "crypto isakmp key mykey address 0.0.0.0",
                "crypto ipsec transform-set myset esp-aes 256 esp-sha-hmac",
                "crypto map mymap 10 ipsec-isakmp",
                "set transform-set myset",
                "set peer <remote-peer-ip>",
                "match address 100",
                "interface GigabitEthernet0/0", 
                "crypto map mymap",
                "access-list 100 permit ip <local-network> <remote-network>",
                "end",
                "write memory",
                "exit",
            ]
            configure_device(ssh_ip_address, ssh_username, ssh_password, ssh_password_enable, commands)

        elif choice == "9":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please select 1, 2, 3, 4, 5, 6, 7, 8, or 9.")

if __name__ == "__main__":
    main()