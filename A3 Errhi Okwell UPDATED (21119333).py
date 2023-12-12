import paramiko
import difflib
import telnetlib
import pexpect
import time

def telnet_connect(ip_address, username, password):
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
    current_lines = current_config.splitlines()
    startup_lines = startup_config.splitlines()
    diff = difflib.unified_diff(current_lines, startup_lines)
    print("\n".join(diff))

def configure_cisco_device(ip_address, username, password, enable_password):
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

        commands = [
            "enable",
            f"{enable_password}",
            "configure terminal",
            "banner motd ^CUnauthorized access prohibited!^C",
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

        for command in commands:
            ssh.exec_command(command)
            time.sleep(1)  # Add a delay to allow commands to execute

        ssh.close()
        print("Configuration successful.")

    except Exception as e:
        print(f"An error occurred during configuration: {str(e)}")

def configure_network_interfaces(ip_address, username, password, enable_password):
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

        commands = [
            "enable",
            f"{enable_password}",
            "configure terminal",
            "interface loopback0",
            "ip address 10.0.0.1 255.255.255.255",  # Change the IP address as needed
            "exit",
            "interface GigabitEthernet0/1",  # Change the interface as needed
            "ip address 192.168.1.1 255.255.255.0",  # Change the IP address as needed
            "exit",
            "end",
            "write memory",
            "exit",
        ]

        for command in commands:
            ssh.exec_command(command)
            time.sleep(1)  # Add a delay to allow commands to execute

        ssh.close()
        print("Network interfaces configured successfully.")

    except Exception as e:
        print(f"An error occurred during network interface configuration: {str(e)}")

def configure_routing_protocol(ip_address, username, password, enable_password, protocol="ospf"):
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

        commands = [
            "enable",
            f"{enable_password}",
            "configure terminal",
            f"router {protocol}",
            "network 10.0.0.1 0.0.0.0 area 0",  # Change the network and area as needed
            "exit",
            "end",
            "write memory",
            "exit",
        ]

        for command in commands:
            ssh.exec_command(command)
            time.sleep(1)  # Add a delay to allow commands to execute

        ssh.close()
        print(f"{protocol.upper()} configured successfully.")

    except Exception as e:
        print(f"An error occurred during {protocol.upper()} configuration: {str(e)}")

def configure_access_control_lists(ip_address, username, password, enable_password):
    # Accessing the ip_address, username, password, and enable_password variables
    print(f"Configuring ACLs for {ip_address} with username {username}, password {password}, and enable password {enable_password}")
    
    # ACL configuration commands
    commands = [
        "enable",
        f"{enable_password}",
        "configure terminal",
        "access-list 1 permit any",  # Example ACL rule, modify as needed
        "interface GigabitEthernet0/0",  # Example interface, modify as needed
        "ip access-group 1 in",  # Apply ACL to interface, modify as needed
        "exit",
        "end",
        "write memory",
        "exit",
    ]
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip_address, username=username, password=password)
        
        for command in commands:
            ssh.exec_command(command)
            time.sleep(1)  # Add a delay to allow commands to execute
        
        ssh.close()
        print("ACLs configured successfully.")
    
    except Exception as e:
        print(f"An error occurred during ACL configuration: {str(e)}")

def configure_ipsec(ip_address, username, password, enable_password):
    # Accessing the ip_address, username, password, and enable_password variables
    print(f"Configuring IPSec for {ip_address} with username {username}, password {password}, and enable password {enable_password}")
    
    # IPSec configuration commands
    commands = [
        "enable",
        f"{enable_password}",
        "configure terminal",
        "crypto isakmp policy 1",
        "encr aes",
        "hash sha",
        "authentication pre-share",
        "group 2",
        "lifetime 86400",
        "exit",
        "crypto isakmp key <pre-shared-key> address <remote-ip-address>",
        "crypto ipsec transform-set myset esp-aes esp-sha-hmac",
        "crypto map mymap 10 ipsec-isakmp",
        "set peer <remote-ip-address>",
        "set transform-set myset",
        "match address 101",
        "exit",
        "access-list 101 permit ip <local-ip-address> <remote-ip-address>",
        "interface GigabitEthernet0/0",  # Example interface, modify as needed
        "crypto map mymap",
        "exit",
        "exit",
        "write memory",
        "exit",
    ]
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip_address, username=username, password=password)
        
        for command in commands:
            ssh.exec_command(command)
            time.sleep(1)  # Add a delay to allow commands to execute
        
        ssh.close()
        print("IPSec configured successfully.")
    
    except Exception as e:
        print(f"An error occurred during IPSec configuration: {str(e)}")

def main():
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
            your_ip_address = ssh_ip_address  
            your_username = ssh_username  
            your_password = ssh_password  
            your_enable_password = ssh_password_enable  
            configure_cisco_device(your_ip_address, your_username, your_password, your_enable_password)

        elif choice == "5":
            your_ip_address = ssh_ip_address  
            your_username = ssh_username  
            your_password = ssh_password  
            your_enable_password = ssh_password_enable  
            configure_network_interfaces(your_ip_address, your_username, your_password, your_enable_password)

        elif choice == "6":
            your_ip_address = ssh_ip_address  
            your_username = ssh_username 
            your_password = ssh_password  
            your_enable_password = ssh_password_enable  
            protocol_choice = "ospf"  
            configure_routing_protocol(your_ip_address, your_username, your_password, your_enable_password, protocol_choice)

        elif choice == "7":
            your_ip_address = ssh_ip_address  
            your_username = ssh_username  
            your_password = ssh_password  
            your_enable_password = ssh_password_enable  
            configure_access_control_lists(your_ip_address, your_username, your_password, your_enable_password)

        elif choice == "8":
            your_ip_address = ssh_ip_address 
            your_username = ssh_username  
            your_password = ssh_password  
            your_enable_password = ssh_password_enable  
            configure_ipsec(your_ip_address, your_username, your_password, your_enable_password)

        elif choice == "9":
            print("Goodbye!")
            exit()
        else:
            print("Invalid choice. Please select 1, 2, 3, 4, 5, 6, 7, 8, or 9.")

if __name__ == "__main__":
    main()
