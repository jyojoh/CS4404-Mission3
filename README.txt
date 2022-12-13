download_dependencies.sh: Downloads all dependencies on machine that has Internet access. This was used to easily gather all the dependencies in order for them to be transferred to the isolated VMs.

install_dependencies.sh: Installs all dependencies needed for the server. Run this on the VM on which you want to deploy the server.py on.

database.py: Creates initial database.

library.py: Contains functions for implementation of database.

server.py: Starts a Flask server. For the genuine web server, this will serve a login page, authentication page, as well as the authentication codes to phone.py. For the attacker, this includes the ability to send POST requests to the genuine web server. 

tables.sql: SQL source file containing database rules.

phone.py: Receives and prints out 2FA code sent from genuine server.py

----- Templates:

login.html: login page for user credentials (username, password)

twofactor.html: Authentication page that requests 2FA code sent by the genuine web server

loginfail.html: Redirect that is presented to users should they fail to provide suitable login credentials. 

twofactorfail.html: Redirect that is presented to users should they fail to provide a correct authentication code.

success.html: Redirect that indicates the successful access to an account.

=============================================================

Instructions:

2.1 Overview======================================
For our infrastructure, we focused on SMS secret code authentication as a two factor authentication method. We implemented an experimental setup using a client web browser, web server, and DNS server. The client queries the DNS server with the domain of the website (example.com) and the DNS server responds with the IP address of the web server (10.64.13.2). This allows the client to connect to the website and enter their credentials to log in.

2.2 Setting up and Connecting to the Virtual Machines======================================
To clone the project source code to a VM, run the command:
scp -P 8246 -r CS4404-Mission2-main/ student@secnet-gateway.cs.wpi.edu:~/


Where 8246 is the port of the VM and CS4404-Mission2-main is the project directory.
In order to connect to a VM and keep the connection alive while idle, run the command:
ssh -o ServerAliveInterval=20 -p 8246 student@secnet-gateway.cs.wpi.edu


The built-in command line tool tmux is a utility that allows multiple windows to be displayed at the same time in the terminal. This is useful as the setup will require multiple command-line programs to be running at once, such as the client browser and phone. Although not strictly necessary for the setup to function properly, it can help to display multiple programs at once and easily read their outputs or enter commands. All imagery shown of the experimental setup in its entirety was captured while using this tool. 

2.3 Client======================================
The client will need a web browser in order to connect and display the web page, so w3m will be used as it is a terminal-based web browser.
To install w3m, run the command:
sudo apt install w3m w3m-img


To connect to the web server running on port 5000 using w3m, run the command:
w3m http://example.com:5000

Or alternatively, connect using the IP address of the web server:
w3m http://10.64.13.2:5000


The client will also need a phone for the two factor authentication, so a simple Python script to simulate a phone is included in the client directory of the project. In order to start the simulated phone so that it receives the authentication code from the web server run the command:
python3 phone.py

The phone.py file may need to be modified by changing the line
host = 'localhost'

to instead be the IP address of the client
host = '10.64.13.1'

The phone script will utilize the socket Python library to wait and listen for messages and print them to the user, which makes it easy for the web server to send codes to the client’s phone. Ideally, the client phone would be on another device or virtual machine, but our constraint to only four virtual machines meant our client phone would need to be run on the same machine. The phone uses a different port, so the web server is able to communicate with the client’s phone separately. This adequately simulates a realistic scenario of a client web browser and a client phone device separately.

In order for the client to query the DNS server, the file /etc/resolv.conf must be modified to include the DNS server’s IP address. This can be accomplished running the command
sudo nano /etc/resolv.conf

and adding the following line to the end of the file:
nameserver 10.64.13.4

The resultant /etc/resolv.conf file should look similar to the following configuration:

The DNS server can then be tested by trying to connect to or pinging example.com or www.example.com and waiting for a response.

2.4 Web Server======================================
The web server consists of a Python web server written using the Flask framework to serve requests and an SQL database to store user data such as usernames, passwords, and phone IP addresses. The necessary code and files for the web server are located under the server directory within the project.
The database is structured from the following SQL statements, and contains a sample client user for demonstration purposes:
CREATE TABLE accounts(
	id INTEGER,
	username varchar(255) NOT NULL,
	password varchar(255) NOT NULL,
	phone varchar(255) NOT NULL
);

INSERT INTO accounts (id, username, password, phone) VALUES
	(1, "user1", "password1", "10.64.13.1");


Our example only makes use of a single user account within the accounts table, however any number can be added, so long as there are available VM connections that can be made to simulate a phone needed for 2FA. 

The web server has three HTTP endpoints: /, /login, and /twofactor.
When a client connects to the web server, they are served with a basic login page containing a username and password field. When the username and password are entered and submitted, this creates a POST request with the data to /login.
Then, the server checks the username and password fields for validity, and if they are valid, generates a random 6-digit authentication code and sends it to the client’s phone. After this, it then displays a page prompting the user for the two factor authentication code.
Once the code is entered to the field and submitted, another POST request containing the code is sent to the /twofactor endpoint which then does a final validation, checking to make sure the code coming from the client’s browser was the same one sent to the client’s phone.
If all validation factors succeed, the user is presented with a success page, and if validation fails at any step along the way, the user is presented with a validation failure page.

If not already installed, the only dependency that the server.py script relies on that is not part of the standard Python libraries is Flask. This can be installed by:
Navigating into the project folder
cd project/

Installing all dependencies
bash install_dependencies.sh


The web server can be run by issuing the command:
FLASK_APP=server.py python3 -m flask run --host=0.0.0.0

within the server directory where server.py is located.

The output from running this command on the experimental setup, as well as the log produced when the client requests the login page is shown in Figure 2.3

Ensure that the server.py script that is being run originates from the /server subfolder within the project files. This is not to be confused with the server.py that is run by the adversary, located in the /attack subfolder.

2.5 Adversary======================================
The adversary will need a modified copy of the web server in order to automatically forward requests and data to the genuine web server. This version of the web server will appear to be the genuine web server to the client, but on the attacker server-side, it will forward the client’s requests to the genuine web server in place of the victim and respond accordingly. This allows the adversary to learn the client’s credentials and two factor authentication code, as well as gain access to their account.

The modified web server for the adversary is provided in the server.py file in the attack directory. In can be run similarly to the genuine web server by running the command
FLASK_APP=server.py python3 -m flask run --host=0.0.0.0

in the correct directory. If Flask is not installed, refer to the previous Web Server infrastructure section on how Flask was installed.

The adversary will also need the arpspoof command in order to establish an on-path presence through ARP poisoning in the attack phase, and this can be installed by running the command
sudo apt install dsniff


Lastly, the adversary will need to install Bettercap which provides DNS spoofing capabilities.
Bettercap requires a few dependencies that can be installed by running the command:
sudo apt install libpcap-dev libusb-1.0-0-dev libnetfilter-queue-dev


Bettercap can be installed by downloading a pre-compiled binary from their website: https://www.bettercap.org/installation/#precompiled-binaries.
For our demonstration, we used the following precompiled binary for version 2.31: https://github.com/bettercap/bettercap/releases/download/v2.31.0/bettercap_linux_amd64_v2.31.0.zip.
The compiled binary can then be downloaded, copied onto the adversary VM, and run. In order to run the executable, navigate to the appropriate directory and allow it to be executable by running the following commands:
cd bettercap_linux_amd64_v2.31.1/
chmod +x bettercap
./bettercap


2.6 DNS Server======================================
The DNS server was set up through referencing materials from DigitalOcean [12]. Due to our constraint of using 4 virtual machines, we could only make one DNS server that would serve queries for the example.com zone. Ideally we would set up DNS servers for .com and “.” as well. 

It is important to note that certain TLD providers require at least one primary and secondary name server in order to operate properly. This is done so that in the case that the primary server fails, the secondary can still serve DNS requests. As we were running our own setup, we did not have such requirements, but it is important to be aware of the real world requirements.

The DNS server will use BIND software, which should come installed by default on most Linux distributions, but it can be manually installed/updated through the command
sudo apt-get install bind9 bind9utils bind9-doc


To begin setting up the DNS server, firstly edit the /etc/hosts file to add a mapping to the local machine for the nameserver’s domain by adding the line 10.64.13.4 ns1.example.com ns1 to the end of the file.

The /etc/hostname file should also be edited to only include ns1, as this will be the hostname of the machine.

Next, the BIND server configuration file, /etc/bind/named.conf.options, will be modified. The default configuration should be edited to include two lines to indicate the server is not a recursive name server and rather an authoritative name server that can handle DNS requests on its own. The configuration should look like the following:
options {
    	directory "/var/cache/bind";
    	recursion no;
    	allow-transfer { none; };

    	dnssec-validation auto;

    	auth-nxdomain no;	# conform to RFC1035
    	listen-on-v6 { any; };
};


Then the DNS server must be configured to specify that it has authority over the example.com zone, and where the zone file is located. This can be done by editing the file /etc/bind/named.conf.local to look like the following:

The DNS server will serve as the authoritative name server for the example.com zone, so we must appropriately configure the named.conf.local file in the /etc/bind directory. This will include configuring the forward zone for the domain that we are using. Afterwards, specify that the relation of the DNS server and the zone to be that of type master, as this is the primary authoritative name server for the example.com zone. Under this, we state that the zone files will be placed in the subdirectory /etc/bind/zones where db.example.com will contain the necessary records.

Then the forward zone file should be created and populated with the DNS records. The zone directory must first be created by running sudo mkdir /etc/bind/zones. We will be copying the default zone file from BIND to serve as the initial zone file and modify it accordingly. This can be done by running sudo cp /etc/bind/db.local /etc/bind/zones/db.example.com.

The forwarding zone file is now located at /etc/bind/zones/db.example.com and must be configured properly. The start of authority (SOA) record must be edited by replacing the fully qualified domain name (FQDN) to the correct FQDN of the nameserver, ns1.example.com. along with the administrator email to a dummy email such as admin.example.com. Make sure to include the final period in all the FQDNs. The serial field in the SOA record can then be updated to any number for testing purposes. The purpose of the serial field is for zone administrators to indicate updates to the zone file by increasing the serial number so the update propagates to the necessary secondary servers, essentially functioning as a version number.

After the SOA record is configured properly, the name server (NS) records and address (A) records must be added to indicate the name servers for the example.com zone. The NS record should be a line added to the zone file and look like:
example.com.	IN	NS	ns1.example.com.

Note the space between each value is actually a tab character, entered by using the tab key. Next, the corresponding A record should be added on a new line to indicate the IP address of the name server we just specified:
ns1	IN	A	10.64.13.4

Once the NS and A records for the nameserver is configured properly for the zone, the A records to map example.com and www.example.com to the correct IP address (10.64.13.2) of the web server can be added:
@	IN	A	10.64.13.2
ns1	IN	A	10.64.13.2

The “@” symbol in the A record represents the domain of the zone we are configuring, which is example.com, so that A record will map example.com to the correct IP address.

After the configurations to the zone file are complete, it should look something like the following:

Although a reverse zone file can also be created to map the IP addresses to domain names, this setup is not necessary for our purposes.
The configuration of the DNS server can be checked through the command
sudo named-checkconf

Which should not return any errors if everything is configured properly, and then the BIND server can be restarted by running
sudo service bind9 restart


Finally, the functionality of the DNS server can then be tested by running the command
dig @10.64.13.4 example.com

Which should return a DNS response containing the A record for example.com in the zone file, mapping the domain to 10.64.13.2, resembling the following output:



