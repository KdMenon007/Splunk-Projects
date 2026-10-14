
---

# **Splunk Installation & Setup on Linux (Lab Walkthrough)**

This lab walks you through installing Splunk Enterprise on a Linux VM. The installer is already downloaded to keep things smooth, so you’ll just extract, move, and launch Splunk — nothing fancy.

---

# **1. Connect to the Lab**

Click **Start Machine** and wait 3–5 minutes for the VM to fully load.  
If the screen doesn’t appear, use **Show Split View** in the top-right.

The Splunk installer files are located in:

```
~/Downloads/splunk
```

Check them with:

```
ls
```

You should see something like:

```
splunk_installer.tgz
splunkforwarder.tgz
```

---

# **2. Switch to Root (Important!)**

Splunk requires elevated privileges for installation, so run:

```
sudo su
```

Now you’ll be operating as root:

```
root@coffely:~/Downloads/splunk#
```

---

# **3. Extract the Splunk Installer**

Install (i.e., unpack) Splunk by uncompressing the tarball:

```
tar xvzf splunk_installer.tgz
```

You’ll see a long list of extracted folders and files — that’s Splunk installing itself.

After extraction, you will now have a new folder called:

```
splunk/
```

Verify with:

```
ls
```

---

# **4. Move Splunk to /opt**

Splunk is typically installed under `/opt` for cleanliness and consistency.

Run:

```
mv splunk /opt/
```

Now Splunk lives here:

```
/opt/splunk
```

---

# **5. Start Splunk for the First Time**

Navigate to the binary directory:

```
cd /opt/splunk/bin
```

Start Splunk and auto-accept the license:

```
./splunk start --accept-license
```

Since this is your first time running Splunk, it will ask you to create an **admin** username and password:

```
Please enter an administrator username: splunkadmin
Please enter a new password:
Please confirm new password:
```

Splunk will boot the services, bring up the management web server, and finish with:

```
The Splunk web interface is at http://coffely:8000
```

Boom — Splunk Enterprise is now live.

---

# **6. Access the Splunk Web Interface**

Inside the VM browser, open:

```
http://coffely:8000
```

If you’re on VPN and want to access Splunk from your real browser outside the VM, use:

```
http://MACHINE_IP:8000
```

Login with the credentials you created (`splunkadmin` / your password).

You should now see the Splunk Home UI with the left-panel apps:

- Search & Reporting
    
- Data Summary
    
- Getting Started
    
- etc.
    

You can now explore, index data, search logs, and start hunting.

---

# **Essential Splunk CLI Commands (Admin Quick-Reference)**

Once Splunk is installed, admins and analysts often interact with it from the CLI.  
All the commands below are run from:

```
/opt/splunk/
```

These commands work the same across Linux, macOS, and (with minor changes) Windows.

---

# **1. `splunk start` — Start the Splunk Service**

### **Purpose**

Starts Splunk Enterprise and all required services:

- splunkd
    
- web UI
    
- KV store
    
- appserver
    

If Splunk is already running, nothing changes.

### **Command**

```
./bin/splunk start
```

### **Example Output**

```
Splunk> Finding your faults, just like mom.
Checking http port [8000]: open
Checking mgmt port [8089]: open
...
The Splunk web interface is at http://coffely:8000
```

---

# **2. `splunk stop` — Gracefully Stop Splunk**

### **Purpose**

Stops all Splunk services and prevents new data ingestion.

### **Command**

```
./bin/splunk stop
```

Useful before configuration changes or system maintenance.

---

# **3. `splunk restart` — Apply Changes / Restart Services**

### **Purpose**

Stops and then immediately restarts all Splunk components.  
Use this after:

- editing config files
    
- installing apps
    
- upgrading Splunk
    
- changing ports
    

### **Command**

```
./bin/splunk restart
```

---

# **4. `splunk status` — Check Whether Splunk Is Running**

### **Purpose**

Shows process status, PIDs, and health.

### **Command**

```
./bin/splunk status
```

### **Example Output**

```
splunkd is running (PID: 2158)
splunk helpers are running (PIDs: 2159 2301 2351 2437)
```

This is your quick health check.

---

# **5. `splunk add oneshot` — Index a Single File Once**

### **Purpose**

Great for testing.  
Adds a single file into Splunk _one time_, without creating a permanent input.

### **Command**

```
./bin/splunk add oneshot <path_to_file>
```

Example:

```
./bin/splunk add oneshot /var/log/auth.log
```

This is commonly used to test parsing, sourcetypes, and indexing behavior.

---

# **6. `splunk search` — Run SPL Queries from the CLI**

### **Purpose**

Allows you to run Splunk searches directly in your terminal — no UI required.

### **Command**

```
./bin/splunk search "<SPL query>"
```

### **Example**

```
./bin/splunk search coffely
```

Example output:

```
Feb 18 21:09:04 coffley ubuntu: coffely-has-the-best-coffee-in-town
Feb 18 13:48:17 coffelly ubuntu: COFFELY
```

Useful for automation and script-based monitoring.

---

# **7. `splunk help` — The Knowledge Superweapon**

### **Purpose**

Lists all available commands, topics, and descriptions.

### **Command**

```
./bin/splunk help
```

### **It provides help for:**

- commands
    
- clustering
    
- distributed search
    
- inputs
    
- licensing
    
- settings
    
- search
    
- tools
    

Example categories you’ll see:

```
help commands
help search
help inputs
help clustering
help licensing
help settings
```

This is your built-in Splunk manual — extremely powerful.

---

# **Data Ingestion in Splunk (Using Universal Forwarders)**

Once Splunk Enterprise is installed, the next big step is **feeding it data**. Splunk doesn't magically know your logs — you have to define _what_ to send and _where_ to send it.  
That’s where **Splunk Forwarders** come in.

---

# **Splunk Forwarder Types**
---

## **1. Heavy Forwarder (HF)**

A **Heavy Forwarder** is essentially a full Splunk instance _without_ the search interface.

It can:

- parse logs
    
- apply filters
    
- run transforms
    
- modify field extractions
    
- route data to multiple destinations
    
- handle complex inputs
    

Use an HF when you need to _process or manipulate_ logs **before** sending them onward.

> It's like a mini-log-processing engine at the source.

---

## **2. Universal Forwarder (UF)**

A **Universal Forwarder** is the lightweight, minimal, no-nonsense version of a forwarder.

It is designed to:

- collect logs
    
- send logs to Splunk Enterprise or a Heavy Forwarder
    
- use almost no system resources
    
- run silently on servers, endpoints, and network devices
    

It **does not**:

- parse
    
- filter
    
- index
    
- modify data
    

It simply _ships raw data as-is_.

This is why it's the standard agent deployed across production environments.

---
# **Splunk UF Installation (Linux)**

The UF package is already downloaded:

```
~/Downloads/splunk/splunkforwarder.tgz
```

---

# **1. Elevate to Root**

UF needs root to install + bind to ports + manage system services.

```
sudo su
```

---

# **2. Extract the Forwarder Package**

```
tar xvzf splunkforwarder.tgz
```

You’ll see the `/splunkforwarder` directory unpacked with all binaries and configs.

---

# **3. Move the Forwarder to `/opt/`**

Standard Splunk hygiene:

```
mv splunkforwarder /opt/
```

Now the UF lives at:

```
/opt/splunkforwarder/
```

---

# **4. Start the Forwarder for the First Time**

Navigate to UF install location:

```
cd /opt/splunkforwarder
```

Start and accept the license:

```
./bin/splunk start --accept-license
```

You’ll be prompted to create the **admin credentials** for the forwarder.

---

# **5. Port Conflict Example (Important)**

UF uses **port 8089** for its management interface (same as Splunk Enterprise).  
If the main Splunk server is on the same box—or 8089 is taken—you’ll get:

```
ERROR: mgmt port [8089] - port is already bound.
Would you like to change ports? [y/n]: y
Enter a new mgmt port: 8090
```

You entered **8090**, which now becomes the UF’s mgmt port.

Totally normal in lab environments.

---

# **6. Forwarder Is Running — But Not Sending Anything… Yet**

Right now, the UF is alive, but:

- it doesn’t know **what logs** it should monitor
    
- it doesn’t know **where** to ship them (your Splunk Enterprise receiver)
    

So the next step is configuring:

1. **inputs.conf** → what data to collect
    
2. **outputs.conf** → where to send it (your main Splunk instance)
    

Example:  
→ Monitor `/var/log/auth.log`  
→ Send it to Splunk Enterprise at `coffely:9997`

We’ll configure this next.

---

# **Installing Splunk Enterprise on Windows**

Installing Splunk on Windows is far simpler than on Linux — it's mostly a point-and-click process. In this lab, you’ll install Splunk Enterprise, configure a forwarder to collect Windows Event Logs, and integrate Coffely web logs into Splunk.

---

# **1. Connect to the Windows Lab Machine**

Click **Start Machine**.  
Wait **3–5 minutes** for the Windows VM to fully boot.

If the VM doesn’t appear, click:

**Show Split View → top-right of the page**

You should now see Windows on the right side.

---

# **2. Downloading Splunk Enterprise**

Normally, you would:

1. Visit the Splunk website
    
2. Log into your Splunk account
    
3. Download the latest Splunk Enterprise Windows installer
    

But to save time, the installer is _already downloaded_ for you and placed in:

```
C:\Users\<User>\Downloads\
```

Just open the Downloads folder and look for:

```
splunk-instance.exe
```

---

# **3. Start the Splunk Installer**

Double-click the installer.

By default, Splunk installs to:

```
C:\Program Files\Splunk
```

The installer will:

- check system requirements
    
- install dependencies
    
- copy Splunk binaries
    
- configure services
    

This takes **5–8 minutes**.

During installation:

1. **Accept the License Agreement**
    
2. Click **Next**
    

---

# **4. Create the Splunk Administrator Account**

This is a required step.

You must define:

- **Username** (usually `admin` or similar)
    
- **Password** (must meet complexity requirements)
    

This account has full privileges and can:

- manage indexes
    
- manage data sources
    
- configure apps
    
- update users
    
- manage system-wide settings
    

Treat this account like a root/admin account.

---

# **5. Installation Complete**

If all compatibility checks pass, the installer will notify you that the Splunk Enterprise setup is successful.

Click **Finish**.

Splunk will now install the Splunkd service and the Splunk Web service.

---

# **6. Accessing Splunk Web Interface**

Splunk Web runs on port **8000** by default.

Open a browser and go to:

```
http://127.0.0.1:8000
```

If accessing remotely (through VPN), you can also use:

```
http://MACHINE_IP:8000
```

You’ll see the login screen.

Enter the admin credentials created earlier.

---

# **7. Splunk Dashboard**

Once logged in, the Splunk Home interface will appear, showing:

- Search & Reporting App
    
- Data Summary
    
- Alerts
    
- Dashboards
    
- Settings
    
- Server controls
    

This means Splunk Enterprise on Windows is fully installed and operational.

---

# **Configuring Splunk to Receive Data From a Windows Forwarder**

Before your Windows host can send logs to Splunk, the Splunk Indexer must be ready to _receive_ them. That means enabling the receiving port and configuring it properly.

---

# **1. Enable Receiving on Splunk Enterprise**

### **Step 1 — Open the Forwarding & Receiving Menu**

Log into Splunk Web → go to:

**Settings → Forwarding and Receiving**

You’ll see two configuration sections:

- **Forwarding** — for sending data _out_ of Splunk
    
- **Receiving** — for accepting data from universal/heavy forwarders
    

We want **Receiving**.

### **Step 2 — Configure a New Receiving Port**

Click:

**Configure Receiving → New Receiving Port**

Splunk’s default data ingestion port for forwarders is:

```
9997
```

You can change the port, but **9997 is the standard**, and it’s what we’ll use.

Enter **9997**, click **Save**.

Splunk is now listening for incoming Windows forwarder data.

---

# **2. Installing the Splunk Universal Forwarder (Windows)**

The Splunk Universal Forwarder is the lightweight agent that collects Windows event logs and forwards them to the Splunk indexer. It must be installed separately from Splunk Enterprise.

### **Step 1 — Download the Forwarder**

Normally, you’d download it from Splunk’s official website.  
As of this writing, the latest version is **9.0.4**.

For this lab, the forwarder installer is _already available_ in:

```
C:\Users\<User>\Downloads\
```

### **Step 2 — Run the Installer**

Double-click the installer.

During installation:

1. **Accept the License Agreement**
    
2. Choose **On-Premises** (not Cloud) — we’re installing locally
    
3. Leave the default install location unless your environment requires otherwise
    
    ```
    C:\Program Files\SplunkUniversalForwarder
    ```
    

### **Step 3 — Create the Forwarder’s Admin Account**

You’ll be prompted to create:

- a username
    
- a password
    

This account is used when connecting the forwarder to the Splunk indexer.

### **Step 4 — Deployment Server Configuration (Optional)**

You’ll be asked about a “Deployment Server.”

This is only necessary if you’re managing **large fleets of forwarders** and want centralized management.

For this lab → **skip it**.

### **Step 5 — Configure the Listener (Important)**

Specify the Splunk Enterprise server’s IP and the receiving port:

```
<YOUR_SPLUNK_SERVER_IP>:9997
```

This tells the UF where to forward logs once it’s installed.

### **Step 6 — Finish Installation**

The Windows UF installation takes **3–5 minutes**.

Once done, the forwarder service will start automatically.

If you had defined a Deployment Server earlier, the host would appear under:

**Settings → Forwarder Management**

---

# **Configuring Splunk to Receive Windows Event Logs From a Forwarder**

Now that:

- the Splunk **Universal Forwarder** is installed on the Windows host, and
    
- Splunk Enterprise is **listening** on port 9997
    

…it’s time to **link the two** and start collecting Windows Event Logs.

We’ll configure both sides:

1. Confirm the forwarder is visible in Splunk
    
2. Select the forwarding host
    
3. Choose the Event Logs to ingest
    
4. Create or choose an index
    
5. Start searching the incoming logs
    

---

# **1. Verify the Forwarder in Forwarder Management**

Go to:

**Settings → Forwarder Management**

This dashboard shows all forwarders reporting to your Splunk Indexer.

- In a real production environment, this page is filled with dozens or hundreds of hosts.
    
- In this lab, you should see the host named something like:
    
    ```
    coffelylab
    ```
    

If the host appears here, it means:

✔ The forwarder is installed correctly  
✔ The forwarder can talk to Splunk  
✔ Splunk is listening on the proper receiving port

Once confirmed, move on.

---

# **2. Add Data From the Forwarder**

Go to:

**Settings → Add Data**

You will see three ingestion methods:

- **Upload** – single files
    
- **Monitor** – local filesystem
    
- **Forward** – data coming from Universal Forwarders
    

Select **Forward**.

This tells Splunk you want to ingest data FROM the Windows UF.

---

# **3. Select the Forwarding Host**

In the **Select Forwarders** screen:

- Click the host `coffelylab` in the **Available host(s)** list
    
- Move it to the **Selected host(s)** list
    
- Click **Next**
    

This assigns the data collection configuration to that specific Windows host.

---

# **4. Choose Log Sources (Windows Event Logs)**

The next screen presents a list of supported data sources.

Choose:

👉 **Local Event Logs**

This opens all default Windows Event Logs such as:

- Security
    
- Application
    
- System
    
- Setup
    
- PowerShell
    
- DNS Server
    
- Sysmon
    
- Forwarded Events
    
- and more
    

Pick the ones you want to ingest (commonly: **Security + System + Application**).

Click **Next**.

---

# **5. Create (or Select) an Index**

Windows Event Logs shouldn’t go into the default `main` index.  
It's better practice to create a dedicated index.

Click:

**Create New Index**

Example:

```
windows_eventlogs
```

Save it, then select it from the list.

Click **Next**.

---

# **6. Review the Configuration**

The **Review** tab shows a summary:

- which host is selected
    
- which Event Logs will be collected
    
- which index they will go into
    
- the method of collection (Forwarder)
    

If it looks good → click **Submit** or **Finish** (depends on UI version).

---

# **7. Start Searching**

Click **Start Searching**.

Splunk opens Search & Reporting.

Run:

```
index=windows_eventlogs
```

If everything is configured properly, Event Logs begin appearing immediately:

- Logons
    
- Process creations
    
- Service start events
    
- Application errors
    
- Security audit events
    

Boom — you’re officially collecting Windows logs via a forwarder.

---

# **Ingesting Coffely Web Logs Into Splunk**

The Windows host you're working with runs a development version of the Coffely website (`http://coffely.thm`). This site logs:

- all HTTP requests
    
- server responses
    
- order submissions
    
- user activity
    

Your job is to configure Splunk to ingest these IIS web logs so the team can trace coffee orders, troubleshoot behavior, and optimize sales.

Let’s walk through the process end-to-end.

---

# **1. Start a New Data Input (Forwarded Data)**

In Splunk Web, go to:

**Settings → Add Data**

You’ll see three ingestion methods:

- Upload
    
- Monitor
    
- Forward
    

Select **Forward**, since the data is coming from the Universal Forwarder installed on the Windows host.

---

# **2. Select the Forwarding Host**

You’ll see a list of forwarders currently communicating with your Splunk instance.

Select the host where the Coffely website is installed. (Example: `coffelylab`)

Move it to the **Selected host(s)** panel.  
Click **Next**.

This tells Splunk: _“Collect data from this machine.”_

---

# **3. Select the Web Log Directory**

IIS web logs live in:

```
C:\inetpub\logs\LogFiles\W3SVC*
```

Each subfolder (e.g., W3SVC1, W3SVC2, etc.) contains rolling log files that IIS continuously writes to.

Splunk will now monitor:

- all log files in those directories
    
- any new logs created as IIS rotates them
    

Click **Next**.

---

# **4. Set the Source Type**

Since these logs come from an IIS web server, select the appropriate sourcetype:

👉 **iis**  
(or **iis-w3c**, depending on your Splunk version)

This sourcetype helps Splunk automatically understand IIS fields like:

- sc-status
    
- cs-method
    
- cs-uri-stem
    
- cs-uri-query
    
- time-taken
    
- c-ip
    
- user-agent
    

Setting the correct sourcetype is critical for future parsing, dashboards, and normalization.

---

# **5. Create (or Select) an Index**

It’s best practice to store web logs in their own index.

Create an index such as:

```
coffely_weblogs
```

Select this index from the dropdown, then proceed.

---

# **6. Review Your Settings**

The Review screen will show:

- Forwarding host selected
    
- Directory being monitored (`C:\inetpub\logs\LogFiles\W3SVC*`)
    
- Sourcetype: `iis`
    
- Target index: `coffely_weblogs`
    

If everything looks correct, finalize the configuration.

---

# **7. Generate Web Activity to Produce Logs**

Visit the Coffely test site:

```
http://coffely.thm/
```

Navigate around the site and place a few test “orders.”  
Your actions will generate fresh IIS log entries.

Logs may take **4–5 minutes** to appear depending on:

- UF batching
    
- network delay
    
- indexing queue time
    

---

# **8. Verify Logs in Splunk Search**

Go to Search & Reporting and run:

```
index=coffely_weblogs
```

If everything is configured correctly, you’ll start seeing web traffic events like:

- GET /coffee
    
- POST /order
    
- 200 / 302 / 404 responses
    
- Query strings
    
- Client IPs
    
- User agents
    

This confirms the web logs are flowing successfully.

---
