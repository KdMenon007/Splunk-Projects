
---

# **Making Sense of Splunk Data (Search, Field Analysis & Reports)**

Splunk centralizes an organization’s logs, but once everything flows in, the sheer **volume** of data becomes overwhelming. Raw events can number in the tens of thousands—or millions—and staring at them manually is pointless.

In this section, you’ll learn how to:

- navigate the Search & Reporting app
    
- understand the available data
    
- summarize events using fields
    
- create reusable, scheduled searches through **Reports**
    

Let’s walk through it step by step.

---

# **1. Navigating to the Search & Reporting App**

When you log into Splunk, you’ll first see the Splunk homepage.

To start analyzing data, click the **Search & Reporting** app in the left menu.

This opens the SPL search interface.

---

# **2. Running Your First Broad Search**

A common way to get a feel for what’s in the environment is to run:

```
index=*
```

And set the time window to **All time** (only in labs—not in real networks).

This shows everything across all indexes.

**Important note:** In production, running `index=*` across all time is a bad idea.  
It burns CPU, impacts search performance, and slows down other analysts.

---

# **3. The Raw Data Problem**

Your broad search may show tens of thousands of events.  
In your example, Splunk returned:

> **35,000+ events**

Looking at raw logs like this:

- makes it hard to identify threats
    
- hides important trends
    
- increases cognitive load
    
- slows down SOC activity
    

This is why Splunk gives you tools to summarize, visualize, and filter data.

And that’s what we’ll explore next.

---

# **4. Using Reports to Automate and Schedule Searches**

SOC teams often need to run the same searches repeatedly:

- every shift
    
- every 8 hours
    
- every morning
    
- after major changes
    

Running them manually wastes time and heats up the search head.

**Reports solve this by:**

1. running searches automatically, on schedule
    
2. saving results for analysts to review
    
3. avoiding simultaneous heavy manual searches
    
4. keeping things organized and consistent
    

Perfect for shift changes and routine monitoring.

---

# **5. Accessing Reports in Splunk**

Go to:

**Search & Reporting → Reports Tab**

You’ll see:

- existing reports
    
- their owners
    
- schedules
    
- permissions (Private or Shared)
    
- “Open in Search” (to run the query manually)
    

Reports are reusable building blocks for workflows.

---

# **6. Creating a New Report**

To create one:

1. Run your desired search
    
2. Click **Save As → Report**
    
3. Fill in the details
    
4. Save it
    

Let’s practice with the VPN login analysis.

---

# **7. Understanding Your Data Using Fields**

In the left sidebar of the Search App, Splunk automatically shows extracted fields such as:

- hosts
    
- usernames
    
- source IPs
    
- EventCodes
    
- sourcetypes
    

Click **host** to see which machines are sending logs.

You identified:

- `network-server`
    
- `web-server`
    
- `vpn_server`
    

---

# **8. Build a Query: Count Logins by Username**

To find how often each VPN user logged in, use:

```
host=vpn_server | stats count by Username
```

Your results display usernames and their login frequency.

This is a perfect candidate for a scheduled report.

---

# **9. Save the Query as a Report**

Click:

**Save As → Report**

Fill in:

- Title
    
- Description
    
- Set “Time Range Picker” to **Yes**
    
- Content: **Statistics Table**
    

Click **Save**.

Splunk confirms the report is created.

---

# **10. Viewing the Report**

Click **View** to open the fresh report.

You’ll see:

- the table of usernames
    
- counts
    
- the time range picker
    

Now go back to the Reports tab — your new report appears there.

It shows:

- Owner: admin
    
- Sharing: Private
    
- Next Scheduled Run (if scheduling is enabled)
    

You can modify permissions with the **Edit** button.

---

# **Creating Dashboards and Visualizations in Splunk**

Dashboards give teams instant visibility into important metrics, trends, and anomalies.  
They’re perfect for:

- SOC triage
    
- executive reporting
    
- highlighting spikes in failed logins
    
- tracking user behavior
    
- summarizing incident activity
    

Instead of scrolling through raw logs, dashboards give you **actionable visual insight** in seconds.

Let’s build one together.

---

# **1. Navigate to the Dashboards Tab**

Open Splunk and go to:

**Search & Reporting → Dashboards**

You’ll see:

1. **Create Dashboard** – start a new one
    
2. **List of dashboards** – existing dashboards
    
3. **Dashboard properties** – owner, permissions, edit options
    

Since we have no dashboards yet, we’ll create one.

Click **Create Dashboard**.

---

# **2. Create a New Dashboard**

You’ll see the creation form:

- **Title** – the dashboard’s display name
    
- **ID** – auto-generated
    
- **Permissions** – choose who can view it
    

Choose **Shared in App** so other Splunk users can access it.

You also get two dashboard creation methods:

- **Classic Dashboards** (simple, reliable, traditional layout)
    
- **Dashboard Studio** (modern, flexible, customizable visual builder)
    

For this lab, select **Classic Dashboards**, then click **Create**.

Splunk loads an empty dashboard canvas with the message:

> _Click Add Panel to Start_

---

# **3. Add a Panel to the Dashboard**

Click **Add Panel**.  
A menu appears with options:

- New Search
    
- New from Report
    
- Clone Existing Panel
    
- Select from Library
    

We already created a report in the previous task, so choose:

👉 **New from Report**

Then select the report you created earlier (the VPN login frequency report).

Click **Add to Dashboard**.

Now the results appear on your dashboard.

---

# **4. Add a Visualization**

Right now, the panel is just a table. Dashboards shine when you transform data visually.

Click **Visualization**.

You’ll see options like:

- Column Chart
    
- Bar Chart
    
- Pie Chart
    
- Area Chart
    
- Line Chart
    
- Single Value
    
- Scatter Plot
    
- and more
    

Choose **Column Chart**.

Instantly, your data becomes visual — and much easier to interpret.

For example:

- Sarah has the highest login count
    
- Emma has the lowest
    

This is exactly the kind of insight dashboards are designed to provide.

---

# **5. Optional: Change Theme to Dark Mode**

Flip the **Dark Theme** toggle for a cleaner, more modern look.

Click **Save**.

---

# **6. Viewing Your Dashboard**

Return to:

**Dashboards Tab**

You’ll now see your newly created dashboard in the list.

It includes:

- Name
    
- Owner
    
- Permissions
    
- Edit options
    

Open it anytime to see updated data.

---

# **Creating Alerts in Splunk (Proactive Threat Detection)**

Reports give you scheduled insights.  
Dashboards give you visual summaries.  
But **alerts**?

Alerts turn Splunk into a real-time warning system for suspicious or dangerous activity.

If something important happens — brute-force attempts, privilege escalation, malware behavior, unauthorized access — Splunk can alert you **immediately or on a schedule**, depending on your configuration.

Although we can't practice alerts on the lab instance due to licensing restrictions, we _can_ walk through how to configure them properly.

---

# **1. Start With a Search Query**

Just like with Reports or Dashboards, alerts begin with a **search**.

For example, earlier we discovered:

> Sarah logged in more than any other user.

Let’s narrow our search to Sarah’s login events:

```
host=vpn_server Username=Sarah
```

Once the results appear, click:

**Save As → Alert**

---

# **2. Configure Alert Details**

You’ll see a form similar to saving Reports, plus additional alert-specific settings.

### **Basic Info**

- **Title** – descriptive name
    
- **Description** – what the alert means
    
- **Permissions** – Private or Shared
    

These help organize alerts and control visibility.

---

# **3. Choose Alert Type**

Most Splunk environments support **Scheduled Alerts**, which run at set intervals.

Depending on license level, you may also see:

- **Real-time Alerts** (trigger as soon as data arrives)
    

For this example, choose:

👉 **Scheduled Alert**

Let it run every hour.

---

# **4. Set Trigger Conditions**

Trigger conditions tell Splunk _when_ to fire the alert.

Common options:

- Number of results
    
- Custom search expression
    
- When a metric crosses a threshold
    

Example condition:

> Trigger an alert when Sarah logs in **more than 5 times** in one hour.

So set:

- **Number of Results → is greater than → 5**
    

---

# **5. Alert Throttling (Very Important in SOC Operations)**

Without throttling, Sarah logging in 50 times would trigger 50 alerts.  
No one wants alert fatigue.

Enable **Throttle** to limit alerts:

Example:

```
Suppress alerts for: 60 minutes
```

Meaning:  
→ Only **one** alert per hour, even if threshold is exceeded multiple times.

---

# **6. Configure Trigger Actions**

Trigger Actions define what Splunk _does_ when the alert fires.

Common actions:

- Send an email
    
- Run a script
    
- Log an event
    
- Webhook call (automation platform / SOAR)
    
- Create a ticket (with integrations)
    

For this example, configure:

**Send Email To:**

```
soc@tryhackme.com
```

**Priority:**  
High

**Subject:**

```
High Login Frequency Alert for Sarah
```

**Message:**

```
Alert: Sarah has logged in more than 5 times this hour.
```

Splunk will attach search results to the email.

---

# **7. Completed Alert Configuration Example**

Based on the screenshots and steps, the alert is configured to:

- Run **every hour**
    
- Trigger if **Sarah’s logins > 5**
    
- Only alert **once every 60 minutes** (throttle)
    
- Send a **high-priority email** to the SOC
    

This is exactly how real SOCs catch early brute force behavior or compromised credentials.

---