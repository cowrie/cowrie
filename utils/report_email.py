#!/usr/bin/env python

#
# Copyright (C) 2016 Matteo Cantoni <matteo.cantoni@nothink.org>
#

#
# Cowrie SSH Honeypot Daily Report (HTML format)
#
# 1. Modify settings
# 2. Add custumo query into 'DB queries'
# 3. Add script to cron
# 4. Check email
#

import smtplib
import MySQLdb as mdb
from datetime import date, timedelta
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
from tabulate import tabulate

"""
Settings
"""
sensor_name   = '-'
email_user    = ''
email_pass    = ''
email_from    = ''
email_to      = ''
email_subject = 'Cowrie SSH Honeypot Daily Report'
email_server  = 'smtp.gmail.com'
email_port    = 587
db_host       = ''
db_user       = ''
db_pass       = ''
db_name       = 'cowrie'

"""
DB queries
"""
queries=[]
queries.append({
	"title":"Total login attempts",
	"sql":"SELECT COUNT(*) AS logins FROM auth WHERE DATE(timestamp) = SUBDATE(CURDATE(),1)",
	"colums":"Attempts"
})
queries.append({
	"title":"Total distinct IPs",
	"sql":"SELECT COUNT(DISTINCT ip) AS IPs FROM sessions WHERE DATE(starttime) = SUBDATE(CURDATE(),1)",
	"colums":"IP address"
})
queries.append({
	"title":"Number connections per IP",
	"sql":"SELECT ip,COUNT(ip) AS occ FROM sessions WHERE DATE(starttime) = SUBDATE(CURDATE(),1) GROUP BY ip ORDER BY COUNT(ip) DESC",
	"colums":"IP address,Occurrences"
})
queries.append({
	"title":"Usernames and count",
	"sql":"SELECT username,COUNT(username) AS occ FROM auth WHERE username <> '' AND DATE(timestamp) = SUBDATE(CURDATE(),1) GROUP BY username ORDER BY COUNT(username) DESC",
	"colums":"Username,Occurrences"
})
queries.append({
	"title":"Passwords and count",
	"sql":"SELECT password,COUNT(password) AS occ FROM auth WHERE password <> '' AND DATE(timestamp) = SUBDATE(CURDATE(),1) GROUP BY password ORDER BY COUNT(password) DESC",
	"colums":"Password,Occurrences"
})
queries.append({
	"title":"Usernames and passwords combinations",
	"sql":"SELECT username, password, COUNT(username) AS occ FROM auth WHERE username <> '' AND password <> '' AND DATE(timestamp) = SUBDATE(CURDATE(),1) GROUP BY username, password ORDER BY COUNT(username) DESC",
	"colums":"Username,Password,Occurrences"
})
queries.append({
	"title":"Success ratio",
	"sql":"SELECT success, COUNT(success) AS occ FROM auth WHERE DATE(timestamp) = SUBDATE(CURDATE(),1) GROUP BY success ORDER BY success",
	"colums":"Success,Occurrences"
})
queries.append({
	"title":"Usernames and passwords combinations login success",
	"sql":"SELECT username, password, COUNT(username) AS occ FROM auth WHERE username <> '' AND password <> '' AND DATE(timestamp) = SUBDATE(CURDATE(),1) AND success = 1 GROUP BY username, password ORDER BY COUNT(username) DESC",
	"colums":"Username,Password,Occurrences"
})
queries.append({
	"title":"Commands input",
	"sql":"SELECT timestamp,input,success FROM input WHERE DATE(timestamp) = SUBDATE(CURDATE(),1)",
	"colums":"Timestamp,Command,Success"
})
queries.append({
	"title":"Login attemps last 7 days",
	"sql":"SELECT date(timestamp) AS dateins,COUNT(session) AS occ FROM auth GROUP BY DATE(timestamp) ORDER BY timestamp DESC LIMIT 7",
	"colums":"Date,Occurrences"
})

today = date.today()
yesterday = date.today() - timedelta(1)

body = ""
body = body + "<pre>"
body = body + "<h2>%s</h2>" % email_subject
body = body + "<b>Sensor name  : %s</b><br>" % sensor_name
body = body + "<b>Report date  : %s</b><br>" % today
body = body + "<b>Session date : %s</b><br>" % yesterday

"""
Connect to database
"""
con = mdb.connect(db_host, db_user, db_pass, db_name);

with con:

    for select in queries:
        cur = con.cursor()
        cur.execute(select["sql"])
        rows = cur.fetchall()

        headers = select["colums"].split(",")
	# According to me "psql format" with "<pre> tag" it's the best solution...
        content = tabulate(rows, headers, tablefmt="psql")
        #content = tabulate(rows, headers, tablefmt="html")

	body = body + "<li style='list-style-type:square'><h3>%s</h3></li>" % select["title"]
        body = body + content + "<br>"

body = body + "</pre>"

"""
Send email
"""
msg = MIMEMultipart()
msg['From'] = email_from
msg['To'] = email_to
msg['Subject'] = email_subject

msg.attach(MIMEText(body, 'html'))

server = smtplib.SMTP(email_server, email_port)
server.starttls()
server.login(email_user, email_pass)
text = msg.as_string()
server.sendmail(email_from, email_to, text)
server.quit()
