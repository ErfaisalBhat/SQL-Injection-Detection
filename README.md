# SQL-Injection-Detection
Automatic SQL Injection detection tool built in Python for real-time heuristic scanning of web applications. It analyzes user-supplied URLs or form fields, injects multiple crafted SQL payloads, and detects vulnerability patterns by analyzing web responses and error signatures
🔍 Automatic detection of SQL injection points (GET & POST forms)

🧩 Built-in list of 15+ common SQL payloads

🧠 Heuristic-based response pattern matching for MySQL, PostgreSQL, Oracle, MSSQL

🌐 Works on any live URL — detects forms dynamically using BeautifulSoup

⚙️ Designed for educational and authorized security testing only

🕒 Execution time tracking & colored CLI output for clarity
Usage
python3 faisal_sql_auto.py


Then simply enter:

Enter target URL (with http:// or https://):
https://demo.testfire.net/login.jsp

🧰 Tech Stack

Language: Python 3

Libraries: requests, colorama, beautifulsoup4, urllib.parse, re, time

📜 Legal Disclaimer

This project is strictly for educational and research purposes.
Perform vulnerability assessments only on systems you own or have explicit permission to test.
Unauthorized scanning of websites is illegal.


#Python #CyberSecurity #RedTeam #WebSecurity #SQLInjection #BTechProject #PenTesting #EthicalHacking
