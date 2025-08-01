# 🛡️ Web-Based Intrusion Detection and Prevention System (IDPS)

A robust **web-based Intrusion Detection and Prevention System** built with **Python and Flask**, combining **real-time URL scanning**, **web-scrapping**, and **Redis caching** to provide a fast, scalable, and proactive approach to threat detection bsed on urls. The system alerts users once the malicious URL is detected and maintains a secure blacklist to prevent repeated threats.

---

## 🎯 Features & Objectives

1. 🔍 **Real-time URL Scanning**  
   - Detects malicious or suspicious links using **VirusTotal API** and pattern matching.  
   - Prevents redirection to harmful URLs.

2. 🚀 **Caching with Redis**  
   - Reduces repetitive API calls by caching previously scanned URLs.  
   - Improves system efficiency and response time.

4. ✉️ **Real-time Alert Notifications**  
   - Sends immediate notifications to users when a malicious link is detected.  

5. 🧱 **URL Blacklisting and Logging**  
   - Stores malicious URLs in a persistent blacklist.  
   - Logs scanning results for future analysis or audits.

6. 📊 **User-Friendly Web Interface**  
   - Clean, responsive UI for input, result display, and scanning reports.  
   - Optional stats dashboard using charts and tables.

---

## 🧰 Tech Stack

| Component      | Technology         |
|----------------|--------------------|
| **Frontend**   | HTML, CSS, JavaScript |
| **Backend**    | Python (Flask)     |
| **Caching**    | Redis              |
| **Database**   | PostgreSQL (for logs/blacklist) |
| **APIs**       | VirusTotal API     |
| **Database Interaction** | SQLAlchemy|
| **IDE**        | VS Code            |

---

##   Future Scope

1. 🧠 **Advanced AI Integration**  
   - Enhance detection with **deep learning models** (e.g., LSTM, CNN) for higher precision.

3. ☁️ **Multi-cloud Deployment**  
   - Containerize and deploy the system on **AWS, GCP, or Azure** for enterprise scalability.

4. ⚙️ **Automated Threat Response**  
   - Implement automatic actions like **IP blocking, firewall updates**, or **session termination**.

---

## 🚀 How to Run Locally

```bash
git clone https://github.com/your-username/your-idps-project.git
cd your-idps-project
pip install -r requirements.txt
python app.py
