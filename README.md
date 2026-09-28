# 🛡️ CyberSentinel X

### AI-Powered Autonomous Cyber Defense, Threat Intelligence & SOC Intelligence Platform

CyberSentinel X is a cybersecurity intelligence and monitoring platform designed to help users explore vulnerabilities, monitor security-related activities, and understand potential risks through a centralized dashboard.

## 📌 Project Overview

CyberSentinel X is an academic cybersecurity project that combines vulnerability intelligence, CVE search, audit log monitoring, and risk prioritization in a single web application. It aims to simplify access to cybersecurity information and support security awareness and learning.

## ✨ Key Features

* **Vulnerability Intelligence:** Search and retrieve publicly available CVE information using the National Vulnerability Database (NVD) API.
* **CVE Search:** Search vulnerabilities using CVE identifiers and view their details.
* **Saved CVE Inventory:** Save, view, filter, and delete selected vulnerability records.
* **Risk Prioritization:** Organize vulnerabilities using factors such as CVSS severity, asset importance, internet exposure, and exploitability.
* **Audit Logs:** View and search recorded user and system activities.
* **Security Dashboard:** Access cybersecurity information through a centralized interface.
* **Explainable Prioritization:** Display risk factors to help users understand vulnerability priority.

## 🧰 Technology Stack

* **Frontend:** React, TypeScript
* **Build Tool:** Vite
* **Styling:** Tailwind CSS
* **Backend:** Node.js, Express
* **Database:** SQLite
* **API Integration:** National Vulnerability Database (NVD) API
* **Development Environment:** Visual Studio Code

## 🏗️ System Architecture

CyberSentinel X uses a web-based architecture consisting of a frontend interface, application services, backend components, and database support.

The frontend provides the user interface and displays cybersecurity information. Application services handle API communication and relevant data operations. Backend and database components support the application's server-side functionality.

## 📂 Project Structure

```text
cybersentinel-x/
├── src/
│   ├── components/
│   ├── pages/
│   ├── services/
│   └── ...
├── server/
├── public/
├── package.json
├── package-lock.json
├── vite.config.ts
├── README.md
└── .gitignore
```

*Note: This is a representative structure. The actual project folders may differ.*

## ⚙️ Installation and Setup

### Prerequisites

Make sure the following tools are installed:

* Node.js
* npm
* Visual Studio Code
* Git (optional)

### 1. Clone the Repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
```

### 2. Navigate to the Project Folder

```bash
cd cybersentinel-x
```

### 3. Install Dependencies

```bash
npm install
```

If dependency compatibility issues occur, use the installation command specified for the project.

### 4. Start the Development Server

```bash
npm run dev
```

Open the local URL displayed in the terminal in your browser.

### 5. Build the Application

```bash
npm run build
```

If the build completes successfully, the production output is generated in the `dist` directory.

## 🔍 Vulnerability Intelligence

The Vulnerability Intelligence module uses the National Vulnerability Database (NVD) API to retrieve publicly available vulnerability information.

Users can search for CVEs, review vulnerability details, and save selected records to a personal inventory within the application. Saved records may be stored in browser local storage.

## 📊 Risk Prioritization

The platform organizes vulnerability information using security-related factors such as:

* **CVSS Severity:** The reported severity of a vulnerability.
* **Asset Importance:** The importance of the affected asset.
* **Internet Exposure:** Whether the asset is exposed to the internet.
* **Exploitability:** The potential ease of exploiting the vulnerability.

These factors support vulnerability review and prioritization. The displayed results should not be treated as a substitute for a formal security assessment.

## 📋 Audit Logs

The Audit Logs module provides an interface to review and search recorded activities. It helps users inspect available audit information and understand activity records within the application.

## 🔐 Security and Privacy

* Do not commit API keys, passwords, access tokens, or sensitive configuration files.
* Keep secrets in a local `.env` file and exclude it from version control.
* Review database contents before sharing project files.
* Avoid uploading personal information or confidential logs to public repositories.
* Perform security testing only on systems for which you have authorization.

## 🧪 Testing

Before presenting or deploying the application, perform the following checks:

1. Install project dependencies.
2. Start the development server.
3. Verify that the dashboard and application pages load.
4. Test CVE search functionality.
5. Verify saving, filtering, and deleting CVE records.
6. Test audit log search and filtering.
7. Run the production build and review any errors.

## 🚀 Future Enhancements

The following are potential future improvements:

* Integrate additional threat intelligence sources.
* Expand vulnerability reporting and export options.
* Add role-based access control.
* Enhance security event analysis.
* Improve dashboards and reporting.
* Expand automated testing and deployment support.

*These are proposed enhancements and may not be implemented in the current version.*

## 🎯 Project Objectives

* Provide a centralized cybersecurity intelligence interface.
* Make vulnerability information easier to search and review.
* Support cybersecurity education and awareness.
* Demonstrate the use of modern web development technologies.
* Encourage explainable and responsible defensive security practices.

## ⚠️ Disclaimer

CyberSentinel X is intended for educational, research, and authorized defensive cybersecurity purposes. It is not a replacement for professional security assessments. Vulnerability information and prioritization results should be independently verified before operational use.

## 👩‍💻 Author

**Praveena Gunasekaran**
B.Sc. Digital and Cyber Forensic Science

## 📄 License

No license has been specified yet. Add a `LICENSE` file before distributing or permitting reuse of this project.
