# IEBS Analytics Tool

This project involves developing a system to streamline patent data analysis and visualization for improved business insights. The core functionality includes:

- 1.Patent Data Ingestion: An automated process will extract patent details contained in Excel files and load this data into a custom-built relational             database. Fields will include patent number, filing date, inventor(s), current assignee, technology classification, etc. Validation checks during         ingestion will help ensure data quality and integrity.
- 2.Patent Analytics & Visualizations: The stored patent data will feed into a suite of interactive visualizations designed to provide actionable insights         for business managers, IP attorneys and administrative teams. Dashboards will provide high-level patent portfolio analytics by timeframe,                 technology type, geography, assignee and more. Customizable reports and charts will enable users to dig deeper into patent trends and performance         metrics relevant to strategic and operational objectives.
- 3.Modular & Scalable Architecture: The backend will employ a modular microservices design, enabling smooth scaling with data volume increases while             maintaining system stability and performance. The frontend will provide a user-friendly interface to access and configure dashboards, reports and         visualizations with ease.
- 4.Cloud-Based Delivery: The solution employs a cloud-native implementation model for reliability and accessibility. Users can access insights securely          from anywhere via desktop or mobile browser. Regular cloud-based backups will prevent data loss.
      The project aims to increase productivity in analyzing volumes of patent data, while equipping leadership with impactful business insights on IP          dynamics. The easy-to-use visualization interfaces will lead to data-driven decision making for current patent portfolio strategy as well as 
      guidance for future filings based on technological and competitive trends.

## Table of Contents
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Contributing](#contributing)


## Requirements
Specify the dependencies and requirements needed to run the project. For example:
- Python 3.12
- Django 5
- Postgresql  

## Installation
1. Clone the repository:
    ```bash
    git clone https://github.com/IngeniousEBrain/IEBS-Analytics.git
    cd IEBS-Analytics
    ```

2. Create a virtual environment on python 3.12 and activate it:
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use: venv\Scripts\activate
    ```

3. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Configuration
ENVFILE FOR LOCALHOST:
```env
DEBUG=True/False
SECRET_KEY=''
DB_ENGINE='django.db.backends.postgresql'
DB_NAME='iebs_analytics'
DB_USER='postgres'
DB_PASSWORD=''
#DB_HOST=''
DB_HOST='localhost'
DB_PORT='5432'
```
4. run docker build command
```
 docker-compose up --build
```

# Contributing
Fork the project.
- Create a new branch (git checkout -b feature/your-feature).
- Commit your changes (git commit -am 'Add new feature').
- Push to the branch (git push origin feature/your-feature).
- Create a new pull request.

