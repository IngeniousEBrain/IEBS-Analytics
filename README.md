# IEBS Analytics Tool

Brief project description and purpose.

## Table of Contents
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## Requirements
Specify the dependencies and requirements needed to run the project. For example:
- Python 3.12
- Django 5
- Postgresql

## Installation
1. Clone the repository:
    ```bash
    git clone https://github.com/IngeniousEBrain/IEBS-Analytics.git
    cd your-project
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
```env
SECRET_KEY=your_secret_key
DEBUG=True
DATABASE_NAME =
DATABASE_PASSWORD =
etc ..
```
4. run docker build command
```
 docker-compose up --build
```
