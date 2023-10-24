
## Project Overview:
The project is a Django REST Framework (DRF) application designed for managing user profiles, family details, and creating meal plans. 
It focuses on ensuring data privacy by storing all member details in encrypted form. 

## Getting Started

These instructions will help you set up and run the project on your local machine.

### Prerequisites

List any prerequisites required to run the project, such as Python and Django versions, dependencies, or other software.

### Installation

A step-by-step guide to installing your project.

1. Create a virtual environment:
python -m venv venv

2. Activate the virtual environment:
On Windows:
venv\Scripts\activate

OnLinux:
source venv/bin/activate

3. Install project dependencies:
pip install -r requirements.txt

4. Apply database migrations:
python manage.py makemigrations
python manage.py migrate

5. Start the development server:
python manage.py runserver




