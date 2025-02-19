# Auth Service

This is a Django-based authentication service that provides user registration, login, OTP verification, and password reset functionalities.

## Features

- User Registration
- User Login with OTP
- Email Verification with OTP
- Password Reset
- User Profile Update
- Admin User Management
- JWT Authentication
- Swagger API Documentation

## Requirements

- Python 3.10.12
- Django 5.1.6
- PostgreSQL
- Redis (for Celery)
- Pytest

## Installation

1. Clone the repository:
    ```
    git clone https://github.com/sanket9018/auth_service
    cd auth_service
    ```

2. Create and activate a virtual environment:
    ```
    python3 -m venv env
    source env/bin/activate
    ```

3. Install the dependencies:
    ```
    pip install -r requirements.txt
    ```
<!-- 
4. Set up the environment variables:
    ```sh
    cp auth_service/.env-sample auth_service/.env
    ``` -->

4. Update the `.env` file with your database and email configurations.

5. Apply the migrations:
    ```
    python manage.py migrate
    ```

7. Create a superuser:
    ```
    python manage.py createsuperuser
    ```

8. Run the development server:
    ```
    python manage.py runserver
    ```

## Running Tests

To run the tests, use the following command:
go to project dir: auth_service 
```
pytest user/tests/ -v
```

## API Endpoints

The API endpoints are documented using Swagger. You can access the documentation at:
```
http://127.0.0.1:8000/swagger/
```

## Project Structure

```
auth_service/
├── auth_service/
│   ├── __init__.py
│   ├── asgi.py
│   ├── celery.py
│   ├── settings.py
│   ├── urls.py
│   ├── wsgi.py
├── user/
│   ├── __init__.py
│   ├── admin.py
│   ├── apps.py
│   ├── decorators.py
│   ├── migrations/
│   ├── models.py
│   ├── serializers.py
│   ├── templates/
│   ├── tests/
│   ├── urls.py
│   ├── views.py
├── manage.py
├── requirements.txt
├── pytest.ini
├── README.MD
```

## Contact

For any inquiries, please contact [sanket.dev025@gmail.com]
