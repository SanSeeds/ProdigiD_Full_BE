# Use an official Python runtime as the base image
FROM python:3.12.2-slim-bullseye

# Set the working directory inside the container
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create a virtual environment
RUN python -m venv /opt/venv

# Ensure the virtual environment is used for subsequent commands
ENV PATH="/opt/venv/bin:$PATH"

# Install setuptools, wheel, and pip inside the virtual environment
RUN pip install --upgrade pip setuptools wheel

# Copy only the requirements file first (to leverage Docker caching)
COPY requirements.txt /app/

# Install Python dependencies inside the virtual environment
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the project code
COPY . .

# Expose the default Django port
EXPOSE 8000

# Set the default command to run the Django development server
CMD ["python", "manage.py", "runserver", "127.0.0.1:8000"]
