FROM python:3.10-slim-buster

# Set the working directory in the container
WORKDIR /app

# Copy only the requirements file first
COPY requirements.txt ./requirements.txt

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy the rest of the project files into the working directory
COPY . .

# Expose the default Django port
EXPOSE 8000

# Command to run the Django development server
CMD ["python3.10", "manage.py", "runserver"]
