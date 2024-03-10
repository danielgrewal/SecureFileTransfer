FROM python:latest

# Set /app as the working directory within the container
WORKDIR /app

# Copy code from context folder into /app folder within the container
COPY . /app

# Install dependencies listed in requirements.txt. 
RUN pip install --no-cache-dir -r requirements.txt

# Run server using uvicorn
CMD uvicorn server:app --reload --host 0.0.0.0 --port 443 --ssl-keyfile ./certificates/localhost-key.pem --ssl-certfile ./certificates/localhost-cert.pem 
