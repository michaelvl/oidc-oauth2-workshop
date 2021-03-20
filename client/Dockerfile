FROM python:3.9.0-buster

RUN pip install --upgrade pip

COPY requirements.txt /usr/src/app/
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt

COPY app /usr/src/app/
WORKDIR /usr/src/app/

EXPOSE 5001

ENTRYPOINT ["python", "/usr/src/app/app.py"]
